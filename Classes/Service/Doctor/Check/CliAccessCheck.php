<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor\Check;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Service\Doctor\DocsLink;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Service\Doctor\ReadinessCheckInterface;

/**
 * Who can read secrets from a shell?
 *
 * `allowCliAccess` is the one switch that grants vault permissions to an actor
 * with no backend user behind it. It exists because deployment scripts need to
 * store credentials, but it is also the widest grant in the extension: a shell on
 * the box becomes read access to every secret whose per-secret ACL admits the CLI
 * actor.
 *
 * Off by default, so the finding here is about a deliberate opt-in that may have
 * outlived the deployment step it was added for — and about the second, easier
 * mistake: turning it on and leaving the group restriction empty.
 *
 * The group also carries `frontendPlaceholderLegacyCli`, the other command-line
 * opt-in that widens what a shell reaches. It is INDEPENDENT of `allowCliAccess`
 * — {@see \Netresearch\NrVault\Security\FrontendPlaceholderPolicy} consults only
 * its own flag — so it is reported whether or not CLI access is granted.
 */
final readonly class CliAccessCheck implements ReadinessCheckInterface
{
    public function __construct(
        private ExtensionConfigurationInterface $configuration,
    ) {}

    public function getId(): string
    {
        return 'cli';
    }

    public function appliesTo(SecurityProfile $profile): bool
    {
        return true;
    }

    public function run(DoctorContext $context): array
    {
        $allowed = $this->configuration->isCliAccessAllowed();

        if (!$allowed) {
            return [
                Finding::pass(
                    id: 'cli.access',
                    summary: 'CLI access to secrets is disabled.',
                    docsUrl: DocsLink::ACCESS_CONTROL,
                    details: ['allowCliAccess' => false],
                ),
                // Reported here too, not only below: the two settings are
                // independent. FrontendPlaceholderPolicy::isLegacyContext()
                // consults isLegacyCliEnabled() and nothing else, so the legacy
                // bypass is fully live on an installation with allowCliAccess
                // off — which is the default, i.e. exactly the installations
                // this branch serves.
                $this->checkFrontendPlaceholderLegacy($context),
            ];
        }

        return [
            $this->checkAccessEnabled($context),
            $this->checkAccessGroups(),
            $this->checkAllowedOperations(),
            $this->checkFrontendPlaceholderLegacy($context),
        ];
    }

    /**
     * Does a command-line render still resolve any placeholder an editor wrote?
     *
     * `frontendPlaceholderLegacyCli` is not part of the `allowCliAccess` grant
     * and is not gated by it — it selects the pre-ADR-035 CLI *mode*, in which
     * the frontend placeholder allow-set is not enforced at all. What it
     * re-opens is concrete: `scheduler:run` authenticates the `_cli_`
     * administrator, so the admin bypass already grants the read, and the
     * allow-set is the only remaining gate between an editor-authored
     * `tt_content` field and a secret in a newsletter or export job's output.
     *
     * Warning under the standard profile rather than a pass: unlike
     * `allowCliAccess` there is no workflow that needs this and cannot be served
     * by publishing the identifier instead, so it is a genuine finding wherever
     * it is on. Critical under hardened, where an editor-reachable resolution
     * site is a broken promise rather than a documented trade-off.
     */
    private function checkFrontendPlaceholderLegacy(DoctorContext $context): Finding
    {
        $id = 'cli.frontend_placeholder_legacy';
        $enabled = $this->configuration->isFrontendPlaceholderLegacyCliEnabled();
        $details = ['frontendPlaceholderLegacyCli' => $enabled];

        if (!$enabled) {
            return Finding::pass(
                id: $id,
                summary: 'Command-line renders enforce the frontend placeholder allow-set.',
                docsUrl: DocsLink::FRONTEND_PLACEHOLDER_LEGACY_CLI,
                details: $details,
            );
        }

        $finding = Finding::warning(
            id: $id,
            summary: 'Legacy CLI placeholder resolution is enabled, so command-line renders resolve '
                . 'every frontend-accessible %vault(id)% placeholder regardless of who authored it.',
            risk: 'The allow-set is switched off for command-line renders, which restores the exposure '
                . 'it was added to close. "scheduler:run" authenticates the _cli_ administrator, so the '
                . 'admin bypass grants the read whatever the per-secret tiers say, and a scheduled '
                . 'newsletter or export job that renders editor-authored tt_content through stdWrap() '
                . 'then substitutes any frontend-accessible secret an editor can name. Where that '
                . 'output goes — a subscriber mail, a file, an HTTP callback — is outside the vault\'s '
                . 'knowledge, so the setting has to be read as re-opening the path, not as narrowing '
                . 'it to a safe one.',
            remediation: 'Publish the identifiers the render jobs legitimately need — one '
                . 'plugin.tx_nrvault.frontendResolvableIdentifiers line, an entry in site configuration, '
                . 'or one FrontendPlaceholderPolicyInterface::allowIdentifier() call in the job — then '
                . 'turn "frontendPlaceholderLegacyCli" off and pin it in config/system/additional.php '
                . 'via $GLOBALS[TYPO3_CONF_VARS][SYS][nrVault][frontendPlaceholderLegacyCli] so a '
                . 'backend admin cannot tick it back on.',
            docsUrl: DocsLink::FRONTEND_PLACEHOLDER_LEGACY_CLI,
            details: $details,
        );

        // Same observation, same wording, one severity apart — so a
        // `--profile=hardened` dry run is comparable to the live report line
        // for line, which is what escalatedTo() exists for.
        return $context->isHardened()
            ? $finding->escalatedTo(FindingSeverity::Critical)
            : $finding;
    }

    /**
     * CLI access is on — is that acceptable for the target profile?
     *
     * A pass under the standard profile: a deployment pipeline that stores
     * credentials needs this, and calling it a defect would make the check noise.
     * A CRITICAL under hardened: that profile promises every operation is
     * attributable to a named actor, and a bare CLI actor is by construction
     * not — the promise is broken as long as the switch is on.
     */
    private function checkAccessEnabled(DoctorContext $context): Finding
    {
        $id = 'cli.access';
        $details = ['allowCliAccess' => true];

        if (!$context->isHardened()) {
            return Finding::pass(
                id: $id,
                summary: 'CLI access to secrets is enabled (required for deployment automation).',
                docsUrl: DocsLink::ACCESS_CONTROL,
                details: $details,
            );
        }

        return Finding::critical(
            id: $id,
            summary: 'Unattributed CLI access to secrets is enabled under the hardened profile.',
            risk: 'Anyone with a shell on the host can use secrets without authenticating as a backend '
                . 'user. The audit trail records the operation but attributes it to the anonymous CLI '
                . 'actor, so it cannot name the human responsible — the hardened profile\'s '
                . 'attributability promise does not hold while this switch is on.',
            remediation: 'Use the technical-actor API (TechnicalActorContext::runAs()) so headless '
                . 'operations are attributed to a named backend user, then disable "allowCliAccess". '
                . 'While migrating, restrict "cliAccessGroups" and keep "cliAllowedOperations" minimal.',
            docsUrl: DocsLink::ACCESS_CONTROL,
            details: $details,
        );
    }

    /**
     * Which operations does the unattributed CLI actor actually hold?
     *
     * The allowlist defaults to `secret.use,secret.create,secret.rotate`. Every
     * high-risk operation present is called out; unknown tokens are reported too
     * — a typo in the list silently revokes the grant the operator believes is
     * configured.
     *
     * "High-risk" is the set that hands a shell more than the deployment step
     * the switch exists for. Two of them are less obvious than the rest and were
     * missing here while being listed as `$known`, so an allowlist containing
     * them read as a clean pass:
     *
     *  - `secret.manage_policy` edits `allowed_groups` / `write_groups`, i.e.
     *    the permission that governs the permissions
     *    ({@see VaultPermission::SecretManagePolicy}). A shell holding it can
     *    widen its own per-secret reach and the widening looks like ordinary
     *    configuration afterwards.
     *  - `audit.view` reads the trail rather than the secrets, but the trail
     *    maps the credential topology ({@see VaultPermission::AuditView}) and
     *    the hardened deployment guide already treats it as an explicit opt-in.
     */
    private function checkAllowedOperations(): Finding
    {
        $id = 'cli.allowed_operations';
        $operations = $this->configuration->getCliAllowedOperations();

        $known = array_map(
            static fn (VaultPermission $permission): string => $permission->value,
            VaultPermission::cases(),
        );
        $highRisk = [
            'secret.reveal',
            'secret.delete',
            'secret.manage_policy',
            'audit.view',
            'audit.export',
            'master_key.rotate',
            'vault.configure',
        ];

        $unknown = array_values(array_diff($operations, $known));
        $risky = array_values(array_intersect($operations, $highRisk));

        $details = [
            'cliAllowedOperations' => implode(',', $operations),
            'highRisk' => implode(',', $risky),
            'unknown' => implode(',', $unknown),
        ];

        if ($risky === [] && $unknown === []) {
            return Finding::pass(
                id: $id,
                // Not "low-risk": the remaining defaults are not harmless
                // writes. secret.create makes the CLI actor the OWNER of what
                // it creates, which is privilege-widening, and secret.rotate
                // substitutes a credential the operator's own systems then
                // use. The pass says the list holds nothing that needs an
                // explicit opt-in — not that its contents are inert.
                summary: \sprintf(
                    'The CLI operation allowlist holds no operation that needs an explicit opt-in: '
                    . '%d automation operation(s) (%s). That is a scoped grant, not a harmless one — '
                    . 'everything listed is available to anyone with a shell on this host, under an '
                    . 'actor the audit trail cannot name.',
                    \count($operations),
                    implode(', ', $operations),
                ),
                docsUrl: DocsLink::ACCESS_CONTROL,
                details: $details,
            );
        }

        $summaryParts = [];
        if ($risky !== []) {
            $summaryParts[] = \sprintf('grants high-risk operation(s) %s to the unattributed CLI actor', implode(', ', $risky));
        }

        if ($unknown !== []) {
            $summaryParts[] = \sprintf('contains unknown value(s) %s', implode(', ', $unknown));
        }

        return Finding::warning(
            id: $id,
            summary: 'The "cliAllowedOperations" list ' . implode(' and ', $summaryParts) . '.',
            risk: 'High-risk operations let anyone with a shell reveal plaintext, delete secrets, walk '
                . 'off with the audit history or rewrite every key envelope — without a named actor in '
                . 'the audit trail. "secret.manage_policy" is the widest of them in the long run: it '
                . 'edits allowed_groups and write_groups, so it is the permission that governs the '
                . 'permissions — a shell can widen its own per-secret reach to secrets the current ACLs '
                . 'do not admit it to, and the widened tiers read as ordinary configuration afterwards. '
                . '"audit.view" grants no secret access at all, but the trail it opens names who touched '
                . 'which identifier when: it maps the credential topology, and it is also where the '
                . "shell's own activity is recorded, so it is reconnaissance handed to the actor the "
                . 'log exists to catch. Unknown values do nothing: the grant the operator believes is '
                . 'configured is silently absent.',
            remediation: 'Remove the high-risk operations from "cliAllowedOperations" (use a named '
                . 'technical actor for those workflows) and fix any typo — valid values are the '
                . 'tx_nrvault permission identifiers, e.g. secret.use, secret.create, secret.rotate. '
                . 'Where a scheduled control genuinely needs one — vault:audit-verify asserts '
                . 'audit.view, the orphan cleanup asserts secret.delete — grant it to a named backend '
                . 'group and run the job as a technical actor instead of widening this list.',
            docsUrl: DocsLink::ACCESS_CONTROL,
            details: $details,
        );
    }

    /**
     * Is the CLI grant scoped to specific groups?
     */
    private function checkAccessGroups(): Finding
    {
        $id = 'cli.access_groups';
        // Drop 0 entries: getCliAccessGroups() maps unparseable values to 0, and
        // group uid 0 does not exist — counting them would report a scoped grant
        // where the configuration actually holds junk.
        $groups = array_values(array_filter(
            $this->configuration->getCliAccessGroups(),
            static fn (int $groupUid): bool => $groupUid > 0,
        ));

        if ($groups === []) {
            return Finding::warning(
                id: $id,
                summary: 'CLI access is enabled but "cliAccessGroups" is empty, so the grant is unscoped.',
                risk: 'The CLI actor is not narrowed to any backend group, so its reach is whatever the '
                    . 'per-secret ACLs happen to allow the CLI context — in practice every secret that is '
                    . 'not owner-restricted. There is no group boundary left to review.',
                remediation: 'List the specific backend group UIDs the deployment identity belongs to in '
                    . '"cliAccessGroups", so an unrelated secret cannot be read from a shell.',
                docsUrl: DocsLink::ACCESS_CONTROL,
                details: ['cliAccessGroupCount' => 0],
            );
        }

        return Finding::pass(
            id: $id,
            summary: \sprintf('CLI access is scoped to %d backend group(s).', \count($groups)),
            docsUrl: DocsLink::ACCESS_CONTROL,
            details: ['cliAccessGroupCount' => \count($groups)],
        );
    }
}
