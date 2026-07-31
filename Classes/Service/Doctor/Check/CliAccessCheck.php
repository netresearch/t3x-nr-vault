<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor\Check;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\DocsLink;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
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
            ];
        }

        return [
            $this->checkAccessEnabled($context),
            $this->checkAccessGroups(),
        ];
    }

    /**
     * CLI access is on — is that acceptable for the target profile?
     *
     * A pass under the standard profile: a deployment pipeline that stores
     * credentials needs this, and calling it a defect would make the check noise.
     * A warning under hardened, where every read is supposed to be attributable
     * to a named actor and a bare CLI actor is not.
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

        return Finding::warning(
            id: $id,
            summary: 'CLI access to secrets is enabled under the hardened profile.',
            risk: 'Anyone with a shell on the host can read secrets without authenticating as a backend '
                . 'user. The audit trail records the operation but attributes it to the CLI actor, so it '
                . 'cannot name the human responsible.',
            remediation: 'Prefer the technical-actor API (TechnicalActorContext::runAs()) so headless '
                . 'reads are attributed to a named backend user, then disable "allowCliAccess". If the '
                . 'switch must stay on, restrict "cliAccessGroups" to the smallest possible group set.',
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
