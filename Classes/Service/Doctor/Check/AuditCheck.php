<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor\Check;

use Netresearch\NrVault\Audit\Anchor\AnchorReaderInterface;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditChainAnchorStatus;
use Netresearch\NrVault\Audit\AuditChainAnchorStoreInterface;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Audit\Sink\SinkDeliveryState;
use Netresearch\NrVault\Audit\Sink\SinkDeliveryStateRepositoryInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\DocsLink;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Service\Doctor\ReadinessCheckInterface;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Is the audit trail being written, kept, verifiable, and witnessed externally?
 *
 * ## Why this check is bounded and `vault:audit-verify` is not
 *
 * The chain pass here covers only the newest {@see self::CHAIN_TAIL_SIZE}
 * entries, and the anchor comparison covers only chain *shrinkage* — not the
 * per-row hash substitution check. Both limits are deliberate: this check runs
 * inside a deployment gate and on every render of the backend status panel, and
 * a full-table HMAC recomputation on a multi-million-row audit log is not
 * something to put on a page load.
 *
 * The consequence is stated in the findings themselves: a passing
 * `audit.hash_chain` means "the recent tail verifies", never "the chain is
 * intact". {@see \Netresearch\NrVault\Command\VaultAuditVerifyCommand} is the
 * authoritative full-range verifier and belongs on a schedule. A gate that
 * silently implied full coverage would be worse than one that admits its scope.
 */
final readonly class AuditCheck implements ReadinessCheckInterface
{
    /**
     * Number of trailing audit entries the bounded chain pass covers.
     *
     * Large enough to catch a fresh tampering attempt (the attacker's own rows
     * are at the tip), small enough to stay cheap on a page load.
     */
    private const CHAIN_TAIL_SIZE = 1000;

    /**
     * Retention floor, in days, for a trail that has to survive an annual audit
     * cycle. Below this a reviewer cannot see the previous cycle's activity.
     */
    private const RETENTION_FLOOR_DAYS = 365;

    public function __construct(
        private ExtensionConfigurationInterface $configuration,
        private AuditLogServiceInterface $auditLogService,
        private AuditSinkRegistryInterface $sinkRegistry,
        private ChainTipAnchorServiceInterface $anchorService,
        private AnchorReaderInterface $anchorReader,
        /**
         * The IN-DATABASE tip anchor (`sys_registry`), which is a different
         * control from the sink-published one {@see $anchorReader} reads. Only
         * `load()` is ever called: the store's mutators are for the audit write
         * path, and a check that repaired what it inspects would report a pass
         * it had just created.
         */
        private AuditChainAnchorStoreInterface $anchorStore,
        private ConnectionPool $connectionPool,
        /**
         * Persisted per-sink delivery health. Optional so pre-existing test
         * constructions keep working; absent means the persisted-state
         * findings are simply not emitted.
         */
        private ?SinkDeliveryStateRepositoryInterface $deliveryState = null,
    ) {}

    public function getId(): string
    {
        return 'audit';
    }

    public function appliesTo(SecurityProfile $profile): bool
    {
        return true;
    }

    public function run(DoctorContext $context): array
    {
        $anchor = $this->anchorReader->readLatestAnchor();
        $currentSequence = $this->anchorService->capture()->sequence;

        return [
            $this->checkReadsLogged($context),
            $this->checkRetention(),
            $this->checkHashChain($currentSequence),
            $this->checkHmacEpoch(),
            $this->checkDatabaseAnchor($currentSequence),
            $this->checkExternalSink($context),
            $this->checkAnchor($context, $anchor, $currentSequence),
            $this->checkSinkFailures(),
            ...$this->checkPersistedDeliveryState($context),
        ];
    }

    /**
     * Has each enabled sink demonstrably accepted a record recently?
     *
     * The per-process counter below answers "did anything fail since this PHP
     * process started" — for a freshly started `vault:doctor` that is always
     * "no failures", which let a collector that has been unreachable for days
     * pass the gate. This check reads the PERSISTED delivery state
     * (sys_registry, written fail-safe by the sink registry) instead.
     *
     * @return list<Finding>
     */
    private function checkPersistedDeliveryState(DoctorContext $context): array
    {
        if (!$this->deliveryState instanceof SinkDeliveryStateRepositoryInterface) {
            return [];
        }

        $findings = [];
        $staleAfterSeconds = $this->configuration->getAuditSinkStaleDeliveryHours() * 3600;

        foreach ($this->sinkRegistry->getEnabledSinkIdentifiers() as $sinkIdentifier) {
            $findings[] = $this->deliveryFindingForSink(
                $context,
                $this->deliveryState->getState($sinkIdentifier),
                $staleAfterSeconds,
            );
        }

        return $findings;
    }

    private function deliveryFindingForSink(
        DoctorContext $context,
        SinkDeliveryState $state,
        int $staleAfterSeconds,
    ): Finding {
        $id = 'audit.sink_state.' . $state->sinkIdentifier;
        $details = $state->toArray();

        if ($state->isFailing()) {
            $summary = \sprintf(
                'Audit sink "%s" is failing: %d consecutive failure(s), last error: %s',
                $state->sinkIdentifier,
                $state->consecutiveFailures,
                $state->lastError !== '' ? $state->lastError : '(not recorded)',
            );
            $risk = 'Audit evidence is not reaching this external sink. The database copy is intact, '
                . 'but the external witness — the part that survives a table reset — has holes, and '
                . 'under the hardened profile the external-evidence promise is currently broken.';
            $remediation = 'Fix the sink (unreachable collector, full disk, unwritable path — see '
                . 'lastError), verify with vendor/bin/typo3 vault:doctor --active-probes, then '
                . 're-anchor with vendor/bin/typo3 vault:audit-anchor.';

            return $context->isHardened()
                ? Finding::critical(id: $id, summary: $summary, risk: $risk, remediation: $remediation, docsUrl: DocsLink::AUDIT_SINKS, details: $details)
                : Finding::warning(id: $id, summary: $summary, risk: $risk, remediation: $remediation, docsUrl: DocsLink::AUDIT_SINKS, details: $details);
        }

        if (!$state->hasEverSucceeded()) {
            $summary = \sprintf(
                'Audit sink "%s" is enabled but no successful delivery has been recorded yet.',
                $state->sinkIdentifier,
            );

            if (!$context->isHardened()) {
                return Finding::pass(
                    id: $id,
                    summary: $summary . ' Delivery state builds up as audit events flow.',
                    docsUrl: DocsLink::AUDIT_SINKS,
                    details: $details,
                );
            }

            return Finding::warning(
                id: $id,
                summary: $summary,
                risk: 'The sink is configured but has never demonstrably accepted a record — external '
                    . 'evidence is assumed, not proven.',
                remediation: 'Run vendor/bin/typo3 vault:doctor --active-probes to push a chain-tip '
                    . 'anchor through every enabled sink and confirm end-to-end delivery.',
                docsUrl: DocsLink::AUDIT_SINKS,
                details: $details,
            );
        }

        $age = max(0, time() - $state->lastSuccessAt);
        if ($age > $staleAfterSeconds) {
            $summary = \sprintf(
                'Audit sink "%s": last successful delivery is %d hour(s) old (threshold: %d).',
                $state->sinkIdentifier,
                intdiv($age, 3600),
                intdiv($staleAfterSeconds, 3600),
            );
            $risk = 'No record has demonstrably reached this sink within the configured window. Either '
                . 'no audit events occurred — or evidence has silently stopped flowing.';
            $remediation = 'Verify end-to-end delivery with vendor/bin/typo3 vault:doctor '
                . '--active-probes; if the probe fails, fix the sink and re-anchor. Adjust '
                . '"auditSinkStaleDeliveryHours" if the installation is genuinely this quiet.';

            return $context->isHardened()
                ? Finding::critical(id: $id, summary: $summary, risk: $risk, remediation: $remediation, docsUrl: DocsLink::AUDIT_SINKS, details: $details)
                : Finding::warning(id: $id, summary: $summary, risk: $risk, remediation: $remediation, docsUrl: DocsLink::AUDIT_SINKS, details: $details);
        }

        return Finding::pass(
            id: $id,
            summary: \sprintf(
                'Audit sink "%s" last accepted a record %d minute(s) ago.',
                $state->sinkIdentifier,
                intdiv($age, 60),
            ),
            docsUrl: DocsLink::AUDIT_SINKS,
            details: $details,
        );
    }

    /**
     * Are reads written to the audit log?
     *
     * Reads are the operation that matters most in an audit: a stolen credential
     * is *read*, not written. With `auditReads` off, the trail records who
     * created a secret and never who used it.
     */
    private function checkReadsLogged(DoctorContext $context): Finding
    {
        $id = 'audit.reads_logged';

        if ($this->configuration->isAuditReadsEnabled()) {
            return Finding::pass(
                id: $id,
                summary: 'Read access is written to the audit log.',
                docsUrl: DocsLink::AUDIT_LOGGING,
            );
        }

        $finding = Finding::warning(
            id: $id,
            summary: 'Read access is NOT written to the audit log (auditReads is disabled).',
            risk: 'The trail records who created and rotated secrets but not who consumed them. '
                . 'Credential misuse — the case audit logging exists for — leaves no record at all.',
            remediation: 'Enable "auditReads", and pin it out of admin reach in '
                . 'config/system/additional.php '
                . '($GLOBALS[TYPO3_CONF_VARS][SYS][nrVault][auditReads] = true) so it cannot be '
                . 'silenced from the backend Settings module.',
            docsUrl: DocsLink::AUDIT_LOGGING,
            details: ['auditReads' => false],
        );

        // Under the hardened profile an unattributable read is not hygiene, it is
        // the profile failing to deliver the thing it exists for.
        return $context->isHardened()
            ? $finding->escalatedTo(FindingSeverity::Critical)
            : $finding;
    }

    /**
     * Will the trail still be there when someone comes to read it?
     *
     * `0` means "keep forever", which is the safest setting for an audit trail
     * and therefore a pass — the finding only fires for a retention window too
     * short to cover a review cycle.
     */
    private function checkRetention(): Finding
    {
        $id = 'audit.retention';
        $days = $this->configuration->getAuditLogRetention();

        if ($days === 0) {
            return Finding::pass(
                id: $id,
                summary: 'Audit entries are retained indefinitely.',
                docsUrl: DocsLink::AUDIT_LOGGING,
                details: ['retentionDays' => 0],
            );
        }

        if ($days < 0) {
            return Finding::warning(
                id: $id,
                summary: \sprintf('Audit log retention is a negative value (%d days).', $days),
                risk: 'The value is not a meaningful retention window; purge behaviour is undefined.',
                remediation: \sprintf(
                    'Set "auditLogRetention" to 0 (keep forever) or to at least %d days.',
                    self::RETENTION_FLOOR_DAYS,
                ),
                docsUrl: DocsLink::AUDIT_LOGGING,
                details: ['retentionDays' => $days],
            );
        }

        if ($days < self::RETENTION_FLOOR_DAYS) {
            return Finding::warning(
                id: $id,
                summary: \sprintf('Audit entries are kept for %d days.', $days),
                risk: \sprintf(
                    'Shorter than a %d-day review cycle, so a reviewer cannot see the previous '
                    . 'cycle\'s access. It also shortens the window in which a slow-burn credential '
                    . 'misuse is still reconstructable.',
                    self::RETENTION_FLOOR_DAYS,
                ),
                remediation: \sprintf(
                    'Raise "auditLogRetention" to at least %d, or to 0 to keep entries indefinitely. '
                    . 'If a shorter window is a data-protection requirement, record that decision — the '
                    . 'purge is legitimate but it does remove evidence.',
                    self::RETENTION_FLOOR_DAYS,
                ),
                docsUrl: DocsLink::AUDIT_LOGGING,
                details: ['retentionDays' => $days],
            );
        }

        return Finding::pass(
            id: $id,
            summary: \sprintf('Audit entries are kept for %d days.', $days),
            docsUrl: DocsLink::AUDIT_LOGGING,
            details: ['retentionDays' => $days],
        );
    }

    /**
     * Does the newest slice of the hash chain still verify?
     */
    private function checkHashChain(int $currentSequence): Finding
    {
        $id = 'audit.hash_chain';

        if ($currentSequence === 0) {
            return Finding::pass(
                id: $id,
                summary: 'The audit log is empty; there is no hash chain to verify yet.',
                docsUrl: DocsLink::AUDIT_HASH_CHAIN,
                details: ['currentSequence' => 0],
            );
        }

        $fromUid = max(1, $currentSequence - self::CHAIN_TAIL_SIZE + 1);
        $result = $this->auditLogService->verifyHashChain($fromUid);

        $details = [
            'fromUid' => $fromUid,
            'toUid' => $currentSequence,
            'errorCount' => $result->getErrorCount(),
            'missingUidCount' => $result->missingUidCount,
        ];

        if (!$result->isValid()) {
            return Finding::critical(
                id: $id,
                summary: \sprintf(
                    'Hash chain verification failed on %d of the last %d audit entries (uid %d..%d)%s.',
                    $result->getErrorCount(),
                    $currentSequence - $fromUid + 1,
                    $fromUid,
                    $currentSequence,
                    $result->hasMissingUids()
                        ? \sprintf('; %d uid(s) missing from the sequence', $result->missingUidCount)
                        : '',
                ),
                risk: 'Stored audit rows no longer match their own HMACs, or rows were deleted from the '
                    . 'sequence. Either way the trail currently proves nothing. A missing uid is the '
                    . 'signature of a deletion whose successor row had its previous_hash patched — the '
                    . 'one attack the per-row check alone cannot see.',
                remediation: 'Run vendor/bin/typo3 vault:audit-verify for the full-range report and the '
                    . 'reason codes (HASH_MISMATCH / UID_GAP / EPOCH_DOWNGRADE). Reconcile any gap '
                    . 'against a documented purge before assuming it is benign. Do not re-seal the chain '
                    . 'first — re-sealing launders the tampering into a valid chain.',
                docsUrl: DocsLink::AUDIT_HASH_CHAIN,
                details: $details,
            );
        }

        return Finding::pass(
            id: $id,
            summary: \sprintf(
                'The last %d audit entries (uid %d..%d) verify against the hash chain. Full-range '
                . 'verification is vault:audit-verify.',
                $currentSequence - $fromUid + 1,
                $fromUid,
                $currentSequence,
            ),
            docsUrl: DocsLink::AUDIT_HASH_CHAIN,
            details: $details,
        );
    }

    /**
     * Is the chain keyed at all?
     *
     * `auditHmacEpoch = 0` is a single integer that switches off three separate
     * controls, and until this finding existed none of them said so:
     *
     *  1. rows are hashed with plain SHA-256 instead of HMAC-SHA256, so the
     *     chain needs no key to recompute;
     *  2. the epoch-downgrade floor in
     *     {@see AuditLogServiceInterface::verifyHashChain()} defaults to the
     *     CONFIGURED epoch, so at 0 no chain can fall below it;
     *  3. {@see AuditChainAnchorStoreInterface::isEnabled()} is `epoch >= 1`, so
     *     the in-DB tip anchor is never read, written or verified.
     *
     * Critical under both profiles: the standard profile does not promise an
     * external witness, but it does promise a tamper-evident chain, and at
     * epoch 0 there is none. The shipped default is 3.
     */
    private function checkHmacEpoch(): Finding
    {
        $id = 'audit.hmac_epoch';
        $epoch = $this->configuration->getAuditHmacEpoch();
        $details = [
            'auditHmacEpoch' => $epoch,
            'auditAnchorRequired' => $this->configuration->isAuditAnchorRequired(),
        ];

        if ($epoch >= 1) {
            return Finding::pass(
                id: $id,
                summary: \sprintf(
                    'Audit chain HMAC epoch is %d: rows are HMAC-signed, the epoch-downgrade floor '
                    . 'is armed, and the in-DB tip anchor is active.',
                    $epoch,
                ),
                docsUrl: DocsLink::AUDIT_HMAC_EPOCH,
                details: $details,
            );
        }

        return Finding::critical(
            id: $id,
            summary: \sprintf(
                'Audit HMAC epoch is %d: the audit log hash chain is keyless.',
                $epoch,
            ),
            risk: 'One setting disables three controls at once. (1) Audit rows carry a plain SHA-256 '
                . 'hash instead of an HMAC, so anyone with database write access can alter entries and '
                . 'recompute a fully self-consistent chain without holding any key. (2) The '
                . 'epoch-downgrade floor equals the configured epoch, so at 0 there is nothing left for '
                . 'a relabelled chain to fall below and the downgrade check can never fire. (3) The '
                . 'in-DB chain-tip anchor in sys_registry is switched off, so a tail truncation or a '
                . 'full wipe of tx_nrvault_audit_log leaves a chain that still verifies as valid.',
            remediation: 'Set "auditHmacEpoch" to 3, re-sign the existing entries with '
                . 'vendor/bin/typo3 vault:audit-migrate-hmac (or the install-tool "Migrate audit hash '
                . 'chain" wizard), then arm the anchor with vendor/bin/typo3 vault:audit '
                . '--reset-anchor.',
            docsUrl: DocsLink::AUDIT_HMAC_EPOCH,
            details: $details,
        );
    }

    /**
     * Is the IN-DATABASE tip anchor there, and does it authenticate?
     *
     * Distinct from `audit.anchor`, which covers the anchor published to the
     * external sinks. This one is the `sys_registry` assertion that commits in
     * the same transaction as the audit row it describes — and no doctor control
     * looked at it before: `audit.hash_chain` verifies a BOUNDED range, and
     * {@see AuditLogServiceInterface::verifyHashChain()} evaluates the anchor
     * only on a full-range pass, so the anchor status reaching this check via
     * the chain result is permanently `NotChecked`. A deleted anchor row was
     * therefore invisible to `vault:doctor` even at the default epoch.
     *
     * Scope, stated the same way `audit.hash_chain` states its own: a pass here
     * means the anchor exists and its MAC verifies under the current master key.
     * Whether the anchored ROW still carries the anchored hash is the deep
     * comparison in `vault:audit-verify`; duplicating it here would put a second
     * implementation of it on a page load.
     */
    private function checkDatabaseAnchor(int $currentSequence): Finding
    {
        $id = 'audit.db_anchor';
        $required = $this->configuration->isAuditAnchorRequired();
        $epoch = $this->configuration->getAuditHmacEpoch();
        $connection = $this->connectionPool->getConnectionForTable(AuditLogService::TABLE_NAME);
        $load = $this->anchorStore->load($connection);
        $details = [
            'anchorStatus' => $load->status->value,
            'auditAnchorRequired' => $required,
            'auditHmacEpoch' => $epoch,
            'currentSequence' => $currentSequence,
        ];

        if ($load->status === AuditChainAnchorStatus::Disabled) {
            return $this->anchorDisabledFinding($id, $required, $epoch, $details);
        }

        if ($load->status === AuditChainAnchorStatus::Unanchored) {
            return $this->unanchoredFinding($id, $connection, $required, $currentSequence, $details);
        }

        if ($load->status === AuditChainAnchorStatus::Unreadable) {
            // Critical whatever "auditAnchorRequired" says, matching
            // AuditLogService::verifyAnchor(): a row that is present but does
            // not authenticate is not a pre-anchor installation, it is an
            // anchor that was written over or a key that changed.
            return Finding::critical(
                id: $id,
                summary: 'The in-DB audit chain tip anchor is unreadable: malformed value or invalid MAC.',
                risk: 'The anchor was tampered with — blanking its value is the documented way to try to '
                    . 'get back to silent truncation — or the master key changed without the chain being '
                    . 're-sealed. Either way the tip is currently not pinned by anything.',
                remediation: 'Run vendor/bin/typo3 vault:audit-verify first and treat a chain error as an '
                    . 'incident. If the master key was rotated or the chain re-keyed without a re-seal, '
                    . 're-arm with vendor/bin/typo3 vault:audit --reset-anchor, which records the reset '
                    . 'in the chain itself. Do NOT re-arm before verifying — it would sign whatever the '
                    . 'chain has been cut down to.',
                docsUrl: DocsLink::AUDIT_TIP_ANCHOR,
                details: $details,
            );
        }

        if ($load->status === AuditChainAnchorStatus::Ok) {
            return Finding::pass(
                id: $id,
                summary: 'The in-DB audit chain tip anchor is present and authenticates. Tip-hash '
                    . 'comparison against the anchored row is vault:audit-verify.',
                docsUrl: DocsLink::AUDIT_TIP_ANCHOR,
                details: $details,
            );
        }

        // No load() path produces the remaining statuses today. Reporting the
        // unknown one rather than falling through to a pass keeps a future
        // status from being read as healthy by a gate that never saw it.
        return Finding::warning(
            id: $id,
            summary: \sprintf(
                'The in-DB audit chain tip anchor reported an unexpected status: %s.',
                $load->status->value,
            ),
            risk: 'The control was not conclusively evaluated. Treat it as unknown, not as satisfied.',
            remediation: 'Run vendor/bin/typo3 vault:audit-verify for the authoritative anchor verdict.',
            docsUrl: DocsLink::AUDIT_TIP_ANCHOR,
            details: $details,
        );
    }

    /**
     * The anchor is off because the epoch is below 1.
     *
     * With `auditAnchorRequired` on this is a contradiction the rest of the
     * system cannot report: `verifyAnchor()` returns on `Disabled` BEFORE the
     * requirement is consulted, so the operator's assertion "this installation
     * is anchored" is satisfied by an anchor that is switched off.
     *
     * @param array<string, bool|int|string> $details
     */
    private function anchorDisabledFinding(string $id, bool $required, int $epoch, array $details): Finding
    {
        if ($required) {
            return Finding::critical(
                id: $id,
                summary: \sprintf(
                    'Contradictory configuration: "auditAnchorRequired" is enabled while '
                    . '"auditHmacEpoch" is %d, which disables the in-DB tip anchor entirely.',
                    $epoch,
                ),
                risk: 'The configuration asserts that this installation is anchored, and the anchor is '
                    . 'switched off at the source: at epoch 0 the store never reads, writes or verifies '
                    . 'one. Verification reports "disabled" and returns before the requirement is ever '
                    . 'consulted, so the setting produces neither a warning nor an error — it silently '
                    . 'protects nothing while reading as the stricter configuration.',
                remediation: 'Raise "auditHmacEpoch" to 3 and migrate the chain with vendor/bin/typo3 '
                    . 'vault:audit-migrate-hmac, then arm the anchor with vendor/bin/typo3 vault:audit '
                    . '--reset-anchor. If keyless operation is genuinely intended, turn '
                    . '"auditAnchorRequired" off so the configuration stops claiming a control it does '
                    . 'not have.',
                docsUrl: DocsLink::AUDIT_TIP_ANCHOR,
                details: $details,
            );
        }

        return Finding::warning(
            id: $id,
            summary: \sprintf(
                'The in-DB audit chain tip anchor is disabled ("auditHmacEpoch" is %d) and was not '
                . 'evaluated.',
                $epoch,
            ),
            risk: 'Nothing outside tx_nrvault_audit_log pins how far the chain had grown, so a tail '
                . 'truncation or a full wipe leaves a chain that still verifies. This is one of the '
                . 'three consequences reported by audit.hmac_epoch.',
            remediation: 'Raise "auditHmacEpoch" to 3 and run vendor/bin/typo3 vault:audit-migrate-hmac; '
                . 'the anchor arms itself on the next audit write.',
            docsUrl: DocsLink::AUDIT_TIP_ANCHOR,
            details: $details,
        );
    }

    /**
     * No anchor is readable at the current epoch.
     *
     * Three different situations, and they do not deserve the same severity:
     * `sys_registry` on a foreign connection is a deployment fact no operator
     * action inside the vault can fix; an empty chain has simply not armed the
     * anchor yet; a populated chain with no anchor is either that same
     * pre-anchor state or an anchor someone removed, which is exactly what
     * `auditAnchorRequired` exists to disambiguate.
     *
     * @param array<string, bool|int|string> $details
     */
    private function unanchoredFinding(
        string $id,
        Connection $connection,
        bool $required,
        int $currentSequence,
        array $details,
    ): Finding {
        if (!$this->anchorStore->sharesConnection($connection)) {
            return Finding::warning(
                id: $id,
                summary: 'The in-DB audit chain tip anchor is unavailable: sys_registry and '
                    . 'tx_nrvault_audit_log are mapped to different database connections.',
                risk: 'The anchor cannot commit atomically with an audit write across two connections, '
                    . 'so it is not armed at all and truncation of the audit table stays undetectable '
                    . 'by this control.',
                remediation: 'Map both tables to the same connection in '
                    . '$GLOBALS[TYPO3_CONF_VARS][DB][TableMapping], or rely on an external audit sink '
                    . 'plus vendor/bin/typo3 vault:audit-anchor for truncation evidence.',
                docsUrl: DocsLink::AUDIT_TIP_ANCHOR,
                details: $details,
            );
        }

        if ($required) {
            return Finding::critical(
                id: $id,
                summary: 'No in-DB audit chain tip anchor is recorded, although "auditAnchorRequired" '
                    . 'is enabled.',
                risk: 'The configuration asserts this installation is already anchored, so an absent '
                    . 'anchor is not the pre-anchor state — it is an anchor that was removed, the step '
                    . 'that precedes a truncation. Ordinary audit writes deliberately refuse to re-arm '
                    . 'it, so this does not heal on its own.',
                remediation: 'Verify the chain first with vendor/bin/typo3 vault:audit-verify. Only once '
                    . 'it is clean, arm the anchor with vendor/bin/typo3 vault:audit --reset-anchor, '
                    . 'which records the reset as an audit entry in the same transaction.',
                docsUrl: DocsLink::AUDIT_TIP_ANCHOR,
                details: $details,
            );
        }

        if ($currentSequence === 0) {
            return Finding::pass(
                id: $id,
                summary: 'The audit log is empty; the in-DB tip anchor arms itself on the first audit '
                    . 'write.',
                docsUrl: DocsLink::AUDIT_TIP_ANCHOR,
                details: $details,
            );
        }

        return Finding::warning(
            id: $id,
            summary: \sprintf(
                'No in-DB audit chain tip anchor is recorded, although the chain has grown to uid %d.',
                $currentSequence,
            ),
            risk: 'Tail truncation and full wipes of tx_nrvault_audit_log are not detectable until the '
                . 'anchor is armed. A never-armed anchor and a deleted one are indistinguishable from '
                . 'database state alone, which is why this is a warning rather than an error.',
            remediation: 'The next audit write arms it. Once it is armed, enable "auditAnchorRequired" '
                . 'so a later deletion of the anchor row becomes an error instead of this warning — the '
                . 'setting lives in a settings file and is out of a database-write attacker\'s reach.',
            docsUrl: DocsLink::AUDIT_TIP_ANCHOR,
            details: $details,
        );
    }

    /**
     * Does the audit trail exist anywhere outside the database it protects?
     *
     * The severity split mirrors {@see AuditIntegrityReason::NoExternalSink}: the
     * standard profile treats sinks as opt-in, so a default installation is not
     * flagged for having no SIEM. Only the hardened profile promises external
     * evidence, and there the absence is the promise being broken.
     */
    private function checkExternalSink(DoctorContext $context): Finding
    {
        $id = 'audit.external_sink';
        $enabled = $this->sinkRegistry->getEnabledSinkIdentifiers();

        if ($enabled !== []) {
            return Finding::pass(
                id: $id,
                summary: \sprintf('External audit sink(s) enabled: %s.', implode(', ', $enabled)),
                docsUrl: DocsLink::AUDIT_SINKS,
                details: ['sinks' => implode(',', $enabled)],
            );
        }

        if (!$context->isHardened()) {
            return Finding::pass(
                id: $id,
                summary: 'No external audit sink is enabled. Sinks are opt-in under the standard profile.',
                docsUrl: DocsLink::AUDIT_SINKS,
                details: ['sinks' => '', 'reasonCode' => AuditIntegrityReason::NoExternalSink->value],
            );
        }

        return Finding::critical(
            id: $id,
            summary: 'The hardened profile requires an external audit sink, but none is enabled and usable.',
            risk: 'The audit trail exists only in the database it is meant to protect. An attacker with '
                . 'DELETE rights can truncate the table and let a fresh, internally consistent chain '
                . 'build from uid 1 — nothing inside the database distinguishes that from a young '
                . 'installation. No chain-tip anchor can be published either, so the reset stays '
                . 'undetectable.',
            remediation: 'Enable at least one of "auditSinkFileEnabled" (append-only NDJSON outside the '
                . 'web root), "auditSinkSyslogEnabled" or "auditSinkWebhookEnabled", then schedule '
                . 'vendor/bin/typo3 vault:audit-anchor.',
            docsUrl: DocsLink::AUDIT_SINKS,
            details: ['sinks' => '', 'reasonCode' => AuditIntegrityReason::NoExternalSink->value],
        );
    }

    /**
     * Is there external evidence of the chain, and is the chain still at least as
     * long as that evidence says?
     *
     * Only the shrinkage half of the anchor comparison is done here — an integer
     * comparison, cheap enough for a page load. The row-hash substitution check
     * lives in {@see ChainTipAnchorServiceInterface::verify()}, which recomputes
     * the full chain; the remediation text points there rather than duplicating
     * its logic, so there is one implementation of the deep comparison.
     */
    private function checkAnchor(
        DoctorContext $context,
        ?ChainTipAnchor $anchor,
        int $currentSequence,
    ): Finding {
        $id = 'audit.anchor';

        if (!$anchor instanceof ChainTipAnchor) {
            if (!$context->isHardened()) {
                return Finding::pass(
                    id: $id,
                    summary: 'No chain-tip anchor has been published. Anchoring is opt-in under the '
                        . 'standard profile.',
                    docsUrl: DocsLink::AUDIT_SINK_SCHEDULING,
                    details: ['anchorAvailable' => $this->anchorReader->isAvailable()],
                );
            }

            return Finding::critical(
                id: $id,
                summary: 'No chain-tip anchor could be read, although the hardened profile requires one.',
                risk: 'A full audit-table reset would be undetectable: there is no external record of '
                    . 'how long the chain had grown or what its tip hashed to.',
                remediation: 'Run vendor/bin/typo3 vault:audit-anchor once, then schedule the '
                    . '"Vault Audit Chain Anchoring" task hourly. The interval is the blind window — an '
                    . 'attacker can only hide entries written since the last anchor.',
                docsUrl: DocsLink::AUDIT_SINK_SCHEDULING,
                details: [
                    'anchorAvailable' => $this->anchorReader->isAvailable(),
                    'reasonCode' => AuditIntegrityReason::NoExternalSink->value,
                ],
            );
        }

        $details = [
            'anchoredSequence' => $anchor->sequence,
            'currentSequence' => $currentSequence,
            'anchoredAt' => $anchor->timestamp,
        ];

        if ($currentSequence < $anchor->sequence) {
            return Finding::critical(
                id: $id,
                summary: \sprintf(
                    'The audit chain shrank: highest uid is %d but sequence %d was anchored on %s UTC.',
                    $currentSequence,
                    $anchor->sequence,
                    gmdate('Y-m-d H:i:s', $anchor->timestamp),
                ),
                risk: 'An append-only chain cannot get shorter. The audit table was truncated or rows '
                    . 'were deleted wholesale — the signature of a truncate-and-rebuild.',
                remediation: 'Treat this as an incident. Run vendor/bin/typo3 vault:audit-verify for the '
                    . 'TABLE_RESET report, and reconstruct the removed interval from the external sink '
                    . 'stream, which the database reset did not touch.',
                docsUrl: DocsLink::AUDIT_SINK_SCHEDULING,
                details: $details + ['reasonCode' => AuditIntegrityReason::TableReset->value],
            );
        }

        return Finding::pass(
            id: $id,
            summary: \sprintf(
                'Chain-tip anchor present (sequence %d, anchored %s UTC); the chain has not shrunk. '
                . 'Tip-hash comparison is vault:audit-verify.',
                $anchor->sequence,
                gmdate('Y-m-d H:i:s', $anchor->timestamp),
            ),
            docsUrl: DocsLink::AUDIT_SINK_SCHEDULING,
            details: $details,
        );
    }

    /**
     * Did any sink refuse delivery in this process?
     *
     * A zero here means "not in this run", not "never" — the persisted state
     * above ({@see self::checkPersistedDeliveryState()}) answers the
     * cross-process question. This process-local view still catches the
     * common case cheaply: a wrong webhook URL or an unwritable log path
     * fails on the very first dispatch of the current run.
     */
    private function checkSinkFailures(): Finding
    {
        $id = 'audit.sink_delivery';
        $failures = $this->sinkRegistry->getFailureCountsBySink();
        $total = $this->sinkRegistry->getFailureCount();

        if ($total === 0) {
            return Finding::pass(
                id: $id,
                summary: 'No audit sink delivery failures observed in this process.',
                docsUrl: DocsLink::AUDIT_SINKS,
                details: ['failureCount' => 0],
            );
        }

        $perSink = [];
        foreach ($failures as $sink => $count) {
            $perSink[] = \sprintf('%s (%d)', $sink, $count);
        }

        return Finding::warning(
            id: $id,
            summary: \sprintf(
                '%d audit sink delivery failure(s) in this process: %s.',
                $total,
                implode(', ', $perSink),
            ),
            risk: 'Audit evidence written during this process did not reach the external sink. The '
                . 'database copy is intact, but the external witness — the part that survives a table '
                . 'reset — has holes.',
            remediation: 'Check the TYPO3 log for the per-sink reason (unreachable collector, full disk, '
                . 'unwritable path), fix it, then re-anchor with vendor/bin/typo3 vault:audit-anchor.',
            docsUrl: DocsLink::AUDIT_SINKS,
            details: ['failureCount' => $total, 'failuresBySink' => implode(',', $perSink)],
        );
    }
}
