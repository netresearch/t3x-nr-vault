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
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\DocsLink;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Service\Doctor\ReadinessCheckInterface;

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
            $this->checkExternalSink($context),
            $this->checkAnchor($context, $anchor, $currentSequence),
            $this->checkSinkFailures(),
        ];
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
     * Per-process by design (persisting the counter would mean writing to the
     * storage a sink failure may indicate is broken), so a zero here means "not
     * in this run", not "never". It still catches the common case: a wrong
     * webhook URL or an unwritable log path fails on the very first dispatch.
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
