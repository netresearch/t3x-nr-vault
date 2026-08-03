<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReport;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;

/**
 * Full audit-integrity verification: internal hash chain plus external anchor.
 *
 * Complements `vault:audit --verify`, which only runs the in-database hash-chain
 * pass. That pass cannot detect a truncate-and-rebuild, because the rebuilt chain
 * is internally consistent. This command additionally compares the chain against
 * the last published chain-tip anchor and reports every finding under a
 * machine-readable reason code:
 *
 *   HASH_MISMATCH      a stored hash does not recompute
 *   UID_GAP            rows were deleted from the middle of the chain
 *   TABLE_RESET        the chain is not the chain that was anchored
 *   EPOCH_DOWNGRADE    the verification algorithm was relabelled downward
 *   NO_EXTERNAL_SINK   hardened profile without usable external evidence
 *   SINK_FAILURE       a sink could not be delivered to during this process
 *
 * Exits non-zero on ANY finding, so it can be wired straight into monitoring.
 * Every finding is also dispatched as
 * {@see \Netresearch\NrVault\Event\AuditIntegrityAlertEvent}, so SIEM listeners
 * fire whether or not anyone reads this output.
 *
 * Gated on `audit.view`: verification recomputes and compares, it mutates
 * nothing, so it is a read of the chain — the same permission
 * `vault:audit --verify` and `AuditController::verifyChainAction()` assert for
 * the same operation. Without the gate this command would be the way around
 * theirs, and it checks strictly more (the external anchor as well as the
 * chain). A refusal exits non-zero without running any verification, and in
 * `--format=json` it reports `valid: false` — a verifier that was not allowed
 * to run must never read as a verifier that found nothing.
 *
 * Usage:
 *   vendor/bin/typo3 vault:audit-verify
 *   vendor/bin/typo3 vault:audit-verify --format=json
 *   vendor/bin/typo3 vault:audit-verify --tamper-only
 */
#[AsCommand(
    name: 'vault:audit-verify',
    description: 'Verify audit log integrity against the hash chain and the external chain-tip anchor',
)]
final class VaultAuditVerifyCommand extends Command
{
    public function __construct(
        private readonly ChainTipAnchorServiceInterface $anchorService,
        private readonly AuditSinkRegistryInterface $sinkRegistry,
        private readonly AccessControlServiceInterface $accessControlService,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'format',
                'f',
                InputOption::VALUE_REQUIRED,
                'Output format: text (default) or json',
                'text',
            )
            ->addOption(
                'tamper-only',
                null,
                InputOption::VALUE_NONE,
                'Only fail on tamper evidence; treat configuration and delivery findings '
                . '(NO_EXTERNAL_SINK, SINK_FAILURE) as warnings',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $formatOption = $input->getOption('format');
        $json = \is_string($formatOption) && strtolower($formatOption) === 'json';
        $tamperOnly = (bool) $input->getOption('tamper-only');

        // Before the verification runs, and before anything is written to the
        // output a monitoring wrapper might parse.
        if (!$this->accessControlService->isGranted(VaultPermission::AuditView)) {
            $this->refuse($io, $output, $json);

            return Command::FAILURE;
        }

        try {
            $report = $this->anchorService->verify();
        } catch (Throwable $e) {
            // A verifier that cannot run must never look like a verifier that
            // found nothing.
            if ($json) {
                $output->writeln(json_encode(
                    ['valid' => false, 'error' => $e->getMessage()],
                    JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR,
                ));
            } else {
                $io->error('Audit integrity verification could not run: ' . $e->getMessage());
            }

            return Command::FAILURE;
        }

        $failed = $tamperOnly ? $report->hasTamperEvidence() : !$report->isValid();

        if ($json) {
            $output->writeln(json_encode(
                $report->toArray() + [
                    'tamperOnly' => $tamperOnly,
                    'exitFailure' => $failed,
                    'sinkFailures' => $this->sinkRegistry->getFailureCountsBySink(),
                    'enabledSinks' => $this->sinkRegistry->getEnabledSinkIdentifiers(),
                ],
                JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR,
            ));

            return $failed ? Command::FAILURE : Command::SUCCESS;
        }

        $this->renderText($io, $report, $failed);

        return $failed ? Command::FAILURE : Command::SUCCESS;
    }

    /**
     * Report the refusal in the shape the caller asked for.
     *
     * The JSON body carries `valid: false` alongside the reason, so a monitor
     * that only reads that field treats a refused verification as a failed one
     * rather than as a clean chain.
     */
    private function refuse(SymfonyStyle $io, OutputInterface $output, bool $json): void
    {
        $message = \sprintf(
            'Access denied: the "%s" permission is required to verify the audit log integrity.',
            VaultPermission::AuditView->value,
        );

        if ($json) {
            $output->writeln(json_encode(
                ['valid' => false, 'error' => $message],
                JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR,
            ));

            return;
        }

        $io->error($message);
    }

    private function renderText(SymfonyStyle $io, AuditIntegrityReport $report, bool $failed): void
    {
        $io->title('Vault Audit Integrity Verification');

        $anchor = $report->anchor;
        $io->definitionList(
            ['Chain length (max uid)' => (string) $report->currentSequence],
            ['Hash chain' => $report->chainValid ? 'valid' : 'INVALID'],
            ['Anchor' => $anchor instanceof ChainTipAnchor
                ? \sprintf(
                    'sequence %d, epoch %d, taken %s UTC',
                    $anchor->sequence,
                    $anchor->hmacEpoch,
                    gmdate('Y-m-d H:i:s', $anchor->timestamp),
                )
                : 'none available'],
            ['Stored HMAC epochs' => $this->formatEpochDistribution($report)],
            ['Enabled sinks' => $this->formatSinkList()],
        );

        if ($report->warnings !== []) {
            $io->warning(\sprintf('%d chain warning(s):', \count($report->warnings)));
            $io->table(
                ['Entry UID', 'Warning'],
                array_map(
                    static fn (int|string $uid, string $warning): array => [(string) $uid, $warning],
                    array_keys($report->warnings),
                    array_values($report->warnings),
                ),
            );
        }

        if ($report->isValid()) {
            $io->success('Audit log integrity verified — hash chain intact and consistent with the external anchor.');

            return;
        }

        $io->section('Findings');
        $io->table(
            ['Code', 'Tamper evidence', 'Detail'],
            array_map(
                static fn (AuditIntegrityAlert $finding): array => [
                    $finding->reason->value,
                    $finding->reason->isTamperEvidence() ? 'YES' : 'no',
                    $finding->detail,
                ],
                $report->findings,
            ),
        );

        $codes = implode(', ', $report->getReasonCodes());

        if ($failed) {
            $io->error(\sprintf('Audit integrity verification FAILED: %s', $codes));

            return;
        }

        // Reached only with --tamper-only and non-tamper findings present.
        $io->warning(\sprintf(
            'Audit integrity findings present but no tamper evidence (%s); '
            . 'exiting successfully because --tamper-only was given.',
            $codes,
        ));
    }

    /**
     * How the stored rows are distributed across HMAC epochs.
     *
     * Reported unconditionally, including on a clean run: "the chain is valid"
     * and "the whole chain is signed at the configured epoch" are different
     * statements, and only this one answers the second. A chain left at epoch 1
     * by a stalled migration verifies perfectly while leaving `success` and the
     * attribution fields outside the MAC — there is no error to raise, and an
     * operator still has to see it. The counts come from the walk this command
     * already performs, so nothing extra is read.
     */
    private function formatEpochDistribution(AuditIntegrityReport $report): string
    {
        if ($report->epochCounts === []) {
            return '(chain empty)';
        }

        $parts = [];
        foreach ($report->epochCounts as $epoch => $count) {
            $parts[] = \sprintf('epoch %d: %d row(s)', $epoch, $count);
        }

        return \sprintf(
            '%s — lowest %d, highest %d',
            implode(', ', $parts),
            (int) $report->getMinEpoch(),
            (int) $report->getMaxEpoch(),
        );
    }

    private function formatSinkList(): string
    {
        $sinks = $this->sinkRegistry->getEnabledSinkIdentifiers();
        if ($sinks === []) {
            return '(none)';
        }

        $failures = $this->sinkRegistry->getFailureCountsBySink();

        return implode(', ', array_map(
            static fn (string $id): string => isset($failures[$id])
                ? \sprintf('%s (%d failure(s))', $id, $failures[$id])
                : $id,
            $sinks,
        ));
    }
}
