<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use DateTimeImmutable;
use Exception;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditChainAnchorStatus;
use Netresearch\NrVault\Audit\AuditChainAnchorStoreInterface;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\AuditLogFilter;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Utility\CsvFormulaSanitizer;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * CLI command to query and export audit logs.
 *
 * Every mode is gated on an operation permission: listing and `--verify` on
 * `audit.view`, `--export` on `audit.export`, and `--reset-anchor` on
 * `vault.configure`. A refusal exits non-zero before any query, file write or
 * anchor change happens.
 *
 * A refusal deliberately writes NO `access_denied` entry. Every sibling
 * operation-permission gate refuses the same way — `VaultRetrieveCommand`,
 * `VaultRotateMasterKeyCommand`, `ModuleAccessGuard` — and only the
 * *per-secret* tiers audit their denials. Auditing here would also let anyone
 * with a shell append rows to the tamper-evident table without holding a
 * single permission, and, worse, `--verify` / `--reset-anchor` are the tools
 * for a chain that is already suspect: their denial path must not append to,
 * and re-anchor, the very chain the operator is about to inspect or reset.
 */
#[AsCommand(
    name: 'vault:audit',
    description: 'Query and export vault audit logs',
)]
final class VaultAuditCommand extends Command
{
    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    /**
     * Pseudo secret identifier for chain-level events that belong to no single
     * secret (mirrors `VaultRotateMasterKeyCommand::AUDIT_PSEUDO_IDENTIFIER`).
     */
    private const AUDIT_PSEUDO_IDENTIFIER = '__audit_anchor__';

    public function __construct(
        private readonly AuditLogServiceInterface $auditLogService,
        private readonly AuditChainAnchorStoreInterface $anchorStore,
        private readonly ConnectionPool $connectionPool,
        private readonly AccessControlServiceInterface $accessControlService,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'identifier',
                'i',
                InputOption::VALUE_REQUIRED,
                'Filter by secret identifier',
            )
            ->addOption(
                'action',
                'a',
                InputOption::VALUE_REQUIRED,
                'Filter by action (create, read, update, delete, rotate, access_denied)',
            )
            ->addOption(
                'actor',
                null,
                InputOption::VALUE_REQUIRED,
                'Filter by actor UID',
            )
            ->addOption(
                'since',
                null,
                InputOption::VALUE_REQUIRED,
                'Filter entries since date (Y-m-d or Y-m-d H:i:s)',
            )
            ->addOption(
                'until',
                null,
                InputOption::VALUE_REQUIRED,
                'Filter entries until date (Y-m-d or Y-m-d H:i:s)',
            )
            ->addOption(
                'success',
                null,
                InputOption::VALUE_REQUIRED,
                'Filter by success status (true/false)',
            )
            ->addOption(
                'format',
                'f',
                InputOption::VALUE_REQUIRED,
                'Output format: table, json, csv',
                'table',
            )
            ->addOption(
                'limit',
                'l',
                InputOption::VALUE_REQUIRED,
                'Maximum number of results',
                '50',
            )
            ->addOption(
                'verify',
                null,
                InputOption::VALUE_NONE,
                'Verify hash chain integrity',
            )
            ->addOption(
                'export',
                'e',
                InputOption::VALUE_REQUIRED,
                'Export to file',
            )
            ->addOption(
                'reset-anchor',
                null,
                InputOption::VALUE_NONE,
                'Clear the audit chain tip anchor after a LEGITIMATE full wipe of the audit log, '
                . 'and record the reset in the chain. Without this, a deliberately truncated log '
                . 'reports a violation forever.',
            )
            ->addOption(
                'force',
                null,
                InputOption::VALUE_NONE,
                'Skip the interactive confirmation of --reset-anchor (for unattended runs)',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $resetAnchor = (bool) $input->getOption('reset-anchor');
        $verify = (bool) $input->getOption('verify');
        $exportFile = $this->exportTarget($input);

        // One gate for the whole command, resolved from the mode the
        // invocation selects — the same mode the dispatch below uses, so no
        // branch can reach its work through an unasserted permission. The
        // audit log names who touched which secret when, which is a sensitive
        // derivative of the secrets themselves; before this gate existed,
        // `vault:audit` was the one privileged vault command that asserted
        // nothing at all.
        [$required, $operation] = $this->gate($resetAnchor, $verify, $exportFile);
        if (!$this->accessControlService->isGranted($required)) {
            $io->error(\sprintf(
                'Access denied: the "%s" permission is required to %s.',
                $required->value,
                $operation,
            ));

            return Command::FAILURE;
        }

        if ($resetAnchor) {
            return $this->resetAnchor($io, (bool) $input->getOption('force'));
        }

        // Hash chain verification
        if ($verify) {
            return $this->verifyHashChain($io);
        }

        // Build filters
        $filters = $this->buildFilters($input);
        $format = $input->getOption('format');
        $limit = $input->getOption('limit');

        \assert(\is_string($format));
        \assert(\is_string($limit) || \is_int($limit));
        $limit = (int) $limit;

        try {
            $entries = $this->auditLogService->query($filters, $limit, 0);

            if ($entries === []) {
                $io->info('No audit entries found');

                return Command::SUCCESS;
            }

            // Export to file
            if ($exportFile !== null) {
                return $this->exportToFile($io, $entries, $exportFile, $format);
            }

            // Output to console
            match ($format) {
                'json' => $output->writeln(json_encode($entries, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR)),
                'csv' => $this->outputCsv($output, $entries),
                default => $this->outputTable($io, $entries),
            };

            return Command::SUCCESS;
        } catch (VaultException $e) {
            $io->error($e->getMessage());

            return Command::FAILURE;
        }
    }

    /**
     * The file `--export` writes to, or null when the entries stay on stdout.
     *
     * Resolved once and reused by both the permission gate and the dispatch:
     * two separate readings of the option could disagree, and the one that
     * disagreed would be an export performed under `audit.view`.
     */
    private function exportTarget(InputInterface $input): ?string
    {
        $exportFile = $input->getOption('export');

        return \is_string($exportFile) && $exportFile !== '' ? $exportFile : null;
    }

    /**
     * The permission this invocation needs, and the operation it guards.
     *
     * Resolved as one value so a refusal can never name a permission belonging
     * to a different mode than the one it gated, and so the operator learns
     * which grant to ask for AND what for.
     *
     * `--verify` recomputes and compares — it mutates nothing, so it is a read
     * of the chain and shares `audit.view` with the listing, exactly as
     * `AuditController::verifyChainAction()` does. `--reset-anchor` is the
     * outlier: it clears the truncation anchor and writes into the chain, so
     * it stays vault administration. Export takes `audit.export` on its own —
     * same rule as `AuditController::exportAction()`, because the exported
     * copy leaves the tamper-evident storage behind.
     *
     * @return array{VaultPermission, string}
     */
    private function gate(bool $resetAnchor, bool $verify, ?string $exportFile): array
    {
        return match (true) {
            $resetAnchor => [VaultPermission::VaultConfigure, 'reset the audit chain tip anchor'],
            $verify => [VaultPermission::AuditView, 'verify the audit hash chain'],
            $exportFile !== null => [VaultPermission::AuditExport, 'export audit entries to a file'],
            default => [VaultPermission::AuditView, 'read the audit log'],
        };
    }

    private function buildFilters(InputInterface $input): ?AuditLogFilter
    {
        $secretIdentifier = $input->getOption('identifier');
        $action = $input->getOption('action');
        $actor = $input->getOption('actor');
        $successOption = $input->getOption('success');
        $sinceOption = $input->getOption('since');
        $untilOption = $input->getOption('until');

        $since = null;
        if (\is_string($sinceOption) && $sinceOption !== '') {
            try {
                $since = new DateTimeImmutable($sinceOption);
            } catch (Exception) {
                // Invalid date, skip
            }
        }

        $until = null;
        if (\is_string($untilOption) && $untilOption !== '') {
            try {
                $until = new DateTimeImmutable($untilOption);
            } catch (Exception) {
                // Invalid date, skip
            }
        }

        $success = \is_string($successOption)
            ? filter_var($successOption, FILTER_VALIDATE_BOOLEAN)
            : null;

        $actorUid = null;
        if (\is_string($actor) || \is_int($actor)) {
            $actorUid = (int) $actor;
        }

        $filter = new AuditLogFilter(
            secretIdentifier: \is_string($secretIdentifier) ? $secretIdentifier : null,
            action: \is_string($action) ? $action : null,
            actorUid: $actorUid,
            success: $success,
            since: $since,
            until: $until,
        );

        return $filter->isEmpty() ? null : $filter;
    }

    private function verifyHashChain(SymfonyStyle $io): int
    {
        $io->section('Verifying hash chain integrity');

        $result = $this->auditLogService->verifyHashChain();

        $io->writeln(\sprintf('Tip anchor: %s', $this->describeAnchorStatus($result->anchorStatus)));

        if ($result->getWarningCount() > 0) {
            $io->warning(\sprintf('%d warning(s) detected:', $result->getWarningCount()));
            $io->table(
                ['Entry UID', 'Warning'],
                array_map(
                    fn ($uid, $warning): array => [$uid, $warning],
                    array_keys($result->warnings),
                    array_values($result->warnings),
                ),
            );
        }

        if ($result->isValid()) {
            $io->success('Hash chain is valid - no tampering detected');

            return Command::SUCCESS;
        }

        $io->error('Hash chain verification FAILED - possible tampering detected');

        if ($result->getErrorCount() > 0) {
            $io->table(
                ['Entry UID', 'Error'],
                array_map(
                    fn ($uid, $error): array => [$uid, $error],
                    array_keys($result->errors),
                    array_values($result->errors),
                ),
            );
        }

        return Command::FAILURE;
    }

    /**
     * Operator-facing wording for the tip-anchor outcome. The anchor is what
     * makes tail truncation and full wipes of the audit log detectable, so its
     * state belongs in the verification output even when the chain is valid.
     */
    private function describeAnchorStatus(AuditChainAnchorStatus $status): string
    {
        return match ($status) {
            AuditChainAnchorStatus::NotChecked => 'not checked (bounded range)',
            AuditChainAnchorStatus::Disabled => 'disabled (audit HMAC epoch 0)',
            AuditChainAnchorStatus::Unanchored => 'NOT ARMED - truncation of the log is not detectable yet',
            AuditChainAnchorStatus::Unreadable => 'UNREADABLE - malformed value or invalid MAC',
            AuditChainAnchorStatus::InFlight => 'inconclusive - a re-seal committed during verification',
            AuditChainAnchorStatus::Ok => 'ok',
            AuditChainAnchorStatus::Violated => 'VIOLATED - the anchored entry is gone or was replaced',
        };
    }

    /**
     * Clear the tip anchor and record that fact inside the chain.
     *
     * The anchor advances forward-only, so after a legitimate `TRUNCATE` or an
     * operator purge it can never catch up again and the install would report a
     * violation forever. Reset and audit entry share one transaction, and the
     * entry is written AFTER the reset so the fresh row becomes the new anchor:
     * the reset cannot be performed invisibly.
     */
    private function resetAnchor(SymfonyStyle $io, bool $force): int
    {
        $io->section('Resetting the audit chain tip anchor');
        $io->warning([
            'This clears the tamper-evidence anchor that detects truncation of the audit log.',
            'Only do this after a wipe or purge you performed deliberately and can account for.',
        ]);

        if (!$force && !$io->confirm('Reset the audit chain tip anchor?', false)) {
            $io->note('Aborted - the anchor was left untouched.');

            return Command::SUCCESS;
        }

        $connection = $this->connectionPool->getConnectionForTable(self::AUDIT_TABLE);
        if (!$this->anchorStore->sharesConnection($connection)) {
            $io->error(
                'sys_registry and tx_nrvault_audit_log are mapped to different database connections; '
                . 'no anchor is recorded on this installation.',
            );

            return Command::FAILURE;
        }

        if (!$this->resetAnchorInTransaction($connection, $io)) {
            return Command::FAILURE;
        }

        $io->success('Tip anchor reset and re-armed on the reset entry; the reset is recorded in the chain.');

        return Command::SUCCESS;
    }

    private function resetAnchorInTransaction(Connection $connection, SymfonyStyle $io): bool
    {
        $connection->beginTransaction();

        try {
            $this->anchorStore->reset($connection);
            $this->auditLogService->log(
                self::AUDIT_PSEUDO_IDENTIFIER,
                AuditAction::AuditAnchorReset->value,
                true,
                null,
                'Audit chain tip anchor reset via vault:audit --reset-anchor',
            );
            // Re-arm explicitly on the entry just written. `log()` alone is not
            // enough: with `auditAnchorRequired` on, `advance()` deliberately
            // refuses to create an absent anchor at all, because an ordinary
            // audit write must never do that. This command is the
            // sanctioned exception — an operator action recorded in the chain.
            $this->anchorStore->arm($connection);
            $connection->commit();

            return true;
        } catch (Throwable $e) {
            $connection->rollBack();
            $io->error('Failed to reset the audit chain tip anchor: ' . $e->getMessage());

            return false;
        }
    }

    /**
     * @param array<int, AuditLogEntry> $entries
     */
    private function outputTable(SymfonyStyle $io, array $entries): void
    {
        $rows = [];
        foreach ($entries as $entry) {
            $rows[] = [
                date('Y-m-d H:i:s', $entry->crdate),
                $entry->secretIdentifier,
                $entry->action,
                $entry->success ? '✓' : '✗',
                $entry->actorUsername,
                $entry->ipAddress,
                substr((string) $entry->entryHash, 0, 8) . '...',
            ];
        }

        $io->table(
            ['Timestamp', 'Secret', 'Action', 'OK', 'Actor', 'IP', 'Hash'],
            $rows,
        );

        $io->writeln(\sprintf('<info>Total: %d entries</info>', \count($entries)));
    }

    /**
     * @param array<int, AuditLogEntry> $entries
     */
    private function outputCsv(OutputInterface $output, array $entries): void
    {
        // Header
        $output->writeln('timestamp,secret_identifier,action,success,actor_username,actor_type,ip_address,entry_hash');

        // Rows
        foreach ($entries as $entry) {
            $output->writeln(\sprintf(
                '%s,%s,%s,%d,%s,%s,%s,%s',
                date('Y-m-d H:i:s', $entry->crdate),
                CsvFormulaSanitizer::escapeField($entry->secretIdentifier),
                CsvFormulaSanitizer::escapeField($entry->action),
                $entry->success ? 1 : 0,
                CsvFormulaSanitizer::escapeField($entry->actorUsername),
                CsvFormulaSanitizer::escapeField($entry->actorType),
                CsvFormulaSanitizer::escapeField($entry->ipAddress),
                CsvFormulaSanitizer::escapeField($entry->entryHash),
            ));
        }
    }

    /**
     * @param array<int, AuditLogEntry> $entries
     */
    private function exportToFile(SymfonyStyle $io, array $entries, string $file, string $format): int
    {
        $data = array_map(static fn (AuditLogEntry $e): array => $e->jsonSerialize(), $entries);

        $content = match ($format) {
            'csv' => $this->formatCsv($data),
            default => json_encode($data, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR),
        };

        $result = file_put_contents($file, $content);
        if ($result === false) {
            $io->error(\sprintf('Failed to write to file: %s', $file));

            return Command::FAILURE;
        }

        $io->success(\sprintf('Exported %d entries to: %s', \count($entries), $file));

        return Command::SUCCESS;
    }

    /**
     * @param array<int, array<string, scalar|array<string, mixed>|null>> $data
     */
    private function formatCsv(array $data): string
    {
        if ($data === []) {
            return '';
        }

        $output = fopen('php://temp', 'r+');
        \assert(\is_resource($output));
        // escape: '' disables PHP's proprietary backslash escaping so that only
        // RFC-4180 quote doubling is emitted; with the default '\\' a value
        // containing \" closes the quoted cell and turns the remaining bytes
        // into further cells that CsvFormulaSanitizer never inspected.
        fputcsv($output, array_keys($data[0]), escape: '');

        foreach ($data as $row) {
            // Convert context array to JSON string for CSV
            if (isset($row['context']) && \is_array($row['context'])) {
                $row['context'] = json_encode($row['context']);
            }

            // Filter to only scalar/null values for fputcsv
            /** @var array<string, bool|float|int|string|null> $csvRow */
            $csvRow = array_map(
                static fn (mixed $v): bool|float|int|string|null => \is_scalar($v) || $v === null ? $v : json_encode($v),
                $row,
            );
            fputcsv($output, CsvFormulaSanitizer::neutralizeRow($csvRow), escape: '');
        }

        rewind($output);
        $csv = stream_get_contents($output);
        fclose($output);

        return $csv;
    }
}
