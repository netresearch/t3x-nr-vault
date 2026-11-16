<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use DateTimeImmutable;
use Exception;
use JsonException;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditChainAnchorStatus;
use Netresearch\NrVault\Audit\AuditChainAnchorStoreInterface;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\AuditLogFilter;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\Export\AuditChainExport;
use Netresearch\NrVault\Audit\Export\AuditChainExporter;
use Netresearch\NrVault\Audit\Export\AuditChainExporterInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\TechnicalActorException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\TechnicalActorContextInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Utility\CsvFormulaSanitizer;
use RuntimeException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

use function assert;
use function count;
use function is_array;
use function is_int;
use function is_scalar;
use function is_string;
use function sprintf;
use function strlen;

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
 *
 * `--as-audit-reader` runs the command, gate included, as the technical
 * backend user configured in `auditReaderBeUserUid`. The TYPO3 CLI never logs
 * a user in, so without it a shell holds these permissions only through
 * `allowCliAccess` and `cliAllowedOperations`. The UID comes from
 * configuration, never from the command line, so setting it opens reading the
 * log to every shell that can run the CLI; it is off by default. The actor is
 * evaluated like any other user (`audit.view`, `audit.export` for `--export`).
 * `--reset-anchor` is refused together with the option before the actor is
 * entered: it writes into the chain, and the reader is a read-only identity.
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
        private readonly ExtensionConfigurationInterface $configuration,
        private readonly TechnicalActorContextInterface $technicalActorContext,
        private readonly AuditChainExporterInterface $chainExporter,
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
                'Maximum number of results (listing default 50). With --export it '
                . 'exports only the newest N rows and fails unless --allow-partial is given',
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
                'Export the whole chain (or the filtered rows) to a file, with the verbatim '
                . 'hash inputs of every row; json (default) or csv',
            )
            ->addOption(
                'allow-partial',
                null,
                InputOption::VALUE_NONE,
                'Let --export with an explicit --limit write fewer rows than the selection holds; '
                . 'the file is marked "truncated"',
            )
            ->addOption(
                'verify-export',
                null,
                InputOption::VALUE_REQUIRED,
                "Re-verify a JSON file written by --export against the installation's master key",
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
            )
            ->addOption(
                'as-audit-reader',
                null,
                InputOption::VALUE_NONE,
                'List, verify or export as the configured audit reader backend user (nr_vault option '
                . '"auditReaderBeUserUid") instead of the unattributed CLI actor. The UID comes from '
                . 'configuration, never from this command line. Not combinable with --reset-anchor.',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        if ($input->getOption('as-audit-reader') === false) {
            return $this->executeForCurrentActor($input, $output, $io);
        }

        // Before the actor is entered: the reset writes into the chain, and the
        // reader is configured as a read-only identity whatever its groups say.
        if ((bool) $input->getOption('reset-anchor')) {
            $io->error(
                '--as-audit-reader cannot be combined with --reset-anchor: the reset writes into the audit chain, '
                . 'and the audit reader is a read-only identity.',
            );

            return Command::FAILURE;
        }

        $readerUid = $this->configuration->getAuditReaderBeUserUid();
        if ($readerUid === 0) {
            $io->error(
                'No audit reader is configured. Set the nr_vault option "auditReaderBeUserUid" to a backend user '
                . 'whose group carries the tx_nrvault:audit.view permission option (listing, --verify) or '
                . 'tx_nrvault:audit.export (--export).',
            );

            return Command::FAILURE;
        }

        try {
            $exitCode = $this->technicalActorContext->runAs(
                $readerUid,
                fn (): int => $this->executeForCurrentActor($input, $output, $io),
            );
        } catch (TechnicalActorException $e) {
            // Refused before the callable ran, so nothing has been read yet.
            $io->error('The audit reader cannot be used: ' . $e->getMessage());

            return Command::FAILURE;
        } catch (Throwable $e) {
            // Resolving the actor reads the database and can fail with something
            // other than a refusal; so can the work inside the scope.
            $io->error('The audit log could not be read as the audit reader: ' . $e->getMessage());

            return Command::FAILURE;
        }

        return is_int($exitCode) ? $exitCode : Command::FAILURE;
    }

    private function executeForCurrentActor(InputInterface $input, OutputInterface $output, SymfonyStyle $io): int
    {
        $resetAnchor      = (bool) $input->getOption('reset-anchor');
        $verify           = (bool) $input->getOption('verify');
        $exportFile       = $this->exportTarget($input);
        $verifyExportFile = $this->verifyExportTarget($input);

        // One gate for the whole command, resolved from the mode the
        // invocation selects — the same mode the dispatch below uses, so no
        // branch can reach its work through an unasserted permission. The
        // audit log names who touched which secret when, which is a sensitive
        // derivative of the secrets themselves; before this gate existed,
        // `vault:audit` was the one privileged vault command that asserted
        // nothing at all.
        [$required, $operation] = $this->gate($resetAnchor, $verify, $exportFile, $verifyExportFile);
        if (!$this->accessControlService->isGranted($required)) {
            $io->error(sprintf(
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

        if ($verifyExportFile !== null) {
            return $this->verifyExport($io, $verifyExportFile);
        }

        // Build filters
        $filters = $this->buildFilters($input);
        $format  = $input->getOption('format');
        $limit   = $input->getOption('limit');

        assert(is_string($format));
        assert(is_string($limit) || is_int($limit));
        $limit = (int) $limit;

        if ($exportFile !== null) {
            // The listing default of 50 must never cut an export: only a
            // --limit the operator typed limits it.
            $explicitLimit = $input->hasParameterOption(['--limit', '-l'], true) ? $limit : null;

            return $this->exportChain(
                $io,
                $filters,
                $explicitLimit,
                (bool) $input->getOption('allow-partial'),
                $exportFile,
                $format,
            );
        }

        try {
            $entries = $this->auditLogService->query($filters, $limit, 0);

            if ($entries === []) {
                $io->info('No audit entries found');

                return Command::SUCCESS;
            }

            // Output to console
            match ($format) {
                'json'  => $output->writeln(json_encode($entries, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR)),
                'csv'   => $this->outputCsv($output, $entries),
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

        return is_string($exportFile) && $exportFile !== '' ? $exportFile : null;
    }

    private function verifyExportTarget(InputInterface $input): ?string
    {
        $file = $input->getOption('verify-export');

        return is_string($file) && $file !== '' ? $file : null;
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
    private function gate(bool $resetAnchor, bool $verify, ?string $exportFile, ?string $verifyExportFile): array
    {
        return match (true) {
            $resetAnchor               => [VaultPermission::VaultConfigure, 'reset the audit chain tip anchor'],
            $verify                    => [VaultPermission::AuditView, 'verify the audit hash chain'],
            $verifyExportFile !== null => [VaultPermission::AuditView, 'verify an audit export file'],
            $exportFile !== null       => [VaultPermission::AuditExport, 'export audit entries to a file'],
            default                    => [VaultPermission::AuditView, 'read the audit log'],
        };
    }

    private function buildFilters(InputInterface $input): ?AuditLogFilter
    {
        $secretIdentifier = $input->getOption('identifier');
        $action           = $input->getOption('action');
        $actor            = $input->getOption('actor');
        $successOption    = $input->getOption('success');
        $sinceOption      = $input->getOption('since');
        $untilOption      = $input->getOption('until');

        $since = null;
        if (is_string($sinceOption) && $sinceOption !== '') {
            try {
                $since = new DateTimeImmutable($sinceOption);
            } catch (Exception) {
                // Invalid date, skip
            }
        }

        $until = null;
        if (is_string($untilOption) && $untilOption !== '') {
            try {
                $until = new DateTimeImmutable($untilOption);
            } catch (Exception) {
                // Invalid date, skip
            }
        }

        $success = is_string($successOption)
            ? filter_var($successOption, FILTER_VALIDATE_BOOLEAN)
            : null;

        $actorUid = null;
        if (is_string($actor) || is_int($actor)) {
            $actorUid = (int) $actor;
        }

        $filter = new AuditLogFilter(
            secretIdentifier: is_string($secretIdentifier) ? $secretIdentifier : null,
            action: is_string($action) ? $action : null,
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

        $io->writeln(sprintf('Tip anchor: %s', $this->describeAnchorStatus($result->anchorStatus)));

        if ($result->getWarningCount() > 0) {
            $io->warning(sprintf('%d warning(s) detected:', $result->getWarningCount()));
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
            AuditChainAnchorStatus::Disabled   => 'disabled (audit HMAC epoch 0)',
            AuditChainAnchorStatus::Unanchored => 'NOT ARMED - truncation of the log is not detectable yet',
            AuditChainAnchorStatus::Unreadable => 'UNREADABLE - malformed value or invalid MAC',
            AuditChainAnchorStatus::InFlight   => 'inconclusive - a re-seal committed during verification',
            AuditChainAnchorStatus::Ok         => 'ok',
            AuditChainAnchorStatus::Violated   => 'VIOLATED - the anchored entry is gone or was replaced',
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

        $io->writeln(sprintf('<info>Total: %d entries</info>', count($entries)));
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
            $output->writeln(sprintf(
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
     * Write the selected rows to `$file` without holding them in memory.
     *
     * The selection is fixed first ({@see AuditChainExporterInterface::select()}),
     * so the refusal of a truncated export happens before a byte is written.
     * The rows go to a temporary file next to the target, which is renamed
     * into place only after the row count matched the declared count: an
     * aborted run never leaves a file that looks like an export.
     */
    private function exportChain(
        SymfonyStyle $io,
        ?AuditLogFilter $filter,
        ?int $limit,
        bool $allowPartial,
        string $file,
        string $format,
    ): int {
        if ($limit !== null && $limit < 1) {
            $io->error('--limit must be at least 1 for an export.');

            return Command::FAILURE;
        }

        try {
            $export = $this->chainExporter->select($filter, $limit);
        } catch (Throwable $e) {
            $io->error('Could not select the audit rows to export: ' . $e->getMessage());

            return Command::FAILURE;
        }

        if ($export->isTruncated() && !$allowPartial) {
            $io->error(sprintf(
                'Refusing a partial export: --limit=%d covers %d of %d matching audit entries. '
                . 'Drop --limit to export all of them, or pass --allow-partial to write a file marked "truncated".',
                (int) $limit,
                $export->count,
                $export->total,
            ));

            return Command::FAILURE;
        }

        $directory = dirname($file);
        if (!is_dir($directory) || !is_writable($directory) || file_exists($file) && !is_writable($file)) {
            $io->error(sprintf('Failed to write to file: %s', $file));

            return Command::FAILURE;
        }

        $temporary = $file . '.part-' . bin2hex(random_bytes(4));
        $handle    = fopen($temporary, 'xb');
        if ($handle === false) {
            $io->error(sprintf('Failed to write to file: %s', $file));

            return Command::FAILURE;
        }

        try {
            $written = $format === 'csv'
                ? $this->writeCsvExport($handle, $export)
                : $this->writeJsonExport($handle, $export);
        } catch (Throwable $e) {
            fclose($handle);
            $this->removeTemporary($temporary);
            $io->error('The export failed and no file was written: ' . $e->getMessage());

            return Command::FAILURE;
        }

        fclose($handle);

        if ($written !== $export->count || !rename($temporary, $file)) {
            $this->removeTemporary($temporary);
            $io->error($written !== $export->count
                ? sprintf('The export failed and no file was written: %d of %d rows were read.', $written, $export->count)
                : sprintf('The export failed and no file was written: could not move it to %s.', $file));

            return Command::FAILURE;
        }

        $io->success(sprintf(
            'Exported %d of %d entries (uid %d to %d) to: %s',
            $export->count,
            $export->total,
            $export->firstUid,
            $export->lastUid,
            $file,
        ));

        if (!$export->isChainComplete()) {
            $io->note($export->isTruncated()
                ? 'The export is truncated (--allow-partial): it holds only the newest entries and cannot be verified as a whole chain.'
                : 'The export is filtered: it holds only the selected entries and cannot be verified as a whole chain.');
        }

        return Command::SUCCESS;
    }

    private function removeTemporary(string $temporary): void
    {
        if (is_file($temporary)) {
            // nosemgrep: php.lang.security.unlink-use.unlink-use - our own temporary file
            unlink($temporary);
        }
    }

    /**
     * @param resource $handle
     */
    private function writeJsonExport($handle, AuditChainExport $export): int
    {
        $flags = JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE;
        $this->writeOrFail($handle, '{"export":' . json_encode($export->metadata(gmdate('c')), $flags) . ",\n\"rows\":[");

        $written = 0;
        foreach ($export->rows as $row) {
            $this->writeOrFail($handle, ($written === 0 ? "\n" : ",\n") . json_encode($row, $flags));
            ++$written;
        }

        $this->writeOrFail($handle, "\n]}\n");

        return $written;
    }

    /**
     * CSV carries the same columns, but the formula neutralization that keeps a
     * spreadsheet from executing a cell rewrites values that start with a
     * formula character, so a CSV export is not byte-exact evidence. The
     * metadata goes into `#` comment lines in front of the header.
     *
     * @param resource $handle
     */
    private function writeCsvExport($handle, AuditChainExport $export): int
    {
        foreach ($export->metadata(gmdate('c')) as $key => $value) {
            $this->writeOrFail($handle, sprintf(
                "# %s: %s\n",
                $key,
                is_scalar($value) ? var_export($value, true) : json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            ));
        }

        // escape: '' disables PHP's proprietary backslash escaping so that only
        // RFC-4180 quote doubling is emitted; with the default '\\' a value
        // containing \" closes the quoted cell and turns the remaining bytes
        // into further cells that CsvFormulaSanitizer never inspected.
        if (fputcsv($handle, AuditChainExporter::columns(), escape: '') === false) {
            throw new RuntimeException('could not write to the export file', 7587470477);
        }

        $written = 0;
        foreach ($export->rows as $row) {
            if (fputcsv($handle, CsvFormulaSanitizer::neutralizeRow($row), escape: '') === false) {
                throw new RuntimeException('could not write to the export file', 8923280063);
            }

            ++$written;
        }

        return $written;
    }

    /**
     * @param resource $handle
     */
    private function writeOrFail($handle, string $data): void
    {
        if (fwrite($handle, $data) !== strlen($data)) {
            throw new RuntimeException('could not write to the export file', 7005647479);
        }
    }

    private function verifyExport(SymfonyStyle $io, string $file): int
    {
        $content = is_file($file) && is_readable($file) ? file_get_contents($file) : false;
        if ($content === false) {
            $io->error(sprintf('Cannot read the export file: %s', $file));

            return Command::FAILURE;
        }

        try {
            $document = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            $io->error('The export file is not valid JSON (only JSON exports can be verified): ' . $e->getMessage());

            return Command::FAILURE;
        }

        $result = $this->chainExporter->verify(is_array($document) ? $document : []);

        $io->section('Verifying audit export ' . $file);
        $io->definitionList(
            ['Rows checked' => sprintf('%d of %d declared', $result->rowsChecked, $result->declaredCount)],
            ['Uid range' => sprintf('%d to %d', $result->firstUid, $result->lastUid)],
            ['Whole chain' => $result->chainComplete ? 'yes' : 'not confirmed'],
            ['HMAC epochs' => $result->epochCounts === []
                ? '(none)'
                : implode(', ', array_map(
                    static fn (int $epoch, int $count): string => sprintf('epoch %d: %d row(s)', $epoch, $count),
                    array_keys($result->epochCounts),
                    array_values($result->epochCounts),
                ))],
        );

        foreach ($result->notes as $note) {
            $io->writeln(' * ' . $note);
        }

        if ($result->isValid()) {
            $io->success($result->chainComplete
                ? 'Export verified: every row matches its entry hash and links to its predecessor.'
                : 'Export verified: every row matches its entry hash. It is not confirmed as the whole chain, so missing rows cannot be ruled out.');

            return Command::SUCCESS;
        }

        foreach ($result->errors as $error) {
            $io->writeln(' - ' . $error);
        }

        $io->error('Export verification FAILED.');

        return Command::FAILURE;
    }
}
