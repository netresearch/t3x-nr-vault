<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Netresearch\NrVault\Domain\Dto\OrphanReference;
use Netresearch\NrVault\Domain\Dto\SecretRecordLink;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Service\OrphanReferenceCheckerInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

use function array_filter;
use function array_map;
use function array_slice;
use function count;
use function is_string;
use function sprintf;

/**
 * CLI command to clean up orphaned vault secrets from TCA fields.
 *
 * When records with vault-backed fields are deleted, the corresponding
 * vault secrets may become orphaned. This command identifies and removes
 * such orphaned secrets.
 *
 * Usage:
 *   vendor/bin/typo3 vault:cleanup-orphans --dry-run
 *   vendor/bin/typo3 vault:cleanup-orphans --retention-days=30
 *   vendor/bin/typo3 vault:cleanup-orphans
 */
#[AsCommand(
    name: 'vault:cleanup-orphans',
    description: 'Clean up orphaned vault secrets from deleted TCA records',
)]
final class VaultCleanupOrphansCommand extends Command
{
    public function __construct(
        private readonly VaultServiceInterface $vaultService,
        private readonly OrphanReferenceCheckerInterface $orphanReferenceChecker,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'dry-run',
                null,
                InputOption::VALUE_NONE,
                'Show what would be deleted without making changes',
            )
            ->addOption(
                'retention-days',
                'r',
                InputOption::VALUE_REQUIRED,
                'Only delete orphans older than this many days',
                0,
            )
            ->addOption(
                'table',
                't',
                InputOption::VALUE_REQUIRED,
                'Only check secrets for this specific table',
            )
            ->addOption(
                'batch-size',
                'b',
                InputOption::VALUE_REQUIRED,
                'Number of secrets to check per batch',
                100,
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io      = new SymfonyStyle($input, $output);
        $options = $this->parseOptions($input);

        $io->title('Vault Orphan Cleanup');
        $io->text([
            sprintf('Mode: <info>%s</info>', $options['dryRun'] ? 'Dry Run' : 'Live'),
            sprintf('Retention: <info>%d days</info>', $options['retentionDays']),
            $options['tableFilter'] !== null ? sprintf('Table filter: <info>%s</info>', $options['tableFilter']) : '',
        ]);

        $secrets = $this->getTcaSecrets($options['tableFilter']);
        if ($secrets === []) {
            $io->success('No TCA-sourced secrets found');

            return Command::SUCCESS;
        }

        $io->text(sprintf('Found <info>%d</info> TCA-sourced secrets to check', count($secrets)));

        $orphans     = $this->findOrphans($io, $secrets, $options['retentionDays'], $options['batchSize']);
        $orphanCount = count($orphans);
        // Secrets whose check failed on a query or connection error are
        // kept, and the run did not do for them what it was asked: exit 1 on
        // every path below. A link that names an unknown table or field is
        // kept and listed, but never clears on its own, so it does not fail
        // the run.
        $unchecked = $this->countTransient($this->orphanReferenceChecker->getUnresolvedReferences());
        if ($orphanCount === 0) {
            if ($unchecked > 0) {
                return $this->failForUnchecked($io, $unchecked);
            }

            $io->success('No orphaned secrets found');

            return Command::SUCCESS;
        }

        $io->text(sprintf('Found <comment>%d</comment> orphaned secrets', $orphanCount));

        if ($options['dryRun']) {
            $io->section('Orphaned secrets that would be deleted:');
            $this->showOrphanTable($io, $orphans);

            return $unchecked > 0 ? $this->failForUnchecked($io, $unchecked) : Command::SUCCESS;
        }

        if (!$io->confirm(sprintf('Delete %d orphaned secrets?', $orphanCount), false)) {
            $io->warning('Cleanup cancelled');

            return $unchecked > 0 ? $this->failForUnchecked($io, $unchecked) : Command::SUCCESS;
        }

        $result = $this->deleteOrphans($io, $orphans);

        // Stated after a failed delete too, so the reason is not lost.
        return $unchecked > 0 ? $this->failForUnchecked($io, $unchecked) : $result;
    }

    /**
     * The kept secrets are listed already; this names the exit reason.
     */
    private function failForUnchecked(SymfonyStyle $io, int $unchecked): int
    {
        $io->writeln(sprintf('<error>Exit code 1: the check of %d kept secret(s) failed on a query or connection error; run the cleanup again.</error>', $unchecked));

        return Command::FAILURE;
    }

    /**
     * @param list<array{identifier: string, table: string, field: string, uid: int, reason: string, transient: bool}> $unresolved
     */
    private function countTransient(array $unresolved): int
    {
        return count(array_filter($unresolved, static fn (array $entry): bool => $entry['transient']));
    }

    /**
     * Parse CLI options into a typed shape so the main flow stays readable.
     *
     * @return array{dryRun: bool, retentionDays: int, tableFilter: ?string, batchSize: int}
     */
    private function parseOptions(InputInterface $input): array
    {
        $retentionDaysOption = $input->getOption('retention-days');
        $tableFilterOption   = $input->getOption('table');
        $batchSizeOption     = $input->getOption('batch-size');

        return [
            'dryRun'        => (bool) $input->getOption('dry-run'),
            'retentionDays' => is_numeric($retentionDaysOption) ? (int) $retentionDaysOption : 0,
            'tableFilter'   => is_string($tableFilterOption) ? $tableFilterOption : null,
            'batchSize'     => is_numeric($batchSizeOption) && (int) $batchSizeOption > 0 ? (int) $batchSizeOption : 100,
        ];
    }

    /**
     * Iterate TCA-sourced secrets and classify each as orphaned when the
     * backing record no longer exists AND the secret is older than the
     * configured retention cutoff.
     *
     * @param array<int, array{identifier: string, metadata: array<string, mixed>, created_at: int}> $secrets
     *
     * @return list<array{identifier: string, table: string, field: string, uid: int, created_at: int, reference: OrphanReference}>
     */
    private function findOrphans(SymfonyStyle $io, array $secrets, int $retentionDays, int $batchSize): array
    {
        $io->section('Checking for orphaned secrets...');
        $progressBar = $io->createProgressBar(count($secrets));
        $progressBar->start();

        $orphans            = [];
        $checker            = $this->orphanReferenceChecker;
        $effectiveBatchSize = max(1, $batchSize);
        $checker->reset();
        // Never younger than the checker's minimum age, even with 0 days:
        // a secret may be stored a moment before its row is written.
        $retentionCutoff = $checker->deletionCutoff($retentionDays, time());

        foreach (array_chunk($secrets, $effectiveBatchSize) as $batch) {
            foreach ($batch as $secret) {
                $orphan = $this->classifyOrphan($checker, $secret, $retentionCutoff);
                if ($orphan !== null) {
                    $orphans[] = $orphan;
                }

                $progressBar->advance();
            }
        }

        $progressBar->finish();
        $io->newLine(2);

        $this->showUnresolvedReferences($io, $checker->getUnresolvedReferences());

        return $orphans;
    }

    /**
     * Classify a single secret. Returns the orphan payload if retention has
     * elapsed and nothing references the secret any more (see
     * OrphanReferenceChecker), otherwise null.
     *
     * @param array{identifier: string, metadata: array<string, mixed>, created_at: int} $secret
     *
     * @return array{identifier: string, table: string, field: string, uid: int, created_at: int, reference: OrphanReference}|null
     */
    private function classifyOrphan(OrphanReferenceCheckerInterface $checker, array $secret, int $retentionCutoff): ?array
    {
        $identifier   = $secret['identifier'];
        $createdAtRaw = $secret['created_at'] ?? 0;
        $createdAt    = is_numeric($createdAtRaw) ? (int) $createdAtRaw : 0;

        $reference = SecretRecordLink::referenceFrom($secret['metadata']);
        if (!$reference instanceof OrphanReference) {
            return null;
        }

        if ($createdAt >= $retentionCutoff || !$checker->isOrphaned($reference, $identifier)) {
            return null;
        }

        return [
            'identifier' => $identifier,
            'table'      => $reference->table,
            'field'      => $reference->field,
            'uid'        => $reference->uid,
            'created_at' => $createdAt,
            'reference'  => $reference,
        ];
    }

    /**
     * Delete the confirmed orphan list, printing a summary table. Returns
     * FAILURE if any deletion threw; the rest still proceed (best-effort
     * cleanup — vault state is consistent either way).
     *
     * @param list<array{identifier: string, table: string, field: string, uid: int, created_at: int, reference: OrphanReference}> $orphans
     */
    private function deleteOrphans(SymfonyStyle $io, array $orphans): int
    {
        $io->section('Deleting orphaned secrets...');
        $deleted   = 0;
        $failed    = 0;
        $kept      = 0;
        $unchecked = [];
        $errors    = [];

        foreach ($orphans as $orphan) {
            // The list was built before the confirmation prompt, which can
            // wait indefinitely: a row may hold the identifier again by now.
            // A check that fails also answers false; the checker records it
            // as unresolved, which tells the two apart.
            $unresolvedBefore = count($this->orphanReferenceChecker->getUnresolvedReferences());
            if (!$this->orphanReferenceChecker->isOrphaned($orphan['reference'], $orphan['identifier'])) {
                $unresolved = array_slice($this->orphanReferenceChecker->getUnresolvedReferences(), $unresolvedBefore);
                if ($unresolved === []) {
                    ++$kept;
                } else {
                    $unchecked[] = sprintf('%s: %s', $orphan['identifier'], $unresolved[0]['reason']);
                }

                continue;
            }

            try {
                $this->vaultService->delete($orphan['identifier'], 'Orphan cleanup');
                ++$deleted;
            } catch (VaultException $e) {
                ++$failed;
                $errors[] = sprintf('%s: %s', $orphan['identifier'], $e->getMessage());
            }
        }

        $io->section('Cleanup Summary');
        $io->definitionList(
            ['Orphans found' => count($orphans)],
            ['Kept (referenced again)' => $kept],
            ['Kept (could not be checked)' => count($unchecked)],
            ['Successfully deleted' => $deleted],
            ['Failed' => $failed],
        );

        foreach ($unchecked as $note) {
            $io->text('<comment>Kept</comment> ' . $note);
        }

        if ($errors !== []) {
            $io->section('Errors');
            foreach (array_slice($errors, 0, 10) as $error) {
                $io->text('<error>✗</error> ' . $error);
            }
        }

        if ($failed > 0) {
            $io->warning(sprintf('Cleanup completed with %d errors', $failed));

            return Command::FAILURE;
        }

        // A secret whose re-check failed is kept; the run did not do what it
        // was asked for it.
        if ($unchecked !== []) {
            $io->warning(sprintf('Cleanup completed, but %d secret(s) could not be checked again and were kept', count($unchecked)));

            return Command::FAILURE;
        }

        $io->success(sprintf('Successfully deleted %d orphaned secrets', $deleted));

        return Command::SUCCESS;
    }

    /**
     * Get all secrets that carry a record link (see SecretRecordLink).
     *
     * @return array<int, array{identifier: string, metadata: array<string, mixed>, created_at: int}>
     */
    private function getTcaSecrets(?string $tableFilter): array
    {
        $allSecrets = $this->vaultService->list();
        $tcaSecrets = [];

        foreach ($allSecrets as $secret) {
            $metadata  = $secret->metadata;
            $reference = SecretRecordLink::referenceFrom($metadata);
            if (!$reference instanceof OrphanReference) {
                continue;
            }

            // Apply table filter if specified
            if ($tableFilter !== null && $reference->table !== $tableFilter) {
                continue;
            }

            $tcaSecrets[] = [
                'identifier' => $secret->identifier,
                'metadata'   => $metadata,
                'created_at' => $secret->createdAt,
            ];
        }

        return $tcaSecrets;
    }

    /**
     * List the secrets kept because their record link could not be checked.
     * Printed after the progress bar, which a warning written while it runs
     * would break.
     *
     * @param list<array{identifier: string, table: string, field: string, uid: int, reason: string, transient: bool}> $unresolved
     */
    private function showUnresolvedReferences(SymfonyStyle $io, array $unresolved): void
    {
        if ($unresolved === []) {
            return;
        }

        $io->warning(sprintf('Kept %d secret(s) whose record link could not be checked', count($unresolved)));
        $io->table(
            ['Identifier', 'Table', 'Field', 'UID', 'Reason'],
            array_map(
                static fn (array $entry): array => [$entry['identifier'], $entry['table'], $entry['field'], $entry['uid'], $entry['reason']],
                $unresolved,
            ),
        );

        if (count($unresolved) > $this->countTransient($unresolved)) {
            $io->text('A link that names no field, an unknown table or an unknown field stays so: delete the secret by hand (vault:delete), or restore the table or field.');
        }
    }

    /**
     * @param array<int, array{identifier: string, table: string, field: string, uid: int, created_at: int, reference: OrphanReference}> $orphans
     */
    private function showOrphanTable(SymfonyStyle $io, array $orphans): void
    {
        $rows = [];
        foreach (array_slice($orphans, 0, 20) as $orphan) {
            $rows[] = [
                $orphan['identifier'],
                $orphan['table'],
                $orphan['field'],
                $orphan['uid'],
                $orphan['created_at'] > 0 ? date('Y-m-d H:i', $orphan['created_at']) : 'Unknown',
            ];
        }

        $io->table(
            ['Identifier', 'Table', 'Field', 'UID', 'Created'],
            $rows,
        );

        if (count($orphans) > 20) {
            $io->text(sprintf('... and %d more orphans', count($orphans) - 20));
        }
    }
}
