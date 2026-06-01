<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Netresearch\NrVault\Seeder\AuditChainSeeder;
use Netresearch\NrVault\Seeder\DemoDataProvider;
use Netresearch\NrVault\Seeder\DemoSecretSpec;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Dev-only: seed the vault with realistic, historic demo secrets + audit log.
 */
#[AsCommand(
    name: 'vault:seed-demo',
    description: 'Seed demo secrets and audit history (development environments only)',
)]
final class VaultSeedDemoCommand extends Command
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const DEMO_SOURCE = 'demo-seed';

    public function __construct(
        private readonly VaultServiceInterface $vaultService,
        private readonly DemoDataProvider $demoDataProvider,
        private readonly AuditChainSeeder $auditChainSeeder,
        private readonly ConnectionPool $connectionPool,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('force', 'f', InputOption::VALUE_NONE, 'Delete existing demo data and reseed');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        if (Environment::getContext()->isProduction()) {
            $io->error('Refusing to seed demo data in Production context.');

            return Command::FAILURE;
        }

        $force = (bool) $input->getOption('force');
        $existing = $this->demoIdentifiers();

        if ($existing !== [] && !$force) {
            $io->note(\sprintf('%d demo secrets already present. Use --force to reseed.', \count($existing)));

            return Command::SUCCESS;
        }

        if ($existing !== [] && $force) {
            // Soft delete (deleted=1); UNIQUE KEY (identifier, deleted) lets reseed
            // insert fresh deleted=0 rows. Dev-only: tombstone rows accumulate.
            foreach ($existing as $identifier) {
                $this->vaultService->delete($identifier, 'demo reseed');
            }
            $io->writeln(\sprintf('Removed %d existing demo secrets.', \count($existing)));
        }

        $now = time();
        $events = [];

        $specs = $this->demoDataProvider->specs();

        foreach ($specs as $spec) {
            $this->vaultService->store($spec->identifier, $spec->value, [
                'description' => $spec->description,
                'context' => $spec->context,
                'frontendAccessible' => $spec->frontendAccessible,
                'expiresAt' => $spec->expiresInDays !== null ? $now + ($spec->expiresInDays * 86400) : 0,
                'metadata' => ['source' => self::DEMO_SOURCE],
            ]);
            $this->backdateSecret($spec, $now);
            foreach ($this->eventsFor($spec, $now) as $event) {
                $events[] = $event;
            }
        }

        usort($events, static fn (array $a, array $b): int => $a['crdate'] <=> $b['crdate']);
        $this->auditChainSeeder->seed($events);

        $io->success(\sprintf('Seeded %d demo secrets and %d historic audit events.', \count($specs), \count($events)));

        return Command::SUCCESS;
    }

    /**
     * @return list<string>
     */
    private function demoIdentifiers(): array
    {
        $qb = $this->connectionPool->getQueryBuilderForTable(self::SECRET_TABLE);
        $qb->getRestrictions()->removeAll();

        $rows = $qb
            ->select('identifier')
            ->from(self::SECRET_TABLE)
            ->where(
                $qb->expr()->eq('deleted', 0),
                $qb->expr()->like('metadata', $qb->createNamedParameter('%"source":"' . self::DEMO_SOURCE . '"%')),
            )
            ->executeQuery()
            ->fetchFirstColumn();

        return array_values(array_filter($rows, \is_string(...)));
    }

    private function backdateSecret(DemoSecretSpec $spec, int $now): void
    {
        $crdate = $now - ($spec->createdDaysAgo * 86400);
        $qb = $this->connectionPool->getQueryBuilderForTable(self::SECRET_TABLE);
        $qb->update(self::SECRET_TABLE)
            ->set('crdate', $crdate)
            ->set('tstamp', $crdate)
            ->set('read_count', $spec->readCount)
            ->set('last_read_at', $spec->lastReadDaysAgo !== null ? $now - ($spec->lastReadDaysAgo * 86400) : 0)
            ->set('last_rotated_at', $spec->lastRotatedDaysAgo !== null ? $now - ($spec->lastRotatedDaysAgo * 86400) : 0)
            ->where($qb->expr()->eq('identifier', $qb->createNamedParameter($spec->identifier)))
            ->executeStatement();
    }

    /**
     * @return list<array{secret_identifier: string, action: string, success: bool, actor_uid: int, actor_type: string, actor_username: string, crdate: int, context: array<string, scalar|null>}>
     */
    private function eventsFor(DemoSecretSpec $spec, int $now): array
    {
        $events = [];
        foreach ($spec->events as $e) {
            $events[] = [
                'secret_identifier' => $spec->identifier,
                'action' => $e->action,
                'success' => $e->success,
                'actor_uid' => $e->actorUid,
                'actor_type' => $e->actorType,
                'actor_username' => $e->actorUsername,
                'crdate' => $now - ($e->daysAgo * 86400),
                'context' => ['source' => self::DEMO_SOURCE],
            ];
        }

        return $events;
    }
}
