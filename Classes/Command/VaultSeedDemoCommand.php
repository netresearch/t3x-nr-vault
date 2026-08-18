<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Netresearch\NrVault\Security\TechnicalActorContextInterface;
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
 *
 * @phpstan-type DemoAuditEvent array{secret_identifier: string, action: string, success: bool, actor_uid: int, actor_type: string, actor_username: string, crdate: int, context: array<string, bool|float|int|string|null>}
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
        private readonly TechnicalActorContextInterface $technicalActorContext,
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

        // Without an actor the seeded secrets belong to uid 0 and the module
        // prints "User #0" on every row -- next to an owner filter that then has
        // nothing to filter by, on a screen whose whole subject is who may reach
        // which credential. The audit rows for these writes read "Unknown (cli)"
        // for the same reason: an unattributed CLI actor has no username.
        //
        // So the writes run as a real backend user, and ownership is spread over
        // whoever is available, exactly as vault:store --as-provisioner does it.
        $owners = $this->seedOwners();

        if ($owners === []) {
            $io->warning(
                'No usable backend user found. The demo secrets will belong to uid 0 '
                . 'and the module will show them as "User #0".',
            );
            $events = $this->storeAll($specs, $now, []);
        } else {
            /** @var list<DemoAuditEvent> $events */
            $events = $this->technicalActorContext->runAs(
                $owners[0],
                fn (): array => $this->storeAll($specs, $now, $owners),
            );
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
            // Scope to the live row only: after a --force reseed a soft-deleted
            // tombstone (deleted=1) shares this identifier (UNIQUE KEY identifier,deleted).
            ->where(
                $qb->expr()->eq('identifier', $qb->createNamedParameter($spec->identifier)),
                $qb->expr()->eq('deleted', 0),
            )
            ->executeStatement();
    }

    /**
     * @return list<array{secret_identifier: string, action: string, success: bool, actor_uid: int, actor_type: string, actor_username: string, crdate: int, context: array<string, scalar|null>}>
     */
    /**
     * Backend users the demo secrets may belong to, admins first.
     *
     * Real rows on this installation rather than invented ones: a demo that
     * claims users who do not exist cannot demonstrate the owner filter either.
     * Capped at eight so the filter has several entries without turning into a
     * user list, and TYPO3's system accounts are left out.
     *
     * @return list<int<1, max>>
     */
    private function seedOwners(): array
    {
        $qb = $this->connectionPool->getQueryBuilderForTable('be_users');
        $qb->getRestrictions()->removeAll();

        $rows = $qb
            ->select('uid')
            ->from('be_users')
            ->where(
                $qb->expr()->eq('deleted', $qb->createNamedParameter(0)),
                $qb->expr()->eq('disable', $qb->createNamedParameter(0)),
                // TYPO3's own system accounts (_cli_, _scheduler_) are not
                // people. Picking one as the acting user puts "_cli_" in the
                // audit log's Actor column, which is what this was meant to get
                // rid of, and owning a secret is not a thing they do.
                $qb->expr()->notLike('username', $qb->createNamedParameter('\_%')),
            )
            ->orderBy('admin', 'DESC')
            ->addOrderBy('uid', 'ASC')
            ->setMaxResults(8)
            ->executeQuery()
            ->fetchAllAssociative();

        $uids = [];
        foreach ($rows as $row) {
            $raw = $row['uid'] ?? null;
            if (!is_numeric($raw)) {
                continue;
            }

            $uid = (int) $raw;
            if ($uid > 0) {
                $uids[] = $uid;
            }
        }

        return $uids;
    }

    /**
     * @param list<DemoSecretSpec> $specs
     * @param list<int<1, max>> $owners
     *
     * @return list<DemoAuditEvent>
     */
    private function storeAll(array $specs, int $now, array $owners): array
    {
        $events = [];

        foreach ($specs as $index => $spec) {
            $options = [
                'description' => $spec->description,
                'context' => $spec->context,
                'frontendAccessible' => $spec->frontendAccessible,
                'expiresAt' => $spec->expiresInDays !== null ? $now + ($spec->expiresInDays * 86400) : 0,
                'metadata' => ['source' => self::DEMO_SOURCE],
            ];

            if ($owners !== []) {
                $options['owner'] = $owners[$index % \count($owners)];
            }

            $this->vaultService->store($spec->identifier, $spec->value, $options);
            $this->backdateSecret($spec, $now);

            foreach ($this->eventsFor($spec, $now) as $event) {
                $events[] = $event;
            }
        }

        return $events;
    }

    /**
     * @return list<DemoAuditEvent>
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
