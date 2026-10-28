<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service;

use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Audit\AuditChainAnchorStoreInterface;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Audit\VaultMutationTransaction;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Event\SecretCreatedEvent;
use Netresearch\NrVault\Exception\AuditWriteException;
use Netresearch\NrVault\Http\VaultHttpClientFactoryInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Service\VaultService;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Database regressions for the mutation/audit transaction boundary.
 */
final class AtomicVaultMutationTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = ['auditHmacEpoch' => 1];

    #[Test]
    public function failureInSecondAclWriteLeavesNeitherSecretNorPartialAclNorAudit(): void
    {
        $pool       = $this->get(ConnectionPool::class);
        $connection = $pool->getConnectionForTable('tx_nrvault_secret');
        $schema     = $connection->createSchemaManager();
        $table      = $schema
            ->introspectSchema()
            ->getTable('tx_nrvault_secret_writegroups_mm');
        $schema->dropTable('tx_nrvault_secret_writegroups_mm');

        try {
            $failure = null;

            try {
                $this
                    ->get(VaultServiceInterface::class)
                    ->store('atomic_mm_failure', 'synthetic-value', ['groups' => [1]]);
            } catch (Throwable $exception) {
                $failure = $exception;
            }

            self::assertNotNull(
                $failure,
                'The injected database failure must be reached',
            );
            self::assertSame(
                [],
                $connection
                    ->select(['uid'], 'tx_nrvault_secret', [])
                    ->fetchAllAssociative(),
                'A failed ACL write must roll back the secret INSERT',
            );
            self::assertSame(
                [],
                $connection
                    ->select(['uid_local'], 'tx_nrvault_secret_begroups_mm', [])
                    ->fetchAllAssociative(),
                'The first ACL tier must roll back with the second',
            );
            self::assertSame(
                0,
                $this->get(AuditLogServiceInterface::class)->count(),
            );
        } finally {
            $schema->createTable($table);
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function mutationProvider(): iterable
    {
        foreach (['create', 'update', 'rotate', 'delete', 'disable'] as $operation) {
            yield $operation => [$operation];
        }
    }

    #[Test]
    #[DataProvider('mutationProvider')]
    public function actualAuditDatabaseFailureRollsBackEveryPersistedField(
        string $operation,
    ): void {
        $service    = $this->get(VaultServiceInterface::class);
        $connection = $this
            ->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_secret');
        if ($operation !== 'create') {
            $service->store(
                'atomic_audit_failure',
                'original-synthetic-value',
                ['groups' => [1]],
            );
        }

        $before = $connection
            ->select(['*'], 'tx_nrvault_secret', [])
            ->fetchAllAssociative();
        $groupsBefore = $connection
            ->select(['*'], 'tx_nrvault_secret_begroups_mm', [])
            ->fetchAllAssociative();
        $schema = $connection->createSchemaManager();
        $table  = $schema->introspectSchema()->getTable('tx_nrvault_audit_log');
        $schema->dropTable('tx_nrvault_audit_log');
        $failure = null;

        try {
            match ($operation) {
                'create', 'update' => $service->store(
                    'atomic_audit_failure',
                    'replacement-synthetic-value',
                    ['groups' => [2]],
                ),
                'rotate' => $service->rotate(
                    'atomic_audit_failure',
                    'replacement-synthetic-value',
                ),
                'delete'  => $service->delete('atomic_audit_failure'),
                'disable' => $service->setEnabled('atomic_audit_failure', false),
                default   => self::fail('Unknown mutation'),
            };
        } catch (Throwable $exception) {
            $failure = $exception;
        } finally {
            $schema->createTable($table);
        }

        self::assertInstanceOf(
            AuditWriteException::class,
            $failure,
        );
        self::assertSame(
            $before,
            $connection
                ->select(['*'], 'tx_nrvault_secret', [])
                ->fetchAllAssociative(),
        );
        self::assertSame(
            $groupsBefore,
            $connection
                ->select(['*'], 'tx_nrvault_secret_begroups_mm', [])
                ->fetchAllAssociative(),
        );
        self::assertFalse($connection->isTransactionActive());
    }

    #[Test]
    public function stockServicePublishesSinksAndEventsOnlyAfterTheOuterCommit(): void
    {
        $connection = $this
            ->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_secret');
        $observed = [];
        $sinks    = $this->createMock(
            AuditSinkRegistryInterface::class,
        );
        $sinks
            ->expects(self::once())
            ->method('dispatch')
            ->willReturnCallback(
                static function () use ($connection, &$observed): int {
                    self::assertFalse($connection->isTransactionActive());
                    self::assertSame(
                        1,
                        (int) $connection->count(
                            '*',
                            'tx_nrvault_secret',
                            ['identifier' => 'atomic_effects'],
                        ),
                    );
                    self::assertSame(
                        1,
                        (int) $connection->count(
                            '*',
                            'tx_nrvault_audit_log',
                            ['secret_identifier' => 'atomic_effects'],
                        ),
                    );
                    $observed[] = 'sink';

                    return 1;
                },
            );
        $events = $this->createMock(EventDispatcherInterface::class);
        $events
            ->expects(self::once())
            ->method('dispatch')
            ->willReturnCallback(
                static function (
                    object $event,
                ) use ($connection, &$observed): object {
                    self::assertFalse($connection->isTransactionActive());
                    self::assertInstanceOf(
                        SecretCreatedEvent::class,
                        $event,
                    );
                    $observed[] = 'event';

                    return $event;
                },
            );
        $service = $this->buildObservedService($sinks, $events);
        $service->store('atomic_effects', 'synthetic-value');
        self::assertSame(['sink', 'event'], $observed);
        self::assertTrue(
            $this
                ->get(AuditLogServiceInterface::class)
                ->verifyHashChain()
                ->isValid(),
        );
    }

    #[Test]
    public function failedAnchorWriteAfterAuditInsertDoesNotLeaveAGapInTheNextCommittedChain(): void
    {
        $service = $this->get(VaultServiceInterface::class);
        $audit   = $this->get(AuditLogServiceInterface::class);
        $service->store('atomic_anchor_failure', 'original-synthetic-value');
        $connection = $this->get(ConnectionPool::class)->getConnectionForTable('sys_registry');
        $schema     = $connection->createSchemaManager();
        $table      = $schema->introspectSchema()->getTable('sys_registry');
        $rows       = $connection->select(['*'], 'sys_registry', [])->fetchAllAssociative();
        $schema->dropTable('sys_registry');
        $failure = null;

        try {
            $service->rotate('atomic_anchor_failure', 'aborted-synthetic-value');
        } catch (Throwable $exception) {
            $failure = $exception;
        } finally {
            $schema->createTable($table);
            foreach ($rows as $row) {
                $connection->insert('sys_registry', $row);
            }
        }

        self::assertInstanceOf(
            AuditWriteException::class,
            $failure,
        );
        self::assertSame(1, $audit->count());
        $service->rotate('atomic_anchor_failure', 'committed-synthetic-value');
        self::assertSame(2, $audit->count());
        self::assertTrue(
            $audit->verifyHashChain()->isValid(),
            'A rolled-back audit INSERT must not create a false tamper alarm on the next append',
        );
        self::assertSame(
            'committed-synthetic-value',
            $service->retrieve('atomic_anchor_failure'),
        );
    }

    private function buildObservedService(
        AuditSinkRegistryInterface $sinks,
        EventDispatcherInterface $events,
    ): VaultService {
        $pool        = $this->get(ConnectionPool::class);
        $transaction = new VaultMutationTransaction($pool);
        $access      = $this->get(
            AccessControlServiceInterface::class,
        );
        $config = $this->get(
            ExtensionConfigurationInterface::class,
        );
        $audit = new AuditLogService(
            $pool,
            $access,
            $this->get(
                MasterKeyProviderInterface::class,
            ),
            $config,
            $this->get(
                AuditChainAnchorStoreInterface::class,
            ),
            $sinks,
            mutationTransaction: $transaction,
        );

        return new VaultService(
            $this->get(
                VaultAdapterInterface::class,
            ),
            $this->get(
                EncryptionServiceInterface::class,
            ),
            $access,
            $audit,
            $config,
            $this->get(
                VaultHttpClientFactoryInterface::class,
            ),
            $events,
            mutationTransaction: $transaction,
        );
    }
}
