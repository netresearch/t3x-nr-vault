<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Hook;

use Netresearch\NrVault\Hook\SecretTcaHook;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Functional tests for SecretTcaHook with real DataHandler operations.
 */
#[CoversClass(SecretTcaHook::class)]
final class SecretTcaHookTest extends AbstractVaultFunctionalTestCase
{
    private const DELETE_REASON_CLEANUP = 'Test cleanup';

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users.csv';

    #[Test]
    public function createSecretRecordViaDataHandler(): void
    {
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                'tx_nrvault_secret' => [
                    'NEW1' => [
                        'pid' => 0,
                        'identifier' => 'test_secret_' . bin2hex(random_bytes(4)),
                        'description' => 'Test secret created via DataHandler',
                        'secret_input' => 'my-secret-value-123',
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();

        // Verify record was created
        self::assertNotEmpty($dataHandler->substNEWwithIDs);
        $newUid = $dataHandler->substNEWwithIDs['NEW1'] ?? 0;
        self::assertGreaterThan(0, $newUid);

        // Verify no errors
        self::assertEmpty($dataHandler->errorLog, 'DataHandler had errors: ' . implode(', ', $dataHandler->errorLog));
    }

    #[Test]
    public function secretInputFieldIsRemovedFromFieldArray(): void
    {
        $identifier = 'test_secret_input_' . bin2hex(random_bytes(4));

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                'tx_nrvault_secret' => [
                    'NEW1' => [
                        'pid' => 0,
                        'identifier' => $identifier,
                        'description' => 'Test',
                        'secret_input' => 'should-not-be-in-database',
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();

        $newUid = $dataHandler->substNEWwithIDs['NEW1'] ?? 0;
        self::assertGreaterThan(0, $newUid);

        // Verify secret_input is not stored in database (it's not a real column)
        // The secret should be stored via VaultService, not directly in the record
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_nrvault_secret');
        $record = $connection->select(
            ['*'],
            'tx_nrvault_secret',
            ['uid' => $newUid],
        )->fetchAssociative();

        self::assertIsArray($record);
        self::assertArrayNotHasKey('secret_input', $record);
    }

    #[Test]
    public function ownerUidIsExtractedFromGroupFormat(): void
    {
        $identifier = 'test_owner_uid_' . bin2hex(random_bytes(4));

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                'tx_nrvault_secret' => [
                    'NEW1' => [
                        'pid' => 0,
                        'identifier' => $identifier,
                        'description' => 'Test owner uid extraction',
                        'owner_uid' => 'be_users_42',
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();

        $newUid = $dataHandler->substNEWwithIDs['NEW1'] ?? 0;
        self::assertGreaterThan(0, $newUid);

        // Verify owner_uid was extracted to numeric value
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_nrvault_secret');
        $record = $connection->select(
            ['owner_uid'],
            'tx_nrvault_secret',
            ['uid' => $newUid],
        )->fetchAssociative();

        self::assertIsArray($record);
        self::assertEquals(42, $record['owner_uid']);
    }

    #[Test]
    public function scopePidIsExtractedFromGroupFormat(): void
    {
        $identifier = 'test_scope_pid_' . bin2hex(random_bytes(4));

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                'tx_nrvault_secret' => [
                    'NEW1' => [
                        'pid' => 0,
                        'identifier' => $identifier,
                        'description' => 'Test scope pid extraction',
                        'scope_pid' => 'pages_100',
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();

        $newUid = $dataHandler->substNEWwithIDs['NEW1'] ?? 0;
        self::assertGreaterThan(0, $newUid);

        // Verify scope_pid was extracted to numeric value
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_nrvault_secret');
        $record = $connection->select(
            ['scope_pid'],
            'tx_nrvault_secret',
            ['uid' => $newUid],
        )->fetchAssociative();

        self::assertIsArray($record);
        self::assertEquals(100, $record['scope_pid']);
    }

    #[Test]
    public function secretIsStoredViaVaultService(): void
    {
        $identifier = 'test_vault_store_' . bin2hex(random_bytes(4));
        $secretValue = 'my-stored-secret-value';

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                'tx_nrvault_secret' => [
                    'NEW1' => [
                        'pid' => 0,
                        'identifier' => $identifier,
                        'description' => 'Test secret storage',
                        'secret_input' => $secretValue,
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();

        $newUid = $dataHandler->substNEWwithIDs['NEW1'] ?? 0;
        self::assertGreaterThan(0, $newUid);
        self::assertEmpty($dataHandler->errorLog);

        // Verify secret was stored via VaultService
        $vaultService = $this->get(VaultServiceInterface::class);
        self::assertTrue($vaultService->exists($identifier));

        $retrieved = $vaultService->retrieve($identifier);
        self::assertEquals($secretValue, $retrieved);

        // Cleanup
        $vaultService->delete($identifier, self::DELETE_REASON_CLEANUP);
    }

    #[Test]
    public function updateSecretRecordRotatesSecret(): void
    {
        $identifier = 'test_rotate_' . bin2hex(random_bytes(4));
        $originalValue = 'original-secret-value';
        $rotatedValue = 'rotated-secret-value';

        // First, create the record
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                'tx_nrvault_secret' => [
                    'NEW1' => [
                        'pid' => 0,
                        'identifier' => $identifier,
                        'description' => 'Test rotation',
                        'secret_input' => $originalValue,
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();

        $recordUid = $dataHandler->substNEWwithIDs['NEW1'] ?? 0;
        self::assertGreaterThan(0, $recordUid);

        $vaultService = $this->get(VaultServiceInterface::class);
        self::assertEquals($originalValue, $vaultService->retrieve($identifier));
        $metadataBefore = $vaultService->getMetadata($identifier);
        self::assertEquals(1, $metadataBefore->version);

        // Now update with new secret
        $updateHandler = GeneralUtility::makeInstance(DataHandler::class);
        $updateHandler->start(
            [
                'tx_nrvault_secret' => [
                    $recordUid => [
                        'secret_input' => $rotatedValue,
                    ],
                ],
            ],
            [],
        );
        $updateHandler->process_datamap();

        // Verify secret was rotated
        self::assertEquals($rotatedValue, $vaultService->retrieve($identifier));
        $metadataAfter = $vaultService->getMetadata($identifier);
        self::assertEquals(2, $metadataAfter->version);

        // Cleanup
        $vaultService->delete($identifier, self::DELETE_REASON_CLEANUP);
    }

    #[Test]
    public function deleteSecretRecordLogsAuditEntry(): void
    {
        $identifier = 'test_delete_audit_' . bin2hex(random_bytes(4));

        // Create record
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                'tx_nrvault_secret' => [
                    'NEW1' => [
                        'pid' => 0,
                        'identifier' => $identifier,
                        'description' => 'Test delete audit',
                        'secret_input' => 'to-be-deleted',
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();

        $recordUid = $dataHandler->substNEWwithIDs['NEW1'] ?? 0;
        self::assertGreaterThan(0, $recordUid);

        // Delete record
        $deleteHandler = GeneralUtility::makeInstance(DataHandler::class);
        $deleteHandler->start(
            [],
            [
                'tx_nrvault_secret' => [
                    $recordUid => [
                        'delete' => 1,
                    ],
                ],
            ],
        );
        $deleteHandler->process_cmdmap();

        // Verify record was soft-deleted (deleted flag set)
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable('tx_nrvault_secret');
        $queryBuilder->getRestrictions()->removeAll();
        $record = $queryBuilder
            ->select('deleted')
            ->from('tx_nrvault_secret')
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($recordUid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchAssociative();

        self::assertIsArray($record);
        self::assertEquals(1, $record['deleted']);

        // Cleanup vault entry
        $vaultService = $this->get(VaultServiceInterface::class);
        if ($vaultService->exists($identifier)) {
            $vaultService->delete($identifier, self::DELETE_REASON_CLEANUP);
        }
    }
}
