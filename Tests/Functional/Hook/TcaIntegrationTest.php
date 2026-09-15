<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Hook;

use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Hook\DataHandlerHook;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Utility\IdentifierValidator;
use Netresearch\NrVault\Utility\VaultFieldResolver;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Functional tests for TCA vault fields driven through the real DataHandler.
 *
 * The record table comes from the `nr_vault_test` fixture extension, so it is
 * part of the TCA schema built at bootstrap. DataHandler then calls the
 * DataHandlerHook that ext_localconf.php registers — no hook is instantiated
 * or seeded by the test.
 */
#[CoversClass(DataHandlerHook::class)]
#[CoversClass(VaultFieldResolver::class)]
final class TcaIntegrationTest extends AbstractVaultFunctionalTestCase
{
    private const TABLE = 'tx_nrvaulttest_record';

    private const DELETE_REASON_CLEANUP = 'Test cleanup';

    /** @var list<string> */
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
        __DIR__ . '/../Fixtures/Extensions/nr_vault_test',
    ];

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users.csv';

    #[Test]
    public function extLocalconfRegistersDataHandlerHookForDatamapAndCmdmap(): void
    {
        $confVars = $GLOBALS['TYPO3_CONF_VARS'];
        self::assertIsArray($confVars);
        $scOptions = $confVars['SC_OPTIONS'] ?? null;
        self::assertIsArray($scOptions);
        $hooks = $scOptions['t3lib/class.t3lib_tcemain.php'] ?? null;
        self::assertIsArray($hooks);
        $datamapHooks = $hooks['processDatamapClass'] ?? null;
        $cmdmapHooks = $hooks['processCmdmapClass'] ?? null;
        self::assertIsArray($datamapHooks);
        self::assertIsArray($cmdmapHooks);

        self::assertContains(DataHandlerHook::class, $datamapHooks);
        self::assertContains(DataHandlerHook::class, $cmdmapHooks);
    }

    #[Test]
    public function dataHandlerStoresVaultSecretOnNewRecord(): void
    {
        $plaintext = 'tca-create-' . bin2hex(random_bytes(8));

        $uid = $this->createRecord($plaintext);
        $record = $this->fetchRecord($uid);
        $identifier = $record['api_key'] ?? null;
        self::assertIsString($identifier);

        self::assertTrue(
            IdentifierValidator::looksLikeVaultIdentifier($identifier),
            'The record column must hold a vault identifier, got: ' . $identifier,
        );
        self::assertStringNotContainsString($plaintext, json_encode($record, JSON_THROW_ON_ERROR));
        self::assertSame($plaintext, $this->vault()->retrieve($identifier));
        self::assertSame('', $record['api_secret'], 'A vault field left empty must stay empty');
    }

    #[Test]
    public function dataHandlerRotatesVaultSecretOnUpdate(): void
    {
        $original = 'tca-original-' . bin2hex(random_bytes(8));
        $rotated = 'tca-rotated-' . bin2hex(random_bytes(8));

        $uid = $this->createRecord($original);
        $identifier = $this->fetchApiKey($uid);
        $versionBefore = $this->vault()->getMetadata($identifier)->version;

        $checksum = $this->get(EncryptionServiceInterface::class)->calculateChecksum($original);
        $this->runDataHandler([
            self::TABLE => [
                $uid => [
                    'api_key' => [
                        'value' => $rotated,
                        '_vault_identifier' => $identifier,
                        '_vault_checksum' => $checksum,
                    ],
                ],
            ],
        ]);

        $record = $this->fetchRecord($uid);
        self::assertSame($identifier, $record['api_key'], 'A rotation must keep the identifier');
        self::assertStringNotContainsString($rotated, json_encode($record, JSON_THROW_ON_ERROR));
        self::assertSame($rotated, $this->vault()->retrieve($identifier));
        self::assertSame($versionBefore + 1, $this->vault()->getMetadata($identifier)->version);
    }

    #[Test]
    public function dataHandlerDeletesVaultSecretOnRecordDelete(): void
    {
        $uid = $this->createRecord('tca-delete-' . bin2hex(random_bytes(8)));
        $identifier = $this->fetchApiKey($uid);
        self::assertTrue($this->vault()->exists($identifier));

        $this->runDataHandler([], [self::TABLE => [$uid => ['delete' => 1]]]);

        self::assertSame(1, (int) $this->fetchRecord($uid)['deleted'], 'The record must be deleted');
        self::assertFalse($this->vault()->exists($identifier), 'The secret of a deleted record must be removed');
    }

    #[Test]
    public function dataHandlerCopiesVaultSecretOnRecordCopy(): void
    {
        $plaintext = 'tca-copy-' . bin2hex(random_bytes(8));
        $uid = $this->createRecord($plaintext);
        $sourceIdentifier = $this->fetchApiKey($uid);

        $this->runDataHandler([], [self::TABLE => [$uid => ['copy' => 0]]]);
        $copyUid = $this->findCopyUid($uid);

        $copyIdentifier = $this->fetchApiKey($copyUid);
        self::assertTrue(IdentifierValidator::looksLikeVaultIdentifier($copyIdentifier));
        self::assertNotSame($sourceIdentifier, $copyIdentifier, 'The copy must get its own secret');
        self::assertSame($plaintext, $this->vault()->retrieve($copyIdentifier));

        // Independence: deleting the copy must leave the source's secret intact.
        $this->runDataHandler([], [self::TABLE => [$copyUid => ['delete' => 1]]]);

        self::assertFalse($this->vault()->exists($copyIdentifier));
        self::assertSame($plaintext, $this->vault()->retrieve($sourceIdentifier));
    }

    #[Test]
    public function vaultFieldResolverResolvesStoredSecrets(): void
    {
        $vaultService = $this->vault();
        // VaultFieldResolver is private in the container; GeneralUtility resolves it through DI.
        $vaultFieldResolver = GeneralUtility::makeInstance(VaultFieldResolver::class);

        $identifier = $this->generateUuidV7();
        $secretValue = 'resolver-secret';
        $vaultService->store($identifier, $secretValue);

        $data = [
            'title' => 'Resolver Test',
            'api_key' => $identifier,
        ];

        $resolved = $vaultFieldResolver->resolveFields($data, ['api_key']);

        self::assertSame($secretValue, $resolved['api_key']);
        self::assertSame('Resolver Test', $resolved['title']);

        $vaultService->delete($identifier, self::DELETE_REASON_CLEANUP);
    }

    #[Test]
    public function multipleVaultFieldsAreHandledCorrectly(): void
    {
        $vaultService = $this->vault();
        $vaultFieldResolver = GeneralUtility::makeInstance(VaultFieldResolver::class);

        $identifier1 = $this->generateUuidV7();
        $identifier2 = $this->generateUuidV7();
        $vaultService->store($identifier1, 'my-key');
        $vaultService->store($identifier2, 'my-secret');

        $data = [
            'title' => 'Multi Field Test',
            'api_key' => $identifier1,
            'api_secret' => $identifier2,
        ];

        $resolved = $vaultFieldResolver->resolveFields($data, ['api_key', 'api_secret']);

        self::assertSame('my-key', $resolved['api_key']);
        self::assertSame('my-secret', $resolved['api_secret']);

        $vaultService->delete($identifier1, self::DELETE_REASON_CLEANUP);
        $vaultService->delete($identifier2, self::DELETE_REASON_CLEANUP);
    }

    private function vault(): VaultServiceInterface
    {
        return $this->get(VaultServiceInterface::class);
    }

    /**
     * Create a record whose `api_key` is entered as plaintext, as FormEngine submits it.
     */
    private function createRecord(string $apiKey): int
    {
        $this->runDataHandler([
            self::TABLE => [
                'NEW1' => [
                    'pid' => 0,
                    'title' => 'Vault TCA integration',
                    'api_key' => $apiKey,
                ],
            ],
        ]);

        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $uid = (int) $queryBuilder
            ->select('uid')
            ->from(self::TABLE)
            ->orderBy('uid', 'DESC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchOne();
        self::assertGreaterThan(0, $uid, 'DataHandler must have created the record');

        return $uid;
    }

    /**
     * Run DataHandler and fail on any error it logged. Errors are read from
     * sys_log, where DataHandler::log() writes them, instead of the @internal
     * `errorLog` property.
     *
     * @param array<string, array<int|string, array<string, mixed>>> $data
     * @param array<string, array<int, array<string, int>>> $commands
     */
    private function runDataHandler(array $data, array $commands = []): void
    {
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start($data, $commands);
        $dataHandler->process_datamap();
        $dataHandler->process_cmdmap();

        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable('sys_log');
        $errors = $queryBuilder
            ->select('details', 'log_data')
            ->from('sys_log')
            ->where($queryBuilder->expr()->gt('error', $queryBuilder->createNamedParameter(0, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchAllAssociative();

        self::assertSame([], $errors, 'DataHandler logged errors: ' . json_encode($errors, JSON_THROW_ON_ERROR));
    }

    private function fetchApiKey(int $uid): string
    {
        $apiKey = $this->fetchRecord($uid)['api_key'] ?? null;
        self::assertIsString($apiKey);

        return $apiKey;
    }

    /**
     * The uid of the one record DataHandler created by copying `$sourceUid`.
     */
    private function findCopyUid(int $sourceUid): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        $uids = $queryBuilder
            ->select('uid')
            ->from(self::TABLE)
            ->where($queryBuilder->expr()->neq('uid', $queryBuilder->createNamedParameter($sourceUid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchFirstColumn();
        self::assertCount(1, $uids, 'DataHandler must have created exactly one copy');

        return (int) $uids[0];
    }

    /**
     * Read a record without any query restriction: `Connection::select()` applies
     * the default restrictions and would hide a soft-deleted record.
     *
     * @return array<string, mixed>
     */
    private function fetchRecord(int $uid): array
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        $record = $queryBuilder
            ->select('*')
            ->from(self::TABLE)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchAssociative();
        self::assertIsArray($record, 'Record ' . $uid . ' not found');

        return $record;
    }
}
