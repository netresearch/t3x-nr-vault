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
use Netresearch\NrVault\Tests\Functional\VaultSecretInventoryTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Every DataHandler command that duplicates a record, driven against real
 * vault fields.
 *
 * `copy` is only the command with a name: a record is also duplicated when it
 * is localized, copied into another language, copied along with its page, or
 * carried along as an inline child of a copied parent. All of them run the new
 * record through a nested `process_datamap()` pass, where the vault field
 * carries the SOURCE record's identifier as a plain string — which is exactly
 * what a freshly typed secret looks like to the datamap hook.
 *
 * Each test therefore asserts an inventory of the whole vault, not only the
 * new record's field: the two failure modes (a secret nothing references, and
 * a secret whose plaintext is another record's identifier) are invisible from
 * the record alone.
 */
#[CoversClass(DataHandlerHook::class)]
final class RecordDuplicationVaultSecretTest extends AbstractVaultFunctionalTestCase
{
    use VaultSecretInventoryTrait;

    private const TABLE = 'tx_nrvaulttest_record';

    private const CHILD_TABLE = 'tx_nrvaulttest_child';

    /** @var list<string> */
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
        __DIR__ . '/../Fixtures/Extensions/nr_vault_test',
    ];

    /** @var list<string> */
    protected array $coreExtensionsToLoad = [
        'backend',
        'frontend',
    ];

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users.csv';

    protected function setUp(): void
    {
        parent::setUp();

        $this->importCSVDataSet(__DIR__ . '/Fixtures/pages.csv');
        $this->writeSiteConfiguration();

        // DataHandler prepends the "copy" label when copying a page and reads
        // it through the language service, which the functional bootstrap does
        // not populate.
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->createFromUserPreferences(null);
    }

    #[Test]
    public function localizeGivesTheTranslationItsOwnSecret(): void
    {
        $plaintext = 'localize-' . bin2hex(random_bytes(8));
        $uid = $this->createRecord($plaintext);
        $sourceIdentifier = $this->fetchVaultField(self::TABLE, $uid);

        $this->runDataHandler([], [self::TABLE => [$uid => ['localize' => 1]]]);

        self::assertSame(
            $this->expectedInventory($plaintext),
            $this->inventoryFor(self::TABLE, $this->findTranslationUid(self::TABLE, $uid), $sourceIdentifier),
        );
    }

    #[Test]
    public function copyToLanguageGivesTheCopyItsOwnSecret(): void
    {
        $plaintext = 'copy-to-language-' . bin2hex(random_bytes(8));
        $uid = $this->createRecord($plaintext);
        $sourceIdentifier = $this->fetchVaultField(self::TABLE, $uid);

        $this->runDataHandler([], [self::TABLE => [$uid => ['copyToLanguage' => 1]]]);

        $copyUid = $this->findOtherUid(self::TABLE, [$uid]);

        self::assertSame(
            $this->expectedInventory($plaintext),
            $this->inventoryFor(self::TABLE, $copyUid, $sourceIdentifier),
        );
    }

    #[Test]
    public function copyingAParentGivesTheInlineChildItsOwnSecret(): void
    {
        $parentSecret = 'inline-parent-' . bin2hex(random_bytes(8));
        $childSecret = 'inline-child-' . bin2hex(random_bytes(8));

        $this->runDataHandler([
            self::TABLE => [
                'NEW-parent' => [
                    'pid' => 1,
                    'title' => 'Parent',
                    'api_key' => $parentSecret,
                    'children' => 'NEW-child',
                ],
            ],
            self::CHILD_TABLE => [
                'NEW-child' => [
                    'pid' => 1,
                    'title' => 'Child',
                    'api_key' => $childSecret,
                ],
            ],
        ]);

        $parentUid = $this->findOtherUid(self::TABLE, []);
        $childUid = $this->findOtherUid(self::CHILD_TABLE, []);
        $childIdentifier = $this->fetchVaultField(self::CHILD_TABLE, $childUid);

        $this->runDataHandler([], [self::TABLE => [$parentUid => ['copy' => 1]]]);

        $copiedChildUid = $this->findOtherUid(self::CHILD_TABLE, [$childUid]);

        self::assertSame(
            [
                'newRecordHasOwnIdentifier' => true,
                'newRecordPlaintext' => $childSecret,
                'activeSecrets' => 4,
                'createAudits' => 4,
                'secretsHoldingAnIdentifier' => 0,
            ],
            $this->inventoryFor(self::CHILD_TABLE, $copiedChildUid, $childIdentifier),
        );
    }

    #[Test]
    public function copyingAPageGivesItsRecordsOwnSecrets(): void
    {
        $plaintext = 'page-copy-' . bin2hex(random_bytes(8));
        $uid = $this->createRecord($plaintext);
        $sourceIdentifier = $this->fetchVaultField(self::TABLE, $uid);

        $this->runDataHandler([], ['pages' => [1 => ['copy' => 0]]]);

        $copyUid = $this->findOtherUid(self::TABLE, [$uid]);

        self::assertSame(
            $this->expectedInventory($plaintext),
            $this->inventoryFor(self::TABLE, $copyUid, $sourceIdentifier),
        );
    }

    /**
     * An ordinary update of the default-language record — no duplicating
     * command anywhere — makes core's DataMapProcessor copy every
     * `l10n_mode = exclude` field of the persisted default record into the data
     * map of each translation. The value it copies is the default record's
     * stored vault identifier, under the translation's numeric uid, which is
     * the one shape an ordinary datamap write and a duplication cannot be told
     * apart by.
     */
    #[Test]
    public function updatingTheDefaultRecordLeavesTheTranslationSecretSound(): void
    {
        $plaintext = 'sync-untouched-' . bin2hex(random_bytes(8));
        $uid = $this->createRecordWithToken($plaintext);
        $translationUid = $this->localizeRecord($uid);

        $this->runDataHandler([self::TABLE => [$uid => ['title' => 'Changed title']]]);

        self::assertSame(
            $this->expectedSynchronisationState($plaintext, $plaintext),
            $this->synchronisationStateOf($uid, $translationUid),
        );
    }

    /**
     * The same synchronisation, but the update rotates the default record's
     * secret: the translation's data map then carries the default record's
     * identifier while a rotation of that very secret is in flight.
     */
    #[Test]
    public function rotatingTheDefaultRecordSecretLeavesTheTranslationSound(): void
    {
        $plaintext = 'sync-rotate-' . bin2hex(random_bytes(8));
        $rotated = 'sync-rotated-' . bin2hex(random_bytes(8));

        $uid = $this->createRecordWithToken($plaintext);
        $translationUid = $this->localizeRecord($uid);
        $identifier = $this->fetchVaultField(self::TABLE, $uid, 'api_token');

        $checksum = $this->get(EncryptionServiceInterface::class)->calculateChecksum($plaintext);
        $this->runDataHandler([
            self::TABLE => [
                $uid => [
                    'api_token' => [
                        'value' => $rotated,
                        '_vault_identifier' => $identifier,
                        '_vault_checksum' => $checksum,
                    ],
                ],
            ],
        ]);

        self::assertSame(
            $this->expectedSynchronisationState($rotated, $rotated),
            $this->synchronisationStateOf($uid, $translationUid),
        );
    }

    /**
     * A translation shares the default record's secret, so deleting the
     * translation must not delete that secret — the default record still
     * references it.
     */
    #[Test]
    public function deletingATranslationKeepsTheSharedSecret(): void
    {
        $plaintext = 'sync-delete-' . bin2hex(random_bytes(8));
        $uid = $this->createRecordWithToken($plaintext);
        $translationUid = $this->localizeRecord($uid);

        $this->runDataHandler([], [self::TABLE => [$translationUid => ['delete' => 1]]]);

        $identifier = $this->fetchVaultField(self::TABLE, $uid, 'api_token');
        $vaultService = $this->get(VaultServiceInterface::class);

        self::assertSame(
            [
                'defaultPlaintext' => $plaintext,
                'secretStillExists' => true,
                'activeSecrets' => 1,
            ],
            [
                'defaultPlaintext' => $identifier === '' ? null : $vaultService->retrieve($identifier),
                'secretStillExists' => $identifier !== '' && $vaultService->exists($identifier),
                'activeSecrets' => \count($this->activeSecretIdentifiers()),
            ],
        );
    }

    /**
     * The state a sound `l10n_mode = exclude` field leaves behind: one secret,
     * one `create` audit entry, and both records resolving to the expected
     * plaintext with no secret holding a vault identifier as its value.
     *
     * @return array<string, bool|int|string|null>
     */
    private function expectedSynchronisationState(string $defaultPlaintext, string $translationPlaintext): array
    {
        return [
            'defaultPlaintext' => $defaultPlaintext,
            'translationPlaintext' => $translationPlaintext,
            'translationSharesTheDefaultIdentifier' => true,
            'activeSecrets' => 1,
            'createAudits' => 1,
            'secretsHoldingAnIdentifier' => 0,
        ];
    }

    /**
     * @return array<string, bool|int|string|null>
     */
    private function synchronisationStateOf(int $uid, int $translationUid): array
    {
        $defaultIdentifier = $this->fetchVaultField(self::TABLE, $uid, 'api_token');
        $translationIdentifier = $this->fetchVaultField(self::TABLE, $translationUid, 'api_token');
        $vaultService = $this->get(VaultServiceInterface::class);

        return [
            'defaultPlaintext' => $defaultIdentifier === '' ? null : $vaultService->retrieve($defaultIdentifier),
            'translationPlaintext' => $translationIdentifier === '' ? null : $vaultService->retrieve($translationIdentifier),
            'translationSharesTheDefaultIdentifier' => $translationIdentifier === $defaultIdentifier,
            'activeSecrets' => \count($this->activeSecretIdentifiers()),
            'createAudits' => $this->countAuditRows('create'),
            'secretsHoldingAnIdentifier' => $this->countSecretsHoldingAVaultIdentifier(),
        ];
    }

    /**
     * A record whose only filled vault field is the `l10n_mode = exclude` one.
     */
    private function createRecordWithToken(string $token): int
    {
        $this->runDataHandler([
            self::TABLE => [
                'NEW1' => [
                    'pid' => 1,
                    'title' => 'Synchronisation source',
                    'api_token' => $token,
                ],
            ],
        ]);

        return $this->findOtherUid(self::TABLE, []);
    }

    private function localizeRecord(int $uid): int
    {
        $this->runDataHandler([], [self::TABLE => [$uid => ['localize' => 1]]]);

        return $this->findTranslationUid(self::TABLE, $uid);
    }

    /**
     * The inventory a correctly duplicated single record leaves behind: one
     * secret for the source, one independent clone for the new record, one
     * `create` audit entry each, and no secret whose plaintext is a vault
     * identifier.
     *
     * @return array<string, bool|int|string|null>
     */
    private function expectedInventory(string $plaintext): array
    {
        return [
            'newRecordHasOwnIdentifier' => true,
            'newRecordPlaintext' => $plaintext,
            'activeSecrets' => 2,
            'createAudits' => 2,
            'secretsHoldingAnIdentifier' => 0,
        ];
    }

    /**
     * Measure the vault state around a duplicated record in one array, so a
     * failure reports every deviation at once instead of the first one.
     *
     * @return array<string, bool|int|string|null>
     */
    private function inventoryFor(
        string $table,
        int $newUid,
        string $sourceIdentifier,
    ): array {
        $newIdentifier = $this->fetchVaultField($table, $newUid);
        $vaultService = $this->get(VaultServiceInterface::class);

        return [
            'newRecordHasOwnIdentifier' => $newIdentifier !== '' && $newIdentifier !== $sourceIdentifier,
            'newRecordPlaintext' => $newIdentifier === '' ? null : $vaultService->retrieve($newIdentifier),
            'activeSecrets' => \count($this->activeSecretIdentifiers()),
            'createAudits' => $this->countAuditRows('create'),
            'secretsHoldingAnIdentifier' => $this->countSecretsHoldingAVaultIdentifier(),
        ];
    }

    private function createRecord(string $apiKey): int
    {
        $this->runDataHandler([
            self::TABLE => [
                'NEW1' => [
                    'pid' => 1,
                    'title' => 'Vault duplication source',
                    'api_key' => $apiKey,
                ],
            ],
        ]);

        return $this->findOtherUid(self::TABLE, []);
    }

    /**
     * Run DataHandler and fail on any error it logged.
     *
     * @param array<string, array<int|string, array<string, mixed>>> $data
     * @param array<string, array<int, array<string, mixed>>> $commands
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

    private function fetchVaultField(string $table, int $uid, string $fieldName = 'api_key'): string
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        $value = $queryBuilder
            ->select($fieldName)
            ->from($table)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();
        self::assertIsString($value, 'Record ' . $table . ':' . $uid . ' not found');

        return $value;
    }

    /**
     * The single uid of $table that is not among $knownUids.
     *
     * @param list<int> $knownUids
     */
    private function findOtherUid(string $table, array $knownUids): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();
        $queryBuilder->select('uid')->from($table);

        foreach ($knownUids as $index => $knownUid) {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->neq('uid', $queryBuilder->createNamedParameter($knownUid, Connection::PARAM_INT, ':known' . $index)),
            );
        }

        $uids = $queryBuilder->executeQuery()->fetchFirstColumn();
        self::assertCount(1, $uids, 'Expected exactly one further record in ' . $table);

        return (int) $uids[0];
    }

    private function findTranslationUid(string $table, int $sourceUid): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        $uids = $queryBuilder
            ->select('uid')
            ->from($table)
            ->where($queryBuilder->expr()->eq('l10n_parent', $queryBuilder->createNamedParameter($sourceUid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchFirstColumn();
        self::assertCount(1, $uids, 'DataHandler must have created exactly one translation');

        return (int) $uids[0];
    }

    /**
     * A site with a second language, which `localize` and `copyToLanguage`
     * need to resolve the target language at all.
     */
    private function writeSiteConfiguration(): void
    {
        $path = $this->instancePath . '/typo3conf/sites/testsite';
        GeneralUtility::mkdir_deep($path);
        file_put_contents($path . '/config.yaml', <<<'YAML'
        rootPageId: 1
        base: /
        languages:
          - title: English
            enabled: true
            languageId: 0
            base: /
            locale: en_US.UTF-8
            flag: us
          - title: German
            enabled: true
            languageId: 1
            base: /de/
            locale: de_DE.UTF-8
            flag: de
        YAML);
    }
}
