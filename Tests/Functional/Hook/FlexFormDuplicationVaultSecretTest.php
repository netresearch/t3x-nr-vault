<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Hook;

use Netresearch\NrVault\Hook\FlexFormVaultHook;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\VaultSecretInventoryTrait;
use Netresearch\NrVault\Utility\IdentifierValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Information\Typo3Version;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * A FlexForm vault field driven through a real DataHandler `copy` command.
 *
 * The FlexForm path duplicates the whole XML, so the copied record arrives in
 * the nested datamap pass with the source record's vault identifier sitting in
 * the `vDEF` node — the same shape a freshly typed secret has.
 */
#[CoversClass(FlexFormVaultHook::class)]
final class FlexFormDuplicationVaultSecretTest extends AbstractVaultFunctionalTestCase
{
    use VaultSecretInventoryTrait;

    private const DATA_STRUCTURE = '<T3DataStructure>
        <sheets>
            <sDEF>
                <ROOT>
                    <type>array</type>
                    <el>
                        <apiKey>
                            <label>API Key</label>
                            <config>
                                <type>input</type>
                                <renderType>vaultSecret</renderType>
                            </config>
                        </apiKey>
                    </el>
                </ROOT>
            </sDEF>
        </sheets>
    </T3DataStructure>';

    /**
     * A table without a `delete` column, so DataHandler removes its records for
     * good and the FlexForm delete path reaches the vault.
     */
    private const HARD_DELETE_TABLE = 'tx_nrvaulttest_flex';

    private const HARD_DELETE_COLUMN = 'settings';

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
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->createFromUserPreferences(null);
        $this->registerDataStructure();
    }

    #[Test]
    public function copyingARecordGivesTheFlexFormFieldItsOwnSecret(): void
    {
        $plaintext = 'flexform-copy-' . bin2hex(random_bytes(8));

        $uid = $this->createContentElement($plaintext);
        $sourceIdentifier = $this->fetchFlexIdentifier('tt_content', 'pi_flexform', $uid);
        self::assertTrue(IdentifierValidator::looksLikeVaultIdentifier($sourceIdentifier));

        $this->runDataHandler([], ['tt_content' => [$uid => ['copy' => 1]]]);

        $copyUid = $this->findCopyUid($uid);
        $copyIdentifier = $this->fetchFlexIdentifier('tt_content', 'pi_flexform', $copyUid);
        $vaultService = $this->get(VaultServiceInterface::class);

        self::assertSame(
            [
                'copyHasOwnIdentifier' => true,
                'copyPlaintext' => $plaintext,
                'activeSecrets' => 2,
                'createAudits' => 2,
                'secretsHoldingAnIdentifier' => 0,
            ],
            [
                'copyHasOwnIdentifier' => $copyIdentifier !== '' && $copyIdentifier !== $sourceIdentifier,
                'copyPlaintext' => $copyIdentifier === '' ? null : $vaultService->retrieve($copyIdentifier),
                'activeSecrets' => \count($this->activeSecretIdentifiers()),
                'createAudits' => $this->countAuditRows('create'),
                'secretsHoldingAnIdentifier' => $this->countSecretsHoldingAVaultIdentifier(),
            ],
        );
    }

    /**
     * Localizing the record makes the translation a record whose FlexForm
     * column is not translatable: TYPO3 keeps its XML identical to the
     * default-language record's, identifiers included. Cloning the secrets into
     * it would fork the credential — rotating the default record would leave
     * the translation on the old secret — so the duplication must leave that
     * column alone and let the translation share the identifier.
     *
     * Asserted twice: directly after the localize command, and again after an
     * ordinary update of the default record, which is when core pushes the
     * default XML into every translation's data map.
     */
    #[Test]
    public function localizingARecordSharesTheFlexFormSecret(): void
    {
        $plaintext = 'flexform-localize-' . bin2hex(random_bytes(8));

        $uid = $this->createContentElement($plaintext);
        $sourceIdentifier = $this->fetchFlexIdentifier('tt_content', 'pi_flexform', $uid);
        self::assertTrue(IdentifierValidator::looksLikeVaultIdentifier($sourceIdentifier));

        $this->runDataHandler([], ['tt_content' => [$uid => ['localize' => 1]]]);
        $translationUid = $this->findTranslationUid('tt_content', $uid);

        self::assertSame(
            $this->expectedSharedState($plaintext),
            $this->sharedStateOf($uid, $translationUid),
            'The translation must share the default record identifier right after localize',
        );

        $this->runDataHandler(['tt_content' => [$uid => ['header' => 'Changed header']]]);

        self::assertSame(
            $this->expectedSharedState($plaintext),
            $this->sharedStateOf($uid, $translationUid),
            'An ordinary update of the default record must leave the shared secret alone',
        );
    }

    /**
     * A translation shares the default-language record's FlexForm secret, so
     * hard-deleting the translation must leave that secret — and the default
     * record's credential — intact. The identifier sits inside the serialised
     * XML, where no equality comparison can find it, so the delete guard has to
     * search the other records for it.
     *
     * Driven against a fixture table without a `delete` column: `tt_content`
     * soft-deletes, and the FlexForm delete path only reaches the vault on a
     * hard delete.
     */
    #[Test]
    public function hardDeletingATranslationKeepsTheSharedFlexFormSecret(): void
    {
        $plaintext = 'flexform-delete-' . bin2hex(random_bytes(8));

        $uid = $this->createFlexRecord($plaintext);
        $this->runDataHandler([], [self::HARD_DELETE_TABLE => [$uid => ['localize' => 1]]]);
        $translationUid = $this->findTranslationUid(self::HARD_DELETE_TABLE, $uid);

        $identifier = $this->fetchFlexIdentifier(self::HARD_DELETE_TABLE, self::HARD_DELETE_COLUMN, $uid);
        self::assertSame(
            $identifier,
            $this->fetchFlexIdentifier(self::HARD_DELETE_TABLE, self::HARD_DELETE_COLUMN, $translationUid),
            'The translation must share the default record identifier',
        );

        $this->runDataHandler([], [self::HARD_DELETE_TABLE => [$translationUid => ['delete' => 1]]]);

        $vaultService = $this->get(VaultServiceInterface::class);

        self::assertSame(
            [
                'defaultPlaintext' => $plaintext,
                'secretStillExists' => true,
                'activeSecrets' => 1,
            ],
            [
                'defaultPlaintext' => $vaultService->retrieve($identifier),
                'secretStillExists' => $vaultService->exists($identifier),
                'activeSecrets' => \count($this->activeSecretIdentifiers()),
            ],
        );

        // The guard must be able to answer the other way: once no other record
        // references the secret, deleting the last one does remove it.
        $this->runDataHandler([], [self::HARD_DELETE_TABLE => [$uid => ['delete' => 1]]]);

        self::assertSame([], $this->activeSecretIdentifiers());
    }

    /**
     * A record of the hard-deleting fixture table whose FlexForm column holds
     * one vault secret.
     */
    private function createFlexRecord(string $plaintext): int
    {
        $this->runDataHandler([
            self::HARD_DELETE_TABLE => [
                'NEW1' => [
                    'pid' => 1,
                    'title' => 'FlexForm vault source',
                    self::HARD_DELETE_COLUMN => [
                        'data' => [
                            'sDEF' => [
                                'lDEF' => [
                                    'apiKey' => [
                                        'vDEF' => [
                                            'value' => $plaintext,
                                            '_vault_identifier' => '',
                                        ],
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ]);

        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::HARD_DELETE_TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        return (int) $queryBuilder
            ->select('uid')
            ->from(self::HARD_DELETE_TABLE)
            ->orderBy('uid', 'DESC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchOne();
    }

    /**
     * The state a sound shared FlexForm column leaves behind: one secret, one
     * `create` audit entry, both records resolving to the same plaintext
     * through the same identifier, and no secret holding a vault identifier as
     * its value.
     *
     * @return array<string, bool|int|string|null>
     */
    private function expectedSharedState(string $plaintext): array
    {
        return [
            'defaultPlaintext' => $plaintext,
            'translationPlaintext' => $plaintext,
            'translationSharesTheDefaultIdentifier' => true,
            'activeSecrets' => 1,
            'createAudits' => 1,
            'secretsHoldingAnIdentifier' => 0,
        ];
    }

    /**
     * @return array<string, bool|int|string|null>
     */
    private function sharedStateOf(int $uid, int $translationUid): array
    {
        $defaultIdentifier = $this->fetchFlexIdentifier('tt_content', 'pi_flexform', $uid);
        $translationIdentifier = $this->fetchFlexIdentifier('tt_content', 'pi_flexform', $translationUid);
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

    private function findTranslationUid(string $table, int $sourceUid): int
    {
        /** @var array<string, array{ctrl?: array{transOrigPointerField?: string}}> $tca */
        $tca = $GLOBALS['TCA'] ?? [];
        $parentField = $tca[$table]['ctrl']['transOrigPointerField'] ?? '';
        self::assertIsString($parentField);
        self::assertNotSame('', $parentField);

        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        $uids = $queryBuilder
            ->select('uid')
            ->from($table)
            ->where($queryBuilder->expr()->eq($parentField, $queryBuilder->createNamedParameter($sourceUid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchFirstColumn();
        self::assertCount(1, $uids, 'DataHandler must have created exactly one translation');

        return (int) $uids[0];
    }

    /**
     * A site with a second language, which `localize` needs to resolve the
     * target language at all.
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

    private function createContentElement(string $plaintext): int
    {
        $this->runDataHandler([
            'tt_content' => [
                'NEW1' => [
                    'pid' => 1,
                    'header' => 'FlexForm vault source',
                    'CType' => 'text',
                    'pi_flexform' => [
                        'data' => [
                            'sDEF' => [
                                'lDEF' => [
                                    'apiKey' => [
                                        'vDEF' => [
                                            'value' => $plaintext,
                                            '_vault_identifier' => '',
                                        ],
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ]);

        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable('tt_content');
        $queryBuilder->getRestrictions()->removeAll();

        return (int) $queryBuilder
            ->select('uid')
            ->from('tt_content')
            ->orderBy('uid', 'DESC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchOne();
    }

    /**
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

    /**
     * The single vault identifier stored in a record's FlexForm XML.
     */
    private function fetchFlexIdentifier(string $table, string $column, int $uid): string
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        $xml = $queryBuilder
            ->select($column)
            ->from($table)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();
        self::assertIsString($xml, 'Record ' . $table . ':' . $uid . ' not found');

        $parsed = GeneralUtility::xml2array($xml);
        self::assertIsArray($parsed);

        return $this->flexValueAtPath($parsed, ['data', 'sDEF', 'lDEF', 'apiKey', 'vDEF']);
    }

    /**
     * The string value a parsed FlexForm holds at the given path of keys.
     *
     * @param array<array-key, mixed> $node
     * @param list<string> $path
     */
    private function flexValueAtPath(array $node, array $path): string
    {
        $current = $node;

        foreach ($path as $key) {
            self::assertIsArray($current);
            self::assertArrayHasKey($key, $current);
            $current = $current[$key];
        }

        self::assertIsString($current);

        return $current;
    }

    private function findCopyUid(int $sourceUid): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable('tt_content');
        $queryBuilder->getRestrictions()->removeAll();

        $uids = $queryBuilder
            ->select('uid')
            ->from('tt_content')
            ->where($queryBuilder->expr()->neq('uid', $queryBuilder->createNamedParameter($sourceUid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchFirstColumn();
        self::assertCount(1, $uids, 'DataHandler must have created exactly one copy');

        return (int) $uids[0];
    }

    /**
     * Register the vault data structure for `tt_content.pi_flexform` in the
     * shape the running core expects: v14 resolves a single data structure
     * string per field, v13.4 requires the `ds` array with a `default` key.
     */
    private function registerDataStructure(): void
    {
        $tca = $GLOBALS['TCA'];
        self::assertIsArray($tca);
        $ttContent = $tca['tt_content'];
        self::assertIsArray($ttContent);
        $columns = $ttContent['columns'];
        self::assertIsArray($columns);
        $piFlexform = $columns['pi_flexform'];
        self::assertIsArray($piFlexform);
        $config = $piFlexform['config'];
        self::assertIsArray($config);

        unset($config['ds_pointerField']);
        $config['ds'] = (new Typo3Version())->getMajorVersion() >= 14
            ? self::DATA_STRUCTURE
            : ['default' => self::DATA_STRUCTURE];

        $piFlexform['config'] = $config;
        // Top-level, as real TCA carries it: what integrators get from
        // VaultFieldHelper::getSecureFieldConfig(). The same-language copy test
        // then also proves that the translation exclusion does not swallow an
        // ordinary copy.
        $piFlexform['l10n_mode'] = 'exclude';
        $columns['pi_flexform'] = $piFlexform;
        $ttContent['columns'] = $columns;
        $tca['tt_content'] = $ttContent;
        $GLOBALS['TCA'] = $tca;

        /** @phpstan-ignore method.internal */
        $this->get(TcaSchemaFactory::class)->rebuild($tca);
    }
}
