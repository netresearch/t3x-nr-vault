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
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->createFromUserPreferences(null);
        $this->registerDataStructure();
    }

    #[Test]
    public function copyingARecordGivesTheFlexFormFieldItsOwnSecret(): void
    {
        $plaintext = 'flexform-copy-' . bin2hex(random_bytes(8));

        $uid = $this->createContentElement($plaintext);
        $sourceIdentifier = $this->fetchFlexIdentifier($uid);
        self::assertTrue(IdentifierValidator::looksLikeVaultIdentifier($sourceIdentifier));

        $this->runDataHandler([], ['tt_content' => [$uid => ['copy' => 1]]]);

        $copyUid = $this->findCopyUid($uid);
        $copyIdentifier = $this->fetchFlexIdentifier($copyUid);
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
    private function fetchFlexIdentifier(int $uid): string
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable('tt_content');
        $queryBuilder->getRestrictions()->removeAll();

        $xml = $queryBuilder
            ->select('pi_flexform')
            ->from('tt_content')
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();
        self::assertIsString($xml, 'Record tt_content:' . $uid . ' not found');

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
        $columns['pi_flexform'] = $piFlexform;
        $ttContent['columns'] = $columns;
        $tca['tt_content'] = $ttContent;
        $GLOBALS['TCA'] = $tca;

        /** @phpstan-ignore method.internal */
        $this->get(TcaSchemaFactory::class)->rebuild($tca);
    }
}
