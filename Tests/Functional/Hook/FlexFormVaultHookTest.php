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
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Throwable;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Information\Typo3Version;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Functional tests for FlexFormVaultHook against the real FlexFormTools.
 *
 * The unit tests mock FlexFormTools, so they cannot catch a data structure
 * lookup that fails on the running core — which silently disabled the whole
 * hook and persisted the submitted secret as cleartext in the record XML.
 * These tests therefore resolve the data structure through the container's
 * FlexFormTools on whichever TYPO3 major the suite runs on.
 */
#[CoversClass(FlexFormVaultHook::class)]
final class FlexFormVaultHookTest extends AbstractVaultFunctionalTestCase
{
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

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 1,
    ];

    #[Test]
    public function hookStoresSubmittedFlexFormSecretInVaultInsteadOfTheRecord(): void
    {
        $this->registerDataStructure(self::DATA_STRUCTURE);

        $vaultService = $this->get(VaultServiceInterface::class);
        $hook = $this->get(FlexFormVaultHook::class);

        $secretValue = 'flexform-api-key-value';
        $fieldArray = $this->buildFieldArray($secretValue);

        $hook->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 'NEW1');

        $vaultIdentifier = $fieldArray['pi_flexform']['data']['sDEF']['lDEF']['apiKey']['vDEF'];

        self::assertIsString($vaultIdentifier, 'The submitted value array must be collapsed to an identifier');
        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
            $vaultIdentifier,
            'The FlexForm field must carry a vault identifier',
        );
        self::assertStringNotContainsString(
            $secretValue,
            (string) json_encode($fieldArray),
            'No plaintext may reach DataHandler, which would serialise it into the FlexForm XML',
        );

        try {
            $dataHandler = $this->createDataHandler();
            $dataHandler->substNEWwithIDs['NEW1'] = 4711;
            $hook->processDatamap_afterDatabaseOperations('new', 'tt_content', 'NEW1', $fieldArray, $dataHandler);

            $vaultService->clearCache();
            self::assertSame(
                $secretValue,
                $vaultService->retrieve($vaultIdentifier),
                'The secret must be readable from the vault under its identifier',
            );
        } finally {
            $this->safeDelete($vaultIdentifier);
        }
    }

    #[Test]
    public function hookDiscardsSubmittedSecretWhenDataStructureCannotBeResolved(): void
    {
        $this->registerDataStructure('FILE:EXT:nr_vault/Tests/Functional/Hook/Fixtures/no-such-data-structure.xml');

        $hook = $this->get(FlexFormVaultHook::class);

        $secretValue = 'must-never-be-persisted';
        $fieldArray = $this->buildFieldArray($secretValue);

        $hook->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 'NEW1');

        self::assertStringNotContainsString(
            $secretValue,
            (string) json_encode($fieldArray),
            'An unresolvable data structure must not let the plaintext through to DataHandler',
        );
        self::assertSame(
            '',
            $fieldArray['pi_flexform']['data']['sDEF']['lDEF']['apiKey']['vDEF'],
            'Without a previous secret the field is emptied',
        );
    }

    #[Test]
    public function hookKeepsExistingIdentifierWhenDiscardingSubmittedSecret(): void
    {
        $this->registerDataStructure('FILE:EXT:nr_vault/Tests/Functional/Hook/Fixtures/no-such-data-structure.xml');

        $hook = $this->get(FlexFormVaultHook::class);

        $existingIdentifier = $this->generateUuidV7();
        $secretValue = 'must-never-be-persisted';
        $fieldArray = $this->buildFieldArray($secretValue, $existingIdentifier);

        $hook->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 'NEW1');

        self::assertStringNotContainsString(
            $secretValue,
            (string) json_encode($fieldArray),
            'An unresolvable data structure must not let the plaintext through to DataHandler',
        );
        self::assertSame(
            $existingIdentifier,
            $fieldArray['pi_flexform']['data']['sDEF']['lDEF']['apiKey']['vDEF'],
            'The already stored secret must stay referenced instead of being orphaned',
        );
    }

    /**
     * Register a data structure for `tt_content.pi_flexform` in the shape the
     * running core expects: TYPO3 v14 resolves a single data structure string
     * per field, v13.4 requires the `ds` array with a `default` key.
     */
    private function registerDataStructure(string $dataStructure): void
    {
        unset($GLOBALS['TCA']['tt_content']['columns']['pi_flexform']['config']['ds_pointerField']);

        $GLOBALS['TCA']['tt_content']['columns']['pi_flexform']['config']['ds']
            = (new Typo3Version())->getMajorVersion() >= 14
                ? $dataStructure
                : ['default' => $dataStructure];

        $this->get(TcaSchemaFactory::class)->rebuild($GLOBALS['TCA']);
    }

    /**
     * Build the field array the vault secret element submits for `apiKey`.
     *
     * @return array<string, mixed>
     */
    private function buildFieldArray(string $secretValue, string $existingIdentifier = ''): array
    {
        return [
            'pi_flexform' => [
                'data' => [
                    'sDEF' => [
                        'lDEF' => [
                            'apiKey' => [
                                'vDEF' => [
                                    'value' => $secretValue,
                                    '_vault_identifier' => $existingIdentifier,
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ];
    }

    private function createDataHandler(): DataHandler
    {
        /** @phpstan-ignore new.internalClass */
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->BE_USER = $GLOBALS['BE_USER'];

        return $dataHandler;
    }

    /**
     * Delete a vault secret by identifier, swallowing failures so cleanup never
     * masks the original assertion.
     */
    private function safeDelete(string $identifier): void
    {
        try {
            $vaultService = $this->get(VaultServiceInterface::class);
            if ($vaultService->exists($identifier)) {
                $vaultService->delete($identifier, 'test cleanup');
            }
        } catch (Throwable) {
            // best-effort cleanup
        }
    }
}
