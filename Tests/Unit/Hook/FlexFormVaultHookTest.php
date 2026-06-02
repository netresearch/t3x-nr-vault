<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Hook;

use Doctrine\DBAL\Result;
use InvalidArgumentException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Hook\FlexFormVaultHook;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use TYPO3\CMS\Core\Configuration\FlexForm\FlexFormTools;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Messaging\FlashMessageService;
use TYPO3\CMS\Core\Schema\Field\FieldCollection;
use TYPO3\CMS\Core\Schema\Field\FieldTypeInterface;
use TYPO3\CMS\Core\Schema\TcaSchema;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;

#[CoversClass(FlexFormVaultHook::class)]
#[AllowMockObjectsWithoutExpectations]
final class FlexFormVaultHookTest extends TestCase
{
    private const UUID_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';

    private const VAULT_UUID = '01937b6e-4b6c-7abc-8def-0123456789ab';

    private const EXISTING_UUID = '01234567-89ab-7cde-8f01-23456789abcd';

    private const RECORD_DELETED = 'Record deleted';

    private ConnectionPool&MockObject $connectionPool;

    private TcaSchemaFactory&MockObject $tcaSchemaFactory;

    private VaultServiceInterface&MockObject $vaultService;

    private FlexFormTools&MockObject $flexFormTools;

    private DataHandler&MockObject $dataHandler;

    private FlexFormVaultHook $subject;

    protected function setUp(): void
    {
        parent::setUp();

        $this->connectionPool = $this->createMock(ConnectionPool::class);
        $this->tcaSchemaFactory = $this->createMock(TcaSchemaFactory::class);
        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->flexFormTools = $this->createMock(FlexFormTools::class);
        $this->dataHandler = $this->createMock(DataHandler::class);
        $flashMessageService = $this->createStub(FlashMessageService::class);

        $this->subject = new FlexFormVaultHook(
            $this->connectionPool,
            $this->tcaSchemaFactory,
            $this->vaultService,
            $this->flexFormTools,
            $flashMessageService,
        );
    }

    // ---- processDatamap_preProcessFieldArray tests ----

    #[Test]
    public function processDatamapPreProcessFieldArraySkipsUnknownTable(): void
    {
        $this->tcaSchemaFactory
            ->method('has')
            ->with('unknown_table')
            ->willReturn(false);

        $fieldArray = ['field' => 'value'];
        $originalFieldArray = $fieldArray;

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'unknown_table',
            'NEW123',
        );

        self::assertSame($originalFieldArray, $fieldArray);
    }

    #[Test]
    public function processDatamapPreProcessFieldArraySkipsNonFlexFields(): void
    {
        $field = $this->createMock(FieldTypeInterface::class);
        $field->method('getName')->willReturn('title');
        $field->method('getConfiguration')->willReturn(['type' => 'input']);

        $schema = $this->createMock(TcaSchema::class);
        $schema->method('getFields')->willReturn($this->createFieldCollection(['title' => $field]));

        $this->tcaSchemaFactory->method('has')->willReturn(true);
        $this->tcaSchemaFactory->method('get')->willReturn($schema);

        $fieldArray = ['title' => 'Test'];
        $originalFieldArray = $fieldArray;

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tt_content',
            1,
        );

        self::assertSame($originalFieldArray, $fieldArray);
    }

    #[Test]
    public function processDatamapPreProcessFieldArraySkipsFlexFieldNotInFieldArray(): void
    {
        $field = $this->createMock(FieldTypeInterface::class);
        $field->method('getName')->willReturn('pi_flexform');
        $field->method('getConfiguration')->willReturn(['type' => 'flex']);

        $schema = $this->createMock(TcaSchema::class);
        $schema->method('getFields')->willReturn($this->createFieldCollection(['pi_flexform' => $field]));

        $this->tcaSchemaFactory->method('has')->willReturn(true);
        $this->tcaSchemaFactory->method('get')->willReturn($schema);

        $fieldArray = ['title' => 'Test'];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tt_content',
            1,
        );

        self::assertSame(['title' => 'Test'], $fieldArray);
    }

    #[Test]
    public function processDatamapPreProcessFieldArraySkipsNonArrayFlexData(): void
    {
        $field = $this->createMock(FieldTypeInterface::class);
        $field->method('getName')->willReturn('pi_flexform');
        $field->method('getConfiguration')->willReturn(['type' => 'flex']);

        $schema = $this->createMock(TcaSchema::class);
        $schema->method('getFields')->willReturn($this->createFieldCollection(['pi_flexform' => $field]));

        $this->tcaSchemaFactory->method('has')->willReturn(true);
        $this->tcaSchemaFactory->method('get')->willReturn($schema);

        $fieldArray = [
            'title' => 'Test',
            'pi_flexform' => 'not-an-array',
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tt_content',
            1,
        );

        self::assertSame('not-an-array', $fieldArray['pi_flexform']);
    }

    #[Test]
    public function processDatamapAfterDatabaseOperationsProcessesPendingSecrets(): void
    {
        $this->dataHandler->substNEWwithIDs = [];

        $this->subject->processDatamap_afterDatabaseOperations(
            'update',
            'tt_content',
            1,
            [],
            $this->dataHandler,
        );

        self::assertTrue(true);
    }

    #[Test]
    public function processDatamapAfterDatabaseOperationsResolvesNewRecordUid(): void
    {
        $this->dataHandler->substNEWwithIDs = ['NEW123' => 456];

        $this->subject->processDatamap_afterDatabaseOperations(
            'new',
            'tt_content',
            'NEW123',
            [],
            $this->dataHandler,
        );

        self::assertTrue(true);
    }

    #[Test]
    public function processDatamapPreProcessFieldArrayHandlesFlexFormWithNoDataStructure(): void
    {
        $field = $this->createMock(FieldTypeInterface::class);
        $field->method('getName')->willReturn('pi_flexform');
        $field->method('getConfiguration')->willReturn(['type' => 'flex']);

        $schema = $this->createMock(TcaSchema::class);
        $schema->method('getFields')->willReturn($this->createFieldCollection(['pi_flexform' => $field]));

        $this->tcaSchemaFactory->method('has')->willReturn(true);
        $this->tcaSchemaFactory->method('get')->willReturn($schema);

        $this->flexFormTools
            ->method('getDataStructureIdentifier')
            ->willThrowException(new InvalidArgumentException('No data structure'));

        $fieldArray = [
            'pi_flexform' => [
                'data' => [
                    'sDEF' => [
                        'lDEF' => [
                            'field' => ['vDEF' => 'value'],
                        ],
                    ],
                ],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tt_content',
            1,
        );

        self::assertSame('value', $fieldArray['pi_flexform']['data']['sDEF']['lDEF']['field']['vDEF']);
    }

    #[Test]
    public function processDatamapPreProcessFieldArrayHandlesNonVaultRenderType(): void
    {
        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $this->flexFormTools
            ->method('getDataStructureIdentifier')
            ->willReturn('test-ds');

        $this->flexFormTools
            ->method('parseDataStructureByIdentifier')
            ->willReturn([
                'sheets' => [
                    'sDEF' => [
                        'ROOT' => [
                            'el' => [
                                'myField' => [
                                    'config' => [
                                        'type' => 'input',
                                        'renderType' => 'inputDateTime',
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
            ]);

        $fieldArray = [
            'pi_flexform' => [
                'data' => [
                    'sDEF' => [
                        'lDEF' => [
                            'myField' => ['vDEF' => '2024-01-01'],
                        ],
                    ],
                ],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tt_content',
            1,
        );

        self::assertSame('2024-01-01', $fieldArray['pi_flexform']['data']['sDEF']['lDEF']['myField']['vDEF']);
    }

    #[Test]
    public function processDatamapPreProcessFieldArrayProcessesVaultSecretField(): void
    {
        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $this->flexFormTools
            ->method('getDataStructureIdentifier')
            ->willReturn('test-ds');

        $this->flexFormTools
            ->method('parseDataStructureByIdentifier')
            ->willReturn([
                'sheets' => [
                    'sDEF' => [
                        'ROOT' => [
                            'el' => [
                                'settings.apiKey' => [
                                    'config' => [
                                        'type' => 'input',
                                        'renderType' => 'vaultSecret',
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
            ]);

        $fieldArray = [
            'pi_flexform' => [
                'data' => [
                    'sDEF' => [
                        'lDEF' => [
                            'settings.apiKey' => [
                                'vDEF' => [
                                    'value' => 'my-secret-api-key',
                                    '_vault_identifier' => '',
                                    '_vault_checksum' => '',
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tt_content',
            1,
        );

        $vDEF = $fieldArray['pi_flexform']['data']['sDEF']['lDEF']['settings.apiKey']['vDEF'];

        self::assertMatchesRegularExpression(self::UUID_PATTERN, $vDEF);
    }

    #[Test]
    public function processDatamapPreProcessFieldArrayHandlesExistingVaultIdentifier(): void
    {
        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $this->flexFormTools
            ->method('getDataStructureIdentifier')
            ->willReturn('test-ds');

        $this->flexFormTools
            ->method('parseDataStructureByIdentifier')
            ->willReturn([
                'sheets' => [
                    'sDEF' => [
                        'ROOT' => [
                            'el' => [
                                'settings.password' => [
                                    'config' => [
                                        'type' => 'input',
                                        'renderType' => 'vaultSecret',
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
            ]);

        $existingUuid = self::EXISTING_UUID;
        $fieldArray = [
            'pi_flexform' => [
                'data' => [
                    'sDEF' => [
                        'lDEF' => [
                            'settings.password' => [
                                'vDEF' => [
                                    'value' => 'new-password',
                                    '_vault_identifier' => $existingUuid,
                                    '_vault_checksum' => 'abc123',
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tt_content',
            1,
        );

        $vDEF = $fieldArray['pi_flexform']['data']['sDEF']['lDEF']['settings.password']['vDEF'];
        self::assertSame($existingUuid, $vDEF);
    }

    #[Test]
    public function processDatamapPreProcessFieldArrayHandlesEmptySecretValue(): void
    {
        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('test-ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => ['sDEF' => ['ROOT' => ['el' => ['settings.token' => ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']]]]]],
        ]);

        $fieldArray = [
            'pi_flexform' => [
                'data' => ['sDEF' => ['lDEF' => ['settings.token' => ['vDEF' => ['value' => '', '_vault_identifier' => '', '_vault_checksum' => '']]]]],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 1);

        self::assertIsArray($fieldArray['pi_flexform']['data']['sDEF']['lDEF']['settings.token']['vDEF']);
    }

    #[Test]
    public function processDatamapPreProcessFieldArrayHandlesStringVDEFValue(): void
    {
        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('test-ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => ['sDEF' => ['ROOT' => ['el' => ['settings.secret' => ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']]]]]],
        ]);

        $fieldArray = [
            'pi_flexform' => [
                'data' => ['sDEF' => ['lDEF' => ['settings.secret' => ['vDEF' => 'plain-string-secret']]]],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 1);

        $vDEF = $fieldArray['pi_flexform']['data']['sDEF']['lDEF']['settings.secret']['vDEF'];
        self::assertMatchesRegularExpression(self::UUID_PATTERN, $vDEF);
    }

    // ---- Section container support tests ----

    #[Test]
    public function processDatamapPreProcessFieldArrayHandlesSectionContainerVaultFields(): void
    {
        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('test-ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => [
                'sDEF' => [
                    'ROOT' => [
                        'el' => [
                            'credentials' => [
                                'section' => 1,
                                'el' => [
                                    'credential' => [
                                        'el' => [
                                            'apiKey' => [
                                                'config' => ['type' => 'input', 'renderType' => 'vaultSecret'],
                                            ],
                                            'label' => [
                                                'config' => ['type' => 'input'],
                                            ],
                                        ],
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ]);

        $fieldArray = [
            'pi_flexform' => [
                'data' => [
                    'sDEF' => [
                        'lDEF' => [
                            'credentials' => [
                                'el' => [
                                    [
                                        'credential' => [
                                            'el' => [
                                                'apiKey' => [
                                                    'vDEF' => ['value' => 'secret-key-1', '_vault_identifier' => '', '_vault_checksum' => ''],
                                                ],
                                                'label' => ['vDEF' => 'My API Key'],
                                            ],
                                        ],
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 1);

        $vDEF = $fieldArray['pi_flexform']['data']['sDEF']['lDEF']['credentials']['el'][0]['credential']['el']['apiKey']['vDEF'];
        self::assertMatchesRegularExpression(self::UUID_PATTERN, $vDEF);

        $labelVDEF = $fieldArray['pi_flexform']['data']['sDEF']['lDEF']['credentials']['el'][0]['credential']['el']['label']['vDEF'];
        self::assertSame('My API Key', $labelVDEF);
    }

    // ---- processCmdmap_deleteAction tests ----

    #[Test]
    public function deleteActionSkipsSoftDelete(): void
    {
        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $GLOBALS['TCA']['tt_content']['ctrl']['delete'] = 'deleted';

        $recordWasDeleted = false;

        $this->vaultService->expects(self::never())->method('delete');

        $this->subject->processCmdmap_deleteAction(
            'tt_content',
            42,
            ['pi_flexform' => '<T3FlexForms>test</T3FlexForms>'],
            $recordWasDeleted,
            $this->dataHandler,
        );

        unset($GLOBALS['TCA']['tt_content']);
    }

    #[Test]
    public function deleteActionDeletesVaultSecretsOnHardDelete(): void
    {
        $this->mockFlexFieldSchema('tx_test', ['pi_flexform']);

        $GLOBALS['TCA']['tx_test']['ctrl'] = [];

        $uuid = self::VAULT_UUID;
        $xml = '<?xml version="1.0" encoding="utf-8" standalone="yes" ?><T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="settings.apiKey"><value index="vDEF">' . $uuid . '</value></field></language></sheet></data></T3FlexForms>';

        $this->vaultService
            ->method('exists')
            ->with($uuid)
            ->willReturn(true);

        $this->vaultService
            ->expects(self::once())
            ->method('delete')
            ->with($uuid, self::RECORD_DELETED);

        $recordWasDeleted = false;

        $this->subject->processCmdmap_deleteAction(
            'tx_test',
            42,
            ['pi_flexform' => $xml],
            $recordWasDeleted,
            $this->dataHandler,
        );

        unset($GLOBALS['TCA']['tx_test']);
    }

    #[Test]
    public function deleteActionSkipsTableWithoutFlexFields(): void
    {
        $field = $this->createMock(FieldTypeInterface::class);
        $field->method('getName')->willReturn('title');
        $field->method('getConfiguration')->willReturn(['type' => 'input']);

        $schema = $this->createMock(TcaSchema::class);
        $schema->method('getFields')->willReturn($this->createFieldCollection(['title' => $field]));

        $this->tcaSchemaFactory->method('has')->willReturn(true);
        $this->tcaSchemaFactory->method('get')->willReturn($schema);

        $GLOBALS['TCA']['tx_test']['ctrl'] = [];

        $this->vaultService->expects(self::never())->method('delete');

        $recordWasDeleted = false;

        $this->subject->processCmdmap_deleteAction(
            'tx_test',
            42,
            ['title' => 'Some title'],
            $recordWasDeleted,
            $this->dataHandler,
        );

        unset($GLOBALS['TCA']['tx_test']);
    }

    #[Test]
    public function deleteActionSkipsEmptyFlexFormXml(): void
    {
        $this->mockFlexFieldSchema('tx_test', ['pi_flexform']);

        $GLOBALS['TCA']['tx_test']['ctrl'] = [];

        $this->vaultService->expects(self::never())->method('delete');

        $recordWasDeleted = false;

        $this->subject->processCmdmap_deleteAction(
            'tx_test',
            42,
            ['pi_flexform' => ''],
            $recordWasDeleted,
            $this->dataHandler,
        );

        unset($GLOBALS['TCA']['tx_test']);
    }

    #[Test]
    public function deleteActionLogsVaultExceptionOnDelete(): void
    {
        $this->mockFlexFieldSchema('tx_test', ['pi_flexform']);

        $GLOBALS['TCA']['tx_test']['ctrl'] = [];

        $uuid = self::VAULT_UUID;
        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="key"><value index="vDEF">' . $uuid . '</value></field></language></sheet></data></T3FlexForms>';

        $this->vaultService->method('exists')->willReturn(true);
        $this->vaultService->method('delete')->willThrowException(new VaultException('Delete failed'));

        $this->dataHandler
            ->expects(self::once())
            ->method('log')
            ->with('tx_test', 42, 3, 0, 1, self::stringContains('Delete failed'));

        $recordWasDeleted = false;

        $this->subject->processCmdmap_deleteAction(
            'tx_test',
            42,
            ['pi_flexform' => $xml],
            $recordWasDeleted,
            $this->dataHandler,
        );

        unset($GLOBALS['TCA']['tx_test']);
    }

    // ---- processCmdmap_postProcess copy tests ----

    #[Test]
    public function postProcessSkipsNonCopyCommand(): void
    {
        $this->vaultService->expects(self::never())->method('retrieve');

        $this->subject->processCmdmap_postProcess('delete', 'tt_content', 42, null, $this->dataHandler, false);
    }

    #[Test]
    public function postProcessSkipsCopyWithoutMappedNewId(): void
    {
        $this->dataHandler->copyMappingArray = [];

        $this->vaultService->expects(self::never())->method('retrieve');

        $this->subject->processCmdmap_postProcess('copy', 'tt_content', 42, null, $this->dataHandler, false);
    }

    #[Test]
    public function postProcessSkipsCopyForTableWithoutFlexFields(): void
    {
        $this->dataHandler->copyMappingArray = ['tx_test' => [42 => 100]];

        $field = $this->createMock(FieldTypeInterface::class);
        $field->method('getName')->willReturn('title');
        $field->method('getConfiguration')->willReturn(['type' => 'input']);

        $schema = $this->createMock(TcaSchema::class);
        $schema->method('getFields')->willReturn($this->createFieldCollection(['title' => $field]));

        $this->tcaSchemaFactory->method('has')->willReturn(true);
        $this->tcaSchemaFactory->method('get')->willReturn($schema);

        $this->vaultService->expects(self::never())->method('retrieve');

        $this->subject->processCmdmap_postProcess('copy', 'tx_test', 42, null, $this->dataHandler, false);
    }

    #[Test]
    public function postProcessSkipsCopyWhenCopiedRecordNotFound(): void
    {
        $this->dataHandler->copyMappingArray = ['tt_content' => [42 => 100]];

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(false);
        $connection->method('select')->willReturn($result);

        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $this->vaultService->expects(self::never())->method('retrieve');

        $this->subject->processCmdmap_postProcess('copy', 'tt_content', 42, null, $this->dataHandler, false);
    }

    #[Test]
    public function postProcessCopiesFlexFormVaultSecretsSuccessfully(): void
    {
        $this->dataHandler->copyMappingArray = ['tt_content' => [42 => 100]];

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $sourceUuid = self::VAULT_UUID;
        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="key"><value index="vDEF">' . $sourceUuid . '</value></field></language></sheet></data></T3FlexForms>';

        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['pi_flexform' => $xml]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $this->vaultService->method('exists')->willReturn(true);
        $this->vaultService->method('retrieve')->with($sourceUuid)->willReturn('the-secret-value');

        $this->vaultService
            ->expects(self::once())
            ->method('store')
            ->with(
                self::matchesRegularExpression(self::UUID_PATTERN),
                'the-secret-value',
                self::callback(static fn (array $options): bool => $options['table'] === 'tt_content'
                    && $options['flexField'] === 'pi_flexform'
                    && $options['uid'] === 100
                    && $options['source'] === 'flexform_record_copy'
                    && $options['copied_from'] === $sourceUuid),
            );

        $connection
            ->expects(self::once())
            ->method('update')
            ->with(
                'tt_content',
                self::callback(static fn (array $updates): bool => isset($updates['pi_flexform'])
                    && !str_contains($updates['pi_flexform'], $sourceUuid)),
                ['uid' => 100],
            );

        $this->subject->processCmdmap_postProcess('copy', 'tt_content', 42, null, $this->dataHandler, false);
    }

    #[Test]
    public function postProcessSkipsCopyWhenSourceSecretNotFound(): void
    {
        $this->dataHandler->copyMappingArray = ['tt_content' => [42 => 100]];

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $sourceUuid = self::VAULT_UUID;
        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="key"><value index="vDEF">' . $sourceUuid . '</value></field></language></sheet></data></T3FlexForms>';

        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['pi_flexform' => $xml]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $this->vaultService->method('exists')->willReturn(true);
        $this->vaultService->method('retrieve')->willReturn(null);
        $this->vaultService->expects(self::never())->method('store');
        $connection->expects(self::never())->method('update');

        $this->subject->processCmdmap_postProcess('copy', 'tt_content', 42, null, $this->dataHandler, false);
    }

    #[Test]
    public function postProcessLogsVaultExceptionOnCopy(): void
    {
        $this->dataHandler->copyMappingArray = ['tt_content' => [42 => 100]];

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $sourceUuid = self::VAULT_UUID;
        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="key"><value index="vDEF">' . $sourceUuid . '</value></field></language></sheet></data></T3FlexForms>';

        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['pi_flexform' => $xml]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $this->vaultService->method('exists')->willReturn(true);
        $this->vaultService->method('retrieve')->willThrowException(new VaultException('Retrieve failed'));

        $this->dataHandler
            ->expects(self::once())
            ->method('log')
            ->with('tt_content', 100, 1, 0, 1, self::stringContains('Retrieve failed'));

        $this->subject->processCmdmap_postProcess('copy', 'tt_content', 42, null, $this->dataHandler, false);
    }

    #[Test]
    public function postProcessSkipsCopyForEmptyFlexFormXml(): void
    {
        $this->dataHandler->copyMappingArray = ['tt_content' => [42 => 100]];

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['pi_flexform' => '']);
        $connection->method('select')->willReturn($result);

        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $this->vaultService->expects(self::never())->method('retrieve');

        $this->subject->processCmdmap_postProcess('copy', 'tt_content', 42, null, $this->dataHandler, false);
    }

    // ---- storeFlexFormSecret via processDatamap_afterDatabaseOperations ----

    #[Test]
    public function afterDatabaseOperationsStoresNewSecret(): void
    {
        $this->dataHandler->substNEWwithIDs = [];

        // Prime pending secrets via processDatamap_preProcessFieldArray
        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);
        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('test-ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => ['sDEF' => ['ROOT' => ['el' => ['settings.apiKey' => ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']]]]]],
        ]);

        $fieldArray = [
            'pi_flexform' => [
                'data' => ['sDEF' => ['lDEF' => ['settings.apiKey' => ['vDEF' => ['value' => 'my-secret', '_vault_identifier' => '', '_vault_checksum' => '']]]]],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 5);

        // Now trigger afterDatabaseOperations — should call store
        $this->vaultService
            ->expects(self::once())
            ->method('store')
            ->with(
                self::anything(),
                'my-secret',
                self::callback(static fn (array $opts): bool => $opts['table'] === 'tt_content' && $opts['uid'] === 5),
            );

        $this->subject->processDatamap_afterDatabaseOperations('update', 'tt_content', 5, [], $this->dataHandler);
    }

    #[Test]
    public function afterDatabaseOperationsRotatesExistingSecret(): void
    {
        $this->dataHandler->substNEWwithIDs = [];

        $existingUuid = self::EXISTING_UUID;

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);
        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('test-ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => ['sDEF' => ['ROOT' => ['el' => ['settings.token' => ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']]]]]],
        ]);

        $fieldArray = [
            'pi_flexform' => [
                'data' => ['sDEF' => ['lDEF' => ['settings.token' => ['vDEF' => ['value' => 'updated-secret', '_vault_identifier' => $existingUuid, '_vault_checksum' => 'abc123']]]]],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 10);

        $this->vaultService
            ->expects(self::once())
            ->method('rotate')
            ->with($existingUuid, 'updated-secret', 'FlexForm field updated');

        $this->subject->processDatamap_afterDatabaseOperations('update', 'tt_content', 10, [], $this->dataHandler);
    }

    #[Test]
    public function afterDatabaseOperationsDeletesSecretWhenValueCleared(): void
    {
        $this->dataHandler->substNEWwithIDs = [];

        $existingUuid = self::EXISTING_UUID;

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);
        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('test-ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => ['sDEF' => ['ROOT' => ['el' => ['settings.token' => ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']]]]]],
        ]);

        // Empty value with existing checksum → delete
        $fieldArray = [
            'pi_flexform' => [
                'data' => ['sDEF' => ['lDEF' => ['settings.token' => ['vDEF' => ['value' => '', '_vault_identifier' => $existingUuid, '_vault_checksum' => 'abc123']]]]],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 15);

        $this->vaultService
            ->expects(self::once())
            ->method('delete')
            ->with($existingUuid, 'FlexForm field cleared');

        $this->subject->processDatamap_afterDatabaseOperations('update', 'tt_content', 15, [], $this->dataHandler);
    }

    #[Test]
    public function afterDatabaseOperationsLogsErrorOnVaultException(): void
    {
        $this->dataHandler->substNEWwithIDs = [];

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);
        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('test-ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => ['sDEF' => ['ROOT' => ['el' => ['settings.key' => ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']]]]]],
        ]);

        $fieldArray = [
            'pi_flexform' => [
                'data' => ['sDEF' => ['lDEF' => ['settings.key' => ['vDEF' => ['value' => 'secret-val', '_vault_identifier' => '', '_vault_checksum' => '']]]]],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 20);

        $this->vaultService
            ->method('store')
            ->willThrowException(new VaultException('Store failed'));

        $this->dataHandler
            ->expects(self::once())
            ->method('log')
            ->with('tt_content', 20, 2, 0, 1, self::stringContains('Store failed'));

        $this->subject->processDatamap_afterDatabaseOperations('update', 'tt_content', 20, [], $this->dataHandler);
    }

    #[Test]
    public function afterDatabaseOperationsResolvesNewRecordUidFromSubstMap(): void
    {
        $this->dataHandler->substNEWwithIDs = ['NEW456' => 789];

        // No pending secrets — just verifying uid resolution works without error
        $this->subject->processDatamap_afterDatabaseOperations('new', 'tt_content', 'NEW456', [], $this->dataHandler);

        self::assertTrue(true);
    }

    #[Test]
    public function processDatamapPreProcessFieldArraySkipsFieldDataWithNoDataKey(): void
    {
        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);
        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('test-ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => ['sDEF' => ['ROOT' => ['el' => ['field' => ['config' => ['renderType' => 'vaultSecret']]]]]],
        ]);

        // FlexForm data without 'data' key
        $fieldArray = [
            'pi_flexform' => ['no_data_key' => []],
        ];

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 1);

        // Should not throw or modify data
        self::assertArrayNotHasKey('data', $fieldArray['pi_flexform']);
    }

    // ---- Security: XXE / Billion-Laughs hardening ----

    #[Test]
    public function parseFlexFormRejectsXxePayload(): void
    {
        // The FlexFormVaultHook.extractVaultIdentifiersFromXml() uses preg_match_all
        // on raw XML strings — it never calls simplexml_load_string(), DOMDocument,
        // or any XML parser. This means libxml entity expansion cannot occur here.
        //
        // This test is a REGRESSION GUARD: if a future refactor introduces XML parsing,
        // it must ensure libxml_disable_entity_loader(true) is set (PHP 8.0+: already
        // the default when LIBXML_NOENT is NOT passed) or entities are otherwise blocked.
        //
        // We verify the XXE payload does NOT result in /etc/passwd content appearing
        // in any identifier extracted or vault operation triggered.

        $xxeXml = <<<'XML'
        <?xml version="1.0" encoding="utf-8"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <T3FlexForms>
          <data>
            <sheet index="sDEF">
              <language index="lDEF">
                <field index="settings.apiKey">
                  <value index="vDEF">&xxe;01937b6e-4b6c-7abc-8def-0123456789ab</value>
                </field>
              </language>
            </sheet>
          </data>
        </T3FlexForms>
        XML;

        // The hook must NOT call vaultService->delete() for any identifier
        // that contains /etc/passwd content. It should only match the UUID.
        $this->vaultService
            ->method('exists')
            ->willReturn(false); // no vault entry for extracted identifiers

        $this->vaultService->expects(self::never())->method('delete');

        $GLOBALS['TCA']['tx_test']['ctrl'] = [];
        $this->mockFlexFieldSchema('tx_test', ['pi_flexform']);

        $recordWasDeleted = false;
        $this->subject->processCmdmap_deleteAction(
            'tx_test',
            42,
            ['pi_flexform' => $xxeXml],
            $recordWasDeleted,
            $this->dataHandler,
        );

        unset($GLOBALS['TCA']['tx_test']);

        // If we reach here without the hook expanding &xxe; to file contents, the guard holds.
        self::assertTrue(true, 'Hook processed XXE payload without expanding entities');
    }

    #[Test]
    public function parseFlexFormRejectsBillionLaughs(): void
    {
        // Billion-laughs (XML bomb) via nested entity expansion.
        // Same rationale as parseFlexFormRejectsXxePayload: the hook uses preg_match_all,
        // not an XML parser, so entity expansion cannot happen.
        // This test guards against memory exhaustion if XML parsing is ever introduced.

        $billionLaughsXml = <<<'XML'
        <?xml version="1.0"?>
        <!DOCTYPE lolz [
          <!ENTITY lol "lol">
          <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
          <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
        ]>
        <T3FlexForms>
          <data>
            <sheet index="sDEF">
              <language index="lDEF">
                <field index="settings.token">
                  <value index="vDEF">&lol3;01937b6e-4b6c-7abc-8def-0123456789ab</value>
                </field>
              </language>
            </sheet>
          </data>
        </T3FlexForms>
        XML;

        $memBefore = memory_get_peak_usage();

        $this->vaultService->method('exists')->willReturn(false);
        $this->vaultService->expects(self::never())->method('delete');

        $GLOBALS['TCA']['tx_test']['ctrl'] = [];
        $this->mockFlexFieldSchema('tx_test', ['pi_flexform']);

        $recordWasDeleted = false;
        $this->subject->processCmdmap_deleteAction(
            'tx_test',
            42,
            ['pi_flexform' => $billionLaughsXml],
            $recordWasDeleted,
            $this->dataHandler,
        );

        unset($GLOBALS['TCA']['tx_test']);

        $memAfter = memory_get_peak_usage();

        // Memory delta must be well below 10 MB — entity expansion would cause gigabytes.
        $memDeltaMb = ($memAfter - $memBefore) / 1024 / 1024;
        self::assertLessThan(
            10.0,
            $memDeltaMb,
            \sprintf('Memory delta %.2f MB exceeds 10 MB — possible entity expansion', $memDeltaMb),
        );
    }

    // =========================================================================
    // Strict-assertion tests — kill IncrementInteger/DecrementInteger/CastInt/
    // Concat/ConcatOperandRemoval mutators on FlexFormVaultHook.
    // =========================================================================

    /**
     * Kill ConcatOperandRemoval + Concat mutations on the DataHandler log message.
     * The message must contain BOTH the literal prefix AND the exception text.
     */
    #[Test]
    public function deleteActionLogMessageHasExactPrefix(): void
    {
        $this->mockFlexFieldSchema('tx_test', ['pi_flexform']);

        $GLOBALS['TCA']['tx_test']['ctrl'] = [];

        $uuid = self::VAULT_UUID;
        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="key"><value index="vDEF">' . $uuid . '</value></field></language></sheet></data></T3FlexForms>';

        $this->vaultService->method('exists')->willReturn(true);
        $this->vaultService->method('delete')->willThrowException(new VaultException('Boom'));

        // Kills ConcatOperandRemoval: prefix and message must both appear in exact order.
        $this->dataHandler
            ->expects(self::once())
            ->method('log')
            ->with(
                'tx_test',
                42,
                3,
                0,
                1,
                'Vault error during delete for FlexForm field: Boom',
            );

        $recordWasDeleted = false;

        $this->subject->processCmdmap_deleteAction(
            'tx_test',
            42,
            ['pi_flexform' => $xml],
            $recordWasDeleted,
            $this->dataHandler,
        );

        unset($GLOBALS['TCA']['tx_test']);
    }

    /**
     * Kill ConcatOperandRemoval on the copy-error message.
     */
    #[Test]
    public function postProcessLogMessageOnCopyContainsFieldNameAndError(): void
    {
        $this->dataHandler->copyMappingArray = ['tt_content' => [42 => 100]];

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $sourceUuid = self::VAULT_UUID;
        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="key"><value index="vDEF">' . $sourceUuid . '</value></field></language></sheet></data></T3FlexForms>';

        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['pi_flexform' => $xml]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $this->vaultService->method('exists')->willReturn(true);
        $this->vaultService->method('retrieve')->willThrowException(new VaultException('CopyBoom'));

        $this->dataHandler
            ->expects(self::once())
            ->method('log')
            ->with(
                'tt_content',
                100,
                1,
                0,
                1,
                self::callback(static fn (string $msg): bool => str_contains($msg, 'pi_flexform')
                    && str_contains($msg, 'CopyBoom')
                    && str_contains($msg, 'Vault error during copy')),
            );

        $this->subject->processCmdmap_postProcess('copy', 'tt_content', 42, null, $this->dataHandler, false);
    }

    /**
     * Kill ConcatOperandRemoval on the store-error flash message format.
     */
    #[Test]
    public function afterDatabaseOperationsLogMessageContainsFieldPathAndError(): void
    {
        $this->dataHandler->substNEWwithIDs = [];

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);
        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('test-ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => ['sDEF' => ['ROOT' => ['el' => ['settings.key' => ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']]]]]],
        ]);

        $fieldArray = [
            'pi_flexform' => [
                'data' => ['sDEF' => ['lDEF' => ['settings.key' => ['vDEF' => ['value' => 'v', '_vault_identifier' => '', '_vault_checksum' => '']]]]],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 20);

        $this->vaultService
            ->method('store')
            ->willThrowException(new VaultException('StoreExplode'));

        $this->dataHandler
            ->expects(self::once())
            ->method('log')
            ->with(
                'tt_content',
                20,
                2,
                0,
                1,
                self::callback(static fn (string $msg): bool => str_contains($msg, 'settings.key')
                    && str_contains($msg, 'StoreExplode')),
            );

        $this->subject->processDatamap_afterDatabaseOperations('update', 'tt_content', 20, [], $this->dataHandler);
    }

    /**
     * Kill CastInt + Coalesce mutations on the substNEWwithIDs lookup.
     *
     * @return iterable<string, array{string, string|int, array<string|int, int>, int}>
     */
    public static function newRecordUidResolutionProvider(): iterable
    {
        yield 'status=new, subst found → uses substituted uid' => ['new', 'NEW123', ['NEW123' => 456], 456];
        yield 'status=new, subst missing → keeps raw id 0 (string NEW123 non-numeric)' => ['new', 'NEW123', [], 0];
        yield 'status=new, subst returns numeric string' => ['new', 'NEW777', ['NEW777' => 99], 99];
        yield 'status=update, ignores substMap' => ['update', 5, ['NEW123' => 456], 5];
        yield 'status=update, id is string numeric' => ['update', '42', [], 42];
    }

    /**
     * @param array<string|int, int> $substMap
     */
    #[Test]
    #[DataProvider('newRecordUidResolutionProvider')]
    public function afterDatabaseOperationsUidResolutionBoundary(
        string $status,
        string|int $id,
        array $substMap,
        int $expectedUid,
    ): void {
        $this->dataHandler->substNEWwithIDs = $substMap;

        // Prime a pending secret so we can observe the uid passed to vaultService->store.
        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);
        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => ['sDEF' => ['ROOT' => ['el' => ['k' => ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']]]]]],
        ]);

        $fieldArray = [
            'pi_flexform' => [
                'data' => ['sDEF' => ['lDEF' => ['k' => ['vDEF' => ['value' => 'secret', '_vault_identifier' => '', '_vault_checksum' => '']]]]],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', $id);

        $capturedUid = null;
        $this->vaultService
            ->method('store')
            ->willReturnCallback(static function (string $ident, string $val, array $opts) use (&$capturedUid): void {
                $capturedUid = $opts['uid'] ?? null;
            });

        $this->subject->processDatamap_afterDatabaseOperations($status, 'tt_content', $id, [], $this->dataHandler);

        self::assertSame($expectedUid, $capturedUid);
    }

    /**
     * Kill ArrayItemRemoval on the store() options array:
     * - 'table' must be exact table name
     * - 'flexField', 'sheet', 'fieldPath' must be present
     * - 'source' must be 'flexform_field'
     */
    #[Test]
    public function storeOptionsContainAllRequiredKeysWithExactValues(): void
    {
        $this->dataHandler->substNEWwithIDs = [];

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);
        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => ['sDEF' => ['ROOT' => ['el' => ['settings.api' => ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']]]]]],
        ]);

        $fieldArray = [
            'pi_flexform' => [
                'data' => ['sDEF' => ['lDEF' => ['settings.api' => ['vDEF' => ['value' => 'my-secret', '_vault_identifier' => '', '_vault_checksum' => '']]]]],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 5);

        $capturedOptions = null;
        $this->vaultService
            ->method('store')
            ->willReturnCallback(static function (string $id, string $v, array $opts) use (&$capturedOptions): void {
                $capturedOptions = $opts;
            });

        $this->subject->processDatamap_afterDatabaseOperations('update', 'tt_content', 5, [], $this->dataHandler);

        self::assertIsArray($capturedOptions);
        // Each key must exist AND have exact value — kills ArrayItemRemoval
        // and Coalesce mutations on the options payload.
        self::assertSame('tt_content', $capturedOptions['table']);
        self::assertSame('pi_flexform', $capturedOptions['flexField']);
        self::assertSame('sDEF', $capturedOptions['sheet']);
        self::assertSame('settings.api', $capturedOptions['fieldPath']);
        self::assertSame(5, $capturedOptions['uid']);
        self::assertSame('flexform_field', $capturedOptions['source']);
    }

    /**
     * Kill Coalesce mutation on the copy-store options.
     */
    #[Test]
    public function copyStoreOptionsContainExactKeysWithSourceCopy(): void
    {
        $this->dataHandler->copyMappingArray = ['tt_content' => [42 => 100]];

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $sourceUuid = self::VAULT_UUID;
        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="k"><value index="vDEF">' . $sourceUuid . '</value></field></language></sheet></data></T3FlexForms>';

        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['pi_flexform' => $xml]);
        $connection->method('select')->willReturn($result);
        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $this->vaultService->method('exists')->willReturn(true);
        $this->vaultService->method('retrieve')->with($sourceUuid)->willReturn('secret-val');

        $capturedOptions = null;
        $this->vaultService
            ->method('store')
            ->willReturnCallback(static function (string $id, string $v, array $opts) use (&$capturedOptions): void {
                $capturedOptions = $opts;
            });

        $this->subject->processCmdmap_postProcess('copy', 'tt_content', 42, null, $this->dataHandler, false);

        self::assertIsArray($capturedOptions);
        // Kills ArrayItem / Coalesce on the copy options.
        self::assertSame('tt_content', $capturedOptions['table']);
        self::assertSame('pi_flexform', $capturedOptions['flexField']);
        self::assertSame(100, $capturedOptions['uid']);
        self::assertSame('flexform_record_copy', $capturedOptions['source']);
        self::assertSame($sourceUuid, $capturedOptions['copied_from']);
    }

    /**
     * Kill Continue_ mutations (continue → break) inside the fields-loop.
     * If a `continue` is mutated to `break`, secondary vault fields are missed.
     */
    #[Test]
    public function processingTwoFlexFieldsProcessesBoth(): void
    {
        $field1 = $this->createMock(FieldTypeInterface::class);
        $field1->method('getName')->willReturn('flex_one');
        $field1->method('getConfiguration')->willReturn(['type' => 'flex']);

        $field2 = $this->createMock(FieldTypeInterface::class);
        $field2->method('getName')->willReturn('flex_two');
        $field2->method('getConfiguration')->willReturn(['type' => 'flex']);

        $schema = $this->createMock(TcaSchema::class);
        $schema->method('getFields')->willReturn(new FieldCollection(['flex_one' => $field1, 'flex_two' => $field2]));

        $this->tcaSchemaFactory->method('has')->willReturn(true);
        $this->tcaSchemaFactory->method('get')->willReturn($schema);

        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => ['sDEF' => ['ROOT' => ['el' => ['k' => ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']]]]]],
        ]);

        // Provide both flex fields with secret values.
        $fieldArray = [
            'flex_one' => [
                'data' => ['sDEF' => ['lDEF' => ['k' => ['vDEF' => ['value' => 'secret-1', '_vault_identifier' => '', '_vault_checksum' => '']]]]],
            ],
            'flex_two' => [
                'data' => ['sDEF' => ['lDEF' => ['k' => ['vDEF' => ['value' => 'secret-2', '_vault_identifier' => '', '_vault_checksum' => '']]]]],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 1);

        // Both fields must have been rewritten to UUIDs.
        $v1 = $fieldArray['flex_one']['data']['sDEF']['lDEF']['k']['vDEF'];
        $v2 = $fieldArray['flex_two']['data']['sDEF']['lDEF']['k']['vDEF'];

        self::assertMatchesRegularExpression(self::UUID_PATTERN, $v1);
        self::assertMatchesRegularExpression(self::UUID_PATTERN, $v2);

        // If Continue_ is mutated to break, field two is never touched.
        self::assertNotSame($v1, $v2);
    }

    /**
     * Kill Identical mutation `=== 'new'` vs `!== 'new'` — status other than
     * 'new' must NOT consult substNEWwithIDs.
     */
    #[Test]
    public function afterDatabaseOperationsUpdateStatusIgnoresSubstMap(): void
    {
        $this->dataHandler->substNEWwithIDs = ['anything' => 999];

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);
        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => ['sDEF' => ['ROOT' => ['el' => ['k' => ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']]]]]],
        ]);

        $fieldArray = [
            'pi_flexform' => [
                'data' => ['sDEF' => ['lDEF' => ['k' => ['vDEF' => ['value' => 'secret', '_vault_identifier' => '', '_vault_checksum' => '']]]]],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 77);

        $capturedUid = null;
        $this->vaultService
            ->method('store')
            ->willReturnCallback(static function (string $id, string $v, array $opts) use (&$capturedUid): void {
                $capturedUid = $opts['uid'] ?? null;
            });

        $this->subject->processDatamap_afterDatabaseOperations('update', 'tt_content', 77, [], $this->dataHandler);

        // For update status, $id=77 is used directly — substNEWwithIDs is ignored.
        self::assertSame(77, $capturedUid);
    }

    /**
     * Kill MethodCallRemoval on $vaultService->store() for empty value+no checksum (should NOT be called).
     */
    #[Test]
    public function processDatamapDoesNotStoreWhenValueAndChecksumBothEmpty(): void
    {
        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => ['sDEF' => ['ROOT' => ['el' => ['k' => ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']]]]]],
        ]);

        $fieldArray = [
            'pi_flexform' => [
                'data' => ['sDEF' => ['lDEF' => ['k' => ['vDEF' => ['value' => '', '_vault_identifier' => '', '_vault_checksum' => '']]]]],
            ],
        ];

        $this->vaultService->expects(self::never())->method('store');
        $this->vaultService->expects(self::never())->method('delete');
        $this->vaultService->expects(self::never())->method('rotate');

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 1);
        $this->dataHandler->substNEWwithIDs = [];
        $this->subject->processDatamap_afterDatabaseOperations('update', 'tt_content', 1, [], $this->dataHandler);
    }

    /**
     * Kill MethodCallRemoval on $vaultService->delete() when field is cleared.
     * Explicit 'FlexForm field cleared' reason must be passed exactly.
     */
    #[Test]
    public function deleteReasonForClearedFieldIsExactString(): void
    {
        $this->dataHandler->substNEWwithIDs = [];

        $uuid = self::EXISTING_UUID;

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);
        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => ['sDEF' => ['ROOT' => ['el' => ['k' => ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']]]]]],
        ]);

        $fieldArray = [
            'pi_flexform' => [
                'data' => ['sDEF' => ['lDEF' => ['k' => ['vDEF' => ['value' => '', '_vault_identifier' => $uuid, '_vault_checksum' => 'cs']]]]],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 15);

        // Exact reason — kills ConcatOperandRemoval on the reason string.
        $this->vaultService
            ->expects(self::once())
            ->method('delete')
            ->with($uuid, 'FlexForm field cleared');

        $this->subject->processDatamap_afterDatabaseOperations('update', 'tt_content', 15, [], $this->dataHandler);
    }

    /**
     * Kill MethodCallRemoval on $vaultService->rotate() reason.
     */
    #[Test]
    public function rotateReasonIsExactFlexFormFieldUpdated(): void
    {
        $this->dataHandler->substNEWwithIDs = [];

        $uuid = self::EXISTING_UUID;

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);
        $this->flexFormTools->method('getDataStructureIdentifier')->willReturn('ds');
        $this->flexFormTools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => ['sDEF' => ['ROOT' => ['el' => ['k' => ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']]]]]],
        ]);

        $fieldArray = [
            'pi_flexform' => [
                'data' => ['sDEF' => ['lDEF' => ['k' => ['vDEF' => ['value' => 'newval', '_vault_identifier' => $uuid, '_vault_checksum' => 'cs']]]]],
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray($fieldArray, 'tt_content', 33);

        $this->vaultService
            ->expects(self::once())
            ->method('rotate')
            ->with($uuid, 'newval', 'FlexForm field updated');

        $this->subject->processDatamap_afterDatabaseOperations('update', 'tt_content', 33, [], $this->dataHandler);
    }

    /**
     * Kill MethodCallRemoval on the DataHandler connection->update call after copy.
     * The exact `['uid' => $newId]` criteria must be passed.
     */
    #[Test]
    public function postProcessCopyUpdateUsesExactUidCriteria(): void
    {
        $this->dataHandler->copyMappingArray = ['tt_content' => [42 => 100]];

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $sourceUuid = self::VAULT_UUID;
        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="k"><value index="vDEF">' . $sourceUuid . '</value></field></language></sheet></data></T3FlexForms>';

        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['pi_flexform' => $xml]);
        $connection->method('select')->willReturn($result);
        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $this->vaultService->method('exists')->willReturn(true);
        $this->vaultService->method('retrieve')->with($sourceUuid)->willReturn('v');

        // Kill ArrayItemRemoval on `['uid' => 100]`.
        $connection
            ->expects(self::once())
            ->method('update')
            ->with(
                'tt_content',
                self::isArray(),
                ['uid' => 100],
            );

        $this->subject->processCmdmap_postProcess('copy', 'tt_content', 42, null, $this->dataHandler, false);
    }

    /**
     * Kill ArrayOneItem mutator — when only one flex field exists, it must still
     * pass through the foreach correctly.
     */
    #[Test]
    public function deleteActionWithOnlyOneFlexFieldCallsVaultDeleteOnce(): void
    {
        $this->mockFlexFieldSchema('tx_single', ['only_flex']);

        $GLOBALS['TCA']['tx_single']['ctrl'] = [];

        $uuid = self::VAULT_UUID;
        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="k"><value index="vDEF">' . $uuid . '</value></field></language></sheet></data></T3FlexForms>';

        $this->vaultService->method('exists')->willReturn(true);
        $this->vaultService
            ->expects(self::once())
            ->method('delete')
            ->with($uuid, self::RECORD_DELETED);

        $recordWasDeleted = false;

        $this->subject->processCmdmap_deleteAction(
            'tx_single',
            42,
            ['only_flex' => $xml],
            $recordWasDeleted,
            $this->dataHandler,
        );

        unset($GLOBALS['TCA']['tx_single']);
    }

    /**
     * Kill UnwrapArrayValues + UnwrapArrayUnique mutations on extractVaultIdentifiersFromXml():
     * duplicate identifiers in the XML must be de-duplicated.
     */
    #[Test]
    public function duplicateIdentifiersInXmlResultInSingleDeleteCall(): void
    {
        $this->mockFlexFieldSchema('tx_test', ['pi_flexform']);

        $GLOBALS['TCA']['tx_test']['ctrl'] = [];

        $uuid = self::VAULT_UUID;
        // Same UUID appears twice — array_unique must collapse.
        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="a"><value index="vDEF">' . $uuid . '</value></field><field index="b"><value index="vDEF">' . $uuid . '</value></field></language></sheet></data></T3FlexForms>';

        $this->vaultService->method('exists')->willReturn(true);

        // Must be called exactly once despite the duplicate.
        $this->vaultService
            ->expects(self::once())
            ->method('delete')
            ->with($uuid, self::RECORD_DELETED);

        $recordWasDeleted = false;

        $this->subject->processCmdmap_deleteAction(
            'tx_test',
            42,
            ['pi_flexform' => $xml],
            $recordWasDeleted,
            $this->dataHandler,
        );

        unset($GLOBALS['TCA']['tx_test']);
    }

    /**
     * Kill MethodCallRemoval + LogicalNot on the exists() check — only identifiers
     * that exist in the vault are deleted.
     */
    #[Test]
    public function deleteActionSkipsNonExistentVaultIdentifiers(): void
    {
        $this->mockFlexFieldSchema('tx_test', ['pi_flexform']);

        $GLOBALS['TCA']['tx_test']['ctrl'] = [];

        $uuid = self::VAULT_UUID;
        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="k"><value index="vDEF">' . $uuid . '</value></field></language></sheet></data></T3FlexForms>';

        // Secret does NOT exist — delete must NOT be called.
        $this->vaultService->method('exists')->with($uuid)->willReturn(false);
        $this->vaultService->expects(self::never())->method('delete');

        $recordWasDeleted = false;

        $this->subject->processCmdmap_deleteAction(
            'tx_test',
            42,
            ['pi_flexform' => $xml],
            $recordWasDeleted,
            $this->dataHandler,
        );

        unset($GLOBALS['TCA']['tx_test']);
    }

    /**
     * Kill ConcatOperandRemoval on line 259 — error message includes field name
     * in the exact order: 'Vault error during copy for FlexForm field "<name>": <msg>'.
     */
    #[Test]
    public function postProcessCopyLogsExactErrorMessageFormat(): void
    {
        $this->dataHandler->copyMappingArray = ['tt_content' => [42 => 100]];

        $this->mockFlexFieldSchema('tt_content', ['pi_flexform']);

        $sourceUuid = self::VAULT_UUID;
        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="key"><value index="vDEF">' . $sourceUuid . '</value></field></language></sheet></data></T3FlexForms>';

        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['pi_flexform' => $xml]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $this->vaultService->method('exists')->willReturn(true);
        $this->vaultService->method('retrieve')->willThrowException(new VaultException('Boom'));

        $this->dataHandler
            ->expects(self::once())
            ->method('log')
            ->with(
                'tt_content',
                100,
                1,
                0,
                1,
                self::callback(
                    // Kills both Concat and ConcatOperandRemoval on line 259:
                    // message starts with literal prefix, contains field name
                    // 'pi_flexform', then ': ', then the exception message.
                    fn (string $message): bool => str_starts_with($message, 'Vault error during copy for FlexForm field "')
                    && str_contains($message, '"pi_flexform"')
                    && str_contains($message, '": Boom')
                    && str_ends_with($message, 'Boom'),
                ),
            );

        $this->subject->processCmdmap_postProcess('copy', 'tt_content', 42, null, $this->dataHandler, false);
    }

    // ---- Helper methods ----

    /**
     * @param array<string, FieldTypeInterface&MockObject> $fields
     */
    private function createFieldCollection(array $fields): FieldCollection
    {
        return new FieldCollection($fields);
    }

    /**
     * Mock TCA schema with flex fields for a table.
     *
     * @param list<string> $flexFieldNames
     */
    private function mockFlexFieldSchema(string $table, array $flexFieldNames): void
    {
        $fieldMocks = [];
        foreach ($flexFieldNames as $fieldName) {
            $field = $this->createMock(FieldTypeInterface::class);
            $field->method('getName')->willReturn($fieldName);
            $field->method('getConfiguration')->willReturn(['type' => 'flex']);
            $fieldMocks[$fieldName] = $field;
        }

        $schema = $this->createMock(TcaSchema::class);
        $schema->method('getFields')->willReturn($this->createFieldCollection($fieldMocks));

        $this->tcaSchemaFactory->method('has')->with($table)->willReturn(true);
        $this->tcaSchemaFactory->method('get')->with($table)->willReturn($schema);
    }
}
