<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Hook;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Hook\DataHandlerHook;
use Netresearch\NrVault\Hook\PendingSecretExtractor;
use Netresearch\NrVault\Hook\PendingSecretPersister;
use Netresearch\NrVault\Hook\VaultFailureReporter;
use Netresearch\NrVault\Service\VaultFieldPermissionService;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Utility\IdentifierValidator;
use Netresearch\NrVault\Utility\VaultFieldResolver;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use ReflectionClass;
use RuntimeException;
use Stringable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Messaging\FlashMessageQueue;
use TYPO3\CMS\Core\Messaging\FlashMessageService;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;

#[CoversClass(DataHandlerHook::class)]
#[AllowMockObjectsWithoutExpectations]
final class DataHandlerHookTest extends TestCase
{
    private const UUID_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';

    private const EXISTING_UUID = '01937b6e-4b6c-7abc-8def-0123456789ab';

    private const SECOND_UUID = '01937b6e-4b6c-7abc-8def-0123456789ac';

    private const THIRD_UUID = '01937b6e-4b6c-7abc-8def-0123456789ad';

    private const RETRIEVE_FAILED = 'Retrieve failed';

    private const TEST_TITLE = 'Test Title';

    private const STORAGE_FAILED = 'Storage failed';

    protected bool $resetSingletonInstances = true;

    protected TcaSchemaFactory&MockObject $tcaSchemaFactory;

    private DataHandlerHook $subject;

    private VaultServiceInterface&MockObject $vaultService;

    private DataHandler&MockObject $dataHandler;

    private ConnectionPool&MockObject $connectionPool;

    private FlashMessageService&MockObject $flashMessageService;

    private LoggerInterface&MockObject $failureLogger;

    protected function setUp(): void
    {
        parent::setUp();

        $this->connectionPool = $this->createMock(ConnectionPool::class);
        $this->tcaSchemaFactory = $this->createMock(TcaSchemaFactory::class);
        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->flashMessageService = $this->createMock(FlashMessageService::class);
        $this->dataHandler = $this->createMock(DataHandler::class);

        // The hook's collaborators are pure extracted logic: wire them for real
        // so the vault-service, flash-message and rollback expectations exercise
        // the actual decision pipeline rather than mock theatre.
        $vaultFieldResolver = new VaultFieldResolver(
            $this->vaultService,
            $this->tcaSchemaFactory,
            $this->createMock(LoggerInterface::class),
        );
        $pendingSecretExtractor = new PendingSecretExtractor();
        $pendingSecretPersister = new PendingSecretPersister(
            $this->vaultService,
            $this->flashMessageService,
        );

        $this->failureLogger = $this->createMock(LoggerInterface::class);

        $this->subject = new DataHandlerHook(
            $this->connectionPool,
            $this->vaultService,
            $vaultFieldResolver,
            $pendingSecretExtractor,
            $pendingSecretPersister,
            new VaultFailureReporter($this->failureLogger),
            new VaultFieldPermissionService(),
        );
    }

    #[Test]
    public function preProcessFieldArrayIgnoresFieldsWithoutVaultRenderType(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'title' => ['type' => 'input'],
        ]);

        $fieldArray = ['title' => self::TEST_TITLE];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            1,
        );

        self::assertSame(['title' => self::TEST_TITLE], $fieldArray);
    }

    #[Test]
    public function preProcessFieldArrayGeneratesUuidForNewSecret(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $fieldArray = [
            'api_key' => [
                'value' => 'my-secret-key',
                '_vault_identifier' => '',
                '_vault_checksum' => '',
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            1,
        );

        // Value should be replaced with a UUID
        self::assertMatchesRegularExpression(self::UUID_PATTERN, $fieldArray['api_key']);
    }

    #[Test]
    public function preProcessFieldArrayKeepsExistingUuidForUpdate(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $existingUuid = self::EXISTING_UUID;
        $fieldArray = [
            'api_key' => [
                'value' => 'updated-secret',
                '_vault_identifier' => $existingUuid,
                '_vault_checksum' => 'existing-checksum',
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            42,
        );

        // Should keep existing UUID
        self::assertSame($existingUuid, $fieldArray['api_key']);
    }

    #[Test]
    public function preProcessFieldArrayHandlesStringValue(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $fieldArray = ['api_key' => 'direct-string-value'];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            1,
        );

        // Should generate UUID for string value
        self::assertMatchesRegularExpression(self::UUID_PATTERN, $fieldArray['api_key']);
    }

    #[Test]
    public function preProcessFieldArrayRemovesEmptyValueWithNoChecksum(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $fieldArray = [
            'api_key' => [
                'value' => '',
                '_vault_identifier' => '',
                '_vault_checksum' => '',
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            1,
        );

        // Empty values with no checksum should be removed entirely
        self::assertArrayNotHasKey('api_key', $fieldArray);
    }

    #[Test]
    public function afterDatabaseOperationsStoresNewSecret(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        // Setup pending secrets via preProcess
        $fieldArray = [
            'api_key' => [
                'value' => 'new-secret',
                '_vault_identifier' => '',
                '_vault_checksum' => '',
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            'NEW123',
        );

        // Mock substitution of NEW id
        $this->dataHandler->substNEWwithIDs = ['NEW123' => 42];

        $this->vaultService
            ->expects(self::once())
            ->method('store')
            ->with(
                self::matchesRegularExpression(self::UUID_PATTERN),
                'new-secret',
                self::callback(static fn (array $options): bool => $options['table'] === 'tx_test'
                    && $options['field'] === 'api_key'
                    && $options['uid'] === 42
                    && $options['source'] === 'tca_field'),
            );

        $this->subject->processDatamap_afterDatabaseOperations(
            'new',
            'tx_test',
            'NEW123',
            $fieldArray,
            $this->dataHandler,
        );
    }

    #[Test]
    public function afterDatabaseOperationsRotatesExistingSecret(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $existingUuid = self::EXISTING_UUID;
        $fieldArray = [
            'api_key' => [
                'value' => 'updated-secret',
                '_vault_identifier' => $existingUuid,
                '_vault_checksum' => 'existing-checksum',
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            42,
        );

        $this->vaultService
            ->expects(self::once())
            ->method('rotate')
            ->with(
                $existingUuid,
                'updated-secret',
                'TCA field updated',
            );

        $this->subject->processDatamap_afterDatabaseOperations(
            'update',
            'tx_test',
            42,
            $fieldArray,
            $this->dataHandler,
        );
    }

    #[Test]
    public function afterDatabaseOperationsDeletesSecretWhenExplicitlyCleared(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $existingUuid = self::EXISTING_UUID;
        // The clear control blanks the checksum while keeping the identifier —
        // that is what distinguishes an explicit clear from an untouched re-save.
        $fieldArray = [
            'api_key' => [
                'value' => '',
                '_vault_identifier' => $existingUuid,
                '_vault_checksum' => '',
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            42,
        );

        $this->vaultService
            ->expects(self::once())
            ->method('delete')
            ->with(
                $existingUuid,
                'TCA field cleared',
            );

        $this->subject->processDatamap_afterDatabaseOperations(
            'update',
            'tx_test',
            42,
            $fieldArray,
            $this->dataHandler,
        );
    }

    /**
     * Regression for issue #223: re-saving a record without retyping the masked
     * secret submits an empty value but the checksum is still present. The stored
     * secret must be kept, not wiped from the record or the vault.
     */
    #[Test]
    public function afterDatabaseOperationsKeepsSecretWhenFieldLeftUntouched(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $existingUuid = self::EXISTING_UUID;
        $fieldArray = [
            'api_key' => [
                'value' => '',
                '_vault_identifier' => $existingUuid,
                '_vault_checksum' => 'existing-checksum',
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            42,
        );

        // The untouched field is dropped from the datamap, so the database keeps
        // its existing identifier untouched.
        self::assertArrayNotHasKey('api_key', $fieldArray, 'Untouched secret field must be left unchanged');

        $this->vaultService
            ->expects(self::never())
            ->method('delete');

        $this->subject->processDatamap_afterDatabaseOperations(
            'update',
            'tx_test',
            42,
            $fieldArray,
            $this->dataHandler,
        );
    }

    #[Test]
    public function afterDatabaseOperationsLogsVaultException(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        // Mock connection for rollback
        $connection = $this->createMock(Connection::class);
        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        // Mock flash message queue
        $flashMessageQueue = $this->createMock(FlashMessageQueue::class);
        $this->flashMessageService->method('getMessageQueueByIdentifier')->willReturn($flashMessageQueue);

        $fieldArray = ['api_key' => 'test-secret'];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            42,
        );

        $this->vaultService
            ->method('store')
            ->willThrowException(new VaultException(self::STORAGE_FAILED));

        $this->dataHandler
            ->expects(self::once())
            ->method('log')
            ->with(
                'tx_test',
                42,
                2,
                null,
                1,
                self::stringContains('api_key'),
            );

        $this->subject->processDatamap_afterDatabaseOperations(
            'update',
            'tx_test',
            42,
            $fieldArray,
            $this->dataHandler,
        );
    }

    /**
     * A submitted `_vault_identifier` reaches
     * `SecretNotFoundException::forIdentifier()` verbatim on the rotate path —
     * `PendingSecretExtractor` runs no `IdentifierValidator` there. Neither the
     * PSR-3 message nor any context value may therefore carry the newlines that
     * would let an editor append fully-formed records to the vault log,
     * including one quoting the reference the editor was told to report.
     */
    #[Test]
    public function craftedIdentifierCannotForgeALineInTheEmittedLogRecord(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $connection = $this->createMock(Connection::class);
        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $flashMessageQueue = $this->createMock(FlashMessageQueue::class);
        $this->flashMessageService->method('getMessageQueueByIdentifier')->willReturn($flashMessageQueue);

        $crafted = self::EXISTING_UUID
            . "\nMon, 01 Jan 2035 00:00:00 +0000 [ALERT] request=\"0\" component=\"forged\": owned\r\n\x07";

        $fieldArray = [
            'api_key' => [
                'value' => 'updated-secret',
                '_vault_identifier' => $crafted,
                '_vault_checksum' => 'existing-checksum',
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            42,
        );

        $this->vaultService
            ->method('rotate')
            ->willThrowException(SecretNotFoundException::forIdentifier($crafted));

        /** @var list<array{string, array<string, mixed>}> $records */
        $records = [];
        $this->failureLogger
            ->method('error')
            ->willReturnCallback(
                static function (string|Stringable $message, array $context = []) use (&$records): void {
                    $records[] = [(string) $message, $context];
                },
            );

        $this->subject->processDatamap_afterDatabaseOperations(
            'update',
            'tx_test',
            42,
            $fieldArray,
            $this->dataHandler,
        );

        self::assertCount(1, $records);

        [$message, $context] = $records[0];

        // Render the record the way TYPO3's FileWriter does before fwrite($message . LF).
        $encodedContext = json_encode($context, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        self::assertIsString($encodedContext, 'The context must survive json_encode()');

        $renderedRecord = \sprintf(
            '%s [%s] request="%s" component="%s": %s - %s',
            'Mon, 01 Jan 2035 00:00:00 +0000',
            'ERROR',
            'requestid',
            'Netresearch.NrVault',
            $message,
            $encodedContext,
        );

        self::assertSame(
            0,
            substr_count($renderedRecord, "\n") + substr_count($renderedRecord, "\r"),
            'A crafted identifier must not be able to append a line to the log',
        );
        self::assertSame('Vault operation failed', $message);
    }

    #[Test]
    public function afterDatabaseOperationsRollsBackFieldOnNewSecretFailure(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        // Mock connection for rollback - new secret should clear field (empty string)
        $connection = $this->createMock(Connection::class);
        $connection
            ->expects(self::once())
            ->method('update')
            ->with('tx_test', ['api_key' => ''], ['uid' => 42]);
        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        // Mock flash message queue
        $flashMessageQueue = $this->createMock(FlashMessageQueue::class);
        $this->flashMessageService->method('getMessageQueueByIdentifier')->willReturn($flashMessageQueue);

        $fieldArray = ['api_key' => 'new-secret'];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            42,
        );

        $this->vaultService
            ->method('store')
            ->willThrowException(new VaultException(self::STORAGE_FAILED));

        $this->subject->processDatamap_afterDatabaseOperations(
            'update',
            'tx_test',
            42,
            $fieldArray,
            $this->dataHandler,
        );
    }

    #[Test]
    public function afterDatabaseOperationsRollsBackFieldPreservingIdentifierOnUpdateFailure(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $existingUuid = self::EXISTING_UUID;

        // Mock connection for rollback - update failure should keep existing identifier
        $connection = $this->createMock(Connection::class);
        $connection
            ->expects(self::once())
            ->method('update')
            ->with('tx_test', ['api_key' => $existingUuid], ['uid' => 42]);
        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        // Mock flash message queue
        $flashMessageQueue = $this->createMock(FlashMessageQueue::class);
        $this->flashMessageService->method('getMessageQueueByIdentifier')->willReturn($flashMessageQueue);

        $fieldArray = [
            'api_key' => [
                'value' => 'updated-secret',
                '_vault_identifier' => $existingUuid,
                '_vault_checksum' => 'existing-checksum',
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            42,
        );

        $this->vaultService
            ->method('rotate')
            ->willThrowException(new VaultException('Rotate failed'));

        $this->subject->processDatamap_afterDatabaseOperations(
            'update',
            'tx_test',
            42,
            $fieldArray,
            $this->dataHandler,
        );
    }

    #[Test]
    public function afterDatabaseOperationsAddsFlashMessageOnVaultFailure(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        // Mock connection for rollback
        $connection = $this->createMock(Connection::class);
        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        // Flash message queue should receive the error message
        $flashMessageQueue = $this->createMock(FlashMessageQueue::class);
        $flashMessageQueue
            ->expects(self::once())
            ->method('addMessage');
        $this->flashMessageService->method('getMessageQueueByIdentifier')->willReturn($flashMessageQueue);

        $fieldArray = ['api_key' => 'new-secret'];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            42,
        );

        $this->vaultService
            ->method('store')
            ->willThrowException(new VaultException(self::STORAGE_FAILED));

        $this->subject->processDatamap_afterDatabaseOperations(
            'update',
            'tx_test',
            42,
            $fieldArray,
            $this->dataHandler,
        );
    }

    #[Test]
    public function afterDatabaseOperationsRollbackSkippedWhenUidIsZero(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        // Connection should NOT be called for rollback when uid is 0
        $this->connectionPool->expects(self::never())->method('getConnectionForTable');

        // Mock flash message queue
        $flashMessageQueue = $this->createMock(FlashMessageQueue::class);
        $this->flashMessageService->method('getMessageQueueByIdentifier')->willReturn($flashMessageQueue);

        $fieldArray = ['api_key' => 'new-secret'];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            'NEW123',
        );

        // Don't set substNEWwithIDs - uid will remain non-numeric string -> cast to 0
        $this->dataHandler->substNEWwithIDs = [];

        $this->vaultService
            ->method('store')
            ->willThrowException(new VaultException(self::STORAGE_FAILED));

        $this->subject->processDatamap_afterDatabaseOperations(
            'new',
            'tx_test',
            'NEW123',
            $fieldArray,
            $this->dataHandler,
        );
    }

    #[Test]
    public function cmdmapPreProcessIgnoresNonDeleteCommands(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $this->vaultService
            ->expects(self::never())
            ->method('delete');

        $this->subject->processCmdmap_preProcess(
            'copy',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function cmdmapPostProcessIgnoresNonCopyCommands(): void
    {
        $this->vaultService
            ->expects(self::never())
            ->method('retrieve');

        $this->subject->processCmdmap_postProcess(
            'delete',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function cmdmapPreProcessAcceptsArrayPasteUpdate(): void
    {
        // Regression for #207: on the localize / copy-to-language path TYPO3 core
        // reassigns $pasteUpdate from its `false` default to `$value['update']` (an
        // array) before invoking the hook. A `bool`-typed parameter threw a
        // TypeError at the signature, before the command guard could run.
        $this->vaultService
            ->expects(self::never())
            ->method('delete');

        $this->subject->processCmdmap_preProcess(
            'localize',
            'tt_content',
            42,
            null,
            $this->dataHandler,
            ['colPos' => 0, 'sys_language_uid' => 1],
        );
    }

    #[Test]
    public function cmdmapPostProcessAcceptsArrayPasteUpdate(): void
    {
        // Regression for #207: the copy path receives the same array $pasteUpdate.
        $this->dataHandler->copyMappingArray = [];

        $this->vaultService
            ->expects(self::never())
            ->method('retrieve');

        $this->subject->processCmdmap_postProcess(
            'copy',
            'tt_content',
            42,
            null,
            $this->dataHandler,
            ['colPos' => 0, 'sys_language_uid' => 1],
        );
    }

    #[Test]
    public function cmdmapPostProcessSkipsWhenNoNewIdFound(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $this->dataHandler->copyMappingArray = [];

        $this->vaultService
            ->expects(self::never())
            ->method('retrieve');

        $this->subject->processCmdmap_postProcess(
            'copy',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function multipleVaultFieldsAreProcessed(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
            'api_secret' => ['type' => 'input', 'renderType' => 'vaultSecret'],
            'title' => ['type' => 'input'],
        ]);

        $fieldArray = [
            'api_key' => 'key-value',
            'api_secret' => 'secret-value',
            'title' => self::TEST_TITLE,
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            42,
        );

        // Both vault fields should be replaced with UUIDs
        self::assertMatchesRegularExpression(self::UUID_PATTERN, $fieldArray['api_key']);
        self::assertMatchesRegularExpression(self::UUID_PATTERN, $fieldArray['api_secret']);
        // UUIDs should be different for each field
        self::assertNotSame($fieldArray['api_key'], $fieldArray['api_secret']);
        // Non-vault field unchanged
        self::assertSame(self::TEST_TITLE, $fieldArray['title']);
    }

    #[Test]
    public function preProcessFieldArrayIgnoresTablesWithoutSchema(): void
    {
        $this->tcaSchemaFactory->method('has')->with('unknown_table')->willReturn(false);

        $fieldArray = ['field' => 'value'];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'unknown_table',
            1,
        );

        self::assertSame(['field' => 'value'], $fieldArray);
    }

    #[Test]
    public function preProcessFieldArrayHandlesArrayWithValueIndexZero(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        // Format with index 0 instead of 'value' key
        $fieldArray = [
            'api_key' => [
                0 => 'my-secret-key',
                '_vault_identifier' => '',
                '_vault_checksum' => '',
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            1,
        );

        self::assertMatchesRegularExpression(self::UUID_PATTERN, $fieldArray['api_key']);
    }

    #[Test]
    public function preProcessFieldArrayHandlesIntegerValue(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $fieldArray = ['api_key' => 12345];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            1,
        );

        self::assertMatchesRegularExpression(self::UUID_PATTERN, $fieldArray['api_key']);
    }

    #[Test]
    public function preProcessFieldArraySetsEmptyStringWhenClearing(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $existingUuid = self::EXISTING_UUID;
        // Explicit clear: the clear control blanks the checksum.
        $fieldArray = [
            'api_key' => [
                'value' => '',
                '_vault_identifier' => $existingUuid,
                '_vault_checksum' => '',
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            42,
        );

        // Should be empty string when explicitly cleared
        self::assertSame('', $fieldArray['api_key']);
    }

    #[Test]
    public function cmdmapPreProcessIgnoresTablesWithoutVaultFields(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'title' => ['type' => 'input'],
        ]);

        $this->connectionPool->expects(self::never())->method('getConnectionForTable');

        $this->subject->processCmdmap_preProcess(
            'delete',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function cmdmapPostProcessIgnoresTablesWithoutVaultFields(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'title' => ['type' => 'input'],
        ]);

        $this->dataHandler->copyMappingArray = ['tx_test' => [42 => 100]];

        $this->connectionPool->expects(self::never())->method('getConnectionForTable');

        $this->subject->processCmdmap_postProcess(
            'copy',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function generateUuidReturnsValidUuidV7Format(): void
    {
        $uuid1 = IdentifierValidator::generateUuid();
        $uuid2 = IdentifierValidator::generateUuid();

        // Both should be valid UUID v7 format
        self::assertMatchesRegularExpression(self::UUID_PATTERN, $uuid1);
        self::assertMatchesRegularExpression(self::UUID_PATTERN, $uuid2);

        // Should be different
        self::assertNotSame($uuid1, $uuid2);
    }

    #[Test]
    public function generateUuidIsTimeOrdered(): void
    {
        $uuids = [];
        for ($i = 0; $i < 5; $i++) {
            $uuids[] = IdentifierValidator::generateUuid();
            usleep(1000); // 1ms delay
        }

        // UUIDs should be in ascending order (time-ordered)
        $sorted = $uuids;
        sort($sorted);
        self::assertSame($sorted, $uuids, 'UUIDs should be time-ordered');
    }

    #[Test]
    public function preProcessFieldArrayHandlesNonStringNonIntValue(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        // Non-string, non-int value should be treated as empty
        $fieldArray = [
            'api_key' => [
                'value' => ['nested' => 'array'],
                '_vault_identifier' => '',
                '_vault_checksum' => '',
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            1,
        );

        // Empty value with no checksum should be removed
        self::assertArrayNotHasKey('api_key', $fieldArray);
    }

    #[Test]
    public function afterDatabaseOperationsHandlesStatusUpdate(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        // Setup pending secrets via preProcess with existing UUID
        $existingUuid = self::EXISTING_UUID;
        $fieldArray = [
            'api_key' => [
                'value' => 'updated-secret',
                '_vault_identifier' => $existingUuid,
                '_vault_checksum' => 'existing-checksum',
            ],
        ];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            42,
        );

        // Rotate should be called (not store)
        $this->vaultService
            ->expects(self::once())
            ->method('rotate')
            ->with($existingUuid, 'updated-secret', 'TCA field updated');

        $this->subject->processDatamap_afterDatabaseOperations(
            'update',
            'tx_test',
            42,
            $fieldArray,
            $this->dataHandler,
        );
    }

    #[Test]
    public function afterDatabaseOperationsCleansPendingSecrets(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $fieldArray = ['api_key' => 'test-secret'];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            42,
        );

        $this->subject->processDatamap_afterDatabaseOperations(
            'update',
            'tx_test',
            42,
            $fieldArray,
            $this->dataHandler,
        );

        // Calling again should not trigger vault operations (pending cleaned up)
        $this->vaultService
            ->expects(self::never())
            ->method('store');

        $this->subject->processDatamap_afterDatabaseOperations(
            'update',
            'tx_test',
            42,
            $fieldArray,
            $this->dataHandler,
        );
    }

    #[Test]
    public function getVaultFieldNamesReturnsEmptyForNonExistentTable(): void
    {
        $this->tcaSchemaFactory->method('has')->with('nonexistent')->willReturn(false);

        $reflection = new ReflectionClass($this->subject);
        $method = $reflection->getMethod('getVaultFieldNames');

        $result = $method->invoke($this->subject, 'nonexistent');

        self::assertSame([], $result);
    }

    #[Test]
    public function getVaultFieldNamesReturnsOnlyVaultSecretFields(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
            'title' => ['type' => 'input'],
            'password' => ['type' => 'password', 'renderType' => 'passwordGenerator'],
            'secret' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $reflection = new ReflectionClass($this->subject);
        $method = $reflection->getMethod('getVaultFieldNames');

        $result = $method->invoke($this->subject, 'tx_test');

        self::assertCount(2, $result);
        self::assertContains('api_key', $result);
        self::assertContains('secret', $result);
        self::assertNotContains('title', $result);
        self::assertNotContains('password', $result);
    }

    #[Test]
    public function cmdmapPreProcessDeletesVaultSecretSuccessfully(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $existingUuid = self::EXISTING_UUID;

        // Mock database connection
        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['api_key' => $existingUuid]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->with('tx_test')
            ->willReturn($connection);

        $this->vaultService
            ->expects(self::once())
            ->method('delete')
            ->with($existingUuid, 'Record deleted');

        $this->subject->processCmdmap_preProcess(
            'delete',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function cmdmapPreProcessLogsVaultExceptionOnDelete(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $existingUuid = self::EXISTING_UUID;

        // Mock database connection
        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['api_key' => $existingUuid]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->with('tx_test')
            ->willReturn($connection);

        $this->vaultService
            ->method('delete')
            ->willThrowException(new VaultException('Delete failed'));

        $this->dataHandler
            ->expects(self::once())
            ->method('log')
            ->with(
                'tx_test',
                42,
                3,
                null,
                1,
                self::stringContains('api_key'),
            );

        $this->subject->processCmdmap_preProcess(
            'delete',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function cmdmapPreProcessSkipsDeleteWhenRecordNotFound(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        // Mock database connection - record not found
        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(false);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->with('tx_test')
            ->willReturn($connection);

        $this->vaultService
            ->expects(self::never())
            ->method('delete');

        $this->subject->processCmdmap_preProcess(
            'delete',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function cmdmapPreProcessSkipsDeleteWhenVaultIdentifierEmpty(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        // Mock database connection - vault field is empty
        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['api_key' => '']);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->with('tx_test')
            ->willReturn($connection);

        $this->vaultService
            ->expects(self::never())
            ->method('delete');

        $this->subject->processCmdmap_preProcess(
            'delete',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function cmdmapPostProcessCopiesVaultSecretSuccessfully(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $sourceUuid = self::EXISTING_UUID;

        // Mock copy mapping
        $this->dataHandler->copyMappingArray = ['tx_test' => [42 => 100]];

        // Mock database connection
        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['api_key' => $sourceUuid]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->with('tx_test')
            ->willReturn($connection);

        // Retrieve source secret
        $this->vaultService
            ->method('retrieve')
            ->with($sourceUuid)
            ->willReturn('the-secret-value');

        // Store new secret with new UUID
        $this->vaultService
            ->expects(self::once())
            ->method('store')
            ->with(
                self::matchesRegularExpression(self::UUID_PATTERN),
                'the-secret-value',
                self::callback(static fn (array $options): bool => $options['table'] === 'tx_test'
                    && $options['field'] === 'api_key'
                    && $options['uid'] === 100
                    && $options['source'] === 'record_copy'),
            );

        // Update the copied record
        $connection
            ->expects(self::once())
            ->method('update')
            ->with(
                'tx_test',
                self::callback(static fn (array $updates): bool => isset($updates['api_key'])
                    && preg_match(self::UUID_PATTERN, $updates['api_key']) === 1),
                ['uid' => 100],
            );

        $this->subject->processCmdmap_postProcess(
            'copy',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function cmdmapPostProcessSkipsCopyWhenSourceRecordNotFound(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $this->dataHandler->copyMappingArray = ['tx_test' => [42 => 100]];

        // Mock database connection - source record not found
        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(false);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        $this->vaultService
            ->expects(self::never())
            ->method('retrieve');

        $this->subject->processCmdmap_postProcess(
            'copy',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function cmdmapPostProcessBlanksCopiedFieldWhenSourceSecretIsMissing(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $sourceUuid = self::EXISTING_UUID;

        $this->dataHandler->copyMappingArray = ['tx_test' => [42 => 100]];

        // Mock database connection
        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['api_key' => $sourceUuid]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        // Retrieve returns null (secret not found in vault)
        $this->vaultService
            ->method('retrieve')
            ->with($sourceUuid)
            ->willReturn(null);

        $this->vaultService
            ->expects(self::never())
            ->method('store');

        // Leaving the DataHandler-duplicated source UUID in the copy would make
        // both records share one secret: the field must be cleared instead.
        $connection
            ->expects(self::once())
            ->method('update')
            ->with('tx_test', ['api_key' => ''], ['uid' => 100]);

        $this->dataHandler
            ->expects(self::once())
            ->method('log')
            ->with('tx_test', 100, 1, null, 2, self::stringContains('api_key'));

        $this->subject->processCmdmap_postProcess(
            'copy',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function cmdmapPreProcessSkipsNonStringVaultIdentifier(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        // Mock database connection - vault field is an integer (non-string)
        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['api_key' => 12345]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->with('tx_test')
            ->willReturn($connection);

        $this->vaultService
            ->expects(self::never())
            ->method('delete');

        $this->subject->processCmdmap_preProcess(
            'delete',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function cmdmapPostProcessSkipsNonStringSourceIdentifier(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $this->dataHandler->copyMappingArray = ['tx_test' => [42 => 100]];

        // Mock database connection - vault field is an integer (non-string)
        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['api_key' => 12345]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        $this->vaultService
            ->expects(self::never())
            ->method('retrieve');

        // No update should happen
        $connection
            ->expects(self::never())
            ->method('update');

        $this->subject->processCmdmap_postProcess(
            'copy',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function cmdmapPostProcessSkipsEmptySourceIdentifier(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $this->dataHandler->copyMappingArray = ['tx_test' => [42 => 100]];

        // Mock database connection - vault field is empty string
        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['api_key' => '']);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        $this->vaultService
            ->expects(self::never())
            ->method('retrieve');

        $connection
            ->expects(self::never())
            ->method('update');

        $this->subject->processCmdmap_postProcess(
            'copy',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function rollBackFieldHandlesExceptionGracefully(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        // Mock connection that throws on rollback update
        $connection = $this->createMock(Connection::class);
        $connection
            ->method('update')
            ->willThrowException(new RuntimeException('DB connection lost'));
        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        // Mock flash message queue
        $flashMessageQueue = $this->createMock(FlashMessageQueue::class);
        $this->flashMessageService->method('getMessageQueueByIdentifier')->willReturn($flashMessageQueue);

        $fieldArray = ['api_key' => 'new-secret'];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            42,
        );

        $this->vaultService
            ->method('store')
            ->willThrowException(new VaultException(self::STORAGE_FAILED));

        // Should not throw - rollback failure is silently caught
        $this->subject->processDatamap_afterDatabaseOperations(
            'update',
            'tx_test',
            42,
            $fieldArray,
            $this->dataHandler,
        );

        // If we get here, the exception was properly caught
        self::assertTrue(true);
    }

    #[Test]
    public function addFlashMessageHandlesExceptionGracefully(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        // Mock connection for rollback
        $connection = $this->createMock(Connection::class);
        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        // Flash message service throws exception
        $this->flashMessageService
            ->method('getMessageQueueByIdentifier')
            ->willThrowException(new RuntimeException('Flash service unavailable'));

        $fieldArray = ['api_key' => 'new-secret'];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            42,
        );

        $this->vaultService
            ->method('store')
            ->willThrowException(new VaultException(self::STORAGE_FAILED));

        // Should not throw - flash message failure is silently caught
        $this->subject->processDatamap_afterDatabaseOperations(
            'update',
            'tx_test',
            42,
            $fieldArray,
            $this->dataHandler,
        );

        // If we get here, the exception was properly caught
        self::assertTrue(true);
    }

    #[Test]
    public function preProcessFieldArraySkipsVaultFieldNotInFieldArray(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
            'title' => ['type' => 'input'],
        ]);

        // Only 'title' is in fieldArray, 'api_key' vault field is not
        $fieldArray = ['title' => self::TEST_TITLE];

        $this->subject->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_test',
            1,
        );

        // Field array should remain unchanged - vault field was not present
        self::assertSame(['title' => self::TEST_TITLE], $fieldArray);
        self::assertArrayNotHasKey('api_key', $fieldArray);
    }

    #[Test]
    public function cmdmapPostProcessLogsVaultExceptionOnCopy(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $sourceUuid = self::EXISTING_UUID;

        $this->dataHandler->copyMappingArray = ['tx_test' => [42 => 100]];

        // Mock database connection
        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn(['api_key' => $sourceUuid]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new VaultException('Retrieve failed'));

        $connection
            ->expects(self::once())
            ->method('update')
            ->with('tx_test', ['api_key' => ''], ['uid' => 100]);

        $this->dataHandler
            ->expects(self::once())
            ->method('log')
            ->with(
                'tx_test',
                100,
                1,
                null,
                2,
                self::stringContains('api_key'),
            );

        $this->subject->processCmdmap_postProcess(
            'copy',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function cmdmapPostProcessBlanksEveryVaultFieldWhenTheFirstFieldFails(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
            'api_secret' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $this->dataHandler->copyMappingArray = ['tx_test' => [42 => 100]];

        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn([
            'api_key' => self::EXISTING_UUID,
            'api_secret' => self::SECOND_UUID,
        ]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new VaultException(self::RETRIEVE_FAILED));

        // Nothing was cloned, so there is nothing to compensate...
        $this->vaultService
            ->expects(self::never())
            ->method('store');
        $this->vaultService
            ->expects(self::never())
            ->method('delete');

        // ...but BOTH fields still carry the source UUIDs DataHandler copied,
        // including the one this method never reached.
        $connection
            ->expects(self::once())
            ->method('update')
            ->with('tx_test', ['api_key' => '', 'api_secret' => ''], ['uid' => 100]);

        $this->subject->processCmdmap_postProcess(
            'copy',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function cmdmapPostProcessDeletesAlreadyClonedSecretWhenALaterFieldFails(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
            'api_secret' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $this->dataHandler->copyMappingArray = ['tx_test' => [42 => 100]];

        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn([
            'api_key' => self::EXISTING_UUID,
            'api_secret' => self::SECOND_UUID,
        ]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        // First field clones fine, second one cannot be read.
        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(static function (string $identifier): string {
                if ($identifier === self::EXISTING_UUID) {
                    return 'the-secret-value';
                }

                throw new VaultException(self::RETRIEVE_FAILED);
            });

        $clonedIdentifier = null;
        $this->vaultService
            ->expects(self::once())
            ->method('store')
            ->willReturnCallback(
                static function (string $identifier) use (&$clonedIdentifier): void {
                    $clonedIdentifier = $identifier;
                },
            );

        $this->vaultService
            ->expects(self::once())
            ->method('delete')
            ->willReturnCallback(
                static function (string $identifier, string $reason) use (&$clonedIdentifier): void {
                    self::assertSame($clonedIdentifier, $identifier, 'Only the clone of THIS copy may be deleted.');
                    self::assertStringContainsString('copy', $reason);
                },
            );

        $connection
            ->expects(self::once())
            ->method('update')
            ->with('tx_test', ['api_key' => '', 'api_secret' => ''], ['uid' => 100]);

        $this->subject->processCmdmap_postProcess(
            'copy',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );

        self::assertNotNull($clonedIdentifier, 'The first field must have been cloned before the failure.');
    }

    #[Test]
    public function cmdmapPostProcessBlanksFieldsEvenWhenTheRollbackDeleteFails(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
            'api_secret' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $this->dataHandler->copyMappingArray = ['tx_test' => [42 => 100]];

        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn([
            'api_key' => self::EXISTING_UUID,
            'api_secret' => self::SECOND_UUID,
        ]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(static function (string $identifier): string {
                if ($identifier === self::EXISTING_UUID) {
                    return 'the-secret-value';
                }

                throw new VaultException(self::RETRIEVE_FAILED);
            });

        $this->vaultService
            ->method('delete')
            ->willThrowException(new VaultException('Rollback delete failed'));

        // An orphaned clone is inert; a copy still pointing at the source's
        // secret is not — so the blanking must happen regardless.
        $connection
            ->expects(self::once())
            ->method('update')
            ->with('tx_test', ['api_key' => '', 'api_secret' => ''], ['uid' => 100]);

        $this->dataHandler
            ->expects(self::once())
            ->method('log')
            ->with('tx_test', 100, 1, null, 2, self::stringContains('api_secret'));

        $this->subject->processCmdmap_postProcess(
            'copy',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );
    }

    #[Test]
    public function cmdmapPreProcessDeletesNoSecretWhenAnyFieldIsNotDeletable(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
            'api_secret' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn([
            'api_key' => self::EXISTING_UUID,
            'api_secret' => self::SECOND_UUID,
        ]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        // The FIRST field is deletable, the second is not: without a preflight
        // the first secret would already be gone — irrecoverably — by the time
        // the denial surfaces.
        $this->vaultService
            ->method('assertDeletable')
            ->willReturnCallback(static function (string $identifier): void {
                if ($identifier === self::SECOND_UUID) {
                    throw new VaultException('Delete permission denied');
                }
            });

        $this->vaultService
            ->expects(self::never())
            ->method('delete');

        $this->dataHandler
            ->expects(self::once())
            ->method('log')
            ->with('tx_test', 42, 3, null, 1, self::stringContains('api_secret'));

        $this->subject->processCmdmap_preProcess(
            'delete',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );

        $commandIsProcessed = false;
        $this->subject->processCmdmap(
            'delete',
            'tx_test',
            42,
            null,
            $commandIsProcessed,
            $this->dataHandler,
            false,
        );

        self::assertTrue($commandIsProcessed, 'The record delete must be cancelled.');
    }

    #[Test]
    public function cmdmapPreProcessTreatsAnAlreadyMissingSecretAsDeleted(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
            'api_secret' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn([
            'api_key' => self::EXISTING_UUID,
            'api_secret' => self::SECOND_UUID,
        ]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        $deleted = [];
        $this->vaultService
            ->method('delete')
            ->willReturnCallback(static function (string $identifier) use (&$deleted): void {
                if ($identifier === self::EXISTING_UUID) {
                    throw SecretNotFoundException::forIdentifier($identifier);
                }

                $deleted[] = $identifier;
            });

        $this->dataHandler
            ->expects(self::never())
            ->method('log');

        $this->subject->processCmdmap_preProcess(
            'delete',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );

        // A dangling reference must not stop the loop, and must not make the
        // record undeletable forever.
        self::assertSame([self::SECOND_UUID], $deleted);

        $commandIsProcessed = false;
        $this->subject->processCmdmap(
            'delete',
            'tx_test',
            42,
            null,
            $commandIsProcessed,
            $this->dataHandler,
            false,
        );

        self::assertFalse($commandIsProcessed, 'A missing secret must not cancel the record delete.');
    }

    #[Test]
    public function cmdmapPreProcessStopsDeletingAfterAMidSequenceFailure(): void
    {
        $this->mockTcaSchemaForTable('tx_test', [
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
            'api_secret' => ['type' => 'input', 'renderType' => 'vaultSecret'],
            'api_token' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        $connection = $this->createMock(Connection::class);
        $result = $this->createMock(Result::class);
        $result->method('fetchAssociative')->willReturn([
            'api_key' => self::EXISTING_UUID,
            'api_secret' => self::SECOND_UUID,
            'api_token' => self::THIRD_UUID,
        ]);
        $connection->method('select')->willReturn($result);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        $deleted = [];
        $this->vaultService
            ->method('delete')
            ->willReturnCallback(static function (string $identifier) use (&$deleted): void {
                if ($identifier === self::SECOND_UUID) {
                    throw new VaultException('Audit write failed');
                }

                $deleted[] = $identifier;
            });

        $this->dataHandler
            ->expects(self::once())
            ->method('log')
            ->with('tx_test', 42, 3, null, 1, self::stringContains('api_secret'));

        $this->subject->processCmdmap_preProcess(
            'delete',
            'tx_test',
            42,
            null,
            $this->dataHandler,
            false,
        );

        // The record survives either way, so deleting the third secret would
        // only enlarge the unrecoverable damage.
        self::assertSame([self::EXISTING_UUID], $deleted);

        $commandIsProcessed = false;
        $this->subject->processCmdmap(
            'delete',
            'tx_test',
            42,
            null,
            $commandIsProcessed,
            $this->dataHandler,
            false,
        );

        self::assertTrue($commandIsProcessed, 'The record delete must be cancelled.');
    }
}
