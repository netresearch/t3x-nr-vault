<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Hook;

use Doctrine\DBAL\Result;
use Error;
use Netresearch\NrVault\Hook\FlexFormVaultHook;
use Netresearch\NrVault\Hook\VaultFailureReporter;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Utility\TranslationSharedSecretResolver;
use Netresearch\NrVault\Utility\VaultFieldResolver;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Throwable;
use TYPO3\CMS\Core\Configuration\FlexForm\FlexFormTools;
use TYPO3\CMS\Core\Configuration\Tca\TcaMigration;
use TYPO3\CMS\Core\Configuration\Tca\TcaPreparation;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Messaging\FlashMessageService;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;
use TYPO3\CMS\Core\Utility\GeneralUtility;

#[CoversClass(FlexFormVaultHook::class)]
#[AllowMockObjectsWithoutExpectations]
#[RunTestsInSeparateProcesses]
#[PreserveGlobalState(false)]
final class FlexFormCopyLinkFailureTest extends TestCase
{
    private const TABLE = 'tx_flex_copy_probe';

    private const SOURCE = '01937b6e-4b6c-7abc-8def-0123456789ab';

    protected TcaSchemaFactory&MockObject $tcaSchemaFactory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tcaSchemaFactory = $this->createMock(TcaSchemaFactory::class);
    }

    /**
     * @param class-string<Throwable> $throwableClass
     * @param class-string<Throwable>|null $writerFailureClass
     * @param class-string<Throwable>|null $cleanupFailureClass
     */
    #[Test]
    #[DataProvider('linkFailures')]
    public function finalLinkFailureAbandonsEveryCreatedClone(
        string $stage,
        string $throwableClass,
        bool $copyStartsBlank = false,
        bool $failurePersists = false,
        bool $recoveryFails = false,
        ?string $writerFailureClass = null,
        ?string $cleanupFailureClass = null,
    ): void {
        if (!\defined('LF')) {
            \define('LF', "\n");
        }

        $failure = new $throwableClass('synthetic private link failure');
        $pool = $this->createMock(ConnectionPool::class);
        $this->mockTcaSchemaForTable(
            self::TABLE,
            ['flex_a' => ['type' => 'flex']],
        );
        $vault = $this->createMock(VaultServiceInterface::class);
        $vault->method('exists')->willReturn(true);
        $vault->method('retrieve')->willReturn('synthetic-copy-value');
        $created = [];
        $abandoned = [];
        $vault
            ->method('store')
            ->willReturnCallback(
                static function (string $id) use (&$created): void {
                    $created[] = $id;
                },
            );
        $vault
            ->method('delete')
            ->willReturnCallback(
                static function (
                    string $id,
                ) use (&$abandoned, $cleanupFailureClass): void {
                    $abandoned[] = $id;
                    if ($cleanupFailureClass !== null) {
                        throw new $cleanupFailureClass(
                            'synthetic private cleanup failure',
                            972712907,
                        );
                    }
                },
            );
        $sourceXml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="key"><value index="vDEF">' . self::SOURCE . '</value></field><field index="label"><value index="vDEF">synthetic nonsecret label</value></field></language></sheet></data></T3FlexForms>';
        $realTools = new FlexFormTools(
            self::createStub(EventDispatcherInterface::class),
            /** @phpstan-ignore classConstant.internalClass */
            self::createStub(TcaMigration::class),
            /** @phpstan-ignore classConstant.internalClass */
            self::createStub(TcaPreparation::class),
        );
        $copyData = GeneralUtility::xml2arrayProcess($sourceXml);
        self::assertIsArray($copyData);
        if ($copyStartsBlank) {
            $copyData['data']['sDEF']['lDEF']['key']['vDEF'] = '';
        }

        /** @phpstan-ignore method.internal */
        $copyXml = $realTools->flexArray2Xml($copyData);
        $storedCopy = $copyXml;
        $result = $this->createMock(Result::class);
        $result
            ->method('fetchAllAssociative')
            ->willReturn(
                [
                    ['uid' => 42, 'flex_a' => $sourceXml],
                    ['uid' => 100, 'flex_a' => $copyXml],
                ],
            );
        $query = $this->createMock(QueryBuilder::class);
        foreach (['select', 'from', 'where'] as $method) {
            $query->method($method)->willReturnSelf();
        }

        $query->method('executeQuery')->willReturn($result);
        $pool->method('getQueryBuilderForTable')->willReturn($query);
        $connection = $this->createMock(Connection::class);
        $updateAttempts = 0;
        $connection
            ->method('update')
            ->willReturnCallback(
                static function (
                    string $table,
                    array $changes,
                ) use ($stage, $failure, $failurePersists, $recoveryFails, &$updateAttempts, &$storedCopy): int {
                    $updateAttempts++;
                    if ($stage === 'database' && ($updateAttempts === 1 || $recoveryFails)) {
                        if ($failurePersists && $updateAttempts === 1) {
                            $storedCopy = $changes['flex_a'];
                        }

                        throw $failure;
                    }

                    $storedCopy = $changes['flex_a'];

                    return 1;
                },
            );
        $pool->method('getConnectionForTable')->willReturn($connection);
        $tools = $this->createMock(FlexFormTools::class);
        $serializationAttempts = 0;
        $tools
            ->method('flexArray2Xml')
            ->willReturnCallback(
                static function (
                    array $flex,
                ) use ($stage, $failure, $realTools, $recoveryFails, &$serializationAttempts): string {
                    $serializationAttempts++;
                    if ($stage === 'serialization' && ($serializationAttempts === 1 || $recoveryFails)) {
                        throw $failure;
                    }

                    /** @phpstan-ignore method.internal */
                    return $realTools->flexArray2Xml($flex);
                },
            );
        $handler = $this->createMock(DataHandler::class);
        /** @phpstan-ignore property.internal */
        $handler->copyMappingArray = [self::TABLE => [42 => 100]];

        $messages = [];
        $handler
            ->method('log')
            ->willReturnCallback(
                static function (
                    string $table,
                    int $uid,
                    int $action,
                    ?int $recpid,
                    int $error,
                    string $message,
                ) use (&$messages): void {
                    $messages[] = $message;
                },
            );
        $logger = $this->diagnosticLogger($writerFailureClass);
        $subject = new FlexFormVaultHook(
            $pool,
            $this->tcaSchemaFactory,
            $vault,
            $tools,
            self::createStub(FlashMessageService::class),
            new VaultFailureReporter($logger),
            new TranslationSharedSecretResolver(
                $pool,
                new VaultFieldResolver($vault, $this->tcaSchemaFactory, $logger),
            ),
        );
        $caught = null;

        try {
            $subject->processCmdmap_postProcess(
                'copy',
                self::TABLE,
                42,
                null,
                $handler,
                false,
            );
        } catch (Throwable $error) {
            $caught = $error;
        }

        self::assertCount(
            1,
            $created,
            'A clone must actually have been created before the final link fails.',
        );
        self::assertSame(
            $created,
            $abandoned,
            'Every known clone must receive a compensation attempt when its final link fails.',
        );
        if ($cleanupFailureClass !== null) {
            self::assertIsString($storedCopy);
            self::assertStringNotContainsString(
                $created[0],
                $storedCopy,
                'Diagnostic delivery failure must not interrupt clearing an already-linked clone.',
            );
        }

        self::assertNull(
            $caught,
            'The editor must receive the existing correlated failure diagnostic.',
        );
        self::assertIsString($storedCopy);

        if (!$recoveryFails) {
            self::assertStringNotContainsString(self::SOURCE, $storedCopy);
            self::assertStringNotContainsString($created[0], $storedCopy);
            self::assertSame($stage === 'database' ? 2 : 1, $updateAttempts);
        } else {
            self::assertSame($stage === 'database' ? 2 : 0, $updateAttempts);
            self::assertStringContainsString('may still', $messages[0] ?? '');
            self::assertStringContainsString(
                'manual review',
                $messages[0] ?? '',
            );
            self::assertStringNotContainsString(
                'were cleared',
                $messages[0] ?? '',
            );
            self::assertStringContainsString(
                $stage === 'database' ? $created[0] : self::SOURCE,
                $storedCopy,
            );
        }

        self::assertStringContainsString(
            'synthetic nonsecret label',
            $storedCopy,
        );
        self::assertCount(1, $messages);
        self::assertMatchesRegularExpression('/\b[0-9a-f]{16}\b/', $messages[0]);
        self::assertStringNotContainsString(
            'synthetic private link failure',
            $messages[0],
        );
    }

    /**
     * @return iterable<string, array{string, class-string<Throwable>, bool, bool, bool, 5?: class-string<Throwable>, 6?: class-string<Throwable>}>
     */
    public static function linkFailures(): iterable
    {
        foreach ([RuntimeException::class, Error::class] as $class) {
            foreach (['serialization', 'database'] as $stage) {
                yield $stage . '-' . $class => [$stage, $class, false, false, false];
                yield 'recovery-' . $stage . '-' . $class => [$stage, $class, false, $stage === 'database', true];
            }

            foreach ([false, true] as $startsBlank) {
                yield 'persisted-before-database-failure-' . (int) $startsBlank . '-' . $class => ['database', $class, $startsBlank, true, false];
            }

            foreach ([RuntimeException::class, Error::class] as $cleanupClass) {
                yield 'cleanup-and-diagnostic-failure-' . $class . '-' . $cleanupClass => [
                    'database',
                    RuntimeException::class,
                    false,
                    true,
                    false,
                    $class,
                    $cleanupClass,
                ];
            }
        }
    }

    /**
     * @param class-string<Throwable>|null $writerFailureClass
     */
    private function diagnosticLogger(
        ?string $writerFailureClass,
    ): LoggerInterface {
        $logger = self::createMock(LoggerInterface::class);
        if ($writerFailureClass !== null) {
            $logger
                ->method('error')
                ->willThrowException(new $writerFailureClass('synthetic private diagnostic failure'));
        }

        return $logger;
    }
}
