<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Hook;

use Doctrine\DBAL\Result;
use Error;
use Netresearch\NrVault\Domain\Dto\SecretDetails;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Hook\FlexFormVaultHook;
use Netresearch\NrVault\Hook\VaultFailureReporter;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Utility\TranslationSharedSecretResolver;
use Netresearch\NrVault\Utility\VaultFieldResolver;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Throwable;
use TYPO3\CMS\Core\Configuration\FlexForm\Exception\InvalidIdentifierException;
use TYPO3\CMS\Core\Configuration\FlexForm\FlexFormTools;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Messaging\FlashMessageService;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;

use function array_slice;
use function count;

#[CoversClass(FlexFormVaultHook::class)]
#[AllowMockObjectsWithoutExpectations]
final class FlexFormDeletePreflightTest extends TestCase
{
    private const TABLE = 'tx_flex_delete_probe';

    private const FIRST = '01937b6e-4b6c-7abc-8def-0123456789ab';

    private const SECOND = '01234567-89ab-7cde-8f01-23456789abcd';

    private const THIRD = '01234567-89ab-7cde-8f01-23456789abce';

    protected TcaSchemaFactory&MockObject $tcaSchemaFactory;

    private ConnectionPool&MockObject $connectionPool;

    private VaultServiceInterface&MockObject $vault;

    private DataHandler&MockObject $dataHandler;

    private FlexFormVaultHook $subject;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tcaSchemaFactory = $this->createMock(TcaSchemaFactory::class);
        $this->connectionPool   = $this->createMock(ConnectionPool::class);
        $this->vault            = $this->createMock(VaultServiceInterface::class);
        $this->dataHandler      = $this->createMock(DataHandler::class);
        $this->mockTcaSchemaForTable(
            self::TABLE,
            ['flex_a' => ['type' => 'flex'], 'flex_b' => ['type' => 'flex']],
        );
        $GLOBALS['TCA'][self::TABLE]['ctrl'] = [];
        $this->subject                       = $this->createSubject(self::createStub(LoggerInterface::class));
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['TCA'][self::TABLE]);
        parent::tearDown();
    }

    #[Test]
    public function allUniqueReferencesArePreflightedBeforeTheFirstDelete(): void
    {
        $calls = [];
        $this->vault->method('exists')->willReturn(true);
        $this->vault
            ->method('assertDeletable')
            ->willReturnCallback(
                static function (string $id) use (&$calls): void {
                    $calls[] = ['preflight', $id];
                },
            );
        $this->vault
            ->method('delete')
            ->willReturnCallback(
                static function (string $id) use (&$calls): void {
                    $calls[] = ['delete', $id];
                },
            );
        $cancelled = false;
        $caught    = $this->runDelete(
            [
                'flex_a' => self::FIRST . ' ' . self::SECOND . ' ' . self::FIRST,
                'flex_b' => self::FIRST . ' ' . self::THIRD,
            ],
            $cancelled,
        );
        self::assertNull($caught);
        self::assertFalse($cancelled);
        self::assertSame(
            [
                ['preflight', self::FIRST],
                ['preflight', self::SECOND],
                ['preflight', self::THIRD],
                ['delete', self::FIRST],
                ['delete', self::SECOND],
                ['delete', self::THIRD],
            ],
            $calls,
            'Duplicate references across columns must not cause duplicate mutations.',
        );
    }

    /**
     * @param class-string<Throwable> $throwableClass
     */
    #[Test]
    #[DataProvider('failingStages')]
    public function failureKeepsTheRecordAndStopsFurtherMutations(
        string $stage,
        string $throwableClass,
        int $failureIndex,
    ): void {
        $failure   = new $throwableClass('synthetic private failure cause');
        $remaining = [self::FIRST, self::SECOND, self::THIRD];
        $calls     = ['exists' => [], 'preflight' => [], 'delete' => []];
        $messages  = [];
        $this->vault
            ->method('exists')
            ->willReturnCallback(
                static function (
                    string $id,
                ) use ($stage, $failureIndex, $failure, &$calls): bool {
                    $calls['exists'][] = $id;
                    if ($stage === 'exists' && count($calls['exists']) === $failureIndex) {
                        throw $failure;
                    }

                    return true;
                },
            );
        $this->vault
            ->method('assertDeletable')
            ->willReturnCallback(
                static function (
                    string $id,
                ) use ($stage, $failureIndex, $failure, &$calls): void {
                    $calls['preflight'][] = $id;
                    if ($stage === 'preflight' && count($calls['preflight']) === $failureIndex) {
                        throw $failure;
                    }
                },
            );
        $this->vault
            ->method('delete')
            ->willReturnCallback(
                static function (
                    string $id,
                ) use ($stage, $failureIndex, $failure, &$calls, &$remaining): void {
                    $calls['delete'][] = $id;
                    if ($stage === 'delete' && count($calls['delete']) === $failureIndex) {
                        throw $failure;
                    }

                    $remaining = array_values(array_diff($remaining, [$id]));
                },
            );
        $this->dataHandler
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
        $cancelled = false;
        $caught    = $this->runDelete(
            [
                'flex_a' => self::FIRST . ' ' . self::SECOND,
                'flex_b' => self::THIRD,
            ],
            $cancelled,
        );
        self::assertNull($caught);
        self::assertTrue($cancelled);
        self::assertSame(
            $stage === 'delete' ? array_slice(
                [self::FIRST, self::SECOND, self::THIRD],
                0,
                $failureIndex,
            ) : [],
            $calls['delete'],
        );
        self::assertSame(
            $stage === 'delete' ? array_slice(
                [self::FIRST, self::SECOND, self::THIRD],
                $failureIndex - 1,
            ) : [self::FIRST, self::SECOND, self::THIRD],
            $remaining,
        );
        self::assertCount(1, $messages);
        self::assertMatchesRegularExpression('/\b[0-9a-f]{16}\b/', $messages[0]);
        self::assertStringNotContainsString(
            'synthetic private failure cause',
            $messages[0],
        );
        if ($stage === 'delete') {
            self::assertStringContainsString(
                'may already have been deleted',
                $messages[0],
            );
        } else {
            self::assertStringNotContainsString(
                'may already have been deleted',
                $messages[0],
            );
        }
    }

    /**
     * @return iterable<string, array{string, class-string<Throwable>, int}>
     */
    public static function failingStages(): iterable
    {
        foreach (['exists', 'preflight', 'delete'] as $stage) {
            foreach ([RuntimeException::class, Error::class] as $throwableClass) {
                foreach ([1, 2] as $index) {
                    yield $stage . '-' . $throwableClass . '-' . $index => [$stage, $throwableClass, $index];
                }
            }
        }
    }

    #[Test]
    public function postPersistenceFailureIncludesTheCurrentDeleteInTheResidual(): void
    {
        $remaining = [self::FIRST, self::SECOND];
        $deletes   = [];
        $messages  = [];
        $this->vault->method('exists')->willReturn(true);
        $this->vault
            ->method('delete')
            ->willReturnCallback(
                static function (
                    string $id,
                ) use (&$remaining, &$deletes): never {
                    $deletes[] = $id;
                    $remaining = array_values(array_diff($remaining, [$id]));

                    throw new Error('synthetic observer after successful persistence', 755733769);
                },
            );
        $this->dataHandler
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
        $cancelled = false;
        $caught    = $this->runDelete(
            ['flex_a' => self::FIRST . ' ' . self::SECOND],
            $cancelled,
        );
        self::assertNull($caught);
        self::assertTrue($cancelled);
        self::assertSame([self::FIRST], $deletes);
        self::assertSame([self::SECOND], $remaining);
        self::assertCount(1, $messages);
        self::assertStringContainsString(
            'may already have been deleted',
            $messages[0],
        );
        self::assertStringNotContainsString('synthetic observer', $messages[0]);
    }

    #[Test]
    #[DataProvider('diagnosticStages')]
    public function cancellationIsSetBeforePotentiallyFailingDiagnostics(
        string $diagnosticStage,
    ): void {
        $diagnosticFailure = new Error('synthetic diagnostic failure');
        $logger            = self::createMock(LoggerInterface::class);
        if ($diagnosticStage === 'reporter') {
            $logger->method('error')->willThrowException($diagnosticFailure);
        } else {
            $this->dataHandler
                ->method('log')
                ->willThrowException($diagnosticFailure);
        }

        $this->subject = $this->createSubject($logger);
        $deletes       = [];
        $this->vault->method('exists')->willReturn(true);
        $this->vault
            ->method('assertDeletable')
            ->willThrowException(new RuntimeException('synthetic refusal'));
        $this->vault
            ->method('delete')
            ->willReturnCallback(
                static function (string $id) use (&$deletes): void {
                    $deletes[] = $id;
                },
            );
        $cancelled = false;
        $caught    = $this->runDelete(['flex_a' => self::FIRST], $cancelled);
        if ($diagnosticStage === 'reporter') {
            // VaultFailureReporter swallows its own logger failure.
            self::assertNull($caught);
        } else {
            self::assertSame($diagnosticFailure, $caught);
        }

        self::assertTrue(
            $cancelled,
            'Even a broken logger must observe the already-set Core cancellation flag.',
        );
        self::assertSame([], $deletes);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function diagnosticStages(): iterable
    {
        yield 'reporter logger' => ['reporter'];
        yield 'editor log' => ['editor'];
    }

    #[Test]
    public function softDeleteKeepsReferencesAndDoesNotEnterTheVault(): void
    {
        $GLOBALS['TCA'][self::TABLE]['ctrl']['delete'] = 'deleted';
        $this->vault->expects(self::never())->method('exists');
        $this->vault->expects(self::never())->method('assertDeletable');
        $this->vault->expects(self::never())->method('delete');
        $cancelled = false;
        self::assertNull(
            $this->runDelete(['flex_a' => self::FIRST], $cancelled),
        );
        self::assertFalse($cancelled);
    }

    /**
     * @param class-string<Throwable> $throwableClass
     */
    #[Test]
    #[DataProvider('discoveryFailures')]
    public function schemaAndSharingDiscoveryFailureCancelBeforeAnyDelete(
        string $origin,
        string $throwableClass,
    ): void {
        $failure = new $throwableClass('synthetic discovery failure');
        if ($origin === 'schema') {
            $this->tcaSchemaFactory = $this->createMock(TcaSchemaFactory::class);
            $this->tcaSchemaFactory->method('has')->willReturn(true);
            $this->tcaSchemaFactory->method('get')->willThrowException($failure);
        } else {
            $this->connectionPool
                ->method('getQueryBuilderForTable')
                ->willThrowException($failure);
        }

        $this->subject = $this->createSubject(self::createStub(LoggerInterface::class));
        $this->vault->method('exists')->willReturn(true);
        $this->vault->expects(self::never())->method('assertDeletable');
        $this->vault->expects(self::never())->method('delete');
        $cancelled = false;
        self::assertNull(
            $this->runDelete(['flex_a' => self::FIRST], $cancelled),
        );
        self::assertTrue($cancelled);
    }

    /**
     * @return iterable<string, array{string, class-string<Throwable>}>
     */
    public static function discoveryFailures(): iterable
    {
        foreach (['schema', 'sharing'] as $origin) {
            foreach ([RuntimeException::class, Error::class] as $throwableClass) {
                yield $origin . '-' . $throwableClass => [$origin, $throwableClass];
            }
        }
    }

    #[Test]
    public function noExistingReferencesLeavesCoreFreeToRemoveTheRecord(): void
    {
        $this->vault
            ->method('getMetadata')
            ->willThrowException(SecretNotFoundException::forIdentifier(self::FIRST));
        $this->vault->method('exists')->willReturn(false);
        $this->vault->expects(self::never())->method('assertDeletable');
        $this->vault->expects(self::never())->method('delete');
        $cancelled = false;
        self::assertNull(
            $this->runDelete(
                ['flex_a' => self::FIRST, 'flex_b' => ''],
                $cancelled,
            ),
        );
        self::assertFalse($cancelled);
    }

    #[Test]
    #[DataProvider('sharedColumnOrder')]
    public function oneSharedColumnExcludesTheIdentityFromEveryColumn(
        bool $sharedFirst,
    ): void {
        if (!$sharedFirst) {
            $this->mockTcaSchemaForTable(
                self::TABLE,
                ['flex_b' => ['type' => 'flex'], 'flex_a' => ['type' => 'flex']],
            );
        }

        $result = $this->createMock(Result::class);
        $result
            ->method('fetchOne')
            ->willReturnOnConsecutiveCalls(...$sharedFirst ? [1, 0] : [0, 1]);
        $query = $this->createMock(QueryBuilder::class);
        foreach (['count', 'from', 'where', 'andWhere'] as $method) {
            $query->method($method)->willReturnSelf();
        }

        $query->method('executeQuery')->willReturn($result);
        $this->connectionPool
            ->method('getQueryBuilderForTable')
            ->willReturn($query);
        $this->vault->method('exists')->willReturn(true);
        $preflights = [];
        $deletes    = [];
        $this->vault
            ->method('assertDeletable')
            ->willReturnCallback(
                static function (string $id) use (&$preflights): void {
                    $preflights[] = $id;
                },
            );
        $this->vault
            ->method('delete')
            ->willReturnCallback(
                static function (string $id) use (&$deletes): void {
                    $deletes[] = $id;
                },
            );
        $cancelled = false;
        self::assertNull(
            $this->runDelete(
                ['flex_a' => self::FIRST, 'flex_b' => self::FIRST],
                $cancelled,
            ),
        );
        self::assertFalse($cancelled);
        self::assertSame([], $preflights);
        self::assertSame(
            [],
            $deletes,
            'An unshared occurrence must not reselect a globally shared identity.',
        );
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function sharedColumnOrder(): iterable
    {
        yield 'shared before unshared' => [true];
        yield 'unshared before shared' => [false];
    }

    #[Test]
    public function storagePresenceCompletesBeforeAnyPreflightOrDeletion(): void
    {
        $calls = [];
        $this->vault
            ->method('exists')
            ->willReturnCallback(
                static function (string $id) use (&$calls): bool {
                    $calls[] = ['availability', $id];

                    return $id === self::FIRST;
                },
            );
        $this->vault
            ->method('getMetadata')
            ->willReturnCallback(
                static function (string $id) use (&$calls): SecretDetails {
                    $calls[] = ['metadata', $id];

                    return SecretDetails::fromSecret(
                        new Secret(identifier: $id, hidden: true),
                    );
                },
            );
        $this->vault
            ->method('assertDeletable')
            ->willReturnCallback(
                static function (string $id) use (&$calls): void {
                    $calls[] = ['preflight', $id];
                },
            );
        $this->vault
            ->method('delete')
            ->willReturnCallback(
                static function (string $id) use (&$calls): void {
                    $calls[] = ['delete', $id];
                },
            );
        $cancelled = false;
        $caught    = $this->runDelete(
            ['flex_a' => self::FIRST, 'flex_b' => self::SECOND],
            $cancelled,
        );
        self::assertNull($caught);
        self::assertFalse($cancelled);
        self::assertSame(
            [
                ['availability', self::FIRST],
                ['availability', self::SECOND],
                ['metadata', self::SECOND],
                ['preflight', self::FIRST],
                ['preflight', self::SECOND],
                ['delete', self::FIRST],
                ['delete', self::SECOND],
            ],
            $calls,
        );
    }

    /**
     * @param class-string<Throwable> $throwableClass
     */
    #[Test]
    #[DataProvider('administrativeFailures')]
    public function administrativePresenceFailureCancelsBeforeEveryPreflightAndDelete(
        string $throwableClass,
    ): void {
        $failure = new $throwableClass('synthetic administrative lookup failure');
        $this->vault
            ->method('exists')
            ->willReturnCallback(static fn (string $id): bool => $id === self::FIRST);
        $this->vault->method('getMetadata')->willThrowException($failure);
        $preflights = [];
        $deletes    = [];
        $this->vault
            ->method('assertDeletable')
            ->willReturnCallback(
                static function (string $id) use (&$preflights): void {
                    $preflights[] = $id;
                },
            );
        $this->vault
            ->method('delete')
            ->willReturnCallback(
                static function (string $id) use (&$deletes): void {
                    $deletes[] = $id;
                },
            );
        $cancelled = false;
        $caught    = $this->runDelete(
            ['flex_a' => self::FIRST, 'flex_b' => self::SECOND],
            $cancelled,
        );
        self::assertNull($caught);
        self::assertTrue($cancelled);
        self::assertSame([], $preflights);
        self::assertSame([], $deletes);
    }

    /**
     * @return iterable<string, array{class-string<Throwable>}>
     */
    public static function administrativeFailures(): iterable
    {
        yield 'permission denial' => [AccessDeniedException::class];
        yield 'storage exception' => [RuntimeException::class];
        yield 'storage error' => [Error::class];
    }

    #[Test]
    public function activeReferenceKeepsTheAvailabilityFastPath(): void
    {
        $this->vault->method('exists')->willReturn(true);
        $this->vault->expects(self::never())->method('getMetadata');
        $deletes = [];
        $this->vault
            ->method('delete')
            ->willReturnCallback(
                static function (string $id) use (&$deletes): void {
                    $deletes[] = $id;
                },
            );
        $cancelled = false;
        self::assertNull(
            $this->runDelete(['flex_a' => self::FIRST], $cancelled),
        );
        self::assertFalse($cancelled);
        self::assertSame([self::FIRST], $deletes);
    }

    #[Test]
    public function onlyMissingMetadataExcludesAnUnsharedReference(): void
    {
        $this->vault
            ->method('exists')
            ->willReturnCallback(static fn (string $id): bool => $id === self::SECOND);
        $this->vault
            ->method('getMetadata')
            ->willThrowException(SecretNotFoundException::forIdentifier(self::FIRST));
        $calls = [];
        $this->vault
            ->method('assertDeletable')
            ->willReturnCallback(
                static function (string $id) use (&$calls): void {
                    $calls[] = ['preflight', $id];
                },
            );
        $this->vault
            ->method('delete')
            ->willReturnCallback(
                static function (string $id) use (&$calls): void {
                    $calls[] = ['delete', $id];
                },
            );
        $cancelled = false;
        self::assertNull(
            $this->runDelete(
                ['flex_a' => self::FIRST, 'flex_b' => self::SECOND],
                $cancelled,
            ),
        );
        self::assertFalse($cancelled);
        self::assertSame(
            [['preflight', self::SECOND], ['delete', self::SECOND]],
            $calls,
        );
    }

    #[Test]
    public function identifierInAnOrdinaryElementIsNeverADeleteCandidate(): void
    {
        $this->vault->method('exists')->willReturn(true);
        $this->vault->expects(self::never())->method('getMetadata');
        $deletes = [];
        $this->vault
            ->method('delete')
            ->willReturnCallback(
                static function (string $id) use (&$deletes): void {
                    $deletes[] = $id;
                },
            );
        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF">'
            . '<field index="note"><value index="vDEF">' . self::SECOND . '</value></field>'
            . '<field index="secret0"><value index="vDEF">' . self::FIRST . '</value></field>'
            . '</language></sheet></data></T3FlexForms>';
        $cancelled = false;
        self::assertNull($this->runDeleteRow(['flex_a' => $xml], $cancelled));
        self::assertFalse($cancelled);
        self::assertSame(
            [self::FIRST],
            $deletes,
            'Only the configured vaultSecret position may select a secret for deletion.',
        );
    }

    #[Test]
    public function vaultSecretInsideASectionContainerIsADeleteCandidate(): void
    {
        $tools = self::createStub(FlexFormTools::class);
        $tools->method('getDataStructureIdentifier')->willReturn('section-ds');
        $tools->method('parseDataStructureByIdentifier')->willReturn([
            'sheets' => [
                'sDEF' => [
                    'ROOT' => [
                        'el' => [
                            'endpoints' => [
                                'section' => '1',
                                'el'      => [
                                    'endpoint' => [
                                        'el' => [
                                            'token' => ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']],
                                            'url'   => ['config' => ['type' => 'input']],
                                        ],
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ]);
        $this->subject = $this->createSubject(self::createStub(LoggerInterface::class), $tools);
        $this->vault->method('exists')->willReturn(true);
        $deletes = [];
        $this->vault
            ->method('delete')
            ->willReturnCallback(
                static function (string $id) use (&$deletes): void {
                    $deletes[] = $id;
                },
            );
        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF">'
            . '<field index="endpoints"><el index="el"><section index="1"><itemType index="endpoint"><el index="el">'
            . '<field index="token"><value index="vDEF">' . self::FIRST . '</value></field>'
            . '<field index="url"><value index="vDEF">' . self::SECOND . '</value></field>'
            . '</el></itemType></section></el></field>'
            . '</language></sheet></data></T3FlexForms>';
        $cancelled = false;
        self::assertNull($this->runDeleteRow(['flex_a' => $xml], $cancelled));
        self::assertFalse($cancelled);
        self::assertSame([self::FIRST], $deletes);
    }

    #[Test]
    #[DataProvider('unresolvablePositions')]
    public function unresolvableVaultPositionsCancelTheDeleteBeforeAnyVaultCall(
        string $failingStep,
        Throwable $failure,
    ): void {
        $tools = self::createStub(FlexFormTools::class);
        if ($failingStep === 'identifier') {
            $tools->method('getDataStructureIdentifier')->willThrowException($failure);
        } else {
            $tools->method('getDataStructureIdentifier')->willReturn('vault-ds');
        }

        if ($failingStep === 'parse') {
            $tools->method('parseDataStructureByIdentifier')->willThrowException($failure);
        } else {
            $tools->method('parseDataStructureByIdentifier')->willReturn(['sheets' => []]);
        }

        $this->subject = $this->createSubject(self::createStub(LoggerInterface::class), $tools);
        $this->vault->expects(self::never())->method('exists');
        $this->vault->expects(self::never())->method('getMetadata');
        $this->vault->expects(self::never())->method('assertDeletable');
        $this->vault->expects(self::never())->method('delete');
        $row = $failingStep === 'xml'
            ? ['flex_a' => '<T3FlexForms><data>' . self::FIRST . '</T3FlexForms>']
            : ['flex_a' => $this->flexXml([self::FIRST])];
        $cancelled = false;
        self::assertNull($this->runDeleteRow($row, $cancelled));
        self::assertTrue(
            $cancelled,
            'Unlocatable vault positions must not read as a column without vault positions.',
        );
    }

    /**
     * @return iterable<string, array{string, Throwable}>
     */
    public static function unresolvablePositions(): iterable
    {
        yield 'identifier lookup refused' => ['identifier', new InvalidIdentifierException('synthetic', 1792483211)];
        yield 'data structure parse refused' => ['parse', new RuntimeException('synthetic', 1792483212)];
        yield 'data structure parse error' => ['parse', new Error('synthetic')];
        yield 'stored XML unparseable' => ['xml', new RuntimeException('unused', 1792483213)];
    }

    #[Test]
    public function valueWithoutIdentifiersNeedsNoDataStructure(): void
    {
        $tools = $this->createMock(FlexFormTools::class);
        $tools
            ->expects(self::never())
            ->method('getDataStructureIdentifier')
            ->willThrowException(new InvalidIdentifierException('synthetic', 1792483214));
        $tools->expects(self::never())->method('parseDataStructureByIdentifier');
        $this->subject = $this->createSubject(self::createStub(LoggerInterface::class), $tools);
        $this->vault->expects(self::never())->method('delete');
        $cancelled = false;
        self::assertNull(
            $this->runDeleteRow(
                ['flex_a' => '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="note"><value index="vDEF">plain</value></field></language></sheet></data></T3FlexForms>'],
                $cancelled,
            ),
        );
        self::assertFalse(
            $cancelled,
            'A record without identifier-shaped values must stay deletable when its data structure is unresolvable.',
        );
    }

    /**
     * Run the hook against a record whose FlexForm columns are given as
     * space-separated identifiers; each one is stored at its own configured
     * vaultSecret position, in the given order.
     *
     * @param array<string, string> $record
     */
    private function runDelete(array $record, bool &$cancelled): ?Throwable
    {
        $row = [];
        foreach ($record as $column => $identifiers) {
            $row[$column] = $identifiers === '' ? '' : $this->flexXml(explode(' ', $identifiers));
        }

        return $this->runDeleteRow($row, $cancelled);
    }

    /**
     * @param array<string, mixed> $row
     */
    private function runDeleteRow(array $row, bool &$cancelled): ?Throwable
    {
        try {
            $this->subject->processCmdmap_deleteAction(
                self::TABLE,
                42,
                $row,
                $cancelled,
                $this->dataHandler,
            );
        } catch (Throwable $failure) {
            return $failure;
        }

        return null;
    }

    /**
     * @param list<string> $identifiers
     */
    private function flexXml(array $identifiers): string
    {
        $fields = '';
        foreach ($identifiers as $index => $identifier) {
            $fields .= '<field index="secret' . $index . '"><value index="vDEF">' . $identifier . '</value></field>';
        }

        return '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF">' . $fields . '</language></sheet></data></T3FlexForms>';
    }

    /**
     * A data structure configuring `secret0` to `secret4` as vault secrets.
     */
    private function vaultSecretFlexTools(): FlexFormTools
    {
        $elements = [];
        foreach (range(0, 4) as $index) {
            $elements['secret' . $index] = ['config' => ['type' => 'input', 'renderType' => 'vaultSecret']];
        }

        $tools = self::createStub(FlexFormTools::class);
        $tools->method('getDataStructureIdentifier')->willReturn('vault-ds');
        $tools->method('parseDataStructureByIdentifier')->willReturn(
            ['sheets' => ['sDEF' => ['ROOT' => ['el' => $elements]]]],
        );

        return $tools;
    }

    private function createSubject(LoggerInterface $logger, ?FlexFormTools $flexFormTools = null): FlexFormVaultHook
    {
        return new FlexFormVaultHook(
            $this->connectionPool,
            $this->tcaSchemaFactory,
            $this->vault,
            $flexFormTools ?? $this->vaultSecretFlexTools(),
            self::createStub(FlashMessageService::class),
            new VaultFailureReporter($logger),
            new TranslationSharedSecretResolver(
                $this->connectionPool,
                new VaultFieldResolver(
                    $this->vault,
                    $this->tcaSchemaFactory,
                    self::createStub(LoggerInterface::class),
                ),
            ),
        );
    }
}
