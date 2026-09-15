<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Utility;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Utility\TranslationSharedSecretResolver;
use Netresearch\NrVault\Utility\VaultFieldResolver;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;

/**
 * The questions both DataHandler hooks ask about a secret shared between a
 * translation and its default-language record.
 */
#[CoversClass(TranslationSharedSecretResolver::class)]
#[AllowMockObjectsWithoutExpectations]
final class TranslationSharedSecretResolverTest extends TestCase
{
    private const TABLE = 'tx_test';

    private const UUID_V7 = '01937b6e-4b6c-7abc-8def-0123456789ab';

    protected TcaSchemaFactory&MockObject $tcaSchemaFactory;

    private ConnectionPool&MockObject $connectionPool;

    private TranslationSharedSecretResolver $subject;

    protected function setUp(): void
    {
        parent::setUp();

        $this->connectionPool = $this->createMock(ConnectionPool::class);
        $this->tcaSchemaFactory = $this->createMock(TcaSchemaFactory::class);

        $this->subject = new TranslationSharedSecretResolver(
            $this->connectionPool,
            new VaultFieldResolver(
                $this->createMock(VaultServiceInterface::class),
                $this->tcaSchemaFactory,
                $this->createMock(LoggerInterface::class),
            ),
        );
    }

    #[Test]
    public function sharedColumnIsTheOneMarkedExcludedFromTranslation(): void
    {
        $this->mockTcaSchemaForTable(self::TABLE, [
            'api_token' => ['type' => 'input', 'renderType' => 'vaultSecret', 'l10n_mode' => 'exclude'],
            'api_key' => ['type' => 'input', 'renderType' => 'vaultSecret'],
        ]);

        self::assertSame(
            [
                'excluded' => true,
                'translatable' => false,
                'unknownColumn' => false,
            ],
            [
                'excluded' => $this->subject->isSharedColumn(self::TABLE, 'api_token'),
                'translatable' => $this->subject->isSharedColumn(self::TABLE, 'api_key'),
                'unknownColumn' => $this->subject->isSharedColumn(self::TABLE, 'nope'),
            ],
        );
    }

    /**
     * A table the schema factory does not know — a hook reached through a
     * command on a table without TCA — has nothing shared.
     */
    #[Test]
    public function aTableWithoutASchemaHasNoSharedColumn(): void
    {
        self::assertFalse($this->subject->isSharedColumn('tx_unknown', 'api_token'));
    }

    #[Test]
    public function parentUidComesFromTheSubmittedPointerWhileLocalizing(): void
    {
        $GLOBALS['TCA'][self::TABLE]['ctrl']['transOrigPointerField'] = 'l10n_parent';

        // No query at all: the pointer travels in the field array of the record
        // being written, which is the only place it exists before the insert.
        $this->connectionPool->expects(self::never())->method('getQueryBuilderForTable');

        self::assertSame(
            17,
            $this->subject->resolveParentUid(self::TABLE, 'NEW1', ['l10n_parent' => '17']),
        );
    }

    #[Test]
    public function parentUidFallsBackToThePersistedRow(): void
    {
        $GLOBALS['TCA'][self::TABLE]['ctrl']['transOrigPointerField'] = 'l10n_parent';
        $this->stubQuery('42');

        self::assertSame(42, $this->subject->resolveParentUid(self::TABLE, 7, []));
    }

    #[Test]
    public function aTableWithoutATranslationPointerHasNoParent(): void
    {
        $GLOBALS['TCA'][self::TABLE]['ctrl'] = [];

        self::assertSame(0, $this->subject->resolveParentUid(self::TABLE, 7, []));
    }

    #[Test]
    public function anUnsavedRecordWithoutASubmittedPointerHasNoParent(): void
    {
        $GLOBALS['TCA'][self::TABLE]['ctrl']['transOrigPointerField'] = 'l10n_parent';

        self::assertSame(0, $this->subject->resolveParentUid(self::TABLE, 'NEW1', []));
    }

    #[Test]
    public function aRecordIsATranslationWhenItsStoredPointerResolves(): void
    {
        $GLOBALS['TCA'][self::TABLE]['ctrl']['transOrigPointerField'] = 'l10n_parent';
        $this->stubQuery('42');

        self::assertTrue($this->subject->isTranslation(self::TABLE, 7));
    }

    #[Test]
    public function aDefaultLanguageRecordIsNoTranslation(): void
    {
        $GLOBALS['TCA'][self::TABLE]['ctrl']['transOrigPointerField'] = 'l10n_parent';
        $this->stubQuery('0');

        self::assertFalse($this->subject->isTranslation(self::TABLE, 7));
    }

    #[Test]
    public function readingAColumnOfANonPersistedRecordQueriesNothing(): void
    {
        $this->connectionPool->expects(self::never())->method('getQueryBuilderForTable');

        self::assertNull($this->subject->readColumn(self::TABLE, 0, 'api_token'));
    }

    #[Test]
    public function readingAColumnOfAMissingRecordYieldsNull(): void
    {
        $this->stubQuery(false);

        self::assertNull($this->subject->readColumn(self::TABLE, 7, 'api_token'));
    }

    #[Test]
    public function anIdentifierHeldByAnotherLiveRecordIsReferencedElsewhere(): void
    {
        $GLOBALS['TCA'][self::TABLE]['ctrl']['delete'] = 'deleted';
        $this->stubQuery(1);

        self::assertTrue(
            $this->subject->isValueReferencedElsewhere(self::TABLE, 'api_token', self::UUID_V7, 7),
        );
    }

    #[Test]
    public function theLastRecordHoldingAnIdentifierIsTheOnlyReference(): void
    {
        $GLOBALS['TCA'][self::TABLE]['ctrl']['delete'] = 'deleted';
        $this->stubQuery(0);

        self::assertFalse(
            $this->subject->isValueReferencedElsewhere(self::TABLE, 'api_token', self::UUID_V7, 7),
        );
    }

    /**
     * A table without a `delete` column has no soft-delete filter to add — the
     * branch a hard-deleting table takes.
     */
    #[Test]
    public function anIdentifierEmbeddedInAnotherLiveRecordIsReferencedElsewhere(): void
    {
        $GLOBALS['TCA'][self::TABLE]['ctrl'] = [];
        $this->stubQuery(1);

        self::assertTrue(
            $this->subject->isIdentifierEmbeddedElsewhere(self::TABLE, 'settings', self::UUID_V7, 7),
        );
    }

    #[Test]
    public function anIdentifierEmbeddedNowhereElseIsNotReferencedElsewhere(): void
    {
        $GLOBALS['TCA'][self::TABLE]['ctrl']['delete'] = 'deleted';
        $this->stubQuery(0);

        self::assertFalse(
            $this->subject->isIdentifierEmbeddedElsewhere(self::TABLE, 'settings', self::UUID_V7, 7),
        );
    }

    /**
     * A query builder whose single `fetchOne()` answers with the given value.
     */
    private function stubQuery(mixed $value): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn($value);

        $queryBuilder = $this->createMock(QueryBuilder::class);
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('count')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('andWhere')->willReturnSelf();
        $queryBuilder->method('createNamedParameter')->willReturn(':dcValue1');
        $queryBuilder->method('escapeLikeWildcards')->willReturnArgument(0);
        $queryBuilder->method('executeQuery')->willReturn($result);

        $this->connectionPool->method('getQueryBuilderForTable')->willReturn($queryBuilder);
    }
}
