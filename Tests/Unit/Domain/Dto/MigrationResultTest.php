<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Domain\Dto;

use Netresearch\NrVault\Domain\Dto\MigrationResult;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(MigrationResult::class)]
final class MigrationResultTest extends TestCase
{
    private const SOME_ERROR = 'some error';

    #[Test]
    public function constructorSetsAllProperties(): void
    {
        $subject = new MigrationResult(
            table: 'tt_content',
            column: 'pi_flexform',
            migrated: 10,
            failed: 2,
            skipped: 1,
            error: self::SOME_ERROR,
        );

        self::assertSame('tt_content', $subject->table);
        self::assertSame('pi_flexform', $subject->column);
        self::assertSame(10, $subject->migrated);
        self::assertSame(2, $subject->failed);
        self::assertSame(1, $subject->skipped);
        self::assertSame(self::SOME_ERROR, $subject->error);
    }

    #[Test]
    public function constructorErrorDefaultsToNull(): void
    {
        $subject = new MigrationResult('pages', 'subtitle', 5, 0, 0);

        self::assertNull($subject->error);
    }

    #[Test]
    public function successFactorySetsMigratedAndZeroFailures(): void
    {
        $subject = MigrationResult::success('pages', 'title', 42);

        self::assertSame('pages', $subject->table);
        self::assertSame('title', $subject->column);
        self::assertSame(42, $subject->migrated);
        self::assertSame(0, $subject->failed);
        self::assertSame(0, $subject->skipped);
        self::assertNull($subject->error);
    }

    #[Test]
    public function successFactoryUsesProvidedSkippedCount(): void
    {
        $subject = MigrationResult::success('pages', 'title', 10, 3);

        self::assertSame(10, $subject->migrated);
        self::assertSame(3, $subject->skipped);
    }

    #[Test]
    public function withFailuresFactorySetsAllCounts(): void
    {
        $subject = MigrationResult::withFailures('tt_content', 'bodytext', 8, 2, 1);

        self::assertSame('tt_content', $subject->table);
        self::assertSame('bodytext', $subject->column);
        self::assertSame(8, $subject->migrated);
        self::assertSame(2, $subject->failed);
        self::assertSame(1, $subject->skipped);
        self::assertNull($subject->error);
    }

    #[Test]
    public function withFailuresFactorySkippedDefaultsToZero(): void
    {
        $subject = MigrationResult::withFailures('table', 'col', 5, 1);

        self::assertSame(0, $subject->skipped);
    }

    #[Test]
    public function errorFactorySetsErrorAndZeroCounts(): void
    {
        $subject = MigrationResult::error('tx_ext_domain', 'secret_ref', 'Connection refused');

        self::assertSame('tx_ext_domain', $subject->table);
        self::assertSame('secret_ref', $subject->column);
        self::assertSame(0, $subject->migrated);
        self::assertSame(0, $subject->failed);
        self::assertSame(0, $subject->skipped);
        self::assertSame('Connection refused', $subject->error);
    }

    #[Test]
    public function isSuccessReturnsTrueForSuccessResult(): void
    {
        $subject = MigrationResult::success('pages', 'col', 5);

        self::assertTrue($subject->isSuccess());
    }

    #[Test]
    public function isSuccessReturnsTrueWhenNoFailuresAndNoError(): void
    {
        $subject = new MigrationResult('t', 'c', 3, 0, 2);

        self::assertTrue($subject->isSuccess());
    }

    #[Test]
    public function isSuccessReturnsFalseWhenFailuresExist(): void
    {
        $subject = MigrationResult::withFailures('t', 'c', 5, 1);

        self::assertFalse($subject->isSuccess());
    }

    #[Test]
    public function isSuccessReturnsFalseWhenErrorIsSet(): void
    {
        $subject = MigrationResult::error('t', 'c', 'DB error');

        self::assertFalse($subject->isSuccess());
    }

    #[Test]
    public function isSuccessReturnsFalseWhenBothFailuresAndError(): void
    {
        $subject = new MigrationResult('t', 'c', 0, 2, 0, 'error');

        self::assertFalse($subject->isSuccess());
    }

    #[Test]
    public function hasErrorReturnsTrueWhenErrorIsSet(): void
    {
        $subject = MigrationResult::error('t', 'c', self::SOME_ERROR);

        self::assertTrue($subject->hasError());
    }

    #[Test]
    public function hasErrorReturnsFalseWhenNoError(): void
    {
        $subject = MigrationResult::success('t', 'c', 5);

        self::assertFalse($subject->hasError());
    }

    #[Test]
    public function hasErrorReturnsFalseForWithFailures(): void
    {
        $subject = MigrationResult::withFailures('t', 'c', 5, 2);

        self::assertFalse($subject->hasError());
    }

    #[Test]
    #[DataProvider('getTotalProvider')]
    public function getTotalSumsMigratedFailedAndSkipped(
        int $migrated,
        int $failed,
        int $skipped,
        int $expectedTotal,
    ): void {
        $subject = new MigrationResult('t', 'c', $migrated, $failed, $skipped);

        self::assertSame($expectedTotal, $subject->getTotal());
    }

    public static function getTotalProvider(): iterable
    {
        yield 'all zeros' => [0, 0, 0, 0];
        yield 'only migrated' => [10, 0, 0, 10];
        yield 'migrated and failed' => [8, 2, 0, 10];
        yield 'all three' => [5, 3, 2, 10];
        yield 'only skipped' => [0, 0, 7, 7];
    }

    #[Test]
    public function toArrayReturnsCorrectStructureWithoutError(): void
    {
        $subject = MigrationResult::success('pages', 'title', 5, 1);

        self::assertSame([
            'table' => 'pages',
            'column' => 'title',
            'migrated' => 5,
            'failed' => 0,
            'skipped' => 1,
        ], $subject->toArray());
    }

    #[Test]
    public function toArrayIncludesErrorKeyWhenErrorIsSet(): void
    {
        $subject = MigrationResult::error('pages', 'col', 'DB down');

        $array = $subject->toArray();

        self::assertArrayHasKey('error', $array);
        self::assertSame('DB down', $array['error']);
    }

    #[Test]
    public function toArrayOmitsErrorKeyWhenNoError(): void
    {
        $subject = MigrationResult::success('pages', 'col', 3);

        $array = $subject->toArray();

        self::assertArrayNotHasKey('error', $array);
    }

    #[Test]
    public function toArrayWithFailuresHasNoErrorKey(): void
    {
        $subject = MigrationResult::withFailures('t', 'c', 5, 2);

        self::assertArrayNotHasKey('error', $subject->toArray());
    }
}
