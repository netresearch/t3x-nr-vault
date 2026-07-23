<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Utility;

use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Utility\CsvFormulaSanitizer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(CsvFormulaSanitizer::class)]
final class CsvFormulaSanitizerTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function formulaLeaderProvider(): iterable
    {
        yield 'equals' => ['=1+1', "'=1+1"];
        yield 'plus' => ['+1+1', "'+1+1"];
        yield 'minus' => ['-1+1', "'-1+1"];
        yield 'at' => ['@SUM(A1)', "'@SUM(A1)"];
        yield 'tab' => ["\t=1", "'\t=1"];
        yield 'carriage-return' => ["\r=1", "'\r=1"];
        yield 'dde-payload' => ["=cmd|'/c calc'!A1", "'=cmd|'/c calc'!A1"];
    }

    #[Test]
    #[DataProvider('formulaLeaderProvider')]
    public function neutralizeCellPrefixesFormulaLeaders(string $input, string $expected): void
    {
        self::assertSame($expected, CsvFormulaSanitizer::neutralizeCell($input));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function benignValueProvider(): iterable
    {
        yield 'plain' => ['hello'];
        yield 'identifier' => ['my_api_key'];
        yield 'hex-hash' => ['abc123def456'];
        yield 'ip' => ['127.0.0.1'];
        yield 'iso-date' => ['2024-01-01T00:00:00+00:00'];
        yield 'empty' => [''];
        yield 'leader-not-first' => ['a=b'];
    }

    #[Test]
    #[DataProvider('benignValueProvider')]
    public function neutralizeCellLeavesBenignValuesByteIdentical(string $input): void
    {
        self::assertSame($input, CsvFormulaSanitizer::neutralizeCell($input));
    }

    #[Test]
    public function neutralizeRowNeutralizesStringsAndPreservesOtherTypes(): void
    {
        $row = [
            'id' => '=cmd',
            'count' => 5,
            'ratio' => 1.5,
            'ok' => true,
            'empty' => null,
            'benign' => 'read',
        ];

        self::assertSame([
            'id' => "'=cmd",
            'count' => 5,
            'ratio' => 1.5,
            'ok' => true,
            'empty' => null,
            'benign' => 'read',
        ], CsvFormulaSanitizer::neutralizeRow($row));
    }

    #[Test]
    public function escapeFieldNeutralizesThenQuotesWhenNeeded(): void
    {
        self::assertSame("\"'=cmd,evil\"", CsvFormulaSanitizer::escapeField('=cmd,evil'));
        self::assertSame("'=cmd", CsvFormulaSanitizer::escapeField('=cmd'));
        self::assertSame('"a,b"', CsvFormulaSanitizer::escapeField('a,b'));
        self::assertSame('plain', CsvFormulaSanitizer::escapeField('plain'));
    }
}
