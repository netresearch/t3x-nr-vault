<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Domain\Dto;

use Netresearch\NrVault\Domain\Dto\OrphanReference;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(OrphanReference::class)]
final class OrphanReferenceTest extends TestCase
{
    #[Test]
    public function constructorSetsAllProperties(): void
    {
        $subject = new OrphanReference(
            table: 'tt_content',
            field: 'secret_ref',
            uid: 42,
        );

        self::assertSame('tt_content', $subject->table);
        self::assertSame('secret_ref', $subject->field);
        self::assertSame(42, $subject->uid);
    }

    #[Test]
    public function fromArrayCreatesObjectWithCorrectValues(): void
    {
        $subject = OrphanReference::fromArray([
            'table' => 'pages',
            'field' => 'api_key_ref',
            'uid'   => 7,
        ]);

        self::assertSame('pages', $subject->table);
        self::assertSame('api_key_ref', $subject->field);
        self::assertSame(7, $subject->uid);
    }

    #[Test]
    #[DataProvider('locationProvider')]
    public function getLocationReturnsHumanReadableString(
        string $table,
        string $field,
        int $uid,
        string $expected,
    ): void {
        $subject = new OrphanReference($table, $field, $uid);

        self::assertSame($expected, $subject->getLocation());
    }

    public static function locationProvider(): iterable
    {
        yield 'standard record' => ['tt_content', 'secret_ref', 42, 'tt_content.secret_ref (uid=42)'];
        yield 'pages table' => ['pages', 'api_key', 1, 'pages.api_key (uid=1)'];
        yield 'uid zero' => ['tx_ext_table', 'field_name', 0, 'tx_ext_table.field_name (uid=0)'];
        yield 'large uid' => ['tx_ext', 'col', 99999, 'tx_ext.col (uid=99999)'];
    }

    #[Test]
    public function getLocationContainsTableFieldAndUid(): void
    {
        $subject  = new OrphanReference('my_table', 'my_field', 123);
        $location = $subject->getLocation();

        self::assertStringContainsString('my_table', $location);
        self::assertStringContainsString('my_field', $location);
        self::assertStringContainsString('123', $location);
    }

    #[Test]
    public function toArrayReturnsCorrectStructure(): void
    {
        $subject = new OrphanReference('tt_content', 'bodytext', 55);

        self::assertSame([
            'table' => 'tt_content',
            'field' => 'bodytext',
            'uid'   => 55,
        ], $subject->toArray());
    }

    #[Test]
    public function toArrayContainsExactlyThreeKeys(): void
    {
        $subject = new OrphanReference('t', 'f', 1);

        self::assertCount(3, $subject->toArray());
    }

    #[Test]
    public function fromArrayRoundTripToArray(): void
    {
        $original = [
            'table' => 'tt_content',
            'field' => 'pi_flexform',
            'uid'   => 99,
        ];

        $subject = OrphanReference::fromArray($original);

        self::assertSame($original, $subject->toArray());
    }
}
