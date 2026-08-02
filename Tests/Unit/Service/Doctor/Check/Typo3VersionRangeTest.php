<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Doctor\Check;

use Netresearch\NrVault\Service\Doctor\Check\Typo3VersionRange;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(Typo3VersionRange::class)]
final class Typo3VersionRangeTest extends TestCase
{
    #[Test]
    public function parsesTheExtensionsOwnConstraint(): void
    {
        $range = Typo3VersionRange::fromConstraint('13.4.0-14.99.99');

        self::assertInstanceOf(Typo3VersionRange::class, $range);
        self::assertSame('13.4.0', $range->minimum);
        self::assertSame('14.99.99', $range->maximum);
        self::assertSame('13.4.0-14.99.99', (string) $range);
    }

    #[Test]
    public function toleratesSurroundingWhitespace(): void
    {
        $range = Typo3VersionRange::fromConstraint('  13.4.0 - 14.99.99  ');

        self::assertInstanceOf(Typo3VersionRange::class, $range);
        self::assertSame('13.4.0', $range->minimum);
    }

    /**
     * Null rather than a permissive fallback: "we could not read the constraint"
     * and "every version is allowed" are different statements, and only the caller
     * knows which finding to raise.
     */
    #[Test]
    #[DataProvider('unusableConstraintProvider')]
    public function refusesToGuessAtAnUnusableConstraint(string $constraint): void
    {
        self::assertNull(Typo3VersionRange::fromConstraint($constraint));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unusableConstraintProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'single version' => ['13.4.0'];
        yield 'composer caret syntax' => ['^13.4'];
        yield 'three parts' => ['13.4.0-14.0.0-15.0.0'];
        yield 'missing lower bound' => ['-14.99.99'];
        yield 'missing upper bound' => ['13.4.0-'];
        yield 'reversed bounds' => ['14.99.99-13.4.0'];
    }

    #[Test]
    #[DataProvider('containmentProvider')]
    public function boundsAreInclusive(string $version, bool $expected): void
    {
        $range = Typo3VersionRange::fromConstraint('13.4.0-14.99.99');

        self::assertInstanceOf(Typo3VersionRange::class, $range);
        self::assertSame($expected, $range->contains($version));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function containmentProvider(): iterable
    {
        yield 'lower bound' => ['13.4.0', true];
        yield 'upper bound' => ['14.99.99', true];
        yield 'inside' => ['14.3.2', true];
        yield 'below' => ['13.3.9', false];
        yield 'above' => ['15.0.0', false];
        yield 'empty version' => ['', false];
    }
}
