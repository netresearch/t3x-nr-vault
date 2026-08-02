<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Hook;

use Netresearch\NrVault\Hook\RecordCreationOutcome;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(RecordCreationOutcome::class)]
final class RecordCreationOutcomeTest extends TestCase
{
    #[Test]
    #[DataProvider('classificationProvider')]
    public function classifyDistinguishesTheThreeCreationOutcomes(
        bool $valueSubmitted,
        bool $valueStored,
        RecordCreationOutcome $expected,
    ): void {
        self::assertSame($expected, RecordCreationOutcome::classify($valueSubmitted, $valueStored));
    }

    /**
     * @return iterable<string, array{bool, bool, RecordCreationOutcome}>
     */
    public static function classificationProvider(): iterable
    {
        yield 'no value submitted' => [false, false, RecordCreationOutcome::ValueLess];

        yield 'value submitted and stored' => [true, true, RecordCreationOutcome::Stored];

        // The regression this enum exists for: refusing a submitted value
        // must NOT read as the value-less creation it superficially
        // resembles — that routed a denied create into the "audit this
        // creation as a success" branch.
        yield 'value submitted but refused' => [true, false, RecordCreationOutcome::Rejected];

        // Cannot occur (nothing can be stored without being submitted); the
        // classification keys on the submission, so it stays value-less.
        yield 'stored without submission is impossible and stays value-less' => [
            false,
            true,
            RecordCreationOutcome::ValueLess,
        ];
    }
}
