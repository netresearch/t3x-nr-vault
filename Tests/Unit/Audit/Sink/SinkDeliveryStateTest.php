<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Sink;

use Netresearch\NrVault\Audit\Sink\SinkDeliveryState;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The persisted delivery health of one external audit sink.
 *
 * `fromArray()` reads a `sys_registry` payload — data that survived a
 * serialisation round trip and an extension update, so it is the one place the
 * class treats its input as untrusted. Every numeric field is coerced through
 * `is_numeric() ? (int) … : 0`, and the readiness surface reports on the
 * result: a `lastSuccessAt` that silently became 1 instead of 0 turns "this
 * sink has never demonstrably accepted a record" into "it succeeded in
 * January 1970".
 */
#[CoversClass(SinkDeliveryState::class)]
final class SinkDeliveryStateTest extends TestCase
{
    #[Test]
    public function fromArrayReadsAWellFormedRow(): void
    {
        $state = SinkDeliveryState::fromArray('syslog', [
            'lastSuccessAt' => 1_700_000_000,
            'lastFailureAt' => 1_700_000_500,
            'consecutiveFailures' => 3,
            'totalFailures' => 12,
            'lastError' => 'connection refused',
        ]);

        self::assertSame('syslog', $state->sinkIdentifier);
        self::assertSame(1_700_000_000, $state->lastSuccessAt);
        self::assertSame(1_700_000_500, $state->lastFailureAt);
        self::assertSame(3, $state->consecutiveFailures);
        self::assertSame(12, $state->totalFailures);
        self::assertSame('connection refused', $state->lastError);
    }

    /**
     * A registry payload comes back with its numbers as strings often enough
     * that the cast is load-bearing rather than defensive: the promoted
     * properties are `int`, so a value that reaches the constructor uncast is
     * a TypeError under `strict_types`, not a quietly wrong number.
     */
    #[Test]
    public function fromArrayCastsNumericStringsToIntegers(): void
    {
        $state = SinkDeliveryState::fromArray('webhook', [
            'lastSuccessAt' => '1700000000',
            'lastFailureAt' => '1700000500',
            'consecutiveFailures' => '3',
            'totalFailures' => '12',
        ]);

        self::assertSame(1_700_000_000, $state->lastSuccessAt);
        self::assertSame(1_700_000_500, $state->lastFailureAt);
        self::assertSame(3, $state->consecutiveFailures);
        self::assertSame(12, $state->totalFailures);
    }

    /**
     * Rows that predate a field, or carry junk in it, must read as zero — the
     * value that means "never observed" everywhere this state is consumed.
     *
     * @param array<string, mixed> $row
     */
    #[Test]
    #[DataProvider('unusableRowProvider')]
    public function fromArrayFallsBackToZeroForUnusableValues(array $row): void
    {
        $state = SinkDeliveryState::fromArray('file', $row);

        self::assertSame(0, $state->lastSuccessAt);
        self::assertSame(0, $state->lastFailureAt);
        self::assertSame(0, $state->consecutiveFailures);
        self::assertSame(0, $state->totalFailures);
        self::assertSame('', $state->lastError);
        self::assertFalse($state->hasEverSucceeded());
        self::assertFalse($state->isFailing());
    }

    /**
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function unusableRowProvider(): iterable
    {
        yield 'empty row' => [[]];
        yield 'null values' => [[
            'lastSuccessAt' => null,
            'lastFailureAt' => null,
            'consecutiveFailures' => null,
            'totalFailures' => null,
            'lastError' => null,
        ]];
        yield 'non-numeric strings' => [[
            'lastSuccessAt' => 'never',
            'lastFailureAt' => '',
            'consecutiveFailures' => 'many',
            'totalFailures' => [],
            'lastError' => 42,
        ]];
    }

    /**
     * The two predicates the readiness surface reads. Both are strict `> 0`,
     * so the zero that means "never observed" must not read as a state.
     *
     * @return iterable<string, array{0: int, 1: int, 2: bool, 3: bool}>
     */
    public static function healthPredicateProvider(): iterable
    {
        yield 'never observed' => [0, 0, false, false];
        yield 'succeeded once, healthy' => [1_700_000_000, 0, true, false];
        yield 'succeeded once, now failing' => [1_700_000_000, 2, true, true];
        yield 'only ever failed' => [0, 1, false, true];
    }

    #[Test]
    #[DataProvider('healthPredicateProvider')]
    public function healthPredicatesReadTheirCounters(
        int $lastSuccessAt,
        int $consecutiveFailures,
        bool $expectedEverSucceeded,
        bool $expectedFailing,
    ): void {
        $state = new SinkDeliveryState(
            sinkIdentifier: 'syslog',
            lastSuccessAt: $lastSuccessAt,
            consecutiveFailures: $consecutiveFailures,
        );

        self::assertSame($expectedEverSucceeded, $state->hasEverSucceeded());
        self::assertSame($expectedFailing, $state->isFailing());
    }

    /**
     * `toArray()` and `fromArray()` are the two halves of the registry round
     * trip; a key renamed on one side alone loses the field silently, since
     * the read side falls back to zero rather than failing.
     */
    #[Test]
    public function toArrayAndFromArrayRoundTrip(): void
    {
        $original = new SinkDeliveryState(
            sinkIdentifier: 'webhook',
            lastSuccessAt: 1_700_000_000,
            lastFailureAt: 1_700_000_500,
            consecutiveFailures: 3,
            totalFailures: 12,
            lastError: 'connection refused',
        );

        $restored = SinkDeliveryState::fromArray($original->sinkIdentifier, $original->toArray());

        self::assertEquals($original, $restored);
    }
}
