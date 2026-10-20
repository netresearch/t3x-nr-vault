<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Hook;

use Closure;
use Netresearch\NrVault\Hook\VaultFailureReporter;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\AbstractLogger;
use RuntimeException;
use Stringable;

#[CoversClass(VaultFailureReporter::class)]
final class VaultFailureReporterContextTest extends TestCase
{
    /** @var list<array{string,array<mixed>}> */
    private array $records = [];

    private VaultFailureReporter $subject;

    protected function setUp(): void
    {
        parent::setUp();
        $this->records = [];
        /** @param array<mixed> $context */
        $capture = function (string $message, array $context): void {
            $this->records[] = [$message, $context];
        };
        $logger = new class ($capture) extends AbstractLogger {
            /**
             * @param Closure(string,array<mixed>):void $capture
             */
            public function __construct(private readonly Closure $capture) {}

            /** @param mixed $level
             * @param array<mixed> $context
             */
            public function log(
                $level,
                string|Stringable $message,
                array $context = [],
            ): void {
                ($this->capture)((string) $message, $context);
            }
        };
        $this->subject = new VaultFailureReporter($logger);
    }

    #[Test]
    #[DataProvider('boundedValues')]
    public function finalUtf8ContextRespectsTheByteCap(
        string $value,
        string $expected,
    ): void {
        $previous = mb_substitute_character();
        mb_substitute_character(0xfffd);

        try {
            $this->subject->report(
                new RuntimeException($value, 972712908),
                ['identifier' => $value],
            );
        } finally {
            mb_substitute_character($previous);
        }

        self::assertCount(1, $this->records);
        foreach (['identifier', 'error'] as $key) {
            $logged = $this->records[0][1][$key];
            self::assertIsString($logged);
            self::assertTrue(mb_check_encoding($logged, 'UTF-8'));
            self::assertSame(
                $expected,
                $logged,
                'Allowed diagnostic text must retain its exact bounded prefix.',
            );
            self::assertLessThanOrEqual(
                200,
                \strlen($logged),
                'The final written value must meet the documented byte cap, including configured UTF-8 replacement.',
            );
        }

        self::assertIsString(
            json_encode($this->records[0][1], JSON_THROW_ON_ERROR),
        );
    }

    /**
     * @return iterable<string,array{string,string}>
     */
    public static function boundedValues(): iterable
    {
        yield 'ordinary ASCII counterpart' => [str_repeat('A', 500), str_repeat('A', 200)];
        yield 'invalid byte replacement expands' => [str_repeat("\xff", 200), str_repeat('�', 66)];
        yield 'truncation splits a valid UTF8 character' => [str_repeat('A', 199) . 'ä', str_repeat('A', 199)];
    }

    #[Test]
    public function callerContextCannotReplaceTheGeneratedCorrelationReference(): void
    {
        $message = $this->subject->report(
            new RuntimeException('synthetic failure', 972712909),
            [
                'reference' => 'caller-provided-reference',
                'table' => 'tx_context',
                'uid' => 42,
                'nullable' => null,
            ],
        );
        self::assertCount(1, $this->records);
        $reference = $this->records[0][1]['reference'];
        self::assertIsString($reference);
        self::assertStringContainsString(
            $reference,
            $message,
            'The editor must quote the reference of this actual written diagnostic.',
        );
        self::assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $reference);
        self::assertNotSame('caller-provided-reference', $reference);
        self::assertSame('tx_context', $this->records[0][1]['table']);
        self::assertSame(42, $this->records[0][1]['uid']);
        self::assertArrayHasKey('nullable', $this->records[0][1]);
        self::assertNull($this->records[0][1]['nullable']);
    }

    #[Test]
    public function anonymousCauseClassHasNoControlBytesInTheWrittenContext(): void
    {
        $cause = new class (
            'synthetic anonymous cause',
            972712910,
        ) extends RuntimeException {};
        $this->subject->report($cause);
        self::assertCount(1, $this->records);
        $class = $this->records[0][1]['exceptionClass'];
        self::assertIsString($class);
        self::assertDoesNotMatchRegularExpression('/[[:cntrl:]]/', $class);
        self::assertLessThanOrEqual(200, \strlen($class));
        self::assertTrue(mb_check_encoding($class, 'UTF-8'));
        self::assertStringContainsString('RuntimeException', $class);
    }

    #[Test]
    public function configuredUtf8ReplacementCannotIntroduceLogControlBytes(): void
    {
        $previous = mb_substitute_character();
        $applied = mb_substitute_character(0xa);

        try {
            $this->subject->report(
                new RuntimeException("synthetic\xffcause", 972712911),
                ['identifier' => "synthetic\xffrecord"],
            );
        } finally {
            mb_substitute_character($previous);
        }

        self::assertTrue($applied);
        self::assertCount(1, $this->records);
        foreach (['identifier', 'error'] as $key) {
            $logged = $this->records[0][1][$key];
            self::assertIsString($logged);
            self::assertDoesNotMatchRegularExpression('/[[:cntrl:]]/', $logged);
            self::assertLessThanOrEqual(200, \strlen($logged));
            self::assertTrue(mb_check_encoding($logged, 'UTF-8'));
        }
    }
}
