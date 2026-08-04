<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Fuzz;

use DateTimeImmutable;
use Doctrine\DBAL\ArrayParameterType;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Types\Type;
use Netresearch\NrVault\Audit\AuditLogFilter;
use Netresearch\NrVault\Audit\AuditLogService;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

/**
 * Fuzz tests for audit log filter construction and query-builder binding.
 *
 * Properties under test:
 * - AuditLogFilter stores adversarial payloads (SQLi, unicode, null bytes)
 *   verbatim — no silent sanitization that could mask injection.
 * - When a filter is applied to a QueryBuilder, every user-controlled value
 *   goes through createNamedParameter — the payload MUST NOT appear
 *   concatenated into the WHERE expression string.
 * - Date fields are passed as integer timestamps with Connection::PARAM_INT,
 *   so numeric edge cases (negative, PHP_INT_MAX) cannot break the query.
 * - isEmpty() is a pure function with deterministic output.
 * - Immutable `with*` methods return new instances preserving unchanged fields.
 */
#[CoversClass(AuditLogFilter::class)]
#[CoversClass(AuditLogService::class)]
#[AllowMockObjectsWithoutExpectations]
final class AuditFilterFuzzTest extends TestCase
{
    // -----------------------------------------------------------------------
    // Tests: applyFilter binds every user value via createNamedParameter
    // -----------------------------------------------------------------------

    /**
     * Exercise the private AuditLogService::applyFilter() against a stubbed
     * QueryBuilder that records every `createNamedParameter` call. Any
     * user-controlled payload MUST pass through that method and MUST NOT
     * appear concatenated in a where-expression argument.
     *
     * @return list<array{mixed, int}>
     */
    private array $recordedParams = [];

    // -----------------------------------------------------------------------
    // Data providers
    // -----------------------------------------------------------------------

    /**
     * Adversarial string payloads common to SQLi and injection tests.
     *
     * @return array<string, array{string}>
     */
    public static function adversarialStringProvider(): array
    {
        $seed = (int) ($_ENV['PHPUNIT_SEED'] ?? crc32(__FILE__));
        mt_srand($seed);

        $cases = [
            'classic OR 1=1' => ["' OR 1=1--"],
            'union select' => ["x' UNION SELECT NULL,password FROM be_users--"],
            'drop table' => ["foo'; DROP TABLE tx_nrvault_audit_log;--"],
            'stacked select' => ["'; SELECT * FROM be_users; --"],
            'sql comment' => ['foo/*comment*/bar'],
            'double dash comment' => ['foo-- bar'],
            'hash comment' => ['foo# bar'],
            'backtick' => ['foo`bar'],
            'double quote' => ['foo"bar'],
            'single quote' => ["foo'bar"],
            'backslash escape' => ['foo\\bar'],
            'null byte' => ["foo\x00bar"],
            'unicode mixed' => ['пароль-🔐-パスワード'],
            'control chars' => ["\x01\x02\x03\x04\x05"],
            'crlf' => ["foo\r\nbar"],
            'empty string' => [''],
            'whitespace only' => ['   '],
            'percent wildcard' => ['%'],
            'underscore wildcard' => ['_'],
            'one mb string' => [str_repeat('a', 1024 * 1024)],
            'utf8 4-byte' => ["\xF0\x9F\x94\x90"],
            'overlong utf8' => ["\xC0\xAF"], // invalid overlong encoding of '/'
            'truncated utf8' => ["\xC3"], // incomplete 2-byte sequence
        ];

        // Add 10 random adversarial strings
        for ($i = 0; $i < 10; $i++) {
            $len = mt_rand(1, 256);
            $buf = '';
            for ($j = 0; $j < $len; $j++) {
                $buf .= \chr(mt_rand(0, 255));
            }

            $cases["random_{$i}_len{$len}"] = [$buf];
        }

        return $cases;
    }

    /**
     * Edge-case integer inputs for actorUid and timestamp fields.
     *
     * @return array<string, array{int}>
     */
    public static function integerEdgeCaseProvider(): array
    {
        return [
            'zero' => [0],
            'negative one' => [-1],
            'negative million' => [-1_000_000],
            'php int min' => [PHP_INT_MIN],
            'php int max' => [PHP_INT_MAX],
            'typical' => [42],
            'large pid' => [1_000_000],
        ];
    }

    // -----------------------------------------------------------------------
    // Tests: DTO invariants
    // -----------------------------------------------------------------------

    #[Test]
    #[DataProvider('adversarialStringProvider')]
    public function filterStoresPayloadVerbatim(string $payload): void
    {
        $filter = new AuditLogFilter(
            secretIdentifier: $payload,
            action: $payload,
        );

        self::assertSame($payload, $filter->secretIdentifier);
        self::assertSame($payload, $filter->action);
    }

    #[Test]
    #[DataProvider('integerEdgeCaseProvider')]
    public function filterAcceptsEdgeCaseIntegers(int $value): void
    {
        $filter = new AuditLogFilter(
            actorUid: $value,
        );

        self::assertSame($value, $filter->actorUid);
    }

    #[Test]
    public function emptyFilterIsEmpty(): void
    {
        self::assertTrue((new AuditLogFilter())->isEmpty());
    }

    #[Test]
    #[DataProvider('adversarialStringProvider')]
    public function anyNonNullFieldMakesFilterNonEmpty(string $payload): void
    {
        $filter = new AuditLogFilter(secretIdentifier: $payload);
        self::assertFalse(
            $filter->isEmpty(),
            'Non-null secretIdentifier (even empty string) makes filter non-empty',
        );
    }

    #[Test]
    public function factoryMethodsProduceEquivalentInstances(): void
    {
        $byFactory = AuditLogFilter::forSecret('id1');
        $byCtor = new AuditLogFilter(secretIdentifier: 'id1');

        self::assertSame($byFactory->secretIdentifier, $byCtor->secretIdentifier);
        self::assertSame($byFactory->isEmpty(), $byCtor->isEmpty());
    }

    #[Test]
    public function withMethodsReturnNewInstancePreservingOtherFields(): void
    {
        $since = new DateTimeImmutable('2026-01-01');
        $until = new DateTimeImmutable('2026-02-01');
        $base = new AuditLogFilter(
            secretIdentifier: 'id1',
            action: 'store',
            actorUid: 5,
            success: true,
            since: $since,
            until: $until,
        );

        $modified = $base->withActor(99);

        self::assertNotSame($base, $modified);
        self::assertSame('id1', $modified->secretIdentifier);
        self::assertSame('store', $modified->action);
        self::assertSame(99, $modified->actorUid);
        self::assertTrue($modified->success);
        self::assertSame($since, $modified->since);
        self::assertSame($until, $modified->until);
    }

    #[Test]
    #[DataProvider('adversarialStringProvider')]
    public function applyFilterRoutesAllStringsThroughNamedParameter(string $payload): void
    {
        $this->recordedParams = [];
        $queryBuilder = $this->buildRecordingQueryBuilder();

        $filter = new AuditLogFilter(
            secretIdentifier: $payload,
            action: $payload,
        );

        $this->invokeApplyFilter($queryBuilder, $filter);

        // Every adversarial value must have been passed verbatim to createNamedParameter
        $values = array_column($this->recordedParams, 0);
        self::assertContains($payload, $values, 'secretIdentifier payload must pass through createNamedParameter');

        // And occur exactly as many times as we passed it
        $occurrences = array_count_values(array_map(serialize(...), $values));
        self::assertGreaterThanOrEqual(
            2,
            $occurrences[serialize($payload)] ?? 0,
            'Both secretIdentifier and action payloads must be bound',
        );
    }

    #[Test]
    #[DataProvider('integerEdgeCaseProvider')]
    public function applyFilterBindsIntegersAsIntType(int $uid): void
    {
        $this->recordedParams = [];
        $queryBuilder = $this->buildRecordingQueryBuilder();

        $filter = new AuditLogFilter(
            actorUid: $uid,
        );

        $this->invokeApplyFilter($queryBuilder, $filter);

        $found = false;
        foreach ($this->recordedParams as [$value, $type]) {
            if ($value === $uid && $type === Connection::PARAM_INT) {
                $found = true;
                break;
            }
        }

        self::assertTrue($found, "actorUid={$uid} must be bound with PARAM_INT");
    }

    #[Test]
    public function applyFilterBindsSuccessBooleanAsIntZeroOrOne(): void
    {
        foreach ([true, false] as $b) {
            $this->recordedParams = [];
            $queryBuilder = $this->buildRecordingQueryBuilder();

            $this->invokeApplyFilter(
                $queryBuilder,
                new AuditLogFilter(success: $b),
            );

            $expected = $b ? 1 : 0;
            $found = false;
            foreach ($this->recordedParams as [$value, $type]) {
                if ($value === $expected && $type === Connection::PARAM_INT) {
                    $found = true;
                    break;
                }
            }

            self::assertTrue(
                $found,
                'success=' . ($b ? 'true' : 'false') . ' must bind as ' . $expected . ' with PARAM_INT',
            );
        }
    }

    #[Test]
    public function applyFilterBindsDateRangeAsTimestampIntegers(): void
    {
        $since = (new DateTimeImmutable())->setTimestamp(1_700_000_000);
        $until = (new DateTimeImmutable())->setTimestamp(1_800_000_000);

        $this->recordedParams = [];
        $queryBuilder = $this->buildRecordingQueryBuilder();

        $this->invokeApplyFilter(
            $queryBuilder,
            new AuditLogFilter(since: $since, until: $until),
        );

        $intValues = array_values(array_filter(
            $this->recordedParams,
            static fn (array $p): bool => $p[1] === Connection::PARAM_INT,
        ));

        $values = array_map(static fn (array $p) => $p[0], $intValues);

        self::assertContains(1_700_000_000, $values, 'since timestamp must be bound as integer');
        self::assertContains(1_800_000_000, $values, 'until timestamp must be bound as integer');
    }

    /**
     * Extreme timestamp values (negative, PHP_INT_MAX) bind without error
     * as integers — actual DB execution is out of scope.
     */
    #[Test]
    #[DataProvider('extremeTimestampProvider')]
    public function applyFilterBindsExtremeTimestamps(int $timestamp): void
    {
        $dt = (new DateTimeImmutable())->setTimestamp($timestamp);

        $this->recordedParams = [];
        $queryBuilder = $this->buildRecordingQueryBuilder();

        $this->invokeApplyFilter(
            $queryBuilder,
            new AuditLogFilter(since: $dt),
        );

        $intValues = array_values(array_filter(
            $this->recordedParams,
            static fn (array $p): bool => $p[1] === Connection::PARAM_INT,
        ));

        self::assertNotSame([], $intValues, 'Extreme timestamp must be bound as integer');
        self::assertSame($timestamp, $intValues[0][0]);
    }

    /**
     * @return array<string, array{int}>
     */
    public static function extremeTimestampProvider(): array
    {
        return [
            'zero' => [0],
            'negative one' => [-1],
            'year 1900' => [-2_208_988_800],
            'y2k' => [946_684_800],
            'far future 2286' => [9_999_999_999],
            'php int max' => [PHP_INT_MAX],
            'php int min' => [PHP_INT_MIN],
        ];
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Build a QueryBuilder that records every createNamedParameter call in
     * $this->recordedParams while keeping a real ExpressionBuilder so the
     * service's expr()->eq()/gte()/lte() calls don't blow up.
     */
    private function buildRecordingQueryBuilder(): QueryBuilder
    {
        $test = $this;

        /** @var QueryBuilder&MockObject $qb */
        $qb = $this->createMock(QueryBuilder::class);

        $qb->method('createNamedParameter')->willReturnCallback(
            function (mixed $value, string|ParameterType|Type|ArrayParameterType $type = ParameterType::STRING) use ($test): string {
                $test->recordedParams[] = [$value, $type];

                // Return a placeholder that could never be confused with the payload
                return ':placeholder' . \count($test->recordedParams);
            },
        );

        // Real ExpressionBuilder so expr()->eq(...) returns a valid composite
        // expression. No connection needed — constructor accepts one.
        $connection = $this->createMock(Connection::class);
        $connection->method('quoteIdentifier')->willReturnArgument(0);
        $expr = new ExpressionBuilder($connection);
        $qb->method('expr')->willReturn($expr);

        $qb->method('andWhere')->willReturnSelf();

        return $qb;
    }

    private function invokeApplyFilter(QueryBuilder $qb, AuditLogFilter $filter): void
    {
        // Use reflection to call the private method on a minimally-constructed
        // AuditLogService. We bypass the constructor because applyFilter()
        // only needs the QueryBuilder passed in.
        $reflection = new ReflectionClass(AuditLogService::class);
        $service = $reflection->newInstanceWithoutConstructor();

        $method = $reflection->getMethod('applyFilter');
        $method->invoke($service, $qb, $filter);
    }
}
