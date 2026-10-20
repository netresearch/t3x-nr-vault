<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Domain\Dto;

use Netresearch\NrVault\Domain\Dto\OrphanSecretInfo;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(OrphanSecretInfo::class)]
final class OrphanSecretInfoTest extends TestCase
{
    #[Test]
    public function constructorSetsAllProperties(): void
    {
        $metadata  = ['env' => 'production', 'owner' => 'team-a'];
        $createdAt = 1700000000;

        $subject = new OrphanSecretInfo(
            identifier: 'my-secret',
            metadata: $metadata,
            createdAt: $createdAt,
        );

        self::assertSame('my-secret', $subject->identifier);
        self::assertSame($metadata, $subject->metadata);
        self::assertSame($createdAt, $subject->createdAt);
    }

    #[Test]
    public function fromArrayCreatesObjectWithAllFields(): void
    {
        $subject = OrphanSecretInfo::fromArray([
            'identifier' => 'api-key',
            'metadata'   => ['service' => 'stripe'],
            'created_at' => 1700000000,
        ]);

        self::assertSame('api-key', $subject->identifier);
        self::assertSame(['service' => 'stripe'], $subject->metadata);
        self::assertSame(1700000000, $subject->createdAt);
    }

    #[Test]
    public function fromArrayUsesEmptyArrayForMissingMetadata(): void
    {
        $subject = OrphanSecretInfo::fromArray([
            'identifier' => 'minimal',
        ]);

        self::assertSame([], $subject->metadata);
    }

    #[Test]
    public function fromArrayUsesZeroForMissingCreatedAt(): void
    {
        $subject = OrphanSecretInfo::fromArray([
            'identifier' => 'minimal',
        ]);

        self::assertSame(0, $subject->createdAt);
    }

    #[Test]
    public function getAgeInSecondsReturnsPositiveValueForPastTimestamp(): void
    {
        $pastTimestamp = time() - 3600; // 1 hour ago
        $subject       = new OrphanSecretInfo('id', [], $pastTimestamp);

        $age = $subject->getAgeInSeconds();

        // Allow a small tolerance for test execution time
        self::assertGreaterThanOrEqual(3599, $age);
        self::assertLessThanOrEqual(3601, $age);
    }

    #[Test]
    public function getAgeInSecondsReturnsApproximatelyZeroForCurrentTimestamp(): void
    {
        $subject = new OrphanSecretInfo('id', [], time());

        self::assertLessThan(5, $subject->getAgeInSeconds());
    }

    #[Test]
    public function getAgeInDaysReturnsCorrectNumberOfDays(): void
    {
        $daysAgo       = 10;
        $pastTimestamp = time() - ($daysAgo * 86400);
        $subject       = new OrphanSecretInfo('id', [], $pastTimestamp);

        // Allow 1 day tolerance for boundary conditions
        self::assertGreaterThanOrEqual($daysAgo - 1, $subject->getAgeInDays());
        self::assertLessThanOrEqual($daysAgo + 1, $subject->getAgeInDays());
    }

    #[Test]
    public function getAgeInDaysReturnsZeroForCurrentTimestamp(): void
    {
        $subject = new OrphanSecretInfo('id', [], time());

        self::assertSame(0, $subject->getAgeInDays());
    }

    #[Test]
    #[DataProvider('isOlderThanDaysProvider')]
    public function isOlderThanDaysReturnsCorrectResult(
        int $ageInDays,
        int $threshold,
        bool $expected,
    ): void {
        $pastTimestamp = time() - ($ageInDays * 86400);
        $subject       = new OrphanSecretInfo('id', [], $pastTimestamp);

        self::assertSame($expected, $subject->isOlderThanDays($threshold));
    }

    public static function isOlderThanDaysProvider(): iterable
    {
        yield '30 days old, threshold 30 => true (equal)' => [30, 30, true];
        yield '31 days old, threshold 30 => true' => [31, 30, true];
        yield '29 days old, threshold 30 => false' => [29, 30, false];
        yield '0 days old, threshold 1 => false' => [0, 1, false];
    }

    #[Test]
    public function getMetadataValueReturnsValueForExistingKey(): void
    {
        $subject = new OrphanSecretInfo('id', ['service' => 'stripe', 'env' => 'prod'], 0);

        self::assertSame('stripe', $subject->getMetadataValue('service'));
        self::assertSame('prod', $subject->getMetadataValue('env'));
    }

    #[Test]
    public function getMetadataValueReturnsNullForMissingKeyByDefault(): void
    {
        $subject = new OrphanSecretInfo('id', [], 0);

        self::assertNull($subject->getMetadataValue('nonexistent'));
    }

    #[Test]
    public function getMetadataValueReturnsProvidedDefaultForMissingKey(): void
    {
        $subject = new OrphanSecretInfo('id', [], 0);

        self::assertSame('fallback', $subject->getMetadataValue('missing', 'fallback'));
        self::assertSame(42, $subject->getMetadataValue('missing', 42));
    }

    #[Test]
    public function getMetadataValueReturnsDefaultWhenStoredValueIsNull(): void
    {
        $subject = new OrphanSecretInfo('id', ['key' => null], 0);

        // When the key exists but is null, ?? returns the default
        // This is standard PHP null-coalescing behavior
        self::assertSame('default', $subject->getMetadataValue('key', 'default'));
    }

    #[Test]
    public function toArrayReturnsCorrectStructure(): void
    {
        $metadata = ['service' => 'aws'];
        $subject  = new OrphanSecretInfo('orphan-key', $metadata, 1700000000);

        self::assertSame([
            'identifier' => 'orphan-key',
            'metadata'   => $metadata,
            'created_at' => 1700000000,
        ], $subject->toArray());
    }

    #[Test]
    public function fromArrayRoundTripToArray(): void
    {
        $original = [
            'identifier' => 'test-secret',
            'metadata'   => ['region' => 'eu-west-1'],
            'created_at' => 1700000000,
        ];

        $subject = OrphanSecretInfo::fromArray($original);

        self::assertSame($original, $subject->toArray());
    }
}
