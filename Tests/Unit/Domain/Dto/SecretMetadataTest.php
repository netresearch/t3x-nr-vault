<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Domain\Dto;

use Netresearch\NrVault\Domain\Dto\SecretMetadata;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(SecretMetadata::class)]
final class SecretMetadataTest extends TestCase
{
    private const TEST_SECRET_DESCRIPTION = 'Test secret';

    #[Test]
    public function constructorSetsAllProperties(): void
    {
        $metadata = new SecretMetadata(
            identifier: 'api-key',
            ownerUid: 5,
            createdAt: 1704067200,
            updatedAt: 1704153600,
            readCount: 10,
            lastReadAt: 1704150000,
            description: 'Payment API key',
            version: 3,
            metadata: ['service' => 'stripe'],
        );

        self::assertEquals('api-key', $metadata->identifier);
        self::assertEquals(5, $metadata->ownerUid);
        self::assertEquals(1704067200, $metadata->createdAt);
        self::assertEquals(1704153600, $metadata->updatedAt);
        self::assertEquals(10, $metadata->readCount);
        self::assertEquals(1704150000, $metadata->lastReadAt);
        self::assertEquals('Payment API key', $metadata->description);
        self::assertEquals(3, $metadata->version);
        self::assertEquals(['service' => 'stripe'], $metadata->metadata);
    }

    #[Test]
    public function metadataDefaultsToEmptyArray(): void
    {
        $metadata = new SecretMetadata(
            identifier: 'test',
            ownerUid: 1,
            createdAt: 0,
            updatedAt: 0,
            readCount: 0,
            lastReadAt: null,
            description: '',
            version: 1,
        );

        self::assertEquals([], $metadata->metadata);
    }

    #[Test]
    public function fromArrayCreatesMetadataWithAllFields(): void
    {
        $row = [
            'identifier' => 'api-key',
            'owner_uid' => 5,
            'crdate' => 1704067200,
            'tstamp' => 1704153600,
            'read_count' => 10,
            'last_read_at' => 1704150000,
            'description' => self::TEST_SECRET_DESCRIPTION,
            'version' => 2,
            'metadata' => ['key' => 'value'],
        ];

        $metadata = SecretMetadata::fromArray($row);

        self::assertEquals('api-key', $metadata->identifier);
        self::assertEquals(5, $metadata->ownerUid);
        self::assertEquals(1704067200, $metadata->createdAt);
        self::assertEquals(1704153600, $metadata->updatedAt);
        self::assertEquals(10, $metadata->readCount);
        self::assertEquals(1704150000, $metadata->lastReadAt);
        self::assertEquals(self::TEST_SECRET_DESCRIPTION, $metadata->description);
        self::assertEquals(2, $metadata->version);
        self::assertEquals(['key' => 'value'], $metadata->metadata);
    }

    #[Test]
    public function fromArrayUsesDefaultsForMissingFields(): void
    {
        $row = ['identifier' => 'minimal'];

        $metadata = SecretMetadata::fromArray($row);

        self::assertEquals('minimal', $metadata->identifier);
        self::assertEquals(0, $metadata->ownerUid);
        self::assertEquals(0, $metadata->createdAt);
        self::assertEquals(0, $metadata->updatedAt);
        self::assertEquals(0, $metadata->readCount);
        self::assertNull($metadata->lastReadAt);
        self::assertEquals('', $metadata->description);
        self::assertEquals(1, $metadata->version);
        self::assertEquals([], $metadata->metadata);
    }

    #[Test]
    public function toArrayReturnsCorrectStructure(): void
    {
        $metadata = new SecretMetadata(
            identifier: 'api-key',
            ownerUid: 5,
            createdAt: 1704067200,
            updatedAt: 1704153600,
            readCount: 10,
            lastReadAt: 1704150000,
            description: self::TEST_SECRET_DESCRIPTION,
            version: 2,
            metadata: ['key' => 'value'],
        );

        $array = $metadata->toArray();

        self::assertEquals([
            'identifier' => 'api-key',
            'owner_uid' => 5,
            'crdate' => 1704067200,
            'tstamp' => 1704153600,
            'read_count' => 10,
            'last_read_at' => 1704150000,
            'description' => self::TEST_SECRET_DESCRIPTION,
            'version' => 2,
            'metadata' => ['key' => 'value'],
            'enabled' => true,
        ], $array);
    }

    /**
     * The listing needs to tell an available secret from one that has been
     * taken out of service, so the flag has to survive the DTO. The row speaks
     * the TCA column's negative form (`hidden`), the DTO the positive one.
     */
    #[Test]
    public function aDisabledRowBecomesADisabledDto(): void
    {
        $metadata = SecretMetadata::fromArray([
            'identifier' => 'retired-key',
            'hidden' => 1,
        ]);

        self::assertFalse($metadata->enabled);
        self::assertFalse($metadata->toArray()['enabled']);
    }

    /**
     * The counterpart, so the mapping is shown to distinguish rather than
     * always report the same answer — and so a row that carries no `hidden`
     * key at all still reads as available.
     */
    #[Test]
    public function aRowWithoutTheHiddenFlagIsEnabled(): void
    {
        self::assertTrue(SecretMetadata::fromArray(['identifier' => 'live-key'])->enabled);
        self::assertTrue(SecretMetadata::fromArray(['identifier' => 'live-key', 'hidden' => 0])->enabled);
    }

    /**
     * The docblock promises a database row, and `last_read_at` is
     * NOT NULL DEFAULT 0 there -- so 0, not null, is what a secret nobody has
     * read carries. Every consumer of $lastReadAt guards with `!== null`, so a
     * 0 arriving here renders as 1970-01-01 on a screen about stale
     * credentials. Same defect as #313, one construction site further in.
     */
    #[Test]
    public function fromArrayReportsANeverReadSecretAsNullRatherThanTheEpoch(): void
    {
        $never = SecretMetadata::fromArray(['identifier' => 'never-read', 'last_read_at' => 0]);
        $read = SecretMetadata::fromArray(['identifier' => 'has-been-read', 'last_read_at' => 1_700_000_000]);
        $absent = SecretMetadata::fromArray(['identifier' => 'column-absent']);

        self::assertNull($never->lastReadAt, 'a 0 from the database means never read');
        self::assertSame(1_700_000_000, $read->lastReadAt, 'a real timestamp survives untouched');
        self::assertNull($absent->lastReadAt, 'a missing column still means never read');
    }

    #[Test]
    public function roundTripFromArrayToArray(): void
    {
        $original = [
            'identifier' => 'roundtrip-test',
            'owner_uid' => 42,
            'crdate' => 1704067200,
            'tstamp' => 1704153600,
            'read_count' => 5,
            'last_read_at' => null,
            'description' => 'Test',
            'version' => 1,
            'metadata' => [],
            'enabled' => true,
        ];

        // `fromArray()` reads the row's `hidden` column, `toArray()` emits the
        // DTO's `enabled` property, so the round trip is over the DTO's own
        // shape with the row's negative form supplied alongside.
        $metadata = SecretMetadata::fromArray([
            'identifier' => 'roundtrip-test',
            'owner_uid' => 42,
            'crdate' => 1704067200,
            'tstamp' => 1704153600,
            'read_count' => 5,
            'last_read_at' => null,
            'description' => 'Test',
            'version' => 1,
            'metadata' => [],
            'hidden' => 0,
        ]);
        $result = $metadata->toArray();

        self::assertEquals($original, $result);
    }
}
