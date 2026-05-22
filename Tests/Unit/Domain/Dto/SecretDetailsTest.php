<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Domain\Dto;

use Netresearch\NrVault\Domain\Dto\SecretDetails;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(SecretDetails::class)]
final class SecretDetailsTest extends TestCase
{
    #[Test]
    public function constructorSetsAllProperties(): void
    {
        $subject = $this->buildSubject([
            'uid' => 42,
            'identifier' => 'api-key',
            'description' => 'Payment API key',
            'ownerUid' => 10,
            'groups' => [3, 4, 5],
            'context' => 'payment',
            'frontendAccessible' => true,
            'version' => 3,
            'createdAt' => 1700000000,
            'updatedAt' => 1700100000,
            'expiresAt' => 1800000000,
            'lastRotatedAt' => 1700050000,
            'readCount' => 17,
            'lastReadAt' => 1700090000,
            'metadata' => ['env' => 'production'],
            'scopePid' => 7,
        ]);

        self::assertSame(42, $subject->uid);
        self::assertSame('api-key', $subject->identifier);
        self::assertSame('Payment API key', $subject->description);
        self::assertSame(10, $subject->ownerUid);
        self::assertSame([3, 4, 5], $subject->groups);
        self::assertSame('payment', $subject->context);
        self::assertTrue($subject->frontendAccessible);
        self::assertSame(3, $subject->version);
        self::assertSame(1700000000, $subject->createdAt);
        self::assertSame(1700100000, $subject->updatedAt);
        self::assertSame(1800000000, $subject->expiresAt);
        self::assertSame(1700050000, $subject->lastRotatedAt);
        self::assertSame(17, $subject->readCount);
        self::assertSame(1700090000, $subject->lastReadAt);
        self::assertSame(['env' => 'production'], $subject->metadata);
        self::assertSame(7, $subject->scopePid);
    }

    #[Test]
    public function isExpiredReturnsFalseWhenNoExpiresAt(): void
    {
        $subject = $this->buildSubject(['expiresAt' => null]);

        self::assertFalse($subject->isExpired());
    }

    #[Test]
    public function isExpiredReturnsFalseWhenExpiresAtIsInFuture(): void
    {
        $subject = $this->buildSubject(['expiresAt' => time() + 86400]);

        self::assertFalse($subject->isExpired());
    }

    #[Test]
    public function isExpiredReturnsTrueWhenExpiresAtIsInPast(): void
    {
        $subject = $this->buildSubject(['expiresAt' => time() - 1]);

        self::assertTrue($subject->isExpired());
    }

    #[Test]
    public function expiresSoonReturnsFalseWhenNoExpiresAt(): void
    {
        $subject = $this->buildSubject(['expiresAt' => null]);

        self::assertFalse($subject->expiresSoon(7));
    }

    #[Test]
    public function expiresSoonReturnsTrueWhenExpiresWithinGivenDays(): void
    {
        // Expires in 3 days, checking threshold of 7 days
        $subject = $this->buildSubject(['expiresAt' => time() + (3 * 86400)]);

        self::assertTrue($subject->expiresSoon(7));
    }

    #[Test]
    public function expiresSoonReturnsFalseWhenExpiresAfterThreshold(): void
    {
        // Expires in 30 days, checking threshold of 7 days
        $subject = $this->buildSubject(['expiresAt' => time() + (30 * 86400)]);

        self::assertFalse($subject->expiresSoon(7));
    }

    #[Test]
    public function expiresSoonReturnsFalseWhenAlreadyExpired(): void
    {
        // Already expired - expiresSoon should return false because isExpired() is true
        $subject = $this->buildSubject(['expiresAt' => time() - 3600]);

        self::assertFalse($subject->expiresSoon(7));
    }

    #[Test]
    public function toArrayContainsAllExpectedKeys(): void
    {
        $subject = $this->buildSubject();
        $array = $subject->toArray();

        $expectedKeys = [
            'uid', 'identifier', 'description', 'owner', 'owner_uid',
            'groups', 'context', 'frontend_accessible', 'version',
            'createdAt', 'updatedAt', 'expiresAt', 'expires_at',
            'lastRotatedAt', 'read_count', 'last_read_at', 'metadata', 'scopePid',
        ];

        foreach ($expectedKeys as $key) {
            self::assertArrayHasKey($key, $array, "Key '{$key}' missing from toArray() output");
        }
    }

    #[Test]
    public function toArrayMapsOwnerUidToBothOwnerAndOwnerUid(): void
    {
        $subject = $this->buildSubject(['ownerUid' => 99]);
        $array = $subject->toArray();

        self::assertSame(99, $array['owner']);
        self::assertSame(99, $array['owner_uid']);
    }

    #[Test]
    public function toArrayMapsExpiresAtToBothCamelAndSnakeCase(): void
    {
        $expiresAt = 1900000000;
        $subject = $this->buildSubject(['expiresAt' => $expiresAt]);
        $array = $subject->toArray();

        self::assertSame($expiresAt, $array['expiresAt']);
        self::assertSame($expiresAt, $array['expires_at']);
    }

    #[Test]
    public function toArrayPreservesNullValues(): void
    {
        $subject = $this->buildSubject([
            'expiresAt' => null,
            'lastRotatedAt' => null,
            'lastReadAt' => null,
        ]);
        $array = $subject->toArray();

        self::assertNull($array['expiresAt']);
        self::assertNull($array['expires_at']);
        self::assertNull($array['lastRotatedAt']);
        self::assertNull($array['last_read_at']);
    }

    #[Test]
    public function toArrayReturnsCorrectValues(): void
    {
        $subject = $this->buildSubject([
            'uid' => 10,
            'identifier' => 'stripe-key',
            'description' => 'Stripe API',
            'ownerUid' => 3,
            'groups' => [1],
            'context' => 'payment',
            'frontendAccessible' => true,
            'version' => 2,
            'createdAt' => 1700000000,
            'updatedAt' => 1700100000,
            'expiresAt' => 1800000000,
            'lastRotatedAt' => 1750000000,
            'readCount' => 5,
            'lastReadAt' => 1700090000,
            'metadata' => ['key' => 'val'],
            'scopePid' => 1,
        ]);

        $array = $subject->toArray();

        self::assertSame(10, $array['uid']);
        self::assertSame('stripe-key', $array['identifier']);
        self::assertSame('Stripe API', $array['description']);
        self::assertSame(3, $array['owner']);
        self::assertSame(3, $array['owner_uid']);
        self::assertSame([1], $array['groups']);
        self::assertSame('payment', $array['context']);
        self::assertTrue($array['frontend_accessible']);
        self::assertSame(2, $array['version']);
        self::assertSame(1700000000, $array['createdAt']);
        self::assertSame(1700100000, $array['updatedAt']);
        self::assertSame(1800000000, $array['expiresAt']);
        self::assertSame(1800000000, $array['expires_at']);
        self::assertSame(1750000000, $array['lastRotatedAt']);
        self::assertSame(5, $array['read_count']);
        self::assertSame(1700090000, $array['last_read_at']);
        self::assertSame(['key' => 'val'], $array['metadata']);
        self::assertSame(1, $array['scopePid']);
    }

    #[Test]
    public function fromSecretMapsAllFieldsFromSecretModel(): void
    {
        $secret = new Secret(
            identifier: 'from-secret-identifier',
            uid: 7,
            scopePid: 11,
            description: 'From secret description',
            ownerUid: 3,
            allowedGroups: [10, 20],
            context: 'backend',
            frontendAccessible: true,
            version: 5,
            expiresAt: 1900000000,
            lastRotatedAt: 1750000000,
            metadata: ['env' => 'prod'],
            tstamp: 1700000002,
            crdate: 1700000001,
            readCount: 42,
            lastReadAt: 1800000000,
        );

        $result = SecretDetails::fromSecret($secret);

        self::assertSame(7, $result->uid);
        self::assertSame('from-secret-identifier', $result->identifier);
        self::assertSame('From secret description', $result->description);
        self::assertSame(3, $result->ownerUid);
        self::assertSame([10, 20], $result->groups);
        self::assertSame('backend', $result->context);
        self::assertTrue($result->frontendAccessible);
        self::assertSame(5, $result->version);
        self::assertSame(1700000001, $result->createdAt);
        self::assertSame(1700000002, $result->updatedAt);
        self::assertSame(1900000000, $result->expiresAt);
        self::assertSame(1750000000, $result->lastRotatedAt);
        self::assertSame(42, $result->readCount);
        self::assertSame(1800000000, $result->lastReadAt);
        self::assertSame(['env' => 'prod'], $result->metadata);
        self::assertSame(11, $result->scopePid);
    }

    #[Test]
    public function fromSecretConvertsZeroTimestampsToNull(): void
    {
        // expiresAt, lastRotatedAt, lastReadAt of 0 should become null in the DTO
        $secret = new Secret(
            identifier: 'zero-timestamps',
            uid: 1,
            expiresAt: 0,
            lastRotatedAt: 0,
            lastReadAt: 0,
        );

        $result = SecretDetails::fromSecret($secret);

        self::assertNull($result->expiresAt);
        self::assertNull($result->lastRotatedAt);
        self::assertNull($result->lastReadAt);
    }

    #[Test]
    public function fromSecretWithNullUidDefaultsToZero(): void
    {
        // Secret with no UID set (getUid() returns null) should default to 0
        $secret = new Secret(identifier: 'null-uid');
        // uid not passed — defaults to null

        $result = SecretDetails::fromSecret($secret);

        self::assertSame(0, $result->uid);
    }

    private function buildSubject(array $overrides = []): SecretDetails
    {
        $defaults = [
            'uid' => 1,
            'identifier' => 'test-secret',
            'description' => 'A test secret',
            'ownerUid' => 5,
            'groups' => [1, 2],
            'context' => 'default',
            'frontendAccessible' => false,
            'version' => 1,
            'createdAt' => 1700000000,
            'updatedAt' => 1700086400,
            'expiresAt' => null,
            'lastRotatedAt' => null,
            'readCount' => 0,
            'lastReadAt' => null,
            'metadata' => [],
            'scopePid' => 0,
        ];

        $params = array_merge($defaults, $overrides);

        return new SecretDetails(
            uid: $params['uid'],
            identifier: $params['identifier'],
            description: $params['description'],
            ownerUid: $params['ownerUid'],
            groups: $params['groups'],
            context: $params['context'],
            frontendAccessible: $params['frontendAccessible'],
            version: $params['version'],
            createdAt: $params['createdAt'],
            updatedAt: $params['updatedAt'],
            expiresAt: $params['expiresAt'],
            lastRotatedAt: $params['lastRotatedAt'],
            readCount: $params['readCount'],
            lastReadAt: $params['lastReadAt'],
            metadata: $params['metadata'],
            scopePid: $params['scopePid'],
        );
    }
}
