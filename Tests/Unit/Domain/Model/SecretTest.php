<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Domain\Model;

use InvalidArgumentException;
use Netresearch\NrVault\Crypto\EncryptedData;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * Unit tests for the immutable Secret entity.
 *
 * The entity uses readonly constructor promotion, so plain
 * "set X, get X" tests are tautological and have been dropped — the
 * constructor / from-row hydration tests below subsume them. What's
 * exercised here is real behaviour:
 *
 *   - default values applied by the ctor (and `fromDatabaseRow`),
 *   - integer / boolean / string casting in `fromDatabaseRow`,
 *   - serialisation round-trip via `toDatabaseRow`,
 *   - the crypto-field tri-state invariant (all set or all empty),
 *   - the four `with*()` lifecycle transitions,
 *   - `isExpired()` boundary conditions.
 *
 * The `incrementVersion` / `incrementReadCount` behaviours moved off
 * the entity (`SecretRepository::incrementReadCount`, value rotation
 * folds version++ into `withValueRotation`); their tests live there now.
 */
#[CoversClass(Secret::class)]
final class SecretTest extends TestCase
{
    private const PAYMENT_GATEWAY_DESCRIPTION = 'Payment gateway API key';

    // ---------------------------------------------------------------
    // Constructor defaults.
    // ---------------------------------------------------------------

    #[Test]
    public function constructorAppliesDocumentedDefaults(): void
    {
        $secret = new Secret(identifier: 't');

        self::assertNull($secret->getUid());
        self::assertSame(0, $secret->getScopePid());
        self::assertSame('t', $secret->getIdentifier());
        self::assertSame('', $secret->getDescription());
        self::assertNull($secret->getEncryptedValue());
        self::assertSame('', $secret->getEncryptedDek());
        self::assertSame('', $secret->getDekNonce());
        self::assertSame('', $secret->getValueNonce());
        self::assertSame(1, $secret->getEncryptionVersion());
        self::assertSame('', $secret->getValueChecksum());
        self::assertSame(0, $secret->getOwnerUid());
        self::assertSame([], $secret->getAllowedGroups());
        self::assertSame('', $secret->getContext());
        self::assertFalse($secret->isFrontendAccessible());
        self::assertSame(1, $secret->getVersion());
        self::assertSame(0, $secret->getExpiresAt());
        self::assertSame(0, $secret->getLastRotatedAt());
        self::assertSame([], $secret->getMetadata());
        self::assertSame('local', $secret->getAdapter());
        self::assertSame('', $secret->getExternalReference());
        self::assertSame(0, $secret->getTstamp());
        self::assertSame(0, $secret->getCrdate());
        self::assertSame(0, $secret->getCruserId());
        self::assertFalse($secret->isDeleted());
        self::assertFalse($secret->isHidden());
        self::assertSame(0, $secret->getReadCount());
        self::assertSame(0, $secret->getLastReadAt());
    }

    #[Test]
    public function constructorAcceptsAllArguments(): void
    {
        $secret = new Secret(
            identifier: 'my-api-key',
            uid: 99,
            scopePid: 10,
            description: 'Stripe key',
            encryptedValue: 'enc_value',
            encryptedDek: 'enc_dek',
            dekNonce: 'dek_nonce',
            valueNonce: 'value_nonce',
            encryptionVersion: 2,
            valueChecksum: 'checksum123',
            ownerUid: 5,
            allowedGroups: [1, 2, 3],
            context: 'payment',
            frontendAccessible: true,
            version: 7,
            expiresAt: 1735689600,
            lastRotatedAt: 1704067200,
            metadata: ['service' => 'stripe'],
            adapter: 'local',
            externalReference: 'vault:foo',
            tstamp: 1704067210,
            crdate: 1704067200,
            cruserId: 11,
            deleted: false,
            hidden: true,
            readCount: 50,
            lastReadAt: 1704153600,
        );

        self::assertSame('my-api-key', $secret->getIdentifier());
        self::assertSame(99, $secret->getUid());
        self::assertSame(10, $secret->getScopePid());
        self::assertSame('Stripe key', $secret->getDescription());
        self::assertSame('enc_value', $secret->getEncryptedValue());
        self::assertSame('enc_dek', $secret->getEncryptedDek());
        self::assertSame('dek_nonce', $secret->getDekNonce());
        self::assertSame('value_nonce', $secret->getValueNonce());
        self::assertSame(2, $secret->getEncryptionVersion());
        self::assertSame('checksum123', $secret->getValueChecksum());
        self::assertSame(5, $secret->getOwnerUid());
        self::assertSame([1, 2, 3], $secret->getAllowedGroups());
        self::assertSame('payment', $secret->getContext());
        self::assertTrue($secret->isFrontendAccessible());
        self::assertSame(7, $secret->getVersion());
        self::assertSame(1735689600, $secret->getExpiresAt());
        self::assertSame(1704067200, $secret->getLastRotatedAt());
        self::assertSame(['service' => 'stripe'], $secret->getMetadata());
        self::assertSame('local', $secret->getAdapter());
        self::assertSame('vault:foo', $secret->getExternalReference());
        self::assertSame(1704067210, $secret->getTstamp());
        self::assertSame(1704067200, $secret->getCrdate());
        self::assertSame(11, $secret->getCruserId());
        self::assertFalse($secret->isDeleted());
        self::assertTrue($secret->isHidden());
        self::assertSame(50, $secret->getReadCount());
        self::assertSame(1704153600, $secret->getLastReadAt());
    }

    #[Test]
    public function constructorAllowsAllCryptoFieldsEmpty(): void
    {
        $secret = new Secret(
            identifier: 'external-ref',
            encryptedValue: 'enc_value',
            valueChecksum: 'checksum',
        );

        self::assertSame('', $secret->getEncryptedDek());
        self::assertSame('', $secret->getDekNonce());
        self::assertSame('', $secret->getValueNonce());
    }

    // ---------------------------------------------------------------
    // Crypto-field tri-state invariant: encryptedDek/dekNonce/valueNonce
    // must all be set or all be empty.
    // ---------------------------------------------------------------

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function partialCryptoFieldsProvider(): iterable
    {
        yield 'only encryptedDek set' => ['has_dek', '', ''];
        yield 'only dekNonce set' => ['', 'has_nonce', ''];
        yield 'only valueNonce set' => ['', '', 'has_vn'];
        yield 'encryptedDek + dekNonce, no valueNonce' => ['dek', 'dn', ''];
        yield 'encryptedDek + valueNonce, no dekNonce' => ['dek', '', 'vn'];
        yield 'dekNonce + valueNonce, no encryptedDek' => ['', 'dn', 'vn'];
    }

    #[Test]
    #[DataProvider('partialCryptoFieldsProvider')]
    public function constructorThrowsOnPartialCryptoFields(
        string $encryptedDek,
        string $dekNonce,
        string $valueNonce,
    ): void {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('encryptedDek, dekNonce, and valueNonce must all be set or all be empty');

        // The constructor MUST throw before returning; assertInstanceOf
        // is unreachable but uses the constructed value so Sonar's S1848
        // ("useless object instantiation") doesn't fire on the throw test.
        self::assertInstanceOf(Secret::class, new Secret(
            identifier: 'broken',
            encryptedValue: 'enc_value',
            encryptedDek: $encryptedDek,
            dekNonce: $dekNonce,
            valueNonce: $valueNonce,
            valueChecksum: 'checksum',
        ));
    }

    #[Test]
    public function constructorAcceptsAllThreeCryptoFieldsSet(): void
    {
        // No exception expected.
        $secret = new Secret(
            identifier: 'id',
            encryptedValue: 'v',
            encryptedDek: 'dek',
            dekNonce: 'dn',
            valueNonce: 'vn',
            valueChecksum: 'cs',
        );

        self::assertSame('dek', $secret->getEncryptedDek());
        self::assertSame('dn', $secret->getDekNonce());
        self::assertSame('vn', $secret->getValueNonce());
    }

    // ---------------------------------------------------------------
    // Lifecycle transitions — each returns a NEW instance.
    // ---------------------------------------------------------------

    #[Test]
    public function withUidReturnsNewInstanceWithAssignedUid(): void
    {
        $secret = new Secret(identifier: 't');

        $result = $secret->withUid(42);

        self::assertNotSame($secret, $result);
        self::assertNull($secret->getUid());
        self::assertSame(42, $result->getUid());
        // Other fields propagated.
        self::assertSame('t', $result->getIdentifier());
    }

    #[Test]
    public function withUidAcceptsNullToClearUid(): void
    {
        $secret = new Secret(identifier: 't', uid: 5);

        $result = $secret->withUid(null);

        self::assertSame(5, $secret->getUid());
        self::assertNull($result->getUid());
    }

    #[Test]
    public function withValueRotationBumpsVersionAndUpdatesAllRotationFields(): void
    {
        $secret = new Secret(
            identifier: 't',
            uid: 1,
            version: 3,
            lastRotatedAt: 1000,
            readCount: 9,
        );
        $encrypted = new EncryptedData(
            encryptedValue: 'new_value',
            encryptedDek: 'new_dek',
            dekNonce: 'new_dn',
            valueNonce: 'new_vn',
            valueChecksum: 'new_cs',
        );

        $rotated = $secret->withValueRotation($encrypted, rotatedAt: 2000);

        self::assertNotSame($secret, $rotated);
        // Original untouched.
        self::assertSame(3, $secret->getVersion());
        self::assertSame(1000, $secret->getLastRotatedAt());
        // New instance has rotated state.
        self::assertSame(4, $rotated->getVersion());
        self::assertSame(2000, $rotated->getLastRotatedAt());
        self::assertSame('new_value', $rotated->getEncryptedValue());
        self::assertSame('new_dek', $rotated->getEncryptedDek());
        self::assertSame('new_dn', $rotated->getDekNonce());
        self::assertSame('new_vn', $rotated->getValueNonce());
        self::assertSame('new_cs', $rotated->getValueChecksum());
        // Untouched fields propagate.
        self::assertSame(1, $rotated->getUid());
        self::assertSame(9, $rotated->getReadCount());
    }

    #[Test]
    public function withReEncryptedDekReplacesOnlyDekEnvelope(): void
    {
        $secret = new Secret(
            identifier: 't',
            uid: 1,
            encryptedValue: 'val',
            encryptedDek: 'old_dek',
            dekNonce: 'old_dn',
            valueNonce: 'vn',
            valueChecksum: 'cs',
            version: 5,
        );

        $rotated = $secret->withReEncryptedDek('new_dek', 'new_dn');

        self::assertNotSame($secret, $rotated);
        // Value envelope untouched.
        self::assertSame('val', $rotated->getEncryptedValue());
        self::assertSame('vn', $rotated->getValueNonce());
        self::assertSame('cs', $rotated->getValueChecksum());
        // Version NOT bumped (master-key rotation doesn't bump it).
        self::assertSame(5, $rotated->getVersion());
        // DEK envelope replaced.
        self::assertSame('new_dek', $rotated->getEncryptedDek());
        self::assertSame('new_dn', $rotated->getDekNonce());
    }

    #[Test]
    public function withMetadataReplacesMetadataArray(): void
    {
        $secret = new Secret(identifier: 't', metadata: ['a' => 1]);

        $merged = $secret->withMetadata(['b' => 2, 'c' => 3]);

        self::assertNotSame($secret, $merged);
        self::assertSame(['a' => 1], $secret->getMetadata());
        self::assertSame(['b' => 2, 'c' => 3], $merged->getMetadata());
    }

    // ---------------------------------------------------------------
    // isExpired() boundary conditions.
    // ---------------------------------------------------------------

    /**
     * Offsets relative to `time()` so the data provider survives a
     * clock tick between evaluation and assertion.
     *
     * @return iterable<string, array{string, bool}>
     */
    public static function isExpiredBoundaryProvider(): iterable
    {
        yield 'zero means no-expiration' => ['zero', false];
        yield 'far future' => ['far-future', false];
        yield '60 seconds in future' => ['+60', false];
        yield '60 seconds in past is expired' => ['-60', true];
        yield 'negative absolute means expiresAt > 0 check fails first' => ['negative', false];
    }

    #[Test]
    #[DataProvider('isExpiredBoundaryProvider')]
    public function isExpiredBoundaries(string $kind, bool $expected): void
    {
        $expiresAt = match ($kind) {
            'zero' => 0,
            'far-future' => PHP_INT_MAX,
            'negative' => -1,
            '+60' => time() + 60,
            '-60' => time() - 60,
            default => throw new InvalidArgumentException("Unknown kind: $kind", 7112662888),
        };
        $secret = new Secret(identifier: 't', expiresAt: $expiresAt);

        self::assertSame($expected, $secret->isExpired());
    }

    /**
     * Kills LessThan mutation on isExpired(): `< time()` vs `<= time()`.
     */
    #[Test]
    public function isExpiredReturnsFalseWhenExpiresAtIsSlightlyInFuture(): void
    {
        $secret = new Secret(identifier: 't', expiresAt: time() + 1);

        self::assertFalse($secret->isExpired());
    }

    // ---------------------------------------------------------------
    // fromDatabaseRow() — DB-row hydration semantics.
    // ---------------------------------------------------------------

    #[Test]
    public function fromDatabaseRowCreatesCorrectSecret(): void
    {
        $row = [
            'uid' => 42,
            'scope_pid' => 1,
            'identifier' => 'api-key',
            'description' => self::PAYMENT_GATEWAY_DESCRIPTION,
            'encrypted_value' => 'base64_encrypted_data',
            'encrypted_dek' => 'base64_encrypted_dek',
            'dek_nonce' => 'base64_nonce',
            'value_nonce' => 'base64_value_nonce',
            'encryption_version' => 1,
            'value_checksum' => 'sha256hash',
            'owner_uid' => 5,
            'allowed_groups' => '1,2,3',
            'context' => 'payment',
            'version' => 3,
            'expires_at' => 1735689600,
            'last_rotated_at' => 1704067200,
            'metadata' => '{"service":"stripe"}',
            'adapter' => 'local',
            'external_reference' => '',
            'tstamp' => 1704067200,
            'crdate' => 1704067200,
            'cruser_id' => 1,
            'deleted' => 0,
            'hidden' => 0,
            'read_count' => 10,
            'last_read_at' => 1704153600,
        ];

        $secret = Secret::fromDatabaseRow($row);

        self::assertSame(42, $secret->getUid());
        self::assertSame(1, $secret->getScopePid());
        self::assertSame('api-key', $secret->getIdentifier());
        self::assertSame(self::PAYMENT_GATEWAY_DESCRIPTION, $secret->getDescription());
        self::assertSame('base64_encrypted_data', $secret->getEncryptedValue());
        self::assertSame(5, $secret->getOwnerUid());
        self::assertSame([1, 2, 3], $secret->getAllowedGroups());
        self::assertSame('payment', $secret->getContext());
        self::assertSame(3, $secret->getVersion());
        self::assertSame(['service' => 'stripe'], $secret->getMetadata());
        self::assertSame(10, $secret->getReadCount());
    }

    #[Test]
    public function fromDatabaseRowHandlesEmptyMetadata(): void
    {
        $secret = Secret::fromDatabaseRow([
            'uid' => 1,
            'identifier' => 'test',
            'metadata' => '',
        ]);

        self::assertSame([], $secret->getMetadata());
    }

    #[Test]
    public function fromDatabaseRowHandlesInvalidMetadataJson(): void
    {
        $secret = Secret::fromDatabaseRow([
            'uid' => 1,
            'identifier' => 'test',
            'metadata' => 'not-valid-json{',
        ]);

        self::assertSame([], $secret->getMetadata());
    }

    #[Test]
    public function fromDatabaseRowHandlesNullValues(): void
    {
        $secret = Secret::fromDatabaseRow([
            'uid' => null,
            'identifier' => null,
            'encrypted_value' => null,
        ]);

        self::assertNull($secret->getUid());
        self::assertSame('', $secret->getIdentifier());
        self::assertNull($secret->getEncryptedValue());
    }

    #[Test]
    public function fromDatabaseRowHandlesEmptyAllowedGroups(): void
    {
        $secret = Secret::fromDatabaseRow([
            'uid' => 1,
            'identifier' => 'test',
            'allowed_groups' => '',
        ]);

        self::assertSame([], $secret->getAllowedGroups());
    }

    #[Test]
    public function fromDatabaseRowHandlesFrontendAccessibleTrue(): void
    {
        $secret = Secret::fromDatabaseRow([
            'uid' => 1,
            'identifier' => 'test',
            'frontend_accessible' => 1,
        ]);

        self::assertTrue($secret->isFrontendAccessible());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, int}>
     */
    public static function scopePidCoalesceProvider(): iterable
    {
        yield 'missing scope_pid' => [['uid' => 1, 'identifier' => 't'], 0];
        yield 'explicit zero' => [['uid' => 1, 'identifier' => 't', 'scope_pid' => 0], 0];
        yield 'positive pid 1' => [['uid' => 1, 'identifier' => 't', 'scope_pid' => 1], 1];
        yield 'pid 42' => [['uid' => 1, 'identifier' => 't', 'scope_pid' => 42], 42];
        yield 'string numeric' => [['uid' => 1, 'identifier' => 't', 'scope_pid' => '99'], 99];
    }

    /**
     * @param array<string, mixed> $row
     */
    #[Test]
    #[DataProvider('scopePidCoalesceProvider')]
    public function fromDatabaseRowScopePidCoalesceFallsBackToZero(array $row, int $expected): void
    {
        $secret = Secret::fromDatabaseRow($row);

        self::assertSame($expected, $secret->getScopePid());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, int}>
     */
    public static function encryptionVersionCoalesceProvider(): iterable
    {
        yield 'missing key defaults to 1' => [['uid' => 1, 'identifier' => 't'], 1];
        yield 'explicit 1' => [['uid' => 1, 'identifier' => 't', 'encryption_version' => 1], 1];
        yield 'explicit 2' => [['uid' => 1, 'identifier' => 't', 'encryption_version' => 2], 2];
        yield 'explicit 10' => [['uid' => 1, 'identifier' => 't', 'encryption_version' => 10], 10];
    }

    /**
     * @param array<string, mixed> $row
     */
    #[Test]
    #[DataProvider('encryptionVersionCoalesceProvider')]
    public function fromDatabaseRowEncryptionVersionDefaultsToOne(array $row, int $expected): void
    {
        $secret = Secret::fromDatabaseRow($row);

        self::assertSame($expected, $secret->getEncryptionVersion());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, int}>
     */
    public static function versionCoalesceProvider(): iterable
    {
        yield 'missing version defaults to 1' => [['uid' => 1, 'identifier' => 't'], 1];
        yield 'explicit 1' => [['uid' => 1, 'identifier' => 't', 'version' => 1], 1];
        yield 'explicit 2' => [['uid' => 1, 'identifier' => 't', 'version' => 2], 2];
        yield 'explicit 5' => [['uid' => 1, 'identifier' => 't', 'version' => 5], 5];
    }

    /**
     * @param array<string, mixed> $row
     */
    #[Test]
    #[DataProvider('versionCoalesceProvider')]
    public function fromDatabaseRowVersionDefaultsToOne(array $row, int $expected): void
    {
        $secret = Secret::fromDatabaseRow($row);

        self::assertSame($expected, $secret->getVersion());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, int}>
     */
    public static function ownerUidCoalesceProvider(): iterable
    {
        yield 'missing defaults to 0' => [['uid' => 1, 'identifier' => 't'], 0];
        yield 'zero stays zero' => [['uid' => 1, 'identifier' => 't', 'owner_uid' => 0], 0];
        yield 'positive one' => [['uid' => 1, 'identifier' => 't', 'owner_uid' => 1], 1];
        yield 'string numeric 42' => [['uid' => 1, 'identifier' => 't', 'owner_uid' => '42'], 42];
    }

    /**
     * @param array<string, mixed> $row
     */
    #[Test]
    #[DataProvider('ownerUidCoalesceProvider')]
    public function fromDatabaseRowOwnerUidCastsToInt(array $row, int $expected): void
    {
        $secret = Secret::fromDatabaseRow($row);

        self::assertSame($expected, $secret->getOwnerUid());
    }

    #[Test]
    public function fromDatabaseRowExpiresAtDefaultsToZero(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't']);

        self::assertSame(0, $secret->getExpiresAt());
    }

    #[Test]
    public function fromDatabaseRowLastRotatedAtDefaultsToZero(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't']);

        self::assertSame(0, $secret->getLastRotatedAt());
    }

    #[Test]
    public function fromDatabaseRowReadCountDefaultsToZero(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't']);

        self::assertSame(0, $secret->getReadCount());
    }

    #[Test]
    public function fromDatabaseRowLastReadAtDefaultsToZero(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't']);

        self::assertSame(0, $secret->getLastReadAt());
    }

    #[Test]
    public function fromDatabaseRowCruserIdDefaultsToZero(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't']);

        self::assertSame(0, $secret->getCruserId());
    }

    #[Test]
    public function fromDatabaseRowAdapterDefaultsToLocal(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't']);

        self::assertSame('local', $secret->getAdapter());
    }

    #[Test]
    public function fromDatabaseRowFrontendAccessibleDefaultsToFalse(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't']);

        self::assertFalse($secret->isFrontendAccessible());
    }

    #[Test]
    public function fromDatabaseRowUidReturnsNullWhenMissing(): void
    {
        $secret = Secret::fromDatabaseRow(['identifier' => 't']);

        self::assertNull($secret->getUid());
    }

    #[Test]
    public function fromDatabaseRowUidCastsStringToInt(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => '42', 'identifier' => 't']);

        self::assertSame(42, $secret->getUid());
    }

    #[Test]
    public function fromDatabaseRowPropagatesAllCryptoFieldDefaultsAsEmptyString(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't']);

        self::assertSame('', $secret->getEncryptedDek());
        self::assertSame('', $secret->getDekNonce());
        self::assertSame('', $secret->getValueNonce());
        self::assertSame('', $secret->getValueChecksum());
    }

    #[Test]
    public function fromDatabaseRowFullRoundTripStrictAssertions(): void
    {
        $row = [
            'uid' => 42,
            'scope_pid' => 1,
            'identifier' => 'api-key',
            'description' => self::PAYMENT_GATEWAY_DESCRIPTION,
            'encrypted_value' => 'enc_data',
            'encrypted_dek' => 'dek',
            'dek_nonce' => 'dn',
            'value_nonce' => 'vn',
            'encryption_version' => 2,
            'value_checksum' => 'cs',
            'owner_uid' => 5,
            'allowed_groups' => '7,8,9',
            'context' => 'payment',
            'frontend_accessible' => 1,
            'version' => 3,
            'expires_at' => 1735689600,
            'last_rotated_at' => 1704067200,
            'metadata' => '{"service":"stripe"}',
            'adapter' => 'hashicorp',
            'external_reference' => 'vault:foo',
            'tstamp' => 1704067210,
            'crdate' => 1704067200,
            'cruser_id' => 11,
            'deleted' => 0,
            'hidden' => 0,
            'read_count' => 10,
            'last_read_at' => 1704153600,
        ];

        $secret = Secret::fromDatabaseRow($row);

        self::assertSame(42, $secret->getUid());
        self::assertSame(1, $secret->getScopePid());
        self::assertSame('api-key', $secret->getIdentifier());
        self::assertSame(self::PAYMENT_GATEWAY_DESCRIPTION, $secret->getDescription());
        self::assertSame('enc_data', $secret->getEncryptedValue());
        self::assertSame('dek', $secret->getEncryptedDek());
        self::assertSame('dn', $secret->getDekNonce());
        self::assertSame('vn', $secret->getValueNonce());
        self::assertSame(2, $secret->getEncryptionVersion());
        self::assertSame('cs', $secret->getValueChecksum());
        self::assertSame(5, $secret->getOwnerUid());
        self::assertSame([7, 8, 9], $secret->getAllowedGroups());
        self::assertSame('payment', $secret->getContext());
        self::assertTrue($secret->isFrontendAccessible());
        self::assertSame(3, $secret->getVersion());
        self::assertSame(1735689600, $secret->getExpiresAt());
        self::assertSame(1704067200, $secret->getLastRotatedAt());
        self::assertSame(['service' => 'stripe'], $secret->getMetadata());
        self::assertSame('hashicorp', $secret->getAdapter());
        self::assertSame('vault:foo', $secret->getExternalReference());
        self::assertSame(1704067210, $secret->getTstamp());
        self::assertSame(1704067200, $secret->getCrdate());
        self::assertSame(11, $secret->getCruserId());
        self::assertFalse($secret->isDeleted());
        self::assertFalse($secret->isHidden());
        self::assertSame(10, $secret->getReadCount());
        self::assertSame(1704153600, $secret->getLastReadAt());
    }

    // ---------------------------------------------------------------
    // fromDatabaseRow() — type / cast / coalesce coverage that kills
    // mutation testing artefacts on the hydration code path.
    // ---------------------------------------------------------------

    #[Test]
    public function fromDatabaseRowEncryptionVersionCastsStringToInt(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't', 'encryption_version' => '3']);

        self::assertSame(3, $secret->getEncryptionVersion());
        self::assertIsInt($secret->getEncryptionVersion());
    }

    #[Test]
    public function fromDatabaseRowVersionCastsStringToInt(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't', 'version' => '7']);

        self::assertSame(7, $secret->getVersion());
        self::assertIsInt($secret->getVersion());
    }

    #[Test]
    public function fromDatabaseRowExpiresAtCastsStringToInt(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't', 'expires_at' => '1735689600']);

        self::assertSame(1735689600, $secret->getExpiresAt());
        self::assertIsInt($secret->getExpiresAt());
    }

    #[Test]
    public function fromDatabaseRowLastRotatedAtCastsStringToInt(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't', 'last_rotated_at' => '1704067200']);

        self::assertSame(1704067200, $secret->getLastRotatedAt());
        self::assertIsInt($secret->getLastRotatedAt());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, int}>
     */
    public static function tstampProvider(): iterable
    {
        yield 'missing defaults exactly to 0' => [['uid' => 1, 'identifier' => 't'], 0];
        yield 'string "42" casts to 42' => [['uid' => 1, 'identifier' => 't', 'tstamp' => '42'], 42];
        yield 'zero stays zero' => [['uid' => 1, 'identifier' => 't', 'tstamp' => 0], 0];
        yield 'positive 1704067200' => [['uid' => 1, 'identifier' => 't', 'tstamp' => 1704067200], 1704067200];
    }

    /**
     * @param array<string, mixed> $row
     */
    #[Test]
    #[DataProvider('tstampProvider')]
    public function fromDatabaseRowTstampCastsAndDefaultsCorrectly(array $row, int $expected): void
    {
        $secret = Secret::fromDatabaseRow($row);

        self::assertSame($expected, $secret->getTstamp());
        self::assertIsInt($secret->getTstamp());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, int}>
     */
    public static function crdateProvider(): iterable
    {
        yield 'missing defaults exactly to 0' => [['uid' => 1, 'identifier' => 't'], 0];
        yield 'string "99" casts to 99' => [['uid' => 1, 'identifier' => 't', 'crdate' => '99'], 99];
        yield 'positive 1600000000' => [['uid' => 1, 'identifier' => 't', 'crdate' => 1600000000], 1600000000];
    }

    /**
     * @param array<string, mixed> $row
     */
    #[Test]
    #[DataProvider('crdateProvider')]
    public function fromDatabaseRowCrdateCastsAndDefaultsCorrectly(array $row, int $expected): void
    {
        $secret = Secret::fromDatabaseRow($row);

        self::assertSame($expected, $secret->getCrdate());
        self::assertIsInt($secret->getCrdate());
    }

    #[Test]
    public function fromDatabaseRowCruserIdCastsStringToInt(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't', 'cruser_id' => '12']);

        self::assertSame(12, $secret->getCruserId());
        self::assertIsInt($secret->getCruserId());
    }

    #[Test]
    public function fromDatabaseRowReadCountCastsStringToInt(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't', 'read_count' => '55']);

        self::assertSame(55, $secret->getReadCount());
        self::assertIsInt($secret->getReadCount());
    }

    #[Test]
    public function fromDatabaseRowLastReadAtCastsStringToInt(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't', 'last_read_at' => '1704153600']);

        self::assertSame(1704153600, $secret->getLastReadAt());
        self::assertIsInt($secret->getLastReadAt());
    }

    #[Test]
    public function fromDatabaseRowDeletedDefaultIsExactlyFalse(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't']);

        self::assertFalse($secret->isDeleted());
    }

    #[Test]
    public function fromDatabaseRowHiddenDefaultIsExactlyFalse(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't']);

        self::assertFalse($secret->isHidden());
    }

    #[Test]
    public function fromDatabaseRowDeletedTrueReturnsTrue(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't', 'deleted' => 1]);

        self::assertTrue($secret->isDeleted());
    }

    #[Test]
    public function fromDatabaseRowHiddenTrueReturnsTrue(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't', 'hidden' => 1]);

        self::assertTrue($secret->isHidden());
    }

    #[Test]
    public function fromDatabaseRowExplicitDeletedTruthyOverridesDefault(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't', 'deleted' => true]);

        self::assertTrue($secret->isDeleted());
    }

    #[Test]
    public function fromDatabaseRowExplicitHiddenTruthyOverridesDefault(): void
    {
        $secret = Secret::fromDatabaseRow(['uid' => 1, 'identifier' => 't', 'hidden' => true]);

        self::assertTrue($secret->isHidden());
    }

    #[Test]
    public function fromDatabaseRowAllowedGroupsFiltersZeroValues(): void
    {
        $secret = Secret::fromDatabaseRow([
            'uid' => 1,
            'identifier' => 't',
            'allowed_groups' => '1,0,2,0,3',
        ]);

        // Zeros must be filtered out — without array_filter() they would remain.
        self::assertNotContains(0, $secret->getAllowedGroups());
        self::assertSame([1, 2, 3], array_values($secret->getAllowedGroups()));
    }

    #[Test]
    public function fromDatabaseRowAllowedGroupsAllZeroReturnsEmpty(): void
    {
        $secret = Secret::fromDatabaseRow([
            'uid' => 1,
            'identifier' => 't',
            'allowed_groups' => '0,0,0',
        ]);

        self::assertSame([], $secret->getAllowedGroups());
    }

    // ---------------------------------------------------------------
    // toDatabaseRow() — serialisation.
    // ---------------------------------------------------------------

    #[Test]
    public function toDatabaseRowReturnsExpectedArray(): void
    {
        $secret = new Secret(
            identifier: 'test-secret',
            scopePid: 1,
            description: 'Test secret',
            encryptedValue: 'encrypted',
            encryptedDek: 'dek',
            dekNonce: 'nonce1',
            valueNonce: 'nonce2',
            valueChecksum: 'checksum',
            ownerUid: 5,
            allowedGroups: [1, 2],
            context: 'testing',
            version: 2,
            expiresAt: 1735689600,
            metadata: ['key' => 'value'],
            adapter: 'local',
        );

        $row = $secret->toDatabaseRow();

        self::assertSame(1, $row['scope_pid']);
        self::assertSame('test-secret', $row['identifier']);
        self::assertSame('Test secret', $row['description']);
        self::assertSame('encrypted', $row['encrypted_value']);
        self::assertSame('dek', $row['encrypted_dek']);
        self::assertSame('checksum', $row['value_checksum']);
        self::assertSame(5, $row['owner_uid']);
        self::assertSame('1,2', $row['allowed_groups']);
        self::assertSame('testing', $row['context']);
        self::assertSame(2, $row['version']);
        self::assertSame('{"key":"value"}', $row['metadata']);
        self::assertSame(0, $row['deleted']);
        self::assertSame(0, $row['hidden']);
    }

    #[Test]
    public function toDatabaseRowIncludesLifecycleFields(): void
    {
        $secret = new Secret(
            identifier: 't',
            frontendAccessible: true,
            lastRotatedAt: 1704067200,
            readCount: 50,
            lastReadAt: 1704153600,
        );

        $row = $secret->toDatabaseRow();

        self::assertArrayHasKey('last_rotated_at', $row);
        self::assertSame(1704067200, $row['last_rotated_at']);
        self::assertArrayHasKey('frontend_accessible', $row);
        self::assertSame(1, $row['frontend_accessible']);
        self::assertArrayHasKey('read_count', $row);
        self::assertSame(50, $row['read_count']);
        self::assertArrayHasKey('last_read_at', $row);
        self::assertSame(1704153600, $row['last_read_at']);
    }

    #[Test]
    public function toDatabaseRowHasExactKeySet(): void
    {
        $secret = new Secret(identifier: 't');
        $row = $secret->toDatabaseRow();

        $expectedKeys = [
            'adapter',
            'allowed_groups',
            'context',
            'cruser_id',
            'dek_nonce',
            'deleted',
            'description',
            'encrypted_dek',
            'encrypted_value',
            'encryption_version',
            'expires_at',
            'external_reference',
            'frontend_accessible',
            'hidden',
            'identifier',
            'last_read_at',
            'last_rotated_at',
            'metadata',
            'owner_uid',
            'read_count',
            'scope_pid',
            'tstamp',
            'value_checksum',
            'value_nonce',
            'version',
            'write_groups',
        ];
        $actualKeys = array_keys($row);
        sort($actualKeys);

        self::assertSame($expectedKeys, $actualKeys);
    }

    #[Test]
    public function toDatabaseRowHasStrictIntegerTypesOnScalarFields(): void
    {
        $secret = new Secret(
            identifier: 'x',
            scopePid: 1,
            encryptedValue: 'ev',
            encryptedDek: 'dek',
            dekNonce: 'dn',
            valueNonce: 'vn',
            encryptionVersion: 1,
            valueChecksum: 'cs',
            ownerUid: 2,
            allowedGroups: [3, 4],
            context: 'ctx',
            frontendAccessible: true,
            version: 5,
            expiresAt: 100,
            lastRotatedAt: 200,
            metadata: ['k' => 'v'],
            adapter: 'hashicorp',
            externalReference: 'ref',
            deleted: false,
            hidden: true,
            readCount: 9,
            lastReadAt: 300,
        );

        $row = $secret->toDatabaseRow();

        self::assertSame(1, $row['scope_pid']);
        self::assertSame('x', $row['identifier']);
        self::assertSame('ev', $row['encrypted_value']);
        self::assertSame('dek', $row['encrypted_dek']);
        self::assertSame('dn', $row['dek_nonce']);
        self::assertSame('vn', $row['value_nonce']);
        self::assertSame(1, $row['encryption_version']);
        self::assertSame('cs', $row['value_checksum']);
        self::assertSame(2, $row['owner_uid']);
        self::assertSame('3,4', $row['allowed_groups']);
        self::assertSame('ctx', $row['context']);
        self::assertSame(1, $row['frontend_accessible']);
        self::assertSame(5, $row['version']);
        self::assertSame(100, $row['expires_at']);
        self::assertSame(200, $row['last_rotated_at']);
        self::assertSame('{"k":"v"}', $row['metadata']);
        self::assertSame('hashicorp', $row['adapter']);
        self::assertSame('ref', $row['external_reference']);
        self::assertSame(0, $row['deleted']);
        self::assertSame(1, $row['hidden']);
        self::assertSame(9, $row['read_count']);
        self::assertSame(300, $row['last_read_at']);
    }

    #[Test]
    public function toDatabaseRowSerialisesEmptyAllowedGroupsAsEmptyString(): void
    {
        $secret = new Secret(identifier: 't');

        $row = $secret->toDatabaseRow();

        // implode(',', []) === ''
        self::assertSame('', $row['allowed_groups']);
    }

    #[Test]
    public function toDatabaseRowSerialisesMetadataAsJsonEmptyArrayFromEmptyArray(): void
    {
        $secret = new Secret(identifier: 't');

        $row = $secret->toDatabaseRow();

        // json_encode([]) === '[]'
        self::assertSame('[]', $row['metadata']);
    }

    /**
     * @return iterable<string, array{bool, int}>
     */
    public static function frontendAccessibleSerialisationProvider(): iterable
    {
        yield 'false serialises to 0' => [false, 0];
        yield 'true serialises to 1' => [true, 1];
    }

    #[Test]
    #[DataProvider('frontendAccessibleSerialisationProvider')]
    public function toDatabaseRowFrontendAccessibleBooleanSerialisedAsZeroOrOne(bool $value, int $expected): void
    {
        $secret = new Secret(identifier: 't', frontendAccessible: $value);

        self::assertSame($expected, $secret->toDatabaseRow()['frontend_accessible']);
    }

    /**
     * @return iterable<string, array{bool, bool, int, int}>
     */
    public static function deletedHiddenSerialisationProvider(): iterable
    {
        yield 'deleted=true hidden=false' => [true, false, 1, 0];
        yield 'deleted=false hidden=true' => [false, true, 0, 1];
    }

    #[Test]
    #[DataProvider('deletedHiddenSerialisationProvider')]
    public function toDatabaseRowDeletedAndHiddenBooleansSerialisedAsZeroOrOne(
        bool $deleted,
        bool $hidden,
        int $expectedDeleted,
        int $expectedHidden,
    ): void {
        $secret = new Secret(identifier: 't', deleted: $deleted, hidden: $hidden);

        $row = $secret->toDatabaseRow();

        self::assertSame($expectedDeleted, $row['deleted']);
        self::assertSame($expectedHidden, $row['hidden']);
    }
}
