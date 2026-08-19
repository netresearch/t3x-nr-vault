<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http\OAuth;

use DateTimeImmutable;
use Netresearch\NrVault\Http\OAuth\OAuthToken;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;

#[CoversClass(OAuthToken::class)]
final class OAuthTokenTest extends TestCase
{
    private const EXPIRY_OFFSET = '+1 hour';

    #[Test]
    public function constructorSetsAllProperties(): void
    {
        $expiresAt = new DateTimeImmutable(self::EXPIRY_OFFSET);

        $token = new OAuthToken(
            accessToken: 'test-access-token',
            tokenType: 'Bearer',
            expiresAt: $expiresAt,
            scope: 'read write',
        );

        self::assertSame('test-access-token', $token->accessToken);
        self::assertSame('Bearer', $token->tokenType);
        self::assertSame($expiresAt, $token->expiresAt);
        self::assertSame('read write', $token->scope);
    }

    #[Test]
    public function scopeDefaultsToNull(): void
    {
        $token = new OAuthToken(
            accessToken: 'test-token',
            tokenType: 'Bearer',
            expiresAt: new DateTimeImmutable(self::EXPIRY_OFFSET),
        );

        self::assertNull($token->scope);
    }

    #[Test]
    public function isExpiredReturnsFalseForFutureExpiry(): void
    {
        $token = new OAuthToken(
            accessToken: 'test-token',
            tokenType: 'Bearer',
            expiresAt: new DateTimeImmutable(self::EXPIRY_OFFSET),
        );

        self::assertFalse($token->isExpired());
    }

    #[Test]
    public function isExpiredReturnsTrueForPastExpiry(): void
    {
        $token = new OAuthToken(
            accessToken: 'test-token',
            tokenType: 'Bearer',
            expiresAt: new DateTimeImmutable('-1 minute'),
        );

        self::assertTrue($token->isExpired());
    }

    /**
     * The default buffer is zero, and the two tests above cannot show it: an
     * expiry a minute away stays in the future even if the default silently
     * became a second, and one a minute past stays past. Both assertions are
     * therefore made against an expiry closer than one second, where a
     * non-zero default flips the answer.
     */
    #[Test]
    public function isExpiredAppliesNoBufferByDefault(): void
    {
        $expiringShortly = new OAuthToken(
            accessToken: 'test-token',
            tokenType: 'Bearer',
            expiresAt: new DateTimeImmutable('+1 second'),
        );

        self::assertFalse(
            $expiringShortly->isExpired(),
            'A token still inside its lifetime must not be reported expired by the default buffer.',
        );

        $expiringNow = new OAuthToken(
            accessToken: 'test-token',
            tokenType: 'Bearer',
            expiresAt: new DateTimeImmutable(),
        );

        self::assertTrue(
            $expiringNow->isExpired(),
            'A token whose expiry has been reached must be reported expired without an extension.',
        );
    }

    #[Test]
    public function isExpiredRespectsBufferTime(): void
    {
        // Token expires in 30 seconds
        $token = new OAuthToken(
            accessToken: 'test-token',
            tokenType: 'Bearer',
            expiresAt: new DateTimeImmutable('+30 seconds'),
        );

        // Without buffer, not expired
        self::assertFalse($token->isExpired(0));

        // With 60 second buffer, considered expired
        self::assertTrue($token->isExpired(60));
    }

    #[Test]
    public function getAuthorizationHeaderFormatsCorrectly(): void
    {
        $token = new OAuthToken(
            accessToken: 'my-access-token',
            tokenType: 'Bearer',
            expiresAt: new DateTimeImmutable(self::EXPIRY_OFFSET),
        );

        self::assertSame('Bearer my-access-token', $token->getAuthorizationHeader());
    }

    #[Test]
    public function getAuthorizationHeaderWorksWithDifferentTokenTypes(): void
    {
        $token = new OAuthToken(
            accessToken: 'my-token',
            tokenType: 'MAC',
            expiresAt: new DateTimeImmutable(self::EXPIRY_OFFSET),
        );

        self::assertSame('MAC my-token', $token->getAuthorizationHeader());
    }

    #[Test]
    public function getExpiresInReturnsPositiveSeconds(): void
    {
        $token = new OAuthToken(
            accessToken: 'test-token',
            tokenType: 'Bearer',
            expiresAt: new DateTimeImmutable('+3600 seconds'),
        );

        $expiresIn = $token->getExpiresIn();

        // Allow some margin for test execution time
        self::assertGreaterThan(3590, $expiresIn);
        self::assertLessThanOrEqual(3600, $expiresIn);
    }

    #[Test]
    public function getExpiresInReturnsZeroForExpiredToken(): void
    {
        $token = new OAuthToken(
            accessToken: 'test-token',
            tokenType: 'Bearer',
            expiresAt: new DateTimeImmutable('-1 hour'),
        );

        self::assertSame(0, $token->getExpiresIn());
    }

    #[Test]
    public function tokenIsReadonly(): void
    {
        $reflection = new ReflectionClass(OAuthToken::class);

        self::assertTrue($reflection->isReadOnly());
    }
}
