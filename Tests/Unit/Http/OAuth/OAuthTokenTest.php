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
use Error;
use Netresearch\NrVault\Http\OAuth\OAuthToken;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;
use Throwable;
use ValueError;

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

    #[Test]
    #[DataProvider('signedExpiryBuffers')]
    public function expiryBuffersKeepTheirSignedMeaningAtIntegerLimits(
        string $expiry,
        int $buffer,
        bool $expected,
    ): void {
        $token = new OAuthToken('synthetic', 'Bearer', new DateTimeImmutable($expiry));
        self::assertSame($expected, $token->isExpired($buffer));
    }

    /**
     * @return iterable<string, array{string, int, bool}>
     */
    public static function signedExpiryBuffers(): iterable
    {
        yield 'positive limit with past timestamp' => ['1900-01-01T00:00:00+00:00', PHP_INT_MAX, true];
        yield 'positive limit with future timestamp' => ['+1 year', PHP_INT_MAX, true];
        yield 'negative limit with past timestamp' => ['-1 year', PHP_INT_MIN, false];
        yield 'negative limit with future timestamp' => ['+1 year', PHP_INT_MIN, false];
        yield 'negative grace still active' => ['-30 seconds', -60, false];
        yield 'negative grace exhausted' => ['-120 seconds', -60, true];
        yield 'positive buffer covers expiry' => ['+30 seconds', 60, true];
        yield 'positive buffer has not reached expiry' => ['+120 seconds', 60, false];
        yield 'negative limit with pre-epoch timestamp' => ['@-1', PHP_INT_MIN, false];
    }

    #[Test]
    #[DataProvider('representableExpiryLimits')]
    public function expiryAtRepresentableLimitsDoesNotWrap(
        int $expiryTimestamp,
        int $buffer,
        bool $expected,
    ): void {
        $expiry = (new DateTimeImmutable('@0'))->setTimestamp($expiryTimestamp);
        self::assertSame($expiryTimestamp, $expiry->getTimestamp());
        $token = new OAuthToken('synthetic', 'Bearer', $expiry);
        self::assertSame($expected, $token->isExpired($buffer));
    }

    /**
     * @return iterable<string, array{int, int, bool}>
     */
    public static function representableExpiryLimits(): iterable
    {
        yield 'oldest expiry zero buffer' => [PHP_INT_MIN, 0, true];
        yield 'latest expiry zero buffer' => [PHP_INT_MAX, 0, false];
        yield 'positive buffer underflows oldest expiry' => [PHP_INT_MIN, 60, true];
        yield 'negative buffer overflows latest expiry' => [PHP_INT_MAX, -60, false];
        yield 'positive limit underflows oldest expiry' => [PHP_INT_MIN, PHP_INT_MAX, true];
        yield 'negative limit overflows latest expiry' => [PHP_INT_MAX, PHP_INT_MIN, false];
        yield 'negative limit extends oldest expiry to epoch' => [PHP_INT_MIN, PHP_INT_MIN, true];
        yield 'positive limit advances latest expiry to epoch' => [PHP_INT_MAX, PHP_INT_MAX, true];
    }

    #[Test]
    #[DataProvider('conversionRangeFailures')]
    public function conversionRangeFallbackPreservesExistingObjectSemantics(
        string $expiry,
        int $buffer,
        bool $expected,
        mixed $rangeFailure,
    ): void {
        self::assertInstanceOf(Error::class, $rangeFailure);
        $expiryObject = new class ($expiry, $rangeFailure) extends DateTimeImmutable {
            public int $conversionAttempts = 0;

            public function __construct(
                string $expiry,
                private readonly Error $rangeFailure,
            ) {
                parent::__construct($expiry);
            }

            public function getTimestamp(): int
            {
                $this->conversionAttempts++;

                throw $this->rangeFailure;
            }
        };
        $token = new OAuthToken('synthetic', 'Bearer', $expiryObject);
        self::assertSame($expected, $token->isExpired($buffer));
        self::assertSame(
            $buffer === 0 ? 0 : 1,
            $expiryObject->conversionAttempts,
        );
    }

    /**
     * Controlled conversion failures exercise the fallback without claiming a
     * native 32-bit timestamp range event occurred on our 64-bit runner. The newer
     * native type is discovered at runtime; each test checks it is an Error.
     *
     * @return iterable<string, array{string, int, bool, mixed}>
     */
    public static function conversionRangeFailures(): iterable
    {
        $failures = [
            'PHP 8.2 ValueError' => new ValueError('timestamp outside native integer range'),
        ];
        $newerRangeType = 'DateRangeError';
        if (class_exists($newerRangeType)) {
            $newerFailure = new $newerRangeType('timestamp outside native integer range');

            $failures['newer DateRangeError'] = $newerFailure;
        }

        foreach ($failures as $name => $failure) {
            yield $name . ' positive buffer reached' => ['+30 seconds', 60, true, $failure];
            yield $name . ' positive buffer future' => ['+120 seconds', 60, false, $failure];
            yield $name . ' negative grace active' => ['-30 seconds', -60, false, $failure];
            yield $name . ' negative grace exhausted' => ['-120 seconds', -60, true, $failure];
            yield $name . ' zero buffer past' => ['-30 seconds', 0, true, $failure];
            yield $name . ' zero buffer future' => ['+30 seconds', 0, false, $failure];
        }
    }

    #[Test]
    public function unexpectedConversionErrorsReachTheCallerUnchanged(): void
    {
        $failure = new Error('unrelated conversion failure');
        $expiry = new class ($failure) extends DateTimeImmutable {
            public function __construct(private readonly Error $failure)
            {
                parent::__construct('-30 seconds');
            }

            public function getTimestamp(): int
            {
                throw $this->failure;
            }
        };
        $caught = null;

        try {
            (new OAuthToken('synthetic', 'Bearer', $expiry))->isExpired(60);
        } catch (Throwable $exception) {
            $caught = $exception;
        }

        self::assertSame($failure, $caught);
    }

    #[Test]
    #[DataProvider('fractionalExpiryBoundaries')]
    public function expiryKeepsMicrosecondsAtAdjustedSameSecond(
        string $expiry,
        int $buffer,
        bool $expected,
    ): void {
        $now = new DateTimeImmutable('2026-10-10T12:00:00.500000+00:00');
        $token = new OAuthToken('synthetic', 'Bearer', new DateTimeImmutable($expiry));
        $predicate = (new ReflectionClass($token))->getMethod('isExpiredAt');
        self::assertSame($expected, $predicate->invoke($token, $now, $buffer));
    }

    /**
     * @return iterable<string, array{string, int, bool}>
     */
    public static function fractionalExpiryBoundaries(): iterable
    {
        yield 'zero buffer fractional expiry reached' => ['2026-10-10T12:00:00.499999+00:00', 0, true];
        yield 'zero buffer exact instant expired' => ['2026-10-10T12:00:00.500000+00:00', 0, true];
        yield 'zero buffer fractional expiry future' => ['2026-10-10T12:00:00.500001+00:00', 0, false];
        yield 'positive buffer fractional expiry reached' => ['2026-10-10T12:01:00.499999+00:00', 60, true];
        yield 'positive buffer exact instant expired' => ['2026-10-10T12:01:00.500000+00:00', 60, true];
        yield 'positive buffer fractional expiry future' => ['2026-10-10T12:01:00.500001+00:00', 60, false];
        yield 'negative buffer fractional expiry reached' => ['2026-10-10T11:59:00.499999+00:00', -60, true];
        yield 'negative buffer exact instant expired' => ['2026-10-10T11:59:00.500000+00:00', -60, true];
        yield 'negative buffer fractional expiry future' => ['2026-10-10T11:59:00.500001+00:00', -60, false];
    }
}
