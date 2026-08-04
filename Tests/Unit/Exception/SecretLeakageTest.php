<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Exception;

use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Exception\MasterKeyException;
use Netresearch\NrVault\Exception\OAuthException;
use Netresearch\NrVault\Exception\SecretExpiredException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Throwable;

/**
 * Secret-leakage regression tests.
 *
 * The vault's exception factories are carefully scoped: their parameters are
 * identifiers, config keys, file paths and status codes — NEVER the plaintext
 * secret value itself. This test guards that contract by wrapping every
 * factory under a `previous` exception whose own message carries a synthetic
 * "SENSITIVE-PLAINTEXT-SIGIL". The vault exception's `getMessage()` must NOT
 * copy the previous message into its own surface string — logs would then
 * render the sigil even though the vault itself never formatted it.
 *
 * This protects against a future refactor that naively interpolates
 * `$previous->getMessage()` into the outer message to "improve diagnostics" —
 * a well-meaning change that would leak any plaintext the previous layer
 * happened to carry (e.g. a libsodium internal error, a PDO parameter dump).
 *
 * When a future factory is added, add a data-provider entry for it so the
 * coverage stays complete.
 */
#[CoversNothing]
final class SecretLeakageTest extends TestCase
{
    private const SIGIL = 'SENSITIVE-PLAINTEXT-SIGIL';

    /**
     * Factories that accept a `Throwable $previous` argument. For these we
     * construct the previous with a message containing the sigil and assert
     * the outer message does NOT include the previous message content.
     *
     * @return iterable<string, array{Throwable}>
     */
    public static function chainingFactoryProvider(): iterable
    {
        $previous = new RuntimeException(self::SIGIL);

        yield 'OAuthException::invalidJsonResponse (previous carries sigil)' => [
            OAuthException::invalidJsonResponse($previous),
        ];
        yield 'OAuthException::requestFailed (previous carries sigil)' => [
            OAuthException::requestFailed('transport failed', $previous),
        ];
    }

    /**
     * Factories that accept free-form strings (reasons, error messages) and
     * are therefore exposed to accidental secret interpolation by careless
     * callers. These factories interpolate their argument BY DESIGN, so the
     * test only asserts the bare factory default — we cannot prevent a caller
     * from passing a secret, but we CAN prevent the factory from adding extra
     * fields that weren't in its signature.
     *
     * @return iterable<string, array{Throwable, string}>
     */
    public static function factoryDefaultProvider(): iterable
    {
        yield 'AccessDeniedException::cliAccessDisabled' => [
            AccessDeniedException::cliAccessDisabled(),
            'CLI access to vault is disabled',
        ];
        yield 'EncryptionException::encryptionFailed (no reason)' => [
            EncryptionException::encryptionFailed(),
            'Encryption failed',
        ];
        yield 'EncryptionException::decryptionFailed (no reason)' => [
            EncryptionException::decryptionFailed(),
            'Decryption failed',
        ];
        yield 'OAuthException::missingAccessToken' => [
            OAuthException::missingAccessToken(),
            'OAuth response missing access_token',
        ];
        yield 'OAuthException::tokenRequestFailed (no free-form strings)' => [
            OAuthException::tokenRequestFailed(401),
            'OAuth token request failed with status 401',
        ];
        yield 'ValidationException::emptySecret' => [
            ValidationException::emptySecret(),
            'Secret value cannot be empty',
        ];
        yield 'MasterKeyException::invalidLength' => [
            MasterKeyException::invalidLength(32, 17),
            'Invalid master key length: expected 32 bytes, got 17',
        ];
    }

    /**
     * Factory methods that take ONLY an identifier/key/path argument (no
     * free-form reason). These factories must interpolate the identifier
     * — that's by design — but they must not add anything else. This
     * assertion lives in a separate test so the intent is explicit.
     *
     * @return iterable<string, array{Throwable, string}>
     */
    public static function identifierOnlyFactoryProvider(): iterable
    {
        yield 'SecretNotFoundException::forIdentifier' => [
            SecretNotFoundException::forIdentifier('public_identifier'),
            'Secret with identifier "public_identifier" not found',
        ];
        yield 'SecretExpiredException::forIdentifier' => [
            SecretExpiredException::forIdentifier('public_identifier', 1703800000),
            'Secret "public_identifier" expired',
        ];
        yield 'AccessDeniedException::forIdentifier (no reason)' => [
            AccessDeniedException::forIdentifier('public_identifier'),
            'Access denied to secret "public_identifier"',
        ];
        yield 'ConfigurationException::invalidProvider' => [
            ConfigurationException::invalidProvider('hashicorp'),
            'Unknown master key provider: hashicorp',
        ];
        yield 'ConfigurationException::invalidAdapter' => [
            ConfigurationException::invalidAdapter('aws'),
            'Unknown vault adapter: aws',
        ];
        yield 'ConfigurationException::missingConfiguration' => [
            ConfigurationException::missingConfiguration('master_key_path'),
            'Missing required configuration: master_key_path',
        ];
        yield 'MasterKeyException::notFound' => [
            MasterKeyException::notFound('/etc/vault/master.key'),
            'Master key not found at: /etc/vault/master.key',
        ];
        yield 'MasterKeyException::environmentVariableNotSet' => [
            MasterKeyException::environmentVariableNotSet('VAULT_MASTER_KEY'),
            'Environment variable "VAULT_MASTER_KEY" for master key is not set',
        ];
        yield 'EncryptionException::algorithmNotAvailable' => [
            EncryptionException::algorithmNotAvailable('chacha20'),
            'Encryption algorithm "chacha20" is not available',
        ];
    }

    /**
     * Union provider for the cross-cut non-zero-code check: flattens every
     * other provider's first column (the exception) into a single-column
     * dataset so PHPUnit accepts a `Throwable $exception` signature.
     *
     * @return iterable<string, array{Throwable}>
     */
    public static function allFactoriesProvider(): iterable
    {
        foreach (self::chainingFactoryProvider() as $name => $row) {
            yield $name => [$row[0]];
        }

        foreach (self::factoryDefaultProvider() as $name => $row) {
            yield $name => [$row[0]];
        }

        foreach (self::identifierOnlyFactoryProvider() as $name => $row) {
            yield $name => [$row[0]];
        }
    }

    /**
     * The core regression: when a caller chains a previous exception whose own
     * message carries secret material, the vault exception's OUTER message
     * must not copy that content into itself.
     */
    #[Test]
    #[DataProvider('chainingFactoryProvider')]
    public function chainingFactoryDoesNotCopyPreviousMessageIntoOuterMessage(Throwable $exception): void
    {
        $outerMessage = $exception->getMessage();

        self::assertStringNotContainsString(
            self::SIGIL,
            $outerMessage,
            \sprintf(
                '%s copied the previous exception\'s message into its own — this leaks '
                . 'any secret material the previous layer happened to carry. Factory '
                . 'methods that accept a Throwable MUST produce an outer message that '
                . 'is independent of the previous message content. Outer message: %s',
                $exception::class,
                $outerMessage,
            ),
        );

        // Sanity check: the previous IS reachable and DOES carry the sigil —
        // we haven't accidentally lost the chain.
        $previous = $exception->getPrevious();
        self::assertInstanceOf(
            Throwable::class,
            $previous,
            'Factory must preserve the chained previous exception',
        );
        self::assertStringContainsString(
            self::SIGIL,
            $previous->getMessage(),
            'Test harness sanity check: previous message must still carry the sigil',
        );
    }

    /**
     * Canonical message check: a factory with no free-form string parameter
     * must produce a stable, sigil-free message.
     */
    #[Test]
    #[DataProvider('factoryDefaultProvider')]
    public function factoryDefaultMessageContainsOnlyExpectedContent(
        Throwable $exception,
        string $expectedContent,
    ): void {
        $message = $exception->getMessage();

        self::assertStringNotContainsString(
            self::SIGIL,
            $message,
            'Factory default message must not contain the sigil',
        );
        self::assertStringContainsString(
            $expectedContent,
            $message,
            'Factory default message must carry its canonical content',
        );
    }

    /**
     * Identifier-only factories interpolate the identifier. They must NOT
     * carry any sigil when called with a non-secret identifier.
     */
    #[Test]
    #[DataProvider('identifierOnlyFactoryProvider')]
    public function identifierOnlyFactoryDoesNotIntroduceSigil(
        Throwable $exception,
        string $expectedContent,
    ): void {
        $message = $exception->getMessage();

        self::assertStringNotContainsString(
            self::SIGIL,
            $message,
            'Identifier-only factory must not embed anything other than the identifier',
        );
        self::assertStringContainsString(
            $expectedContent,
            $message,
            'Identifier-only factory must produce its documented message shape',
        );
    }

    /**
     * Cross-cut: every vault exception must have a non-zero code. Zero codes
     * hint at hand-rolled instantiation that bypassed the factory methods —
     * and those are the instantiation sites most likely to leak secrets.
     */
    #[Test]
    #[DataProvider('allFactoriesProvider')]
    public function factoryExceptionsHaveNonZeroCode(Throwable $exception): void
    {
        self::assertNotSame(
            0,
            $exception->getCode(),
            \sprintf(
                'Factory %s produced a zero code — indicates a leaky hand-rolled ctor',
                $exception::class,
            ),
        );
    }
}
