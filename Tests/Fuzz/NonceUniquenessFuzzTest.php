<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Fuzz;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\EncryptionAlgorithm;
use Netresearch\NrVault\Crypto\EncryptionService;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Nonce-uniqueness regression tests.
 *
 * XChaCha20-Poly1305 and AES-256-GCM both catastrophically fail if a nonce is
 * re-used with the same key (key+nonce collision leaks plaintext XOR and may
 * leak the authentication key for AES-GCM). This test suite asserts that
 * 1000 encryptions of the same plaintext under the same identifier produce
 * 1000 distinct nonces AND 1000 distinct DEK nonces.
 *
 * This is a unit-level test — no DB, no container. It uses a stub master key
 * provider so it can run in the standard Fuzz test suite.
 */
#[CoversClass(EncryptionService::class)]
final class NonceUniquenessFuzzTest extends TestCase
{
    private const ITERATIONS = 1000;

    private EncryptionService $xchacha;

    private EncryptionService $aes;

    private string $masterKey;

    protected function setUp(): void
    {
        parent::setUp();

        $this->masterKey = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);

        $provider = $this->createStub(MasterKeyProviderInterface::class);
        $provider->method('getMasterKey')->willReturnCallback(fn (): string => $this->masterKey);

        $xchachaConfig = $this->createStub(ExtensionConfigurationInterface::class);
        $xchachaConfig->method('getEncryptionAlgorithm')->willReturn('xchacha20poly1305');

        $aesConfig = $this->createStub(ExtensionConfigurationInterface::class);
        $aesConfig->method('getEncryptionAlgorithm')->willReturn('aes256gcm');

        $this->xchacha = new EncryptionService($provider, $xchachaConfig);
        $this->aes = new EncryptionService($provider, $aesConfig);
    }

    #[Test]
    public function xchachaEncryptProducesUniqueValueNoncesOverThousandIterations(): void
    {
        $identifier = '01937b6e-4b6c-7abc-8def-000000000001';
        $plaintext = 'same-plaintext-for-every-iteration';

        /** @var array<string, true> $valueNonces */
        $valueNonces = [];
        for ($i = 0; $i < self::ITERATIONS; $i++) {
            $encrypted = $this->xchacha->encrypt($plaintext, $identifier);
            $valueNonces[$encrypted->valueNonce] = true;
        }

        self::assertCount(
            self::ITERATIONS,
            $valueNonces,
            \sprintf(
                'XChaCha20: expected %d distinct value nonces after %d encryptions, got %d — NONCE COLLISION (critical)',
                self::ITERATIONS,
                self::ITERATIONS,
                \count($valueNonces),
            ),
        );
    }

    #[Test]
    public function xchachaEncryptProducesUniqueDekNoncesOverThousandIterations(): void
    {
        $identifier = '01937b6e-4b6c-7abc-8def-000000000002';
        $plaintext = 'same-plaintext-for-every-iteration';

        /** @var array<string, true> $dekNonces */
        $dekNonces = [];
        for ($i = 0; $i < self::ITERATIONS; $i++) {
            $encrypted = $this->xchacha->encrypt($plaintext, $identifier);
            $dekNonces[$encrypted->dekNonce] = true;
        }

        self::assertCount(
            self::ITERATIONS,
            $dekNonces,
            \sprintf(
                'XChaCha20: expected %d distinct DEK nonces after %d encryptions, got %d — NONCE COLLISION (critical)',
                self::ITERATIONS,
                self::ITERATIONS,
                \count($dekNonces),
            ),
        );
    }

    #[Test]
    public function aesEncryptProducesUniqueValueNoncesOverThousandIterations(): void
    {
        if (!sodium_crypto_aead_aes256gcm_is_available()) {
            self::markTestSkipped('AES-256-GCM not available on this platform');
        }

        $identifier = '01937b6e-4b6c-7abc-8def-000000000003';
        $plaintext = 'same-plaintext-for-every-iteration';

        /** @var array<string, true> $valueNonces */
        $valueNonces = [];
        for ($i = 0; $i < self::ITERATIONS; $i++) {
            $encrypted = $this->aes->encrypt($plaintext, $identifier);
            self::assertSame(EncryptionAlgorithm::Aes256Gcm, $encrypted->encryptionAlgorithm);
            self::assertSame(
                SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES,
                \strlen((string) base64_decode($encrypted->valueNonce, true)),
            );
            $valueNonces[$encrypted->valueNonce] = true;
        }

        self::assertCount(
            self::ITERATIONS,
            $valueNonces,
            \sprintf(
                'AES-256-GCM: expected %d distinct value nonces after %d encryptions, got %d — NONCE COLLISION (catastrophic for GCM)',
                self::ITERATIONS,
                self::ITERATIONS,
                \count($valueNonces),
            ),
        );
    }

    #[Test]
    public function aesEncryptProducesUniqueDekNoncesOverThousandIterations(): void
    {
        if (!sodium_crypto_aead_aes256gcm_is_available()) {
            self::markTestSkipped('AES-256-GCM not available on this platform');
        }

        $identifier = '01937b6e-4b6c-7abc-8def-000000000004';
        $plaintext = 'same-plaintext-for-every-iteration';

        /** @var array<string, true> $dekNonces */
        $dekNonces = [];
        for ($i = 0; $i < self::ITERATIONS; $i++) {
            $encrypted = $this->aes->encrypt($plaintext, $identifier);
            self::assertSame(EncryptionAlgorithm::Aes256Gcm, $encrypted->encryptionAlgorithm);
            self::assertSame(
                SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES,
                \strlen((string) base64_decode($encrypted->dekNonce, true)),
            );
            $dekNonces[$encrypted->dekNonce] = true;
        }

        self::assertCount(
            self::ITERATIONS,
            $dekNonces,
            \sprintf(
                'AES-256-GCM: expected %d distinct DEK nonces after %d encryptions, got %d — NONCE COLLISION (catastrophic for GCM)',
                self::ITERATIONS,
                self::ITERATIONS,
                \count($dekNonces),
            ),
        );
    }

    /**
     * Cross-check: value nonces and DEK nonces should also not collide
     * WITH EACH OTHER. A shared nonce across keys is less catastrophic but
     * still indicates a broken RNG and MUST be caught.
     */
    #[Test]
    public function xchachaValueAndDekNoncesAreDisjointAcrossThousandIterations(): void
    {
        $identifier = '01937b6e-4b6c-7abc-8def-000000000005';
        $plaintext = 'disjoint-nonce-check';

        /** @var array<string, true> $all */
        $all = [];
        for ($i = 0; $i < self::ITERATIONS; $i++) {
            $encrypted = $this->xchacha->encrypt($plaintext, $identifier);
            $all[$encrypted->valueNonce] = true;
            $all[$encrypted->dekNonce] = true;
        }

        self::assertCount(
            self::ITERATIONS * 2,
            $all,
            'value-nonces and DEK-nonces must never collide across or within encryptions',
        );
    }
}
