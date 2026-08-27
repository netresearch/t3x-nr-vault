<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\Typo3MasterKeyProvider;
use Netresearch\NrVault\Exception\MasterKeyException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;

#[CoversClass(Typo3MasterKeyProvider::class)]
final class Typo3MasterKeyProviderTest extends TestCase
{
    private ExtensionConfigurationInterface&MockObject $configurationMock;

    protected function setUp(): void
    {
        parent::setUp();

        $this->configurationMock = $this->createMock(ExtensionConfigurationInterface::class);
        // Reset request-lifetime cache between tests
        Typo3MasterKeyProvider::clearCachedKey();
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        Typo3MasterKeyProvider::clearCachedKey();
    }

    private function createProvider(): Typo3MasterKeyProvider
    {
        return new Typo3MasterKeyProvider($this->configurationMock);
    }

    #[Test]
    public function getIdentifierReturnsTypo3(): void
    {
        $provider = $this->createProvider();

        self::assertEquals('typo3', $provider->getIdentifier());
    }

    #[Test]
    public function isAvailableReturnsTrueWhenEncryptionKeySet(): void
    {
        $this->configurationMock
            ->method('getTypo3EncryptionKey')
            ->willReturn('a-very-long-encryption-key-for-typo3-that-is-at-least-32-chars');

        $provider = $this->createProvider();

        self::assertTrue($provider->isAvailable());
    }

    #[Test]
    public function isAvailableReturnsFalseWhenEncryptionKeyEmpty(): void
    {
        $this->configurationMock
            ->method('getTypo3EncryptionKey')
            ->willReturn('');

        $provider = $this->createProvider();

        self::assertFalse($provider->isAvailable());
    }

    #[Test]
    public function isAvailableReturnsFalseWhenEncryptionKeyNotSet(): void
    {
        $this->configurationMock
            ->method('getTypo3EncryptionKey')
            ->willReturn('');

        $provider = $this->createProvider();

        self::assertFalse($provider->isAvailable());
    }

    #[Test]
    public function getMasterKeyDerives32ByteKey(): void
    {
        $this->configurationMock
            ->method('getTypo3EncryptionKey')
            ->willReturn('test-encryption-key-for-unit-testing-purposes');

        $provider = $this->createProvider();
        $key = $provider->getMasterKey();

        self::assertEquals(32, \strlen($key));
    }

    #[Test]
    public function getMasterKeyReturnsSameKeyForSameInput(): void
    {
        $this->configurationMock
            ->method('getTypo3EncryptionKey')
            ->willReturn('consistent-encryption-key-value-at-least-32-chars');

        $provider = $this->createProvider();
        $key1 = $provider->getMasterKey();
        $key2 = $provider->getMasterKey();

        self::assertEquals($key1, $key2);
    }

    #[Test]
    public function getMasterKeyReturnsDifferentKeyForDifferentInput(): void
    {
        $provider = $this->createProvider();

        $this->configurationMock
            ->method('getTypo3EncryptionKey')
            ->willReturnOnConsecutiveCalls(
                'encryption-key-one-at-least-32-chars-long-aaaa',
                'encryption-key-two-at-least-32-chars-long-bbbb',
            );
        $key1 = $provider->getMasterKey();

        Typo3MasterKeyProvider::clearCachedKey();

        $key2 = $provider->getMasterKey();

        self::assertNotEquals($key1, $key2);
    }

    #[Test]
    public function getMasterKeyThrowsOnShortEncryptionKey(): void
    {
        $this->configurationMock
            ->method('getTypo3EncryptionKey')
            ->willReturn('too-short');

        $provider = $this->createProvider();

        $this->expectException(MasterKeyException::class);

        $provider->getMasterKey();
    }

    #[Test]
    public function getMasterKeyThrowsWhenEncryptionKeyEmpty(): void
    {
        $this->configurationMock
            ->method('getTypo3EncryptionKey')
            ->willReturn('');

        $provider = $this->createProvider();

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionMessageToContain('TYPO3 encryption key is not set');

        $provider->getMasterKey();
    }

    #[Test]
    public function storeMasterKeyThrowsException(): void
    {
        $provider = $this->createProvider();

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionMessageToContain('TYPO3 provider derives the key');

        $provider->storeMasterKey(random_bytes(32));
    }

    #[Test]
    public function generateMasterKeyReturns32Bytes(): void
    {
        $provider = $this->createProvider();

        $key = $provider->generateMasterKey();

        self::assertEquals(32, \strlen($key));
    }
}
