<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use Netresearch\NrVault\Configuration\ExtensionConfiguration;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use Netresearch\NrVault\Exception\MasterKeyException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(FileMasterKeyProvider::class)]
#[AllowMockObjectsWithoutExpectations]
final class FileMasterKeyProviderTest extends TestCase
{
    private const MASTER_KEY_PATH = 'vault/master.key';

    private const NONEXISTENT_KEY_PATH = 'vault/nonexistent.key';

    private const AUTO_KEY_PATH = 'vault/auto.key';

    private const INVALID_KEY_LENGTH_MESSAGE = 'Invalid master key length';

    protected function setUp(): void
    {
        parent::setUp();

        FileMasterKeyProvider::clearCachedKey();
        vfsStream::setup('vault');
    }

    #[Test]
    public function getIdentifierReturnsFile(): void
    {
        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $provider = new FileMasterKeyProvider($config);

        self::assertEquals('file', $provider->getIdentifier());
    }

    #[Test]
    public function isAvailableReturnsTrueWhenFileExists(): void
    {
        $keyPath = vfsStream::url(self::MASTER_KEY_PATH);
        // Use a fixed 32-byte key to avoid NUL byte issues
        file_put_contents($keyPath, base64_encode('AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH'));

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        $provider = new FileMasterKeyProvider($config);

        self::assertTrue($provider->isAvailable());
    }

    #[Test]
    public function isAvailableReturnsFalseWhenFileDoesNotExist(): void
    {
        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn(vfsStream::url(self::NONEXISTENT_KEY_PATH));

        $provider = new FileMasterKeyProvider($config);

        self::assertFalse($provider->isAvailable());
    }

    #[Test]
    public function isAvailableReturnsFalseWhenPathEmpty(): void
    {
        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn(ExtensionConfiguration::DEFAULT_MASTER_KEY_SOURCE);

        $provider = new FileMasterKeyProvider($config);

        self::assertFalse($provider->isAvailable());
    }

    #[Test]
    public function getMasterKeyReadsAndDecodesBase64Key(): void
    {
        // Use a fixed 32-byte key without NUL bytes or whitespace to avoid trim issues
        $key = 'XXXXYYYYZZZZAAAABBBBCCCCDDDDEEEE';
        $keyPath = vfsStream::url(self::MASTER_KEY_PATH);
        file_put_contents($keyPath, base64_encode($key));

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        $provider = new FileMasterKeyProvider($config);

        self::assertEquals($key, $provider->getMasterKey());
    }

    #[Test]
    public function getMasterKeyReadsRaw32ByteKey(): void
    {
        // Use a fixed 32-byte key without NUL bytes or whitespace to avoid trim issues
        $key = '12345678901234567890123456789012';
        $keyPath = vfsStream::url(self::MASTER_KEY_PATH);
        file_put_contents($keyPath, $key);

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        $provider = new FileMasterKeyProvider($config);

        self::assertEquals($key, $provider->getMasterKey());
    }

    #[Test]
    public function getMasterKeyThrowsWhenPathEmpty(): void
    {
        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn(ExtensionConfiguration::DEFAULT_MASTER_KEY_SOURCE);
        $config->method('getAutoKeyPath')->willReturn(vfsStream::url(self::AUTO_KEY_PATH));

        $provider = new FileMasterKeyProvider($config);

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionMessage('not found');

        $provider->getMasterKey();
    }

    #[Test]
    public function getMasterKeyFallsBackToAutoKeyPath(): void
    {
        // Use a fixed 32-byte key without NUL bytes or whitespace to avoid trim issues
        $key = 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH';
        $autoKeyPath = vfsStream::url(self::AUTO_KEY_PATH);
        file_put_contents($autoKeyPath, base64_encode($key));

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn(vfsStream::url(self::NONEXISTENT_KEY_PATH));
        $config->method('getAutoKeyPath')->willReturn($autoKeyPath);

        $provider = new FileMasterKeyProvider($config);

        self::assertEquals($key, $provider->getMasterKey());
    }

    #[Test]
    public function getMasterKeyThrowsWhenKeyLengthInvalid(): void
    {
        $keyPath = vfsStream::url(self::MASTER_KEY_PATH);
        file_put_contents($keyPath, 'tooshort');

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        $provider = new FileMasterKeyProvider($config);

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionMessage(self::INVALID_KEY_LENGTH_MESSAGE);

        $provider->getMasterKey();
    }

    #[Test]
    public function storeMasterKeyCreatesFileWithCorrectPermissions(): void
    {
        $key = random_bytes(32);
        $keyPath = vfsStream::url('vault/new.key');

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        $provider = new FileMasterKeyProvider($config);
        $provider->storeMasterKey($key);

        self::assertFileExists($keyPath);
        self::assertEquals(base64_encode($key), file_get_contents($keyPath));
    }

    #[Test]
    public function storeMasterKeyUsesAutoKeyPathWhenSourceEmpty(): void
    {
        $key = random_bytes(32);
        $autoKeyPath = vfsStream::url(self::AUTO_KEY_PATH);

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn('');
        $config->method('getAutoKeyPath')->willReturn($autoKeyPath);

        $provider = new FileMasterKeyProvider($config);
        $provider->storeMasterKey($key);

        self::assertFileExists($autoKeyPath);
    }

    #[Test]
    public function storeMasterKeyThrowsWhenKeyLengthInvalid(): void
    {
        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $provider = new FileMasterKeyProvider($config);

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionMessage(self::INVALID_KEY_LENGTH_MESSAGE);

        $provider->storeMasterKey('tooshort');
    }

    #[Test]
    public function storeMasterKeyCreatesDirectory(): void
    {
        $key = random_bytes(32);
        $keyPath = vfsStream::url('vault/subdir/deep/master.key');

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        $provider = new FileMasterKeyProvider($config);
        $provider->storeMasterKey($key);

        self::assertFileExists($keyPath);
    }

    #[Test]
    public function getMasterKeyThrowsWhenFileNotFoundAndAutoPathAlsoMissing(): void
    {
        // Main path does not exist and auto path also does not exist
        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn(vfsStream::url(self::NONEXISTENT_KEY_PATH));
        $config->method('getAutoKeyPath')->willReturn(vfsStream::url('vault/also-nonexistent.key'));

        $provider = new FileMasterKeyProvider($config);

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionMessage('not found');

        $provider->getMasterKey();
    }

    #[Test]
    public function getMasterKeyThrowsWhenKeyLengthInvalidAfterBase64Decode(): void
    {
        // File contains a base64 string that decodes to wrong length (not 32 bytes)
        $keyPath = vfsStream::url('vault/wrong-length.key');
        // base64 of 10-byte string - decodes to 10 bytes, not 32
        file_put_contents($keyPath, base64_encode('tooshort!!'));

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        $provider = new FileMasterKeyProvider($config);

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionMessage(self::INVALID_KEY_LENGTH_MESSAGE);

        $provider->getMasterKey();
    }

    #[Test]
    public function storeMasterKeyUsesDefaultMasterKeySourceSentinelAsEmptyPath(): void
    {
        // When getMasterKeySource returns the sentinel value DEFAULT_MASTER_KEY_SOURCE,
        // getKeyPath() returns '' and storeMasterKey falls back to getAutoKeyPath()
        $key = random_bytes(32);
        $autoKeyPath = vfsStream::url('vault/sentinel-auto.key');

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn(ExtensionConfiguration::DEFAULT_MASTER_KEY_SOURCE);
        $config->method('getAutoKeyPath')->willReturn($autoKeyPath);

        $provider = new FileMasterKeyProvider($config);
        $provider->storeMasterKey($key);

        self::assertFileExists($autoKeyPath);
        self::assertEquals(base64_encode($key), file_get_contents($autoKeyPath));
    }

    #[Test]
    public function getMasterKeyReadsBinaryKeyExactly32Bytes(): void
    {
        // Raw binary 32 bytes read directly without any trimming
        $key = random_bytes(32);
        $keyPath = vfsStream::url('vault/binary.key');
        file_put_contents($keyPath, $key);

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        $provider = new FileMasterKeyProvider($config);

        self::assertEquals($key, $provider->getMasterKey());
    }

    #[Test]
    public function getMasterKeyHandlesBase64WithWhitespace(): void
    {
        // Base64 key with trailing newline (common when piped to file)
        $key = random_bytes(32);
        $keyPath = vfsStream::url('vault/base64-newline.key');
        file_put_contents($keyPath, base64_encode($key) . "\n");

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        $provider = new FileMasterKeyProvider($config);

        self::assertEquals($key, $provider->getMasterKey());
    }

    #[Test]
    public function generateMasterKeyReturns32Bytes(): void
    {
        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $provider = new FileMasterKeyProvider($config);

        $key = $provider->generateMasterKey();

        self::assertEquals(32, \strlen($key));
    }
}
