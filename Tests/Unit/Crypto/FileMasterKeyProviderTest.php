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
use Netresearch\NrVault\Tests\Unit\Traits\ErrorSuppressionTrait;
use org\bovigo\vfs\vfsStream;
use org\bovigo\vfs\vfsStreamDirectory;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(FileMasterKeyProvider::class)]
#[AllowMockObjectsWithoutExpectations]
final class FileMasterKeyProviderTest extends TestCase
{
    use ErrorSuppressionTrait;

    private const MASTER_KEY_PATH = 'vault/master.key';

    private const NONEXISTENT_KEY_PATH = 'vault/nonexistent.key';

    private const AUTO_KEY_PATH = 'vault/auto.key';

    private const INVALID_KEY_LENGTH_MESSAGE = 'Invalid master key length';

    private vfsStreamDirectory $root;

    protected function setUp(): void
    {
        parent::setUp();

        FileMasterKeyProvider::clearCachedKey();
        $this->root = vfsStream::setup('vault');
    }

    protected function tearDown(): void
    {
        FileMasterKeyProvider::clearCachedKey();

        parent::tearDown();
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
        $this->expectExceptionMessageToContain('not found');

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
        $this->expectExceptionMessageToContain(self::INVALID_KEY_LENGTH_MESSAGE);

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
        $this->expectExceptionMessageToContain(self::INVALID_KEY_LENGTH_MESSAGE);

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
        $this->expectExceptionMessageToContain('not found');

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
        $this->expectExceptionMessageToContain(self::INVALID_KEY_LENGTH_MESSAGE);

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

    #[Test]
    public function storeMasterKeyChmodsTheKeyFileToOwnerReadOnly(): void
    {
        $keyPath = vfsStream::url('vault/perm.key');

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        (new FileMasterKeyProvider($config))->storeMasterKey(sodium_crypto_secretbox_keygen());

        $file = $this->root->getChild('perm.key');
        self::assertNotNull($file);
        self::assertSame(0o400, $file->getPermissions());
    }

    #[Test]
    public function storeMasterKeyCreatesTheKeyDirectoryWithOwnerOnlyPermissions(): void
    {
        $keyPath = vfsStream::url('vault/created/deep/master.key');

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        (new FileMasterKeyProvider($config))->storeMasterKey(sodium_crypto_secretbox_keygen());

        $outer = $this->root->getChild('created');
        self::assertNotNull($outer);
        self::assertSame(0o700, $outer->getPermissions());

        $inner = $this->root->getChild('created/deep');
        self::assertNotNull($inner);
        self::assertSame(0o700, $inner->getPermissions());
    }

    #[Test]
    public function storeMasterKeyRestoresThePreviousUmask(): void
    {
        $keyPath = vfsStream::url('vault/umask.key');

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        $outerUmask = umask(0o022);

        try {
            (new FileMasterKeyProvider($config))->storeMasterKey(sodium_crypto_secretbox_keygen());

            self::assertSame(0o022, umask());
        } finally {
            umask($outerUmask);
        }
    }

    #[Test]
    public function storeMasterKeyReportsAnUncreatableDirectoryRatherThanTheFailedWrite(): void
    {
        // A read-only parent makes the recursive mkdir() fail, which must be
        // reported as such instead of leaking through to the write attempt.
        mkdir(vfsStream::url('vault/readonly'), 0o500);
        $keyPath = vfsStream::url('vault/readonly/nested/master.key');

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        $provider = new FileMasterKeyProvider($config);

        try {
            $this->withoutPhpDiagnostics(
                static fn (): null => $provider->storeMasterKey(sodium_crypto_secretbox_keygen()),
            );
            self::fail('Expected MasterKeyException was not thrown.');
        } catch (MasterKeyException $e) {
            self::assertSame(
                'Cannot store master key: Cannot create directory: ' . vfsStream::url('vault/readonly/nested'),
                $e->getMessage(),
            );
        }
    }

    #[Test]
    public function getMasterKeyRefusesAnUnconfiguredPathEvenWhenAnAutoKeyExists(): void
    {
        // The empty-path guard fires BEFORE the auto-key fallback: an operator
        // who cleared the setting must get a configuration error, not a silent
        // switch to the development key.
        $autoKeyPath = vfsStream::url('vault/present-auto.key');
        file_put_contents($autoKeyPath, base64_encode(sodium_crypto_secretbox_keygen()));

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn(ExtensionConfiguration::DEFAULT_MASTER_KEY_SOURCE);
        $config->method('getAutoKeyPath')->willReturn($autoKeyPath);

        $provider = new FileMasterKeyProvider($config);

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionMessageToContain('Master key not found at: No path configured');

        $provider->getMasterKey();
    }

    #[Test]
    public function getMasterKeyReportsAMissingFileWithoutClaimingItIsUnreadable(): void
    {
        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn(vfsStream::url(self::NONEXISTENT_KEY_PATH));
        $config->method('getAutoKeyPath')->willReturn(vfsStream::url('vault/also-missing.key'));

        $provider = new FileMasterKeyProvider($config);

        try {
            $provider->getMasterKey();
            self::fail('Expected MasterKeyException was not thrown.');
        } catch (MasterKeyException $e) {
            self::assertSame(
                'Master key not found at: ' . vfsStream::url(self::NONEXISTENT_KEY_PATH),
                $e->getMessage(),
            );
        }
    }

    #[Test]
    public function getMasterKeyNamesThePathAndTheReasonWhenTheKeyFileIsUnreadable(): void
    {
        $keyPath = vfsStream::url('vault/unreadable.key');
        file_put_contents($keyPath, base64_encode(sodium_crypto_secretbox_keygen()));
        chmod($keyPath, 0o000);

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        $provider = new FileMasterKeyProvider($config);

        try {
            $provider->getMasterKey();
            self::fail('Expected MasterKeyException was not thrown.');
        } catch (MasterKeyException $e) {
            self::assertSame(
                'Master key not found at: ' . $keyPath . ' (not readable)',
                $e->getMessage(),
            );
        }
    }

    #[Test]
    public function getMasterKeyTrimsATrailingNewlineFromARawBinaryKey(): void
    {
        // A 32-byte raw key written by `printf ... > file` picks up a newline.
        // Only the trimmed value has the key length; the untrimmed bytes are
        // neither 32 bytes nor decodable base64.
        $key = '12345678901234567890123456789012';
        $keyPath = vfsStream::url('vault/raw-newline.key');
        file_put_contents($keyPath, $key . "\n");

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        $provider = new FileMasterKeyProvider($config);

        self::assertSame($key, $provider->getMasterKey());
    }

    #[Test]
    public function destructionClearsTheRequestLifetimeKeyCache(): void
    {
        $keyPath = vfsStream::url(self::MASTER_KEY_PATH);

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn($keyPath);

        $first = sodium_crypto_secretbox_keygen();
        file_put_contents($keyPath, base64_encode($first));

        $provider = new FileMasterKeyProvider($config);
        self::assertSame($first, $provider->getMasterKey());
        unset($provider);

        $second = sodium_crypto_secretbox_keygen();
        file_put_contents($keyPath, base64_encode($second));

        self::assertSame($second, (new FileMasterKeyProvider($config))->getMasterKey());
    }
}
