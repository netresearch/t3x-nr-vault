<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use Netresearch\NrVault\Configuration\ExtensionConfiguration;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\EnvironmentMasterKeyProvider;
use Netresearch\NrVault\Exception\MasterKeyException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(EnvironmentMasterKeyProvider::class)]
#[AllowMockObjectsWithoutExpectations]
final class EnvironmentMasterKeyProviderTest extends TestCase
{
    private const TEST_ENV_VAR = 'NR_VAULT_TEST_KEY_12345';

    protected function setUp(): void
    {
        parent::setUp();
        EnvironmentMasterKeyProvider::clearCachedKey();
        // Clean up environment variable before each test
        putenv(self::TEST_ENV_VAR);
    }

    protected function tearDown(): void
    {
        putenv(self::TEST_ENV_VAR);
        parent::tearDown();
    }

    #[Test]
    public function getIdentifierReturnsEnv(): void
    {
        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $provider = new EnvironmentMasterKeyProvider($config);

        self::assertEquals('env', $provider->getIdentifier());
    }

    #[Test]
    public function isAvailableReturnsTrueWhenEnvVarSet(): void
    {
        $key = random_bytes(32);
        putenv(self::TEST_ENV_VAR . '=' . base64_encode($key));

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn(self::TEST_ENV_VAR);

        $provider = new EnvironmentMasterKeyProvider($config);

        self::assertTrue($provider->isAvailable());
    }

    #[Test]
    public function isAvailableReturnsFalseWhenEnvVarNotSet(): void
    {
        putenv(self::TEST_ENV_VAR);

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn(self::TEST_ENV_VAR);

        $provider = new EnvironmentMasterKeyProvider($config);

        self::assertFalse($provider->isAvailable());
    }

    #[Test]
    public function getMasterKeyReturnsDecodedKey(): void
    {
        $key = random_bytes(32);
        putenv(self::TEST_ENV_VAR . '=' . base64_encode($key));

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn(self::TEST_ENV_VAR);

        $provider = new EnvironmentMasterKeyProvider($config);

        self::assertEquals($key, $provider->getMasterKey());
    }

    #[Test]
    public function getMasterKeyReturnsRawKeyWhen32Bytes(): void
    {
        // Use a fixed 32-byte key without NUL bytes (which would truncate in env vars)
        $key = 'abcdefghijklmnopqrstuvwxyz123456';
        putenv(self::TEST_ENV_VAR . '=' . $key);

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn(self::TEST_ENV_VAR);

        $provider = new EnvironmentMasterKeyProvider($config);

        self::assertEquals($key, $provider->getMasterKey());
    }

    #[Test]
    public function getMasterKeyThrowsWhenEnvVarNotSet(): void
    {
        putenv(self::TEST_ENV_VAR);

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn(self::TEST_ENV_VAR);

        $provider = new EnvironmentMasterKeyProvider($config);

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionMessageToContain('Environment variable');

        $provider->getMasterKey();
    }

    #[Test]
    public function getMasterKeyThrowsWhenKeyLengthInvalid(): void
    {
        putenv(self::TEST_ENV_VAR . '=tooshort');

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn(self::TEST_ENV_VAR);

        $provider = new EnvironmentMasterKeyProvider($config);

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionMessageToContain('Invalid master key length');

        $provider->getMasterKey();
    }

    #[Test]
    public function storeMasterKeyThrowsException(): void
    {
        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $provider = new EnvironmentMasterKeyProvider($config);

        $this->expectException(MasterKeyException::class);
        $this->expectExceptionMessageToContain('cannot be persisted');

        $provider->storeMasterKey(random_bytes(32));
    }

    #[Test]
    public function generateMasterKeyReturns32Bytes(): void
    {
        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $provider = new EnvironmentMasterKeyProvider($config);

        $key = $provider->generateMasterKey();

        self::assertEquals(32, \strlen($key));
    }

    #[Test]
    public function usesDefaultEnvVarNameWhenSourceEmpty(): void
    {
        $key = random_bytes(32);
        putenv(ExtensionConfiguration::DEFAULT_MASTER_KEY_SOURCE . '=' . base64_encode($key));

        $config = $this->createMock(ExtensionConfigurationInterface::class);
        $config->method('getMasterKeySource')->willReturn('');

        $provider = new EnvironmentMasterKeyProvider($config);

        self::assertEquals($key, $provider->getMasterKey());

        putenv(ExtensionConfiguration::DEFAULT_MASTER_KEY_SOURCE);
    }
}
