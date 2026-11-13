<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Storage;

use Netresearch\NrVault\Adapter\AwsSecretsManagerAdapter;
use Netresearch\NrVault\Adapter\HashiCorpAdapter;
use Netresearch\NrVault\Adapter\LocalEncryptionAdapter;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Storage\Aws\AwsSecretStoreInterface;
use Netresearch\NrVault\Storage\ExternalStoreJournal;
use Netresearch\NrVault\Storage\HashiCorp\KvStoreInterface;
use Netresearch\NrVault\Storage\InstallationMarker;
use Netresearch\NrVault\Storage\StorageAdapterFactory;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\NullLogger;

#[CoversClass(StorageAdapterFactory::class)]
#[AllowMockObjectsWithoutExpectations]
final class StorageAdapterFactoryTest extends TestCase
{
    /**
     * @return iterable<string, array{string, class-string}>
     */
    public static function selections(): iterable
    {
        yield 'local' => ['local', LocalEncryptionAdapter::class];
        yield 'hashicorp' => ['hashicorp', HashiCorpAdapter::class];
        yield 'aws' => ['aws', AwsSecretsManagerAdapter::class];
    }

    /**
     * @param class-string $expected
     */
    #[Test]
    #[DataProvider('selections')]
    public function selectsTheAdapterNamedInTheConfiguration(string $setting, string $expected): void
    {
        self::assertInstanceOf($expected, $this->factory($setting)->create());
    }

    #[Test]
    public function awsNeverFallsBackToLocal(): void
    {
        self::assertNotInstanceOf(LocalEncryptionAdapter::class, $this->factory('aws')->create());
    }

    #[Test]
    public function refusesAValueThatNamesNoAdapter(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1703800016);

        $this->factory('hashicrop')->create();
    }

    private function factory(string $setting): StorageAdapterFactory
    {
        $configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $configuration->method('getStorageAdapter')->willReturn($setting);

        $local = new LocalEncryptionAdapter($this->createMock(SecretRepositoryInterface::class));

        return new StorageAdapterFactory(
            $configuration,
            $local,
            new HashiCorpAdapter(
                $local,
                $this->createMock(KvStoreInterface::class),
                $configuration,
                new InstallationMarker($this->createMock(MasterKeyProviderInterface::class)),
                new ExternalStoreJournal(),
                new NullLogger(),
            ),
            new AwsSecretsManagerAdapter($local, $this->createMock(AwsSecretStoreInterface::class), $configuration),
        );
    }
}
