<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service;

use Netresearch\NrVault\Crypto\MasterKeyProviderFactoryInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Exception\MasterKeyException;
use Netresearch\NrVault\Service\VaultHealthService;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Unit tests for the read-only master-key liveness probe.
 *
 * Two contracts are under test, and the second one is why the service exists:
 * the four booleans must describe what the probe found, and no failure detail
 * may travel out of it. Every failure path here asserts both — the status object
 * stays free of exception text (SEC-INJECTION-LEAK-2: the message can carry the
 * master-key file path) while the detail reaches PSR-3.
 */
#[CoversClass(VaultHealthService::class)]
final class VaultHealthServiceTest extends TestCase
{
    private LoggerInterface&MockObject $logger;

    protected function setUp(): void
    {
        parent::setUp();

        $this->logger = $this->createMock(LoggerInterface::class);
    }

    #[Test]
    public function reportsAHealthyVaultWhenTheKeyCanBeRead(): void
    {
        $factory = $this->factoryReturning(
            $this->provider(identifier: 'file', available: true, key: 'a-readable-master-key'),
        );

        $this->logger->expects(self::never())->method('warning');

        $status = (new VaultHealthService($factory, $this->logger))->checkHealth();

        self::assertTrue($status->masterKeyAvailable);
        self::assertTrue($status->encryptionWorking);
        self::assertFalse($status->hasIssues);
        self::assertSame('file', $status->masterKeyProvider);
    }

    /**
     * A provider that answers "available" and then hands back nothing is the
     * case a plain `isAvailable()` check reports as healthy — the probe exists
     * to catch exactly that.
     */
    #[Test]
    public function anEmptyKeyIsAnIssueEvenThoughTheProviderIsAvailable(): void
    {
        $factory = $this->factoryReturning($this->provider(identifier: 'env', available: true, key: ''));

        $this->logger->expects(self::once())
            ->method('warning')
            ->with(
                self::stringContains('empty key'),
                ['provider' => 'env'],
            );

        $status = (new VaultHealthService($factory, $this->logger))->checkHealth();

        self::assertTrue($status->masterKeyAvailable);
        self::assertFalse($status->encryptionWorking);
        self::assertTrue($status->hasIssues);
        self::assertSame('env', $status->masterKeyProvider);
    }

    #[Test]
    public function anUnreadableKeyIsAnIssueAndTheReasonReachesTheLogOnly(): void
    {
        $factory = $this->factoryReturning($this->provider(
            identifier: 'file',
            available: true,
            key: '',
            failure: new MasterKeyException('/var/secrets/master.key is not readable'),
        ));

        $this->logger->expects(self::once())
            ->method('warning')
            ->with(
                self::stringContains('could not be read'),
                [
                    'provider' => 'file',
                    'exception' => '/var/secrets/master.key is not readable',
                ],
            );

        $status = (new VaultHealthService($factory, $this->logger))->checkHealth();

        self::assertTrue($status->masterKeyAvailable);
        self::assertFalse($status->encryptionWorking);
        self::assertTrue($status->hasIssues);
        // The key path from the exception must not travel into the UI: the only
        // string the caller gets back is the provider identifier.
        self::assertSame('file', $status->masterKeyProvider);
    }

    #[Test]
    public function aConfiguredButUnavailableProviderIsAnIssue(): void
    {
        $provider = $this->createMock(MasterKeyProviderInterface::class);
        $provider->method('getIdentifier')->willReturn('typo3');
        $provider->method('isAvailable')->willReturn(false);
        // Reading the key of a provider that just said it has none would be a
        // pointless failure path — and, for the file provider, a stat of a path
        // that is not there.
        $provider->expects(self::never())->method('getMasterKey');

        $factory = $this->factoryReturning($provider);

        $this->logger->expects(self::once())
            ->method('warning')
            ->with(
                self::stringContains('not available'),
                ['provider' => 'typo3'],
            );

        $status = (new VaultHealthService($factory, $this->logger))->checkHealth();

        self::assertFalse($status->masterKeyAvailable);
        self::assertFalse($status->encryptionWorking);
        self::assertTrue($status->hasIssues);
        self::assertSame('typo3', $status->masterKeyProvider);
    }

    /**
     * No provider at all: the identifier stays empty because there is nothing to
     * name, and the configuration message — which in the hardened profile spells
     * out the rejected provider — is logged rather than returned.
     */
    #[Test]
    public function aFailingProviderFactoryIsAnIssueWithoutAProviderName(): void
    {
        $factory = self::createStub(MasterKeyProviderFactoryInterface::class);
        $factory->method('getAvailableProvider')
            ->willThrowException(new ConfigurationException('provider "typo3" is forbidden'));

        $this->logger->expects(self::once())
            ->method('warning')
            ->with(
                self::stringContains('no master key provider'),
                ['exception' => 'provider "typo3" is forbidden'],
            );

        $status = (new VaultHealthService($factory, $this->logger))->checkHealth();

        self::assertFalse($status->masterKeyAvailable);
        self::assertFalse($status->encryptionWorking);
        self::assertTrue($status->hasIssues);
        self::assertSame('', $status->masterKeyProvider);
    }

    private function factoryReturning(
        MasterKeyProviderInterface $provider,
    ): MasterKeyProviderFactoryInterface&Stub {
        $factory = self::createStub(MasterKeyProviderFactoryInterface::class);
        $factory->method('getAvailableProvider')->willReturn($provider);

        return $factory;
    }

    private function provider(
        string $identifier,
        bool $available,
        string $key,
        ?Throwable $failure = null,
    ): MasterKeyProviderInterface&Stub {
        $provider = self::createStub(MasterKeyProviderInterface::class);
        $provider->method('getIdentifier')->willReturn($identifier);
        $provider->method('isAvailable')->willReturn($available);

        if ($failure instanceof Throwable) {
            $provider->method('getMasterKey')->willThrowException($failure);
        } else {
            $provider->method('getMasterKey')->willReturn($key);
        }

        return $provider;
    }
}
