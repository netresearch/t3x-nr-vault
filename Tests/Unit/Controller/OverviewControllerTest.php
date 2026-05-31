<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Controller;

use Netresearch\NrVault\Controller\OverviewController;
use Netresearch\NrVault\Service\VaultHealthServiceInterface;
use Netresearch\NrVault\Service\VaultHealthStatus;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use ReflectionClass;

/**
 * Unit tests for OverviewController health checks.
 *
 * The master-key liveness probe no longer lives in the controller: it was
 * extracted into {@see VaultHealthServiceInterface} so the presentation layer
 * does not depend on the Crypto namespace (ARCHITECTURE-2). The controller's
 * private getHealthChecks() now merely projects a {@see VaultHealthStatus}
 * onto the array shape the Fluid template consumes. These tests exercise that
 * projection through the interface seam (a mocked VaultHealthServiceInterface),
 * not via reflection on a removed property.
 *
 * Because the SUT is excluded from unit coverage in Build/phpunit.xml (its
 * indexAction is covered functionally), we mark this test as `CoversNothing`
 * so PHPUnit 12 does not raise "Class X is not a valid target for code
 * coverage" warnings that `failOnWarning=true` would promote to errors.
 */
#[CoversNothing]
#[AllowMockObjectsWithoutExpectations]
final class OverviewControllerTest extends TestCase
{
    private VaultHealthServiceInterface&MockObject $vaultHealthService;

    private OverviewController $subject;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultHealthService = $this->createMock(VaultHealthServiceInterface::class);

        // Build the controller without invoking its constructor (it pulls in
        // final readonly TYPO3 services we don't need here), then inject only
        // the health-service seam that getHealthChecks() consults.
        $reflection = new ReflectionClass(OverviewController::class);
        $this->subject = $reflection->newInstanceWithoutConstructor();

        $serviceProperty = $reflection->getProperty('vaultHealthService');
        $serviceProperty->setValue($this->subject, $this->vaultHealthService);
    }

    #[Test]
    public function healthChecksReportGreenWhenStatusIsHealthy(): void
    {
        $this->vaultHealthService
            ->method('checkHealth')
            ->willReturn(new VaultHealthStatus(
                masterKeyAvailable: true,
                masterKeyProvider: 'file',
                encryptionWorking: true,
                hasIssues: false,
            ));

        $result = $this->invokeGetHealthChecks();

        self::assertTrue($result['masterKeyAvailable']);
        self::assertTrue($result['encryptionWorking']);
        self::assertFalse($result['hasIssues']);
        self::assertSame('file', $result['masterKeyProvider']);
    }

    #[Test]
    public function healthChecksReportIssuesWhenNoProviderAvailable(): void
    {
        // VaultHealthService swallows the "no provider" failure into a status
        // with an empty provider id and hasIssues=true (no raw error leaks to
        // the view — SEC-INJECTION-LEAK-2).
        $this->vaultHealthService
            ->method('checkHealth')
            ->willReturn(new VaultHealthStatus(
                masterKeyAvailable: false,
                masterKeyProvider: '',
                encryptionWorking: false,
                hasIssues: true,
            ));

        $result = $this->invokeGetHealthChecks();

        self::assertFalse($result['masterKeyAvailable']);
        self::assertFalse($result['encryptionWorking']);
        self::assertTrue($result['hasIssues']);
        self::assertSame('', $result['masterKeyProvider']);
    }

    #[Test]
    public function healthChecksReportIssuesWhenProviderConfiguredButUnavailable(): void
    {
        // Provider is known (identifier surfaces) but not usable.
        $this->vaultHealthService
            ->method('checkHealth')
            ->willReturn(new VaultHealthStatus(
                masterKeyAvailable: false,
                masterKeyProvider: 'env',
                encryptionWorking: false,
                hasIssues: true,
            ));

        $result = $this->invokeGetHealthChecks();

        self::assertFalse($result['masterKeyAvailable']);
        self::assertFalse($result['encryptionWorking']);
        self::assertTrue($result['hasIssues']);
        self::assertSame('env', $result['masterKeyProvider']);
    }

    #[Test]
    public function healthChecksReportIssuesWhenKeyAvailableButEncryptionBroken(): void
    {
        // Master key provider is available but reading/deriving the key fails:
        // masterKeyAvailable stays true, encryptionWorking flips false.
        $this->vaultHealthService
            ->method('checkHealth')
            ->willReturn(new VaultHealthStatus(
                masterKeyAvailable: true,
                masterKeyProvider: 'file',
                encryptionWorking: false,
                hasIssues: true,
            ));

        $result = $this->invokeGetHealthChecks();

        self::assertTrue($result['masterKeyAvailable']);
        self::assertFalse($result['encryptionWorking']);
        self::assertTrue($result['hasIssues']);
        self::assertSame('file', $result['masterKeyProvider']);
    }

    #[Test]
    public function healthChecksExposeOnlyGenericBooleansAndProviderId(): void
    {
        // Guard SEC-INJECTION-LEAK-2: the projection must not introduce any
        // error-text keys — the array shape is exactly the four generic fields.
        $this->vaultHealthService
            ->method('checkHealth')
            ->willReturn(new VaultHealthStatus(
                masterKeyAvailable: true,
                masterKeyProvider: 'file',
                encryptionWorking: true,
                hasIssues: false,
            ));

        $result = $this->invokeGetHealthChecks();

        self::assertSame(
            ['masterKeyAvailable', 'masterKeyProvider', 'encryptionWorking', 'hasIssues'],
            array_keys($result),
        );
    }

    /**
     * Invoke the private getHealthChecks() method via reflection.
     *
     * @return array{masterKeyAvailable: bool, masterKeyProvider: string, encryptionWorking: bool, hasIssues: bool}
     */
    private function invokeGetHealthChecks(): array
    {
        $method = (new ReflectionClass(OverviewController::class))->getMethod('getHealthChecks');

        /** @var array{masterKeyAvailable: bool, masterKeyProvider: string, encryptionWorking: bool, hasIssues: bool} */
        return $method->invoke($this->subject);
    }
}
