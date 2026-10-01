<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Netresearch\NrVault\Command\VaultScanCommand;
use Netresearch\NrVault\Service\Detection\ConfigSecretFinding;
use Netresearch\NrVault\Service\Detection\DatabaseSecretFinding;
use Netresearch\NrVault\Service\Detection\Severity;
use Netresearch\NrVault\Service\SecretDetectionServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

#[CoversClass(VaultScanCommand::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultScanCommandTest extends TestCase
{
    private SecretDetectionServiceInterface&MockObject $detectionService;

    private CommandTester $commandTester;

    protected function setUp(): void
    {
        parent::setUp();

        $this->detectionService = $this->createMock(SecretDetectionServiceInterface::class);

        $command = new VaultScanCommand($this->detectionService);

        $application = new Application();
        $application->addCommand($command);

        $this->commandTester = new CommandTester($command);
    }

    #[Test]
    public function hasCorrectName(): void
    {
        $command = new VaultScanCommand($this->detectionService);

        self::assertSame('vault:scan', $command->getName());
    }

    #[Test]
    public function showsSuccessWhenNoSecretsFound(): void
    {
        $this->detectionService
            ->expects($this->once())
            ->method('scan')
            ->with([]);

        $this->detectionService
            ->method('getDetectedSecretsBySeverity')
            ->willReturn([]);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('No potential plaintext secrets detected', $this->commandTester->getDisplay());
    }

    #[Test]
    public function scansWithExcludedTables(): void
    {
        $this->detectionService
            ->expects($this->once())
            ->method('scan')
            ->with(['tx_cache', 'tx_temp']);

        $this->detectionService
            ->method('getDetectedSecretsBySeverity')
            ->willReturn([]);

        $this->commandTester->execute([
            '--exclude' => 'tx_cache, tx_temp',
        ]);
    }

    #[Test]
    public function outputsTableFormat(): void
    {
        $finding = new DatabaseSecretFinding(
            table: 'be_users',
            column: 'api_key',
            recordCount: 10,
            plaintextCount: 5,
            severity: Severity::High,
            patterns: ['API Key'],
        );

        $this->detectionService
            ->method('scan');

        $this->detectionService
            ->method('getDetectedSecretsBySeverity')
            ->willReturn([
                'high' => [$finding->getKey() => $finding],
            ]);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('HIGH', $display);
        self::assertStringContainsString('be_users', $display);
    }

    #[Test]
    public function outputsJsonFormat(): void
    {
        $finding = new ConfigSecretFinding(
            path: 'MAIL/smtp_password',
            severity: Severity::Critical,
            isLocalConfiguration: true,
        );

        $this->detectionService
            ->method('scan');

        $this->detectionService
            ->method('getDetectedSecretsBySeverity')
            ->willReturn([
                'critical' => [$finding->getKey() => $finding],
            ]);

        $exitCode = $this->commandTester->execute([
            '--format' => 'json',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();

        // Extract JSON from output (output includes title text before JSON)
        self::assertMatchesRegularExpression('/\{[^}]+\}/', $display);
        preg_match('/(\{.*\})/s', $display, $matches);
        self::assertArrayHasKey(1, $matches);

        $decoded = json_decode($matches[1], true);
        self::assertIsArray($decoded);
        self::assertArrayHasKey('critical', $decoded);
        self::assertIsArray($decoded['critical']);
        self::assertNotSame([], $decoded['critical']);

        // The key is "config:MAIL/smtp_password", check any entry has the path
        $finding = reset($decoded['critical']);
        self::assertSame('MAIL/smtp_password', $finding['path']);
    }

    #[Test]
    public function outputsSummaryFormat(): void
    {
        $finding = new DatabaseSecretFinding(
            table: 'tx_myext',
            column: 'secret',
            recordCount: 1,
            plaintextCount: 1,
            severity: Severity::Medium,
        );

        $this->detectionService
            ->method('scan');

        $this->detectionService
            ->method('getDetectedSecretsBySeverity')
            ->willReturn([
                'medium' => [$finding->getKey() => $finding],
            ]);

        $exitCode = $this->commandTester->execute([
            '--format' => 'summary',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('Summary', $display);
        self::assertStringContainsString('Medium', $display);
    }

    #[Test]
    public function filtersBySeverity(): void
    {
        $lowFinding = new DatabaseSecretFinding(
            table: 'tx_low',
            column: 'field',
            recordCount: 1,
            plaintextCount: 1,
            severity: Severity::Low,
        );

        $highFinding = new DatabaseSecretFinding(
            table: 'tx_high',
            column: 'password',
            recordCount: 1,
            plaintextCount: 1,
            severity: Severity::High,
        );

        $this->detectionService
            ->method('scan');

        $this->detectionService
            ->method('getDetectedSecretsBySeverity')
            ->willReturn([
                'high' => [$highFinding->getKey() => $highFinding],
                'low' => [$lowFinding->getKey() => $lowFinding],
            ]);

        $exitCode = $this->commandTester->execute([
            '--severity' => 'high',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('tx_high', $display);
        self::assertStringNotContainsString('tx_low', $display);
    }

    #[Test]
    public function scansDatabaseOnly(): void
    {
        $this->detectionService
            ->expects($this->once())
            ->method('scanDatabaseTables')
            ->with([]);

        $this->detectionService
            ->expects($this->never())
            ->method('scanExtensionConfiguration');

        $this->detectionService
            ->method('getDetectedSecretsBySeverity')
            ->willReturn([]);

        $this->commandTester->execute([
            '--database-only' => true,
        ]);
    }

    #[Test]
    public function scansConfigOnly(): void
    {
        $this->detectionService
            ->expects($this->never())
            ->method('scanDatabaseTables');

        $this->detectionService
            ->expects($this->once())
            ->method('scanExtensionConfiguration');

        $this->detectionService
            ->expects($this->once())
            ->method('scanLocalConfiguration');

        $this->detectionService
            ->method('getDetectedSecretsBySeverity')
            ->willReturn([]);

        $this->commandTester->execute([
            '--config-only' => true,
        ]);
    }

    #[Test]
    public function failsWithBothDatabaseAndConfigOnlyOptions(): void
    {
        $exitCode = $this->commandTester->execute([
            '--database-only' => true,
            '--config-only' => true,
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Cannot use both', $this->commandTester->getDisplay());
    }

    #[Test]
    public function displaysWarningWhenSecretsFound(): void
    {
        $finding = new DatabaseSecretFinding(
            table: 'tx_myext',
            column: 'api_key',
            recordCount: 5,
            plaintextCount: 3,
            severity: Severity::High,
        );

        $this->detectionService
            ->method('scan');

        $this->detectionService
            ->method('getDetectedSecretsBySeverity')
            ->willReturn([
                'high' => [$finding->getKey() => $finding],
            ]);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('Found 1 potential plaintext secret', $display);
        self::assertStringContainsString('vault:migrate-field', $display);
    }
}
