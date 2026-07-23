<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Netresearch\NrVault\Command\VaultListCommand;
use Netresearch\NrVault\Domain\Dto\SecretMetadata;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

#[CoversClass(VaultListCommand::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultListCommandTest extends TestCase
{
    private VaultServiceInterface&MockObject $vaultService;

    private CommandTester $commandTester;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);

        $command = new VaultListCommand($this->vaultService);

        $application = new Application();
        $application->addCommand($command);

        $this->commandTester = new CommandTester($command);
    }

    #[Test]
    public function hasCorrectName(): void
    {
        $command = new VaultListCommand($this->vaultService);

        self::assertSame('vault:list', $command->getName());
    }

    #[Test]
    public function showsInfoWhenNoSecretsFound(): void
    {
        $this->vaultService
            ->expects($this->once())
            ->method('list')
            ->with(null)
            ->willReturn([]);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('No secrets found', $this->commandTester->getDisplay());
    }

    #[Test]
    public function listsSecretsInTableFormat(): void
    {
        $secrets = [
            new SecretMetadata(
                identifier: 'api-key-1',
                ownerUid: 1,
                createdAt: 1704067200,
                updatedAt: 1704153600,
                readCount: 5,
                lastReadAt: 1704150000,
                description: 'Test secret',
                version: 1,
            ),
        ];

        $this->vaultService
            ->expects($this->once())
            ->method('list')
            ->with(null)
            ->willReturn($secrets);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('api-key-1', $display);
        self::assertStringContainsString('Total: 1 secrets', $display);
    }

    #[Test]
    public function filtersSecretsWithPattern(): void
    {
        $this->vaultService
            ->expects($this->once())
            ->method('list')
            ->with('api-*')
            ->willReturn([]);

        $this->commandTester->execute([
            '--pattern' => 'api-*',
        ]);
    }

    #[Test]
    public function outputsJsonFormat(): void
    {
        $secrets = [
            new SecretMetadata(
                identifier: 'test-secret',
                ownerUid: 1,
                createdAt: 1704067200,
                updatedAt: 1704153600,
                readCount: 0,
                lastReadAt: null,
                description: '',
                version: 1,
            ),
        ];

        $this->vaultService
            ->method('list')
            ->willReturn($secrets);

        $exitCode = $this->commandTester->execute([
            '--format' => 'json',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertJson($display);
        self::assertStringContainsString('"identifier": "test-secret"', $display);
    }

    #[Test]
    public function outputsCsvFormat(): void
    {
        $secrets = [
            new SecretMetadata(
                identifier: 'csv-test',
                ownerUid: 2,
                createdAt: 1704067200,
                updatedAt: 1704153600,
                readCount: 3,
                lastReadAt: 1704150000,
                description: '',
                version: 1,
            ),
        ];

        $this->vaultService
            ->method('list')
            ->willReturn($secrets);

        $exitCode = $this->commandTester->execute([
            '--format' => 'csv',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('identifier,owner_uid,created,updated,read_count,last_read', $display);
        self::assertStringContainsString('csv-test,2', $display);
    }

    #[Test]
    public function appliesLimitToResults(): void
    {
        $secrets = [];
        for ($i = 1; $i <= 10; $i++) {
            $secrets[] = new SecretMetadata(
                identifier: "secret-$i",
                ownerUid: 1,
                createdAt: 1704067200,
                updatedAt: 1704153600,
                readCount: 0,
                lastReadAt: null,
                description: '',
                version: 1,
            );
        }

        $this->vaultService
            ->method('list')
            ->willReturn($secrets);

        $exitCode = $this->commandTester->execute([
            '--limit' => '3',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('Total: 3 secrets', $display);
    }

    #[Test]
    public function handlesVaultException(): void
    {
        $this->vaultService
            ->method('list')
            ->willThrowException(new VaultException('Test error'));

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Test error', $this->commandTester->getDisplay());
    }

    #[Test]
    public function escapesSpecialCharactersInCsv(): void
    {
        $secrets = [
            new SecretMetadata(
                identifier: 'secret,with,commas',
                ownerUid: 1,
                createdAt: 1704067200,
                updatedAt: 1704153600,
                readCount: 0,
                lastReadAt: null,
                description: '',
                version: 1,
            ),
        ];

        $this->vaultService
            ->method('list')
            ->willReturn($secrets);

        $exitCode = $this->commandTester->execute([
            '--format' => 'csv',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        // CSV escaping wraps values with commas in quotes
        self::assertStringContainsString('"secret,with,commas"', $display);
    }

    #[Test]
    public function escapesQuotesInCsv(): void
    {
        $secrets = [
            new SecretMetadata(
                identifier: 'secret"with"quotes',
                ownerUid: 1,
                createdAt: 1704067200,
                updatedAt: 1704153600,
                readCount: 0,
                lastReadAt: null,
                description: '',
                version: 1,
            ),
        ];

        $this->vaultService
            ->method('list')
            ->willReturn($secrets);

        $exitCode = $this->commandTester->execute([
            '--format' => 'csv',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        // CSV escaping doubles quotes and wraps in quotes
        self::assertStringContainsString('"secret""with""quotes"', $display);
    }

    #[Test]
    public function listsMultipleSecretsInTable(): void
    {
        $secrets = [
            new SecretMetadata(
                identifier: 'secret-1',
                ownerUid: 1,
                createdAt: 1704067200,
                updatedAt: 1704153600,
                readCount: 1,
                lastReadAt: 1704150000,
                description: '',
                version: 1,
            ),
            new SecretMetadata(
                identifier: 'secret-2',
                ownerUid: 2,
                createdAt: 1704067200,
                updatedAt: 1704153600,
                readCount: 2,
                lastReadAt: null,
                description: '',
                version: 1,
            ),
        ];

        $this->vaultService
            ->method('list')
            ->willReturn($secrets);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('secret-1', $display);
        self::assertStringContainsString('secret-2', $display);
        self::assertStringContainsString('Total: 2 secrets', $display);
    }

    #[Test]
    public function zeroLimitReturnsAllSecrets(): void
    {
        $secrets = [];
        for ($i = 1; $i <= 5; $i++) {
            $secrets[] = new SecretMetadata(
                identifier: "secret-$i",
                ownerUid: 1,
                createdAt: 1704067200,
                updatedAt: 1704153600,
                readCount: 0,
                lastReadAt: null,
                description: '',
                version: 1,
            );
        }

        $this->vaultService
            ->method('list')
            ->willReturn($secrets);

        $exitCode = $this->commandTester->execute([
            '--limit' => '0',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('Total: 5 secrets', $display);
    }

    #[Test]
    public function outputsMultipleSecretsAsJsonArray(): void
    {
        $secrets = [
            new SecretMetadata(
                identifier: 'json-1',
                ownerUid: 1,
                createdAt: 1704067200,
                updatedAt: 1704153600,
                readCount: 0,
                lastReadAt: null,
                description: '',
                version: 1,
            ),
            new SecretMetadata(
                identifier: 'json-2',
                ownerUid: 1,
                createdAt: 1704067200,
                updatedAt: 1704153600,
                readCount: 0,
                lastReadAt: null,
                description: '',
                version: 1,
            ),
        ];

        $this->vaultService
            ->method('list')
            ->willReturn($secrets);

        $exitCode = $this->commandTester->execute([
            '--format' => 'json',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertJson($display);
        $data = json_decode($display, true);
        self::assertCount(2, $data);
        self::assertSame('json-1', $data[0]['identifier']);
        self::assertSame('json-2', $data[1]['identifier']);
    }

    #[Test]
    public function showsNeverReadIndicatorInTable(): void
    {
        $secrets = [
            new SecretMetadata(
                identifier: 'never-read',
                ownerUid: 1,
                createdAt: 1704067200,
                updatedAt: 1704153600,
                readCount: 0,
                lastReadAt: null,
                description: '',
                version: 1,
            ),
        ];

        $this->vaultService
            ->method('list')
            ->willReturn($secrets);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        // Last read shows "-" when never read
        self::assertStringContainsString('-', $display);
    }

    #[Test]
    public function outputCsvNeutralizesFormulaInIdentifier(): void
    {
        $secrets = [
            new SecretMetadata(
                identifier: '=cmd',
                ownerUid: 1,
                createdAt: 1704067200,
                updatedAt: 1704153600,
                readCount: 0,
                lastReadAt: null,
                description: '',
                version: 1,
            ),
        ];

        $this->vaultService
            ->method('list')
            ->willReturn($secrets);

        $exitCode = $this->commandTester->execute([
            '--format' => 'csv',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString("'=cmd", $display);
        self::assertStringNotContainsString("\n=cmd", $display);
    }
}
