<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Netresearch\NrVault\Command\VaultDeleteCommand;
use Netresearch\NrVault\Domain\Dto\SecretDetails;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

#[CoversClass(VaultDeleteCommand::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultDeleteCommandTest extends TestCase
{
    private VaultServiceInterface&MockObject $vaultService;

    private CommandTester $commandTester;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);

        $command = new VaultDeleteCommand($this->vaultService);

        $application = new Application();
        $application->addCommand($command);

        $this->commandTester = new CommandTester($command);
    }

    #[Test]
    public function hasCorrectName(): void
    {
        $command = new VaultDeleteCommand($this->vaultService);

        self::assertSame('vault:delete', $command->getName());
    }

    #[Test]
    public function failsWhenSecretNotFound(): void
    {
        $this->vaultService
            ->expects(self::atLeastOnce())
            ->method('getMetadata')
            ->with('nonexistent')
            ->willThrowException(SecretNotFoundException::forIdentifier('nonexistent'));

        $exitCode = $this->commandTester->execute([
            'identifier' => 'nonexistent',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Secret not found', $this->commandTester->getDisplay());
    }

    #[Test]
    public function deletesSecretWhenConfirmed(): void
    {
        $this->vaultService
            ->expects(self::atLeastOnce())
            ->method('getMetadata')
            ->with('to-delete')
            ->willReturn($this->createSecretDetails(
                identifier: 'to-delete',
                createdAt: 1704067200,
                readCount: 5,
                lastReadAt: 1704150000,
            ));

        $this->vaultService
            ->expects($this->once())
            ->method('delete')
            ->with('to-delete', 'Manual deletion via CLI');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'identifier' => 'to-delete',
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('deleted successfully', $this->commandTester->getDisplay());
    }

    #[Test]
    public function deletesSecretWithForceOption(): void
    {
        $this->vaultService
            ->method('getMetadata')
            ->willReturn($this->createSecretDetails(
                identifier: 'force-delete',
                createdAt: 1704067200,
            ));

        $this->vaultService
            ->expects($this->once())
            ->method('delete')
            ->with('force-delete', 'Forced deletion');

        $exitCode = $this->commandTester->execute([
            'identifier' => 'force-delete',
            '--force' => true,
            '--reason' => 'Forced deletion',
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function cancelsWhenNotConfirmed(): void
    {
        $this->vaultService
            ->method('getMetadata')
            ->willReturn($this->createSecretDetails(
                identifier: 'cancelled',
                createdAt: 1704067200,
            ));

        $this->vaultService
            ->expects($this->never())
            ->method('delete');

        $this->commandTester->setInputs(['no']);
        $exitCode = $this->commandTester->execute([
            'identifier' => 'cancelled',
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('cancelled', $this->commandTester->getDisplay());
    }

    #[Test]
    public function handlesSecretNotFoundException(): void
    {
        $this->vaultService
            ->method('getMetadata')
            ->willReturn($this->createSecretDetails(
                identifier: 'gone',
                createdAt: 1704067200,
            ));

        $this->vaultService
            ->method('delete')
            ->willThrowException(SecretNotFoundException::forIdentifier('gone'));

        $exitCode = $this->commandTester->execute([
            'identifier' => 'gone',
            '--force' => true,
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('not found', $this->commandTester->getDisplay());
    }

    #[Test]
    public function handlesVaultException(): void
    {
        $this->vaultService
            ->method('getMetadata')
            ->willReturn($this->createSecretDetails(
                identifier: 'error',
                createdAt: 1704067200,
            ));

        $this->vaultService
            ->method('delete')
            ->willThrowException(new VaultException('Delete failed'));

        $exitCode = $this->commandTester->execute([
            'identifier' => 'error',
            '--force' => true,
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Delete failed', $this->commandTester->getDisplay());
    }

    #[Test]
    public function displaysSecretMetadataBeforeDeletion(): void
    {
        $this->vaultService
            ->method('getMetadata')
            ->willReturn($this->createSecretDetails(
                identifier: 'show-metadata',
                createdAt: 1704067200,
                readCount: 10,
                lastReadAt: 1704150000,
            ));

        $this->commandTester->setInputs(['no']);
        $this->commandTester->execute([
            'identifier' => 'show-metadata',
        ]);

        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('Secret to be deleted', $display);
        self::assertStringContainsString('show-metadata', $display);
        self::assertStringContainsString('10', $display);
    }

    private function createSecretDetails(
        string $identifier = 'test-secret',
        int $createdAt = 1704067200,
        int $readCount = 0,
        ?int $lastReadAt = null,
    ): SecretDetails {
        return new SecretDetails(
            uid: 1,
            identifier: $identifier,
            description: 'Test secret',
            ownerUid: 1,
            groups: [],
            context: 'default',
            frontendAccessible: false,
            version: 1,
            createdAt: $createdAt,
            updatedAt: $createdAt,
            expiresAt: null,
            lastRotatedAt: null,
            readCount: $readCount,
            lastReadAt: $lastReadAt,
            metadata: [],
            scopePid: 0,
        );
    }
}
