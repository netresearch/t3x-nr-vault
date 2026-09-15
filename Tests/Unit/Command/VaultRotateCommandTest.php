<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Netresearch\NrVault\Command\VaultRotateCommand;
use Netresearch\NrVault\Domain\Dto\SecretDetails;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

#[CoversClass(VaultRotateCommand::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultRotateCommandTest extends TestCase
{
    private VaultServiceInterface&MockObject $vaultService;

    private CommandTester $commandTester;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);

        $command = new VaultRotateCommand($this->vaultService);

        $application = new Application();
        $application->addCommand($command);

        $this->commandTester = new CommandTester($command);
    }

    #[Test]
    public function hasCorrectName(): void
    {
        $command = new VaultRotateCommand($this->vaultService);

        self::assertSame('vault:rotate', $command->getName());
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
            '--value' => 'new-secret',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Secret not found', $this->commandTester->getDisplay());
    }

    #[Test]
    public function rotatesSecretWithValueOption(): void
    {
        $this->vaultService
            ->method('getMetadata')
            ->willReturn($this->createSecretDetails('my-secret'));

        $this->vaultService
            ->expects($this->once())
            ->method('rotate')
            ->with('my-secret', 'new-secret-value', 'Manual rotation via CLI');

        $exitCode = $this->commandTester->execute([
            'identifier' => 'my-secret',
            '--value' => 'new-secret-value',
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('rotated successfully', $this->commandTester->getDisplay());
    }

    #[Test]
    public function rotatesSecretWithCustomReason(): void
    {
        $this->vaultService
            ->method('getMetadata')
            ->willReturn($this->createSecretDetails('rotated'));

        $this->vaultService
            ->expects($this->once())
            ->method('rotate')
            ->with('rotated', 'new-value', 'Security incident');

        $exitCode = $this->commandTester->execute([
            'identifier' => 'rotated',
            '--value' => 'new-value',
            '--reason' => 'Security incident',
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function rotatesSecretFromFile(): void
    {
        $root = vfsStream::setup('test');
        vfsStream::newFile('new-secret.txt')
            ->withContent('file-based-secret')
            ->at($root);

        $this->vaultService
            ->method('getMetadata')
            ->willReturn($this->createSecretDetails('file-rotate'));

        $this->vaultService
            ->expects($this->once())
            ->method('rotate')
            ->with('file-rotate', 'file-based-secret', 'Manual rotation via CLI');

        $exitCode = $this->commandTester->execute([
            'identifier' => 'file-rotate',
            '--file' => vfsStream::url('test/new-secret.txt'),
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function failsWhenNoNewValueProvided(): void
    {
        $this->vaultService
            ->method('getMetadata')
            ->willReturn($this->createSecretDetails('no-value'));

        $exitCode = $this->commandTester->execute(
            ['identifier' => 'no-value'],
            ['interactive' => false],
        );

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('No new secret value provided', $this->commandTester->getDisplay());
    }

    #[Test]
    public function failsWhenFileNotFound(): void
    {
        $this->vaultService
            ->method('getMetadata')
            ->willReturn($this->createSecretDetails('file-missing'));

        $exitCode = $this->commandTester->execute([
            'identifier' => 'file-missing',
            '--file' => '/nonexistent/file.txt',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('File not found', $this->commandTester->getDisplay());
    }

    #[Test]
    public function handlesSecretNotFoundException(): void
    {
        $this->vaultService
            ->method('getMetadata')
            ->willReturn($this->createSecretDetails('gone'));

        $this->vaultService
            ->method('rotate')
            ->willThrowException(SecretNotFoundException::forIdentifier('gone'));

        $exitCode = $this->commandTester->execute([
            'identifier' => 'gone',
            '--value' => 'new-value',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('not found', $this->commandTester->getDisplay());
    }

    #[Test]
    public function handlesVaultException(): void
    {
        $this->vaultService
            ->method('getMetadata')
            ->willReturn($this->createSecretDetails('error'));

        $this->vaultService
            ->method('rotate')
            ->willThrowException(new VaultException('Rotation failed'));

        $exitCode = $this->commandTester->execute([
            'identifier' => 'error',
            '--value' => 'new-value',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Rotation failed', $this->commandTester->getDisplay());
    }

    #[Test]
    public function displaysRotationDetails(): void
    {
        $this->vaultService
            ->method('getMetadata')
            ->willReturn($this->createSecretDetails('show-details'));

        $this->vaultService
            ->method('rotate');

        $this->commandTester->execute([
            'identifier' => 'show-details',
            '--value' => 'new-value',
            '--reason' => 'Scheduled rotation',
        ]);

        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('show-details', $display);
        self::assertStringContainsString('Scheduled rotation', $display);
        self::assertStringContainsString('Rotated at', $display);
    }

    private function createSecretDetails(string $identifier): SecretDetails
    {
        return new SecretDetails(
            uid: 1,
            identifier: $identifier,
            description: 'Test secret',
            ownerUid: 1,
            groups: [],
            context: 'default',
            frontendAccessible: false,
            version: 1,
            createdAt: 1704067200,
            updatedAt: 1704067200,
            expiresAt: null,
            lastRotatedAt: null,
            readCount: 0,
            lastReadAt: null,
            metadata: [],
            scopePid: 0,
        );
    }
}
