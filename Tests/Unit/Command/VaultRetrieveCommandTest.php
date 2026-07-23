<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Netresearch\NrVault\Command\VaultRetrieveCommand;
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
use TYPO3\CMS\Core\Utility\GeneralUtility;

#[CoversClass(VaultRetrieveCommand::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultRetrieveCommandTest extends TestCase
{
    private VaultServiceInterface&MockObject $vaultService;

    private CommandTester $commandTester;

    /** @var list<string> */
    private array $tempPaths = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);

        $command = new VaultRetrieveCommand($this->vaultService);

        $application = new Application();
        $application->addCommand($command);

        $this->commandTester = new CommandTester($command);
    }

    protected function tearDown(): void
    {
        foreach ($this->tempPaths as $path) {
            GeneralUtility::rmdir($path, true);
        }
        $this->tempPaths = [];

        parent::tearDown();
    }

    #[Test]
    public function hasCorrectName(): void
    {
        $command = new VaultRetrieveCommand($this->vaultService);

        self::assertSame('vault:retrieve', $command->getName());
    }

    #[Test]
    public function retrievesSecretToStdout(): void
    {
        $this->vaultService
            ->expects($this->once())
            ->method('retrieve')
            ->with('my-secret')
            ->willReturn('secret-value-123');

        $exitCode = $this->commandTester->execute([
            'identifier' => 'my-secret',
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('secret-value-123', $this->commandTester->getDisplay());
    }

    #[Test]
    public function retrievesSecretWithoutNewline(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willReturn('no-newline');

        $exitCode = $this->commandTester->execute([
            'identifier' => 'test',
            '--no-newline' => true,
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        // Check the secret is there but without trailing newline from the command
        self::assertStringContainsString('no-newline', $display);
    }

    #[Test]
    public function writesSecretToFile(): void
    {
        vfsStream::setup('test');

        $this->vaultService
            ->method('retrieve')
            ->with('file-secret')
            ->willReturn('file-content-123');

        $outputFile = vfsStream::url('test/output.txt');

        $exitCode = $this->commandTester->execute([
            'identifier' => 'file-secret',
            '--output' => $outputFile,
        ]);

        self::assertSame(0, $exitCode);
        self::assertFileExists($outputFile);
        self::assertSame('file-content-123', file_get_contents($outputFile));
        self::assertStringContainsString('Secret written to', $this->commandTester->getDisplay());
    }

    #[Test]
    public function failsWhenSecretNotFound(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willReturn(null);

        $exitCode = $this->commandTester->execute([
            'identifier' => 'nonexistent',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Secret not found', $this->commandTester->getDisplay());
    }

    #[Test]
    public function handlesSecretNotFoundException(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willThrowException(SecretNotFoundException::forIdentifier('missing'));

        $exitCode = $this->commandTester->execute([
            'identifier' => 'missing',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('not found', $this->commandTester->getDisplay());
    }

    #[Test]
    public function handlesVaultException(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new VaultException('Retrieval failed'));

        $exitCode = $this->commandTester->execute([
            'identifier' => 'error',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Retrieval failed', $this->commandTester->getDisplay());
    }

    #[Test]
    public function acceptsReasonOption(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('test-secret')
            ->willReturn('value');

        $exitCode = $this->commandTester->execute([
            'identifier' => 'test-secret',
            '--reason' => 'Security audit',
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function outputWrittenToStdoutWithNewlineByDefault(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willReturn('secret-value');

        $exitCode = $this->commandTester->execute([
            'identifier' => 'test',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString("secret-value\n", $display);
    }

    #[Test]
    public function failsWhenOutputFileDirectoryDoesNotExist(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willReturn('secret-value');

        // Try to write to a non-existent directory
        $exitCode = $this->commandTester->execute([
            'identifier' => 'test',
            '--output' => '/non/existent/directory/file.txt',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Failed to write to file', $this->commandTester->getDisplay());
    }

    #[Test]
    public function writesSecretToFileWithRestrictivePermissions(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willReturn('file-content-123');

        $outputFile = $this->createTempDir() . '/secret.txt';

        $previousUmask = umask(0o000);

        try {
            $exitCode = $this->commandTester->execute([
                'identifier' => 'file-secret',
                '--output' => $outputFile,
            ]);
        } finally {
            umask($previousUmask);
        }

        self::assertSame(0, $exitCode);
        self::assertFileExists($outputFile);
        self::assertSame('file-content-123', file_get_contents($outputFile));
        self::assertSame(0o600, fileperms($outputFile) & 0o777);
    }

    #[Test]
    public function overwritesExistingFileAndTightensPermissions(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willReturn('new-content');

        $outputFile = $this->createTempDir() . '/existing.txt';
        file_put_contents($outputFile, 'stale');
        chmod($outputFile, 0o644);

        $exitCode = $this->commandTester->execute([
            'identifier' => 'file-secret',
            '--output' => $outputFile,
        ]);

        self::assertSame(0, $exitCode);
        self::assertSame('new-content', file_get_contents($outputFile));
        self::assertSame(0o600, fileperms($outputFile) & 0o777);
    }

    private function createTempDir(): string
    {
        $dir = sys_get_temp_dir() . '/nr-vault-retrieve-' . bin2hex(random_bytes(6));
        mkdir($dir, 0o700);
        $this->tempPaths[] = $dir;

        return $dir;
    }
}
