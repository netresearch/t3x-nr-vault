<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Netresearch\NrVault\Command\VaultInitCommand;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Utility\GeneralUtility;

#[CoversClass(VaultInitCommand::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultInitCommandTest extends TestCase
{
    private const MASTER_KEY_PATH = 'vault/master.key';

    private ExtensionConfigurationInterface&MockObject $configuration;

    private CommandTester $commandTester;

    /** @var list<string> */
    private array $tempPaths = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->configuration = $this->createMock(ExtensionConfigurationInterface::class);

        $command = new VaultInitCommand($this->configuration);

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
        $command = new VaultInitCommand($this->configuration);

        self::assertSame('vault:init', $command->getName());
    }

    #[Test]
    public function succeedsWithTypo3Provider(): void
    {
        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('typo3');

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('No initialization needed', $display);
        self::assertStringContainsString('TYPO3 encryption key', $display);
    }

    #[Test]
    public function generatesKeyAsEnvironmentVariable(): void
    {
        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('env');

        $exitCode = $this->commandTester->execute([
            '--env' => true,
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('export TYPO3_VAULT_MASTER_KEY', $display);
        self::assertStringContainsString('Store this key securely', $display);
    }

    #[Test]
    public function generatesKeyToFile(): void
    {
        vfsStream::setup('vault');

        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('file');

        $this->configuration
            ->method('getMasterKeySource')
            ->willReturn('');

        $outputFile = vfsStream::url(self::MASTER_KEY_PATH);

        $exitCode = $this->commandTester->execute([
            '--output' => $outputFile,
        ]);

        self::assertSame(0, $exitCode);
        self::assertFileExists($outputFile);
        // Key should be 32 bytes (SODIUM_CRYPTO_SECRETBOX_KEYBYTES)
        self::assertSame(32, \strlen(file_get_contents($outputFile)));
        self::assertStringContainsString('generated and saved', $this->commandTester->getDisplay());
    }

    #[Test]
    public function failsIfKeyExistsWithoutForce(): void
    {
        $root = vfsStream::setup('vault');
        vfsStream::newFile('master.key')
            ->withContent(str_repeat('x', 32))
            ->at($root);

        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('file');

        $outputFile = vfsStream::url(self::MASTER_KEY_PATH);

        $exitCode = $this->commandTester->execute([
            '--output' => $outputFile,
        ]);

        self::assertSame(1, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('already exists', $display);
        self::assertStringContainsString('--force', $display);
    }

    #[Test]
    public function overwritesKeyWithForce(): void
    {
        $root = vfsStream::setup('vault');
        vfsStream::newFile('master.key')
            ->withContent(str_repeat('x', 32))
            ->at($root);

        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('file');

        $outputFile = vfsStream::url(self::MASTER_KEY_PATH);

        $exitCode = $this->commandTester->execute([
            '--output' => $outputFile,
            '--force' => true,
        ]);

        self::assertSame(0, $exitCode);
        // Should have a new key (different from original)
        self::assertNotSame(str_repeat('x', 32), file_get_contents($outputFile));
    }

    #[Test]
    public function usesConfiguredSourcePath(): void
    {
        vfsStream::setup('vault');

        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('file');

        $this->configuration
            ->method('getMasterKeySource')
            ->willReturn(vfsStream::url('vault/configured.key'));

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        self::assertFileExists(vfsStream::url('vault/configured.key'));
    }

    #[Test]
    public function createsDirectoryIfNeeded(): void
    {
        vfsStream::setup('vault');

        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('file');

        $outputFile = vfsStream::url('vault/subdir/master.key');

        $exitCode = $this->commandTester->execute([
            '--output' => $outputFile,
        ]);

        self::assertSame(0, $exitCode);
        self::assertFileExists($outputFile);
    }

    #[Test]
    public function displaysSecurityInformation(): void
    {
        vfsStream::setup('vault');

        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('file');

        $exitCode = $this->commandTester->execute([
            '--output' => vfsStream::url(self::MASTER_KEY_PATH),
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('IMPORTANT SECURITY NOTES', $display);
        self::assertStringContainsString('Back up this key', $display);
        self::assertStringContainsString('XSalsa20-Poly1305', $display);
    }

    #[Test]
    public function generatesKeyToFileWithRestrictivePermissions(): void
    {
        $this->configuration->method('getMasterKeyProvider')->willReturn('file');
        $this->configuration->method('getMasterKeySource')->willReturn('');

        $outputFile = $this->createTempDir() . '/master.key';

        $previousUmask = umask(0o000);

        try {
            $exitCode = $this->commandTester->execute(['--output' => $outputFile]);
        } finally {
            umask($previousUmask);
        }

        self::assertSame(0, $exitCode);
        self::assertFileExists($outputFile);
        self::assertSame(0o600, fileperms($outputFile) & 0o777);
    }

    #[Test]
    public function overwritesExistingKeyFileAndTightensPermissions(): void
    {
        $this->configuration->method('getMasterKeyProvider')->willReturn('file');

        $outputFile = $this->createTempDir() . '/master.key';
        file_put_contents($outputFile, str_repeat('x', 32));
        chmod($outputFile, 0o644);

        $exitCode = $this->commandTester->execute([
            '--output' => $outputFile,
            '--force' => true,
        ]);

        self::assertSame(0, $exitCode);
        self::assertSame(0o600, fileperms($outputFile) & 0o777);
    }

    private function createTempDir(): string
    {
        $dir = sys_get_temp_dir() . '/nr-vault-init-' . bin2hex(random_bytes(6));
        mkdir($dir, 0o700);
        $this->tempPaths[] = $dir;

        return $dir;
    }
}
