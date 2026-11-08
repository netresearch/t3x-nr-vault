<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Netresearch\NrVault\Audit\AuditChainRekeyServiceInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\RotationGapScan;
use Netresearch\NrVault\Audit\RotationGapScannerInterface;
use Netresearch\NrVault\Command\VaultRotationGapRepairCommand;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Tests\Unit\TestCase;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * The paths that end before anything is read or changed. The repair itself
 * runs against a real database in the functional test of the same name.
 */
#[CoversClass(VaultRotationGapRepairCommand::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultRotationGapRepairCommandTest extends TestCase
{
    private const CURRENT_KEY = 'cccccccccccccccccccccccccccccccc';

    private const PREVIOUS_KEY = 'pppppppppppppppppppppppppppppppp';

    private const OPTION_OLD_KEY = '--old-key';

    private AccessControlServiceInterface&MockObject $accessControlService;

    private SecretRepositoryInterface&MockObject $secretRepository;

    private AuditLogServiceInterface&MockObject $auditLogService;

    private RotationGapScannerInterface&MockObject $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        vfsStream::setup('keys');

        $this->accessControlService = $this->createMock(AccessControlServiceInterface::class);
        $this->secretRepository     = $this->createMock(SecretRepositoryInterface::class);
        $this->auditLogService      = $this->createMock(AuditLogServiceInterface::class);
        $this->scanner              = $this->createMock(RotationGapScannerInterface::class);
    }

    #[Test]
    public function hasItsName(): void
    {
        self::assertSame('vault:rotation-gap-repair', $this->createCommand()->getName());
    }

    #[Test]
    public function refusesWithoutTheMasterKeyRotatePermission(): void
    {
        $this->accessControlService->expects(self::once())->method('isGranted')->with(VaultPermission::MasterKeyRotate)->willReturn(false);
        $this->scanner->expects(self::never())->method('scan');

        $tester = $this->execute([self::OPTION_OLD_KEY => $this->keyFile(self::PREVIOUS_KEY)]);

        self::assertSame(1, $tester->getStatusCode());
        self::assertStringContainsString('master_key.rotate', $tester->getDisplay());
    }

    #[Test]
    public function requiresTheOldKey(): void
    {
        $this->accessControlService->method('isGranted')->willReturn(true);
        $this->scanner->expects(self::never())->method('scan');

        $tester = $this->execute([]);

        self::assertSame(1, $tester->getStatusCode());
        self::assertStringContainsString('--old-key is required', $tester->getDisplay());
    }

    #[Test]
    public function refusesTheConfiguredKeyAsTheOldKey(): void
    {
        $this->accessControlService->method('isGranted')->willReturn(true);
        $this->scanner->expects(self::never())->method('scan');

        $tester = $this->execute([self::OPTION_OLD_KEY => $this->keyFile(self::CURRENT_KEY)]);

        self::assertSame(1, $tester->getStatusCode());
        self::assertStringContainsString('the configuration uses now', $tester->getDisplay());
    }

    #[Test]
    public function aRefusedDryRunWritesNoAuditRow(): void
    {
        $this->accessControlService->method('isGranted')->willReturn(true);
        $this->secretRepository->method('findIdentifiers')->willReturn([]);
        $this->scanner->method('scan')->willReturn(new RotationGapScan(problems: ['Row uid 7 verifies under neither key.']));
        $this->auditLogService->expects(self::never())->method('log');

        $tester = $this->execute([self::OPTION_OLD_KEY => $this->keyFile(self::PREVIOUS_KEY), '--dry-run' => true]);

        self::assertSame(1, $tester->getStatusCode());
        self::assertStringContainsString('Row uid 7 verifies under neither key.', $tester->getDisplay());
    }

    #[Test]
    public function aRefusedRepairLeavesAFailedAuditRow(): void
    {
        $this->accessControlService->method('isGranted')->willReturn(true);
        $this->secretRepository->method('findIdentifiers')->willReturn([]);
        $this->scanner->method('scan')->willReturn(new RotationGapScan(problems: ['Rows uid 4 to 4 are missing.']));
        $this->auditLogService->expects(self::once())->method('log')->with('__master_key__', 'audit_chain_rekey', false);

        $tester = $this->execute([self::OPTION_OLD_KEY => $this->keyFile(self::PREVIOUS_KEY), '--confirm' => true]);

        self::assertSame(1, $tester->getStatusCode());
    }

    #[Test]
    public function requiresConfirmationBeforeChangingAnything(): void
    {
        $this->accessControlService->method('isGranted')->willReturn(true);
        $this->secretRepository->method('findIdentifiers')->willReturn([]);
        $this->scanner->method('scan')->willReturn(new RotationGapScan(previousKeyRows: [
            ['uid' => 9, 'action' => 'read', 'secretIdentifier' => 'api-token', 'crdate' => 1_700_000_000],
        ]));
        $this->secretRepository->expects(self::never())->method('save');
        $this->auditLogService->expects(self::never())->method('log');

        $tester = $this->execute([self::OPTION_OLD_KEY => $this->keyFile(self::PREVIOUS_KEY)]);

        self::assertSame(1, $tester->getStatusCode());
        self::assertStringContainsString('--confirm', $tester->getDisplay());
        self::assertStringContainsString('api-token', $tester->getDisplay());
    }

    /**
     * @param array<string, mixed> $input
     */
    private function execute(array $input): CommandTester
    {
        $tester = new CommandTester($this->createCommand());
        $tester->execute($input);

        return $tester;
    }

    private function createCommand(): VaultRotationGapRepairCommand
    {
        $provider = self::createStub(MasterKeyProviderInterface::class);
        $provider->method('getMasterKey')->willReturn(self::CURRENT_KEY);

        return new VaultRotationGapRepairCommand(
            $this->accessControlService,
            $this->secretRepository,
            self::createStub(EncryptionServiceInterface::class),
            $provider,
            self::createStub(ConnectionPool::class),
            $this->auditLogService,
            self::createStub(AuditChainRekeyServiceInterface::class),
            $this->scanner,
        );
    }

    private function keyFile(string $content): string
    {
        $path = vfsStream::url('keys/old.key');
        file_put_contents($path, $content);

        return $path;
    }
}
