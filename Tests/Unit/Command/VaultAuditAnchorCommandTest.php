<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Command\VaultAuditAnchorCommand;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The operation-permission gate on `vault:audit-anchor`.
 *
 * Publishing an anchor mutates tamper evidence: an actor who truncates the log
 * and then anchors makes the external sink attest the truncated chain. So the
 * command asserts `vault.configure` — the same permission `vault:audit
 * --reset-anchor` asserts for the other half of the anchor lifecycle.
 */
#[CoversClass(VaultAuditAnchorCommand::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultAuditAnchorCommandTest extends TestCase
{
    private ChainTipAnchorServiceInterface&MockObject $anchorService;

    private AuditSinkRegistryInterface&MockObject $sinkRegistry;

    private AccessControlServiceInterface&MockObject $accessControlService;

    /** @var list<VaultPermission> */
    private array $grantedPermissions = [];

    private CommandTester $commandTester;

    protected function setUp(): void
    {
        parent::setUp();

        $this->anchorService = $this->createMock(ChainTipAnchorServiceInterface::class);
        $this->sinkRegistry = $this->createMock(AuditSinkRegistryInterface::class);
        $this->sinkRegistry->method('getEnabledSinkIdentifiers')->willReturn(['file']);

        $this->accessControlService = $this->createMock(AccessControlServiceInterface::class);
        $this->grantedPermissions = VaultPermission::cases();
        $this->accessControlService
            ->method('isGranted')
            ->willReturnCallback(
                fn (VaultPermission $permission): bool => \in_array($permission, $this->grantedPermissions, true),
            );

        $this->commandTester = new CommandTester(new VaultAuditAnchorCommand(
            $this->anchorService,
            $this->sinkRegistry,
            $this->accessControlService,
        ));
    }

    #[Test]
    public function hasCorrectName(): void
    {
        $command = new VaultAuditAnchorCommand(
            $this->anchorService,
            $this->sinkRegistry,
            $this->accessControlService,
        );

        self::assertSame('vault:audit-anchor', $command->getName());
    }

    /**
     * A refusal must publish nothing AND read nothing: the chain tip it would
     * print is the value a forged anchor has to reproduce.
     */
    #[Test]
    public function refusesWithoutVaultConfigureAndPublishesNothing(): void
    {
        $this->grantedPermissions = $this->allPermissionsExcept(VaultPermission::VaultConfigure);

        $this->anchorService->expects($this->never())->method('capture');
        $this->anchorService->expects($this->never())->method('publish');

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString(
            'Access denied: the "vault.configure" permission is required to publish the audit chain tip.',
            $this->normalizedDisplay(),
        );
    }

    /**
     * `audit.view` reads the log; it does not re-attest the chain to an
     * external observer.
     */
    #[Test]
    public function auditViewAloneDoesNotSatisfyTheGate(): void
    {
        $this->grantedPermissions = [VaultPermission::AuditView];

        $this->anchorService->expects($this->never())->method('publish');

        self::assertSame(Command::FAILURE, $this->commandTester->execute([]));
    }

    /**
     * `--dry-run` publishes nothing, but it is the rehearsal of an
     * administrative operation and prints the current chain tip, so it is gated
     * identically rather than as a read.
     */
    #[Test]
    public function dryRunIsGatedTheSameWay(): void
    {
        $this->grantedPermissions = [VaultPermission::AuditView];

        $this->anchorService->expects($this->never())->method('capture');

        $exitCode = $this->commandTester->execute(['--dry-run' => true]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString(
            'Access denied: the "vault.configure" permission is required to publish the audit chain tip.',
            $this->normalizedDisplay(),
        );
    }

    #[Test]
    public function vaultConfigureAloneSatisfiesTheGate(): void
    {
        $this->grantedPermissions = [VaultPermission::VaultConfigure];

        $this->anchorService
            ->method('capture')
            ->willReturn(new ChainTipAnchor(10, 'tip', 1_750_000_000, 3));
        $this->anchorService
            ->expects($this->once())
            ->method('publish')
            ->willReturn(1);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(Command::SUCCESS, $exitCode, $this->commandTester->getDisplay());
        self::assertStringNotContainsString('Access denied', $this->commandTester->getDisplay());
    }

    /**
     * A scheduled wrapper parsing JSON must see the refusal, not an empty
     * object it would read as "nothing to report".
     */
    #[Test]
    public function jsonRefusalCarriesTheReason(): void
    {
        $this->grantedPermissions = [];

        $exitCode = $this->commandTester->execute(['--format' => 'json']);

        self::assertSame(Command::FAILURE, $exitCode);

        $payload = json_decode($this->commandTester->getDisplay(), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($payload);
        self::assertIsString($payload['error']);
        self::assertStringContainsString('vault.configure', $payload['error']);
        self::assertArrayNotHasKey('anchor', $payload);
    }

    /**
     * @return list<VaultPermission>
     */
    private function allPermissionsExcept(VaultPermission $excluded): array
    {
        return array_values(array_filter(
            VaultPermission::cases(),
            static fn (VaultPermission $permission): bool => $permission !== $excluded,
        ));
    }

    /**
     * SymfonyStyle word-wraps its error block to the terminal width; collapsing
     * whitespace lets the assertions pin the whole refusal sentence.
     */
    private function normalizedDisplay(): string
    {
        return (string) preg_replace('/\s+/', ' ', $this->commandTester->getDisplay());
    }
}
