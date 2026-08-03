<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditIntegrityReport;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Command\VaultAuditVerifyCommand;
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
 * The operation-permission gate on `vault:audit-verify`.
 *
 * The wrapper checked strictly more than `vault:audit --verify` — the external
 * anchor as well as the in-database chain — while asserting no permission at
 * all, which made the gate on the interactive command advisory: an actor who
 * was refused there simply called this instead. Both now answer to `audit.view`
 * because they perform the same operation.
 */
#[CoversClass(VaultAuditVerifyCommand::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultAuditVerifyCommandTest extends TestCase
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
        $this->sinkRegistry->method('getFailureCountsBySink')->willReturn([]);

        $this->accessControlService = $this->createMock(AccessControlServiceInterface::class);
        $this->grantedPermissions = VaultPermission::cases();
        $this->accessControlService
            ->method('isGranted')
            ->willReturnCallback(
                fn (VaultPermission $permission): bool => \in_array($permission, $this->grantedPermissions, true),
            );

        $this->commandTester = new CommandTester(new VaultAuditVerifyCommand(
            $this->anchorService,
            $this->sinkRegistry,
            $this->accessControlService,
        ));
    }

    #[Test]
    public function hasCorrectName(): void
    {
        $command = new VaultAuditVerifyCommand(
            $this->anchorService,
            $this->sinkRegistry,
            $this->accessControlService,
        );

        self::assertSame('vault:audit-verify', $command->getName());
    }

    /**
     * A refusal must run no verification: the report it would produce is the
     * chain state the permission withholds.
     */
    #[Test]
    public function refusesWithoutAuditViewAndVerifiesNothing(): void
    {
        $this->grantedPermissions = $this->allPermissionsExcept(VaultPermission::AuditView);

        $this->anchorService->expects($this->never())->method('verify');

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString(
            'Access denied: the "audit.view" permission is required to verify the audit log integrity.',
            $this->normalizedDisplay(),
        );
    }

    /**
     * `vault.configure` is not a substitute: holding every other permission
     * still does not buy the verification.
     */
    #[Test]
    public function vaultConfigureAloneDoesNotSatisfyTheGate(): void
    {
        $this->grantedPermissions = [VaultPermission::VaultConfigure];

        $this->anchorService->expects($this->never())->method('verify');

        self::assertSame(Command::FAILURE, $this->commandTester->execute([]));
    }

    #[Test]
    public function auditViewAloneSatisfiesTheGate(): void
    {
        $this->grantedPermissions = [VaultPermission::AuditView];

        $this->anchorService
            ->expects($this->once())
            ->method('verify')
            ->willReturn(new AuditIntegrityReport(findings: [], chainValid: true, currentSequence: 7));

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(Command::SUCCESS, $exitCode, $this->commandTester->getDisplay());
        self::assertStringNotContainsString('Access denied', $this->commandTester->getDisplay());
    }

    /**
     * The command is meant to be wired into monitoring, so a consumer reading
     * only `valid` must see a refused verification as a failed one — never as a
     * clean chain.
     */
    #[Test]
    public function jsonRefusalReportsInvalidRatherThanAnEmptyPass(): void
    {
        $this->grantedPermissions = [];

        $exitCode = $this->commandTester->execute(['--format' => 'json']);

        self::assertSame(Command::FAILURE, $exitCode);

        $payload = json_decode($this->commandTester->getDisplay(), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($payload);
        self::assertFalse($payload['valid']);
        self::assertIsString($payload['error']);
        self::assertStringContainsString('audit.view', $payload['error']);
    }

    /**
     * `--tamper-only` downgrades configuration findings to warnings. It must
     * not downgrade a refusal — that is not a finding about the chain.
     */
    #[Test]
    public function tamperOnlyDoesNotSoftenTheRefusal(): void
    {
        $this->grantedPermissions = [];

        $this->anchorService->expects($this->never())->method('verify');

        self::assertSame(Command::FAILURE, $this->commandTester->execute(['--tamper-only' => true]));
    }

    /**
     * The distribution is reported on a CLEAN run, not only on a failure: a
     * chain left at epoch 1 by a stalled migration verifies perfectly and still
     * leaves `success` and the attribution fields outside the MAC. There is no
     * finding to raise and an operator still has to see it, so the text report
     * carries the per-epoch counts the walk already produced.
     */
    #[Test]
    public function theTextReportNamesTheStoredEpochDistributionOnACleanChain(): void
    {
        $this->anchorService->method('verify')->willReturn(new AuditIntegrityReport(
            findings: [],
            chainValid: true,
            currentSequence: 945,
            epochCounts: [1 => 45, 3 => 900],
        ));

        self::assertSame(Command::SUCCESS, $this->commandTester->execute([]));

        $display = $this->normalizedDisplay();

        self::assertStringContainsString('Stored HMAC epochs', $display);
        self::assertStringContainsString('epoch 1: 45 row(s)', $display);
        self::assertStringContainsString('epoch 3: 900 row(s)', $display);
        self::assertStringContainsString('lowest 1, highest 3', $display);
    }

    /**
     * An empty chain has no epoch to report, and must not be rendered as
     * "epoch 0" — that is a real state meaning keyless.
     */
    #[Test]
    public function theTextReportSaysTheChainIsEmptyRatherThanReportingEpochZero(): void
    {
        $this->anchorService->method('verify')->willReturn(
            new AuditIntegrityReport(findings: [], chainValid: true, currentSequence: 0),
        );

        $this->commandTester->execute([]);

        $display = $this->normalizedDisplay();

        self::assertStringContainsString('Stored HMAC epochs (chain empty)', $display);
        self::assertStringNotContainsString('epoch 0', $display);
    }

    /**
     * The JSON body is the monitoring interface — the same distribution has to
     * be machine-readable, not only printed.
     */
    #[Test]
    public function theJsonReportCarriesTheStoredEpochDistribution(): void
    {
        $this->anchorService->method('verify')->willReturn(new AuditIntegrityReport(
            findings: [],
            chainValid: true,
            currentSequence: 945,
            epochCounts: [1 => 45, 3 => 900],
        ));

        $this->commandTester->execute(['--format' => 'json']);

        $payload = json_decode($this->commandTester->getDisplay(), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($payload);
        self::assertTrue($payload['valid']);
        self::assertSame(['1' => 45, '3' => 900], $payload['epochCounts']);
        self::assertSame(1, $payload['minEpoch']);
        self::assertSame(3, $payload['maxEpoch']);
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
