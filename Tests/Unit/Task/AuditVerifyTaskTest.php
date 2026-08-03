<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Task;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditIntegrityReport;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Task\AuditVerifyTask;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Scheduler\Scheduler;

#[CoversClass(AuditVerifyTask::class)]
final class AuditVerifyTaskTest extends TestCase
{
    protected bool $resetSingletonInstances = true;

    protected function setUp(): void
    {
        parent::setUp();

        // See AuditAnchorTaskTest::setUp() — v13's AbstractTask resolves the
        // Scheduler through GeneralUtility, whose 3-arg constructor is not
        // autowirable in a unit test.
        GeneralUtility::setSingletonInstance(Scheduler::class, $this->createMock(Scheduler::class));
    }

    #[Test]
    public function cleanReportReportsSuccess(): void
    {
        $task = $this->createTask($this->report());

        self::assertTrue($task->execute());
    }

    #[Test]
    #[DataProvider('tamperReasonProvider')]
    public function tamperEvidenceFailsRegardlessOfTheTamperOnlySetting(AuditIntegrityReason $reason, bool $tamperOnly): void
    {
        $task = $this->createTask($this->report($reason));
        $task->setTaskParameters(['nr_vault_tamper_only' => $tamperOnly ? 1 : 0]);

        self::assertFalse($task->execute());
    }

    /**
     * @return iterable<string, array{AuditIntegrityReason, bool}>
     */
    public static function tamperReasonProvider(): iterable
    {
        foreach ([true, false] as $tamperOnly) {
            $suffix = $tamperOnly ? ' (tamper-only)' : ' (strict)';
            yield 'hash mismatch' . $suffix => [AuditIntegrityReason::HashMismatch, $tamperOnly];
            yield 'uid gap' . $suffix => [AuditIntegrityReason::UidGap, $tamperOnly];
            yield 'table reset' . $suffix => [AuditIntegrityReason::TableReset, $tamperOnly];
            yield 'epoch downgrade' . $suffix => [AuditIntegrityReason::EpochDowngrade, $tamperOnly];
        }
    }

    #[Test]
    public function configurationFindingFailsByDefault(): void
    {
        $task = $this->createTask($this->report(AuditIntegrityReason::NoExternalSink));

        self::assertFalse($task->execute());
    }

    /**
     * The rollout escape hatch: while sinks are still being wired up, a pending
     * integration must not keep the task permanently red — that would train
     * operators to ignore it and mask a real tamper alarm.
     */
    #[Test]
    public function configurationFindingPassesWhenTamperOnlyIsSet(): void
    {
        $task = $this->createTask($this->report(AuditIntegrityReason::NoExternalSink));
        $task->setTaskParameters(['nr_vault_tamper_only' => 1]);

        self::assertTrue($task->execute());
    }

    #[Test]
    public function sinkFailureFindingPassesWhenTamperOnlyIsSet(): void
    {
        $task = $this->createTask($this->report(AuditIntegrityReason::SinkFailure));
        $task->setTaskParameters(['nr_vault_tamper_only' => 1]);

        self::assertTrue($task->execute());
    }

    /**
     * A verification that could not run must never look like a verification that
     * found nothing.
     */
    #[Test]
    public function verificationThatCannotRunFails(): void
    {
        $service = self::createStub(ChainTipAnchorServiceInterface::class);
        $service->method('verify')->willThrowException(new RuntimeException('database unavailable'));

        self::assertFalse($this->task($service)->execute());
    }

    #[Test]
    public function verificationThatCannotRunFailsEvenInTamperOnlyMode(): void
    {
        $service = self::createStub(ChainTipAnchorServiceInterface::class);
        $service->method('verify')->willThrowException(new RuntimeException('database unavailable'));

        $task = $this->task($service);
        $task->setTaskParameters(['nr_vault_tamper_only' => 1]);

        self::assertFalse($task->execute());
    }

    #[Test]
    public function taskParametersRoundTripThroughTheTcaField(): void
    {
        $task = $this->createTask($this->report());

        $task->setTaskParameters(['nr_vault_tamper_only' => 1]);
        self::assertSame(['nr_vault_tamper_only' => 1], $task->getTaskParameters());

        $task->setTaskParameters(['nr_vault_tamper_only' => 0]);
        self::assertSame(['nr_vault_tamper_only' => 0], $task->getTaskParameters());
    }

    #[Test]
    public function absentParameterDefaultsToStrictMode(): void
    {
        $task = $this->createTask($this->report(AuditIntegrityReason::NoExternalSink));

        $task->setTaskParameters([]);

        self::assertSame(['nr_vault_tamper_only' => 0], $task->getTaskParameters());
        self::assertFalse($task->execute(), 'strict mode fails on a configuration finding');
    }

    #[Test]
    public function additionalInformationDistinguishesTheTwoModes(): void
    {
        $task = $this->createTask($this->report());

        $strict = $task->getAdditionalInformation();
        $task->setTaskParameters(['nr_vault_tamper_only' => 1]);

        self::assertNotSame($strict, $task->getAdditionalInformation());
    }

    /**
     * Verification is a read of the chain, so it answers to `audit.view` from
     * the scheduler exactly as it does from `vault:audit-verify`,
     * `vault:audit --verify` and the backend module.
     */
    #[Test]
    public function verificationIsRefusedWithoutAuditView(): void
    {
        $service = $this->createMock(ChainTipAnchorServiceInterface::class);
        $service->expects($this->never())->method('verify');

        self::assertFalse(
            $this->task($service, granted: false)->execute(),
            'a verification that was not allowed to run must not report success',
        );
    }

    /**
     * `--tamper-only` downgrades configuration findings to warnings. A refusal
     * is not a finding about the chain, so it must not be downgraded with them.
     */
    #[Test]
    public function refusalFailsEvenInTamperOnlyMode(): void
    {
        $service = $this->createMock(ChainTipAnchorServiceInterface::class);
        $service->expects($this->never())->method('verify');

        $task = $this->task($service, granted: false);
        $task->setTaskParameters(['nr_vault_tamper_only' => 1]);

        self::assertFalse($task->execute());
    }

    private function task(ChainTipAnchorServiceInterface $service, bool $granted = true): AuditVerifyTask
    {
        $accessControlService = self::createStub(AccessControlServiceInterface::class);
        $accessControlService
            ->method('isGranted')
            ->willReturnCallback(
                static fn (VaultPermission $permission): bool => $granted
                    && $permission === VaultPermission::AuditView,
            );

        return new AuditVerifyTask($service, null, $accessControlService);
    }

    private function createTask(AuditIntegrityReport $report): AuditVerifyTask
    {
        $service = self::createStub(ChainTipAnchorServiceInterface::class);
        $service->method('verify')->willReturn($report);

        return $this->task($service);
    }

    private function report(?AuditIntegrityReason $reason = null): AuditIntegrityReport
    {
        return new AuditIntegrityReport(
            findings: $reason instanceof AuditIntegrityReason ? [AuditIntegrityAlert::create($reason, 'detail')] : [],
            chainValid: !$reason instanceof AuditIntegrityReason,
            currentSequence: 10,
        );
    }
}
