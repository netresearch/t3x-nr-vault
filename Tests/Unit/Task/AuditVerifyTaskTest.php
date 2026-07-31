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
use Netresearch\NrVault\Task\AuditVerifyTask;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;

#[CoversClass(AuditVerifyTask::class)]
final class AuditVerifyTaskTest extends TestCase
{
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

        self::assertFalse((new AuditVerifyTask($service))->execute());
    }

    #[Test]
    public function verificationThatCannotRunFailsEvenInTamperOnlyMode(): void
    {
        $service = self::createStub(ChainTipAnchorServiceInterface::class);
        $service->method('verify')->willThrowException(new RuntimeException('database unavailable'));

        $task = new AuditVerifyTask($service);
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

    private function createTask(AuditIntegrityReport $report): AuditVerifyTask
    {
        $service = self::createStub(ChainTipAnchorServiceInterface::class);
        $service->method('verify')->willReturn($report);

        return new AuditVerifyTask($service);
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
