<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Task;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Task\AuditAnchorTask;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Scheduler\Scheduler;

#[CoversClass(AuditAnchorTask::class)]
final class AuditAnchorTaskTest extends TestCase
{
    protected bool $resetSingletonInstances = true;

    protected function setUp(): void
    {
        parent::setUp();

        // TYPO3 v13's AbstractTask::__construct() resolves the Scheduler via
        // GeneralUtility::makeInstance(); its 3-argument constructor is not
        // autowirable in a unit-test context (no DI container), so register a
        // stand-in. v14's AbstractTask no longer does this, but the mock is
        // harmless there.
        GeneralUtility::setSingletonInstance(Scheduler::class, $this->createMock(Scheduler::class));
    }

    #[Test]
    public function successfulAnchoringReportsSuccess(): void
    {
        $service = self::createStub(ChainTipAnchorServiceInterface::class);
        $service->method('capture')->willReturn(new ChainTipAnchor(10, 'tip', 1_750_000_000, 3));
        $service->method('publish')->willReturn(2);

        self::assertTrue((new AuditAnchorTask($service))->execute());
    }

    /**
     * An anchor that reached no external sink gives no table-reset protection. A
     * green scheduler entry would misreport that as working tamper evidence, so
     * the task must fail.
     */
    #[Test]
    public function anchoringThatReachedNoSinkFails(): void
    {
        $service = self::createStub(ChainTipAnchorServiceInterface::class);
        $service->method('capture')->willReturn(new ChainTipAnchor(10, 'tip', 1_750_000_000, 3));
        $service->method('publish')->willReturn(0);

        self::assertFalse((new AuditAnchorTask($service))->execute());
    }

    #[Test]
    public function captureFailureIsContainedAndReportedAsFailure(): void
    {
        $service = self::createStub(ChainTipAnchorServiceInterface::class);
        $service->method('capture')->willThrowException(new RuntimeException('database unavailable'));

        self::assertFalse((new AuditAnchorTask($service))->execute());
    }

    #[Test]
    public function publishFailureIsContainedAndReportedAsFailure(): void
    {
        $service = self::createStub(ChainTipAnchorServiceInterface::class);
        $service->method('capture')->willReturn(new ChainTipAnchor(10, 'tip', 1_750_000_000, 3));
        $service->method('publish')->willThrowException(new RuntimeException('sink exploded'));

        self::assertFalse((new AuditAnchorTask($service))->execute());
    }

    #[Test]
    public function additionalInformationReportsTheCurrentSequence(): void
    {
        $service = self::createStub(ChainTipAnchorServiceInterface::class);
        $service->method('capture')->willReturn(new ChainTipAnchor(128, 'tip', 1_750_000_000, 3));

        self::assertStringContainsString('128', (new AuditAnchorTask($service))->getAdditionalInformation());
    }

    /**
     * The scheduler list view must render even when the vault is misconfigured —
     * otherwise an operator cannot reach the task to fix or disable it.
     */
    #[Test]
    public function additionalInformationSurvivesAnUnavailableVault(): void
    {
        $service = self::createStub(ChainTipAnchorServiceInterface::class);
        $service->method('capture')->willThrowException(new RuntimeException('no master key'));

        self::assertNotSame('', (new AuditAnchorTask($service))->getAdditionalInformation());
    }
}
