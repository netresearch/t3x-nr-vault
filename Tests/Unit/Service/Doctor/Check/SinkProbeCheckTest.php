<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Doctor\Check;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\Sink\AuditSinkInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\Check\SinkProbeCheck;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\DoctorFindingTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Throwable;

#[CoversClass(SinkProbeCheck::class)]
final class SinkProbeCheckTest extends TestCase
{
    use DoctorFindingTrait;

    #[Test]
    public function emitsNothingWithoutTheActiveProbesFlag(): void
    {
        // The probe talks to external systems — the passive doctor run and
        // the backend status panel must never trigger it implicitly.
        $sink = new ProbeSpySink('webhook');

        $findings = $this->check([$sink])->run($this->context(activeProbes: false));

        self::assertSame([], $findings);
        self::assertSame(0, $sink->anchorCalls);
    }

    #[Test]
    public function anAcceptingSinkYieldsAPassWithTheAnchorSequence(): void
    {
        $sink = new ProbeSpySink('file');

        $findings = $this->check([$sink])->run($this->context(activeProbes: true));

        $finding = $this->findingById($findings, 'audit.sink_probe.file');
        self::assertTrue($finding->isPass());
        self::assertSame(1, $sink->anchorCalls, 'the probe must actually deliver the anchor');
        self::assertSame(42, $finding->details['anchorSequence']);
    }

    #[Test]
    public function aRefusedProbeIsCriticalInBothProfiles(): void
    {
        // The review's acceptance scenario: syntactically valid webhook,
        // collector unreachable => the ACTIVE check must report critical.
        $sink = new ProbeSpySink('webhook', throwOnAnchor: new RuntimeException('connection refused'));

        foreach (SecurityProfile::cases() as $profile) {
            $finding = $this->assertFindingSeverity(
                FindingSeverity::Critical,
                $this->check([$sink])->run($this->context(activeProbes: true, profile: $profile)),
                'audit.sink_probe.webhook',
            );

            self::assertStringContainsString('connection refused', $finding->summary);
        }
    }

    #[Test]
    public function disabledSinksAreNotProbed(): void
    {
        $disabled = new ProbeSpySink('syslog', enabled: false);

        $findings = $this->check([$disabled])->run($this->context(activeProbes: true));

        self::assertSame(0, $disabled->anchorCalls);
        self::assertSame(['audit.sink_probe.none'], $this->findingIds($findings));
        self::assertTrue($findings[0]->isPass());
    }

    /**
     * @param list<AuditSinkInterface> $sinks
     */
    private function check(array $sinks): SinkProbeCheck
    {
        $anchorService = self::createStub(ChainTipAnchorServiceInterface::class);
        $anchorService->method('capture')->willReturn(new ChainTipAnchor(42, 'tip-hash', 1_750_000_000, 3));

        return new SinkProbeCheck($sinks, $anchorService);
    }

    private function context(
        bool $activeProbes,
        SecurityProfile $profile = SecurityProfile::Standard,
    ): DoctorContext {
        return new DoctorContext(
            profile: $profile,
            configuredProfile: $profile,
            activeProbes: $activeProbes,
        );
    }
}

/**
 * Minimal probe target: counts anchor deliveries, optionally refuses them.
 *
 * @internal test helper
 */
final class ProbeSpySink implements AuditSinkInterface
{
    public int $anchorCalls = 0;

    public function __construct(
        private readonly string $identifier,
        private readonly bool $enabled = true,
        private readonly ?Throwable $throwOnAnchor = null,
    ) {}

    public function publish(AuditLogEntry $entry, string $chainTip): void {}

    public function publishAnchor(ChainTipAnchor $anchor): void
    {
        ++$this->anchorCalls;

        if ($this->throwOnAnchor instanceof Throwable) {
            throw $this->throwOnAnchor;
        }
    }

    public function publishAlert(AuditIntegrityAlert $alert): void {}

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }
}
