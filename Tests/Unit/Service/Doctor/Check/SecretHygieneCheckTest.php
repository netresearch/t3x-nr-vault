<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Doctor\Check;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Domain\Dto\StaleSecret;
use Netresearch\NrVault\Domain\Dto\VaultUsageStats;
use Netresearch\NrVault\Domain\StalenessRule;
use Netresearch\NrVault\Service\Analytics\VaultAnalyticsServiceInterface;
use Netresearch\NrVault\Service\Doctor\Check\SecretHygieneCheck;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\DoctorFindingTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(SecretHygieneCheck::class)]
final class SecretHygieneCheckTest extends TestCase
{
    use DoctorFindingTrait;

    #[Test]
    public function appliesToBothProfiles(): void
    {
        $check = $this->check();

        self::assertTrue($check->appliesTo(SecurityProfile::Standard));
        self::assertTrue($check->appliesTo(SecurityProfile::Hardened));
    }

    #[Test]
    public function acleanInventoryPassesEveryControl(): void
    {
        $findings = $this->check()->run($this->doctorContext(SecurityProfile::Hardened));

        self::assertSame(
            ['secrets.expired', 'secrets.never_rotated', 'secrets.dead'],
            $this->findingIds($findings),
        );
        foreach ($findings as $finding) {
            self::assertTrue($finding->isPass(), $finding->id . ': ' . $finding->summary);
        }
    }

    #[Test]
    public function expiredSecretsAreAWarningWithTheCount(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(expired: 4)->run($this->doctorContext(SecurityProfile::Standard)),
            'secrets.expired',
        );

        self::assertSame(4, $finding->details['expiredCount']);
        self::assertStringContainsString('4 stored secret(s)', $finding->summary);
    }

    #[Test]
    public function neverRotatedSecretsAreAWarningNamingTheThreshold(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(neverRotated: 2, neverRotatedDays: 90)
                ->run($this->doctorContext(SecurityProfile::Standard)),
            'secrets.never_rotated',
        );

        self::assertSame(90, $finding->details['thresholdDays']);
        self::assertStringContainsString('90 days', $finding->summary);
    }

    /**
     * Only the `dead` staleness rule counts here. The other rules already have
     * their own controls (`expired`) or describe usage patterns rather than
     * removable inventory, and folding them together would double-report the same
     * secret under two findings.
     */
    #[Test]
    public function onlyDeadCandidatesCountTowardsTheDeadControl(): void
    {
        $findings = $this->check(candidates: [
            $this->staleSecret([StalenessRule::Dead]),
            $this->staleSecret([StalenessRule::Dead, StalenessRule::NeverRotated]),
            $this->staleSecret([StalenessRule::AutomationStale]),
            $this->staleSecret([StalenessRule::Expired]),
        ])->run($this->doctorContext(SecurityProfile::Standard));

        $finding = $this->assertFindingSeverity(FindingSeverity::Warning, $findings, 'secrets.dead');
        self::assertSame(2, $finding->details['deadCount']);
    }

    /**
     * No secret identifier may reach a finding: an identifier names a credential
     * and the JSON report travels into CI logs.
     */
    #[Test]
    public function noSecretIdentifierLeaksIntoAnyFinding(): void
    {
        $findings = $this->check(
            expired: 1,
            neverRotated: 1,
            candidates: [$this->staleSecret([StalenessRule::Dead], 'stripe_live_api_key')],
        )->run($this->doctorContext(SecurityProfile::Standard));

        foreach ($findings as $finding) {
            $text = $finding->summary . $finding->risk . $finding->remediation
                . implode(' ', array_map(static fn (bool|int|string $v): string => (string) $v, $finding->details));
            self::assertStringNotContainsString('stripe_live_api_key', $text, $finding->id);
        }
    }

    /**
     * @param list<StaleSecret> $candidates
     */
    private function check(
        int $expired = 0,
        int $neverRotated = 0,
        int $neverRotatedDays = 180,
        array $candidates = [],
    ): SecretHygieneCheck {
        $analytics = self::createStub(VaultAnalyticsServiceInterface::class);
        $analytics->method('getUsageStats')->willReturn(new VaultUsageStats(
            total: 10,
            active: 10,
            disabled: 0,
            expired: $expired,
            frontendAccessible: 0,
            neverRotated: $neverRotated,
            automatedReads: 100,
            manualReveals: 5,
            windowDays: 180,
            byAdapter: [],
            byContext: [],
        ));
        $analytics->method('getRedactionCandidates')->willReturn($candidates);

        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getStaleNeverRotatedDays')->willReturn($neverRotatedDays);

        return new SecretHygieneCheck($analytics, $configuration);
    }

    /**
     * @param list<StalenessRule> $rules
     */
    private function staleSecret(array $rules, string $identifier = 'some_secret'): StaleSecret
    {
        return new StaleSecret(
            uid: 1,
            identifier: $identifier,
            context: 'default',
            adapter: 'local',
            lastReadAt: null,
            automatedReads: 0,
            manualReveals: 0,
            ageDays: 400,
            rules: $rules,
        );
    }
}
