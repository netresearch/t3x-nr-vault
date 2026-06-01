<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service\Analytics;

use Netresearch\NrVault\Domain\StalenessRule;
use Netresearch\NrVault\Service\Analytics\VaultAnalyticsService;
use Netresearch\NrVault\Service\Analytics\VaultAnalyticsServiceInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

#[CoversClass(VaultAnalyticsService::class)]
final class VaultAnalyticsServiceTest extends FunctionalTestCase
{
    private const NOW = 1_700_000_000;

    private const DAY = 86_400;

    protected array $testExtensionsToLoad = ['netresearch/nr-vault'];

    protected array $coreExtensionsToLoad = ['backend'];

    #[Test]
    public function computesKpisAndCandidates(): void
    {
        $this->seedSecret(1, 'healthy_key', 'payment', 'local', crdate: self::NOW - 30 * self::DAY, readCount: 50, lastReadAt: self::NOW - self::DAY, lastRotatedAt: self::NOW - 10 * self::DAY, expiresAt: 0, hidden: 0, frontend: 0);
        $this->seedSecret(2, 'dead_key', 'mail', 'local', crdate: self::NOW - 300 * self::DAY, readCount: 0, lastReadAt: 0, lastRotatedAt: 0, expiresAt: 0, hidden: 0, frontend: 0);
        $this->seedSecret(3, 'expired_key', 'integration', 'local', crdate: self::NOW - 100 * self::DAY, readCount: 4, lastReadAt: self::NOW - self::DAY, lastRotatedAt: self::NOW - self::DAY, expiresAt: self::NOW - 5 * self::DAY, hidden: 0, frontend: 1);
        $this->seedSecret(4, 'manual_only', 'mail', 'local', crdate: self::NOW - 320 * self::DAY, readCount: 9, lastReadAt: self::NOW - 41 * self::DAY, lastRotatedAt: 0, expiresAt: 0, hidden: 0, frontend: 0);
        $this->seedSecret(5, 'disabled_key', 'payment', 'local', crdate: self::NOW - 5 * self::DAY, readCount: 1, lastReadAt: self::NOW - self::DAY, lastRotatedAt: self::NOW - self::DAY, expiresAt: 0, hidden: 1, frontend: 0);

        for ($i = 0; $i < 9; $i++) {
            $this->seedReadEvent('manual_only', 'backend', self::NOW - (40 + $i) * self::DAY);
        }
        $this->seedReadEvent('healthy_key', 'api', self::NOW - 2 * self::DAY);
        $this->seedReadEvent('healthy_key', 'cli', self::NOW - 3 * self::DAY);

        $service = $this->get(VaultAnalyticsServiceInterface::class);
        $stats = $service->getUsageStats(90);

        self::assertSame(5, $stats->total);
        self::assertSame(4, $stats->active);
        self::assertSame(1, $stats->disabled);
        self::assertSame(1, $stats->expired);
        self::assertSame(1, $stats->frontendAccessible);
        self::assertSame(2, $stats->automatedReads);
        self::assertSame(9, $stats->manualReveals);
        self::assertSame(2, $stats->neverRotated);
        self::assertSame(90, $stats->windowDays);

        // Distributions use active rows only (deleted=0 AND hidden=0) -> uid 1-4.
        self::assertCount(1, $stats->byAdapter);
        self::assertSame('local', $stats->byAdapter[0]->label);
        self::assertSame(4, $stats->byAdapter[0]->value);
        self::assertSame(100, $stats->byAdapter[0]->percent);

        self::assertCount(3, $stats->byContext);
        self::assertSame('mail', $stats->byContext[0]->label); // cnt 2 = max -> ordered first
        self::assertSame(2, $stats->byContext[0]->value);
        self::assertSame(100, $stats->byContext[0]->percent);
        $contextPercent = [];
        foreach ($stats->byContext as $bar) {
            $contextPercent[$bar->label] = $bar->percent;
        }
        self::assertSame(50, $contextPercent['payment']);
        self::assertSame(50, $contextPercent['integration']);

        $candidates = $service->getRedactionCandidates(90);
        $byId = [];
        foreach ($candidates as $c) {
            $byId[$c->identifier] = $c->rules;
        }

        self::assertArrayHasKey('dead_key', $byId);
        self::assertContains(StalenessRule::Dead, $byId['dead_key']);
        self::assertArrayHasKey('expired_key', $byId);
        self::assertContains(StalenessRule::Expired, $byId['expired_key']);
        self::assertArrayHasKey('manual_only', $byId);
        self::assertContains(StalenessRule::AutomationStale, $byId['manual_only']);
        self::assertSame(0, $this->candidate($candidates, 'manual_only')->automatedReads);
        self::assertSame(9, $this->candidate($candidates, 'manual_only')->manualReveals);
        self::assertArrayNotHasKey('healthy_key', $byId);
    }

    #[Test]
    public function emptyVaultProducesZeroStatsAndNoCandidates(): void
    {
        $service = $this->get(VaultAnalyticsServiceInterface::class);
        $stats = $service->getUsageStats(90);

        self::assertSame(0, $stats->total);
        self::assertSame([], $service->getRedactionCandidates(90));
    }

    /**
     * @param list<\Netresearch\NrVault\Domain\Dto\StaleSecret> $candidates
     */
    private function candidate(array $candidates, string $identifier): \Netresearch\NrVault\Domain\Dto\StaleSecret
    {
        foreach ($candidates as $c) {
            if ($c->identifier === $identifier) {
                return $c;
            }
        }
        self::fail('candidate not found: ' . $identifier);
    }

    private function seedSecret(int $uid, string $identifier, string $context, string $adapter, int $crdate, int $readCount, int $lastReadAt, int $lastRotatedAt, int $expiresAt, int $hidden, int $frontend): void
    {
        // The service uses time(); fixtures are written NOW-relative and shifted
        // to real now so ages line up.
        $shift = time() - self::NOW;
        $conn = $this->get(ConnectionPool::class)->getConnectionForTable('tx_nrvault_secret');
        $conn->insert('tx_nrvault_secret', [
            'uid' => $uid,
            'pid' => 0,
            'identifier' => $identifier,
            'context' => $context,
            'adapter' => $adapter,
            'crdate' => $crdate + $shift,
            'tstamp' => $crdate + $shift,
            'read_count' => $readCount,
            'last_read_at' => $lastReadAt === 0 ? 0 : $lastReadAt + $shift,
            'last_rotated_at' => $lastRotatedAt === 0 ? 0 : $lastRotatedAt + $shift,
            'expires_at' => $expiresAt === 0 ? 0 : $expiresAt + $shift,
            'hidden' => $hidden,
            'deleted' => 0,
            'frontend_accessible' => $frontend,
        ]);
    }

    private function seedReadEvent(string $identifier, string $actorType, int $crdate): void
    {
        $shift = time() - self::NOW;
        $conn = $this->get(ConnectionPool::class)->getConnectionForTable('tx_nrvault_audit_log');
        $conn->insert('tx_nrvault_audit_log', [
            'pid' => 0,
            'secret_identifier' => $identifier,
            'action' => 'read',
            'success' => 1,
            'actor_type' => $actorType,
            'crdate' => $crdate + $shift,
        ]);
    }
}
