<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Analytics;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Domain\Dto\StaleSecret;
use Netresearch\NrVault\Domain\Dto\UsageBar;
use Netresearch\NrVault\Domain\Dto\VaultUsageStats;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

/**
 * Aggregates KPIs and redaction candidates from `tx_nrvault_secret` (durable
 * signals) and `tx_nrvault_audit_log` (automated-vs-manual read split).
 */
final readonly class VaultAnalyticsService implements VaultAnalyticsServiceInterface
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    /** actor_type values that count as automated (machine) reads. */
    private const AUTOMATED_ACTORS = ['cli', 'api', 'scheduler'];

    public function __construct(
        private ConnectionPool $connectionPool,
        private ExtensionConfigurationInterface $extensionConfiguration,
    ) {}

    public function getUsageStats(int $windowDays): VaultUsageStats
    {
        $now = time();
        $windowStart = $now - ($windowDays * 86400);
        $rotateCutoff = $now - ($this->extensionConfiguration->getStaleNeverRotatedDays() * 86400);

        $total = $this->countSecrets(static fn (QueryBuilder $qb) => $qb);
        $disabled = $this->countSecrets(static fn (QueryBuilder $qb) => $qb->andWhere($qb->expr()->eq('hidden', 1)));
        $expired = $this->countSecrets(static fn (QueryBuilder $qb) => $qb->andWhere(
            $qb->expr()->gt('expires_at', 0),
            $qb->expr()->lt('expires_at', $qb->createNamedParameter($now, Connection::PARAM_INT)),
        ));
        $frontend = $this->countSecrets(static fn (QueryBuilder $qb) => $qb->andWhere($qb->expr()->eq('frontend_accessible', 1)));
        $neverRotated = $this->countSecrets(static fn (QueryBuilder $qb) => $qb->andWhere(
            $qb->expr()->or(
                $qb->expr()->and(
                    $qb->expr()->gt('last_rotated_at', 0),
                    $qb->expr()->lt('last_rotated_at', $qb->createNamedParameter($rotateCutoff, Connection::PARAM_INT)),
                ),
                $qb->expr()->and(
                    $qb->expr()->eq('last_rotated_at', 0),
                    $qb->expr()->lt('crdate', $qb->createNamedParameter($rotateCutoff, Connection::PARAM_INT)),
                ),
            ),
        ));

        [$automated, $manual] = $this->totalReadSplit($windowStart);

        return new VaultUsageStats(
            total: $total,
            active: $total - $disabled,
            disabled: $disabled,
            expired: $expired,
            frontendAccessible: $frontend,
            neverRotated: $neverRotated,
            automatedReads: $automated,
            manualReveals: $manual,
            windowDays: $windowDays,
            byAdapter: $this->distribution('adapter'),
            byContext: $this->distribution('context'),
        );
    }

    public function getRedactionCandidates(int $windowDays): array
    {
        $now = time();
        $windowStart = $now - ($windowDays * 86400);
        $evaluator = new StalenessEvaluator(
            $this->extensionConfiguration->getStaleNeverReadDays(),
            $this->extensionConfiguration->getStaleNotReadDays(),
            $this->extensionConfiguration->getStaleNeverRotatedDays(),
        );

        $readMap = $this->readSplitByIdentifier($windowStart);
        $candidates = [];

        foreach ($this->allSecretRows() as $row) {
            $identifier = $this->toStr($row['identifier']);
            $automated = $readMap[$identifier]['automated'] ?? 0;
            $manual = $readMap[$identifier]['manual'] ?? 0;
            $crdate = $this->toInt($row['crdate']);
            $lastReadAt = $this->toInt($row['last_read_at']);

            $rules = $evaluator->evaluate(
                now: $now,
                crdate: $crdate,
                readCount: $this->toInt($row['read_count']),
                lastReadAt: $lastReadAt === 0 ? null : $lastReadAt,
                lastRotatedAt: $this->toInt($row['last_rotated_at']),
                expiresAt: $this->toInt($row['expires_at']),
                automatedReads: $automated,
                manualReveals: $manual,
            );

            if ($rules === []) {
                continue;
            }

            $candidates[] = new StaleSecret(
                uid: $this->toInt($row['uid']),
                identifier: $identifier,
                context: $this->toStr($row['context']),
                adapter: $this->toStr($row['adapter']),
                lastReadAt: $lastReadAt === 0 ? null : $lastReadAt,
                automatedReads: $automated,
                manualReveals: $manual,
                ageDays: (int) floor(($now - $crdate) / 86400),
                rules: $rules,
            );
        }

        return $candidates;
    }

    /**
     * @param callable(QueryBuilder): QueryBuilder $constrain
     */
    private function countSecrets(callable $constrain): int
    {
        $qb = $this->secretQuery();
        $qb->count('uid')->from(self::SECRET_TABLE)->where($qb->expr()->eq('deleted', 0));
        $constrain($qb);
        $result = $qb->executeQuery()->fetchOne();

        return is_numeric($result) ? (int) $result : 0;
    }

    /**
     * @return list<UsageBar>
     */
    private function distribution(string $column): array
    {
        $qb = $this->secretQuery();
        $rows = $qb
            ->select($column)
            ->addSelectLiteral($qb->expr()->count('uid', 'cnt'))
            ->from(self::SECRET_TABLE)
            ->where($qb->expr()->eq('deleted', 0), $qb->expr()->eq('hidden', 0))
            ->groupBy($column)
            ->orderBy('cnt', 'DESC')
            ->executeQuery()
            ->fetchAllAssociative();

        $max = 0;
        foreach ($rows as $r) {
            $max = max($max, $this->toInt($r['cnt']));
        }

        $bars = [];
        foreach ($rows as $r) {
            $value = $this->toInt($r['cnt']);
            $label = $this->toStr($r[$column]);
            $bars[] = new UsageBar(
                label: $label === '' ? '(none)' : $label,
                value: $value,
                percent: $max > 0 ? (int) round($value / $max * 100) : 0,
            );
        }

        return $bars;
    }

    /**
     * @return array{0: int, 1: int} [automated, manual]
     */
    private function totalReadSplit(int $windowStart): array
    {
        $automated = 0;
        $manual = 0;
        foreach ($this->readSplitByIdentifier($windowStart) as $split) {
            $automated += $split['automated'];
            $manual += $split['manual'];
        }

        return [$automated, $manual];
    }

    /**
     * @return array<string, array{automated: int, manual: int}>
     */
    private function readSplitByIdentifier(int $windowStart): array
    {
        // Audit table has no TCA enable-fields; use the connection's plain
        // QueryBuilder (no restrictions), mirroring AuditLogService.
        $qb = $this->connectionPool->getConnectionForTable(self::AUDIT_TABLE)->createQueryBuilder();
        $rows = $qb
            ->select('secret_identifier', 'actor_type')
            ->addSelectLiteral($qb->expr()->count('uid', 'cnt'))
            ->from(self::AUDIT_TABLE)
            ->where(
                $qb->expr()->eq('action', $qb->createNamedParameter('read')),
                $qb->expr()->eq('success', 1),
                $qb->expr()->gte('crdate', $qb->createNamedParameter($windowStart, Connection::PARAM_INT)),
            )
            ->groupBy('secret_identifier', 'actor_type')
            ->executeQuery()
            ->fetchAllAssociative();

        $map = [];
        foreach ($rows as $r) {
            $id = $this->toStr($r['secret_identifier']);
            $map[$id] ??= ['automated' => 0, 'manual' => 0];
            $bucket = \in_array($this->toStr($r['actor_type']), self::AUTOMATED_ACTORS, true) ? 'automated' : 'manual';
            $map[$id][$bucket] += $this->toInt($r['cnt']);
        }

        return $map;
    }

    /**
     * Narrow a `mixed` database value to int (PHPStan level 10 safe).
     */
    private function toInt(mixed $value): int
    {
        return is_numeric($value) ? (int) $value : 0;
    }

    /**
     * Narrow a `mixed` database value to string (PHPStan level 10 safe).
     */
    private function toStr(mixed $value): string
    {
        return \is_scalar($value) ? (string) $value : '';
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function allSecretRows(): array
    {
        $qb = $this->secretQuery();

        return $qb
            ->select('uid', 'identifier', 'context', 'adapter', 'crdate', 'read_count', 'last_read_at', 'last_rotated_at', 'expires_at')
            ->from(self::SECRET_TABLE)
            ->where($qb->expr()->eq('deleted', 0))
            ->executeQuery()
            ->fetchAllAssociative();
    }

    /**
     * QueryBuilder with all default restrictions removed (mirrors
     * OverviewController::getVaultStatistics) so hidden secrets are counted;
     * `deleted = 0` is always added explicitly by callers.
     */
    private function secretQuery(): QueryBuilder
    {
        $qb = $this->connectionPool->getQueryBuilderForTable(self::SECRET_TABLE);
        $qb->getRestrictions()->removeAll();

        return $qb;
    }
}
