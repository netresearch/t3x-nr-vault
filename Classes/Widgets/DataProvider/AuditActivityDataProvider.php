<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Widgets\DataProvider;

use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Dashboard\Widgets\ChartDataProviderInterface;

/**
 * Chart.js bar-chart data provider for "vault audit activity (last 14 days)".
 *
 * Aggregates tx_nrvault_audit_log rows into per-day event counts with a
 * single GROUP BY query on `crdate`. Days are bucketed as UTC calendar days
 * (`crdate - (crdate % 86400)`) — an at-a-glance activity trend, not an
 * audit report; exact per-entry timestamps live in the audit log module.
 */
final readonly class AuditActivityDataProvider implements ChartDataProviderInterface
{
    private const TABLE = 'tx_nrvault_audit_log';

    private const DEFAULT_DAYS = 14;

    private const SECONDS_PER_DAY = 86400;

    private const BAR_COLOR = '#2F99A4';

    public function __construct(
        private ConnectionPool $connectionPool,
        private int $days = self::DEFAULT_DAYS,
    ) {}

    /**
     * @return array{labels: list<string>, datasets: list<array{label: string, data: list<int>, backgroundColor: list<string>}>}
     */
    public function getChartData(): array
    {
        $days = max(1, $this->days);
        $todayStart = intdiv(time(), self::SECONDS_PER_DAY) * self::SECONDS_PER_DAY;
        $firstDayStart = $todayStart - (($days - 1) * self::SECONDS_PER_DAY);

        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(self::TABLE);
        $rows = $queryBuilder
            ->addSelectLiteral('(crdate - (crdate % 86400)) AS day_start')
            ->addSelectLiteral('COUNT(*) AS entry_count')
            ->from(self::TABLE)
            ->where(
                $queryBuilder->expr()->gte(
                    'crdate',
                    $queryBuilder->createNamedParameter($firstDayStart, Connection::PARAM_INT),
                ),
            )
            ->groupBy('day_start')
            ->executeQuery()
            ->fetchAllAssociative();

        return self::shapeChartData($rows, $firstDayStart, $days);
    }

    /**
     * Shape the SQL rows into chart.js bar-chart format, zero-filling days
     * without audit activity so the time axis stays continuous.
     *
     * Extracted as a pure static method for unit-testability — the
     * ConnectionPool-driven query path is exercised via mocks.
     *
     * @param array<int, array<string, mixed>> $rows
     *
     * @return array{labels: list<string>, datasets: list<array{label: string, data: list<int>, backgroundColor: list<string>}>}
     */
    public static function shapeChartData(array $rows, int $firstDayStart, int $days): array
    {
        $countPerDay = [];

        foreach ($rows as $row) {
            $bucket = $row['day_start'] ?? null;
            if (!is_numeric($bucket)) {
                continue;
            }

            $count = $row['entry_count'] ?? 0;

            $countPerDay[(int) $bucket] = is_numeric($count) ? (int) $count : 0;
        }

        $labels = [];
        $data = [];

        for ($i = 0; $i < $days; ++$i) {
            $dayStart = $firstDayStart + ($i * self::SECONDS_PER_DAY);
            $labels[] = gmdate('Y-m-d', $dayStart);
            $data[] = $countPerDay[$dayStart] ?? 0;
        }

        return [
            'labels' => $labels,
            'datasets' => [
                [
                    'label' => 'Audit events',
                    'data' => $data,
                    'backgroundColor' => array_fill(0, \count($data), self::BAR_COLOR),
                ],
            ],
        ];
    }
}
