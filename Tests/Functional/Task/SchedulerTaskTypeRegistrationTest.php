<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Task;

use Netresearch\NrVault\Task\AuditAnchorTask;
use Netresearch\NrVault\Task\AuditVerifyTask;
use Netresearch\NrVault\Task\OrphanCleanupTask;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Information\Typo3Version;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * Configuration/TCA/Overrides/tx_scheduler_task.php registers the three
 * scheduler tasks as record types of tx_scheduler_task. That table is TCA from
 * TYPO3 14 on; on 13.4 the override registers nothing.
 */
final class SchedulerTaskTypeRegistrationTest extends FunctionalTestCase
{
    protected array $testExtensionsToLoad = ['netresearch/nr-vault'];

    protected array $coreExtensionsToLoad = ['backend', 'scheduler'];

    /**
     * @return iterable<string, array{class-string, string, string}>
     */
    public static function taskTypes(): iterable
    {
        yield 'orphan cleanup' => [OrphanCleanupTask::class, 'orphanCleanup', 'actions-database-clean'];
        yield 'audit anchor' => [AuditAnchorTask::class, 'auditAnchor', 'actions-lock'];
        yield 'audit verify' => [AuditVerifyTask::class, 'auditVerify', 'actions-check'];
    }

    #[Test]
    public function tcaHasNoSchedulerTaskTableBeforeTypo3Fourteen(): void
    {
        if ((new Typo3Version())->getMajorVersion() >= 14) {
            self::markTestSkipped('tx_scheduler_task is a TCA table from TYPO3 14 on.');
        }

        $tca = $GLOBALS['TCA'] ?? null;
        self::assertIsArray($tca);
        self::assertArrayNotHasKey('tx_scheduler_task', $tca);
    }

    #[Test]
    #[DataProvider('taskTypes')]
    public function taskIsRegisteredAsSelectableRecordType(string $taskClass, string $labelKey, string $icon): void
    {
        if ((new Typo3Version())->getMajorVersion() < 14) {
            self::markTestSkipped('tx_scheduler_task is a TCA table from TYPO3 14 on.');
        }

        $tca = $GLOBALS['TCA'] ?? null;
        self::assertIsArray($tca);
        $taskTca = $tca['tx_scheduler_task'] ?? null;
        self::assertIsArray($taskTca);
        $types = $taskTca['types'] ?? null;
        self::assertIsArray($types);
        self::assertArrayHasKey($taskClass, $types);

        $columns = $taskTca['columns'] ?? null;
        self::assertIsArray($columns);
        $typeColumn = $columns['tasktype'] ?? null;
        self::assertIsArray($typeColumn);
        $config = $typeColumn['config'] ?? null;
        self::assertIsArray($config);
        $items = $config['items'] ?? null;
        self::assertIsArray($items);
        $typeItem = null;
        foreach ($items as $item) {
            if (is_array($item) && ($item['value'] ?? null) === $taskClass) {
                $typeItem = $item;
            }
        }

        self::assertIsArray($typeItem);
        self::assertSame(
            [
                'label'       => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:task.' . $labelKey . '.title',
                'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:task.' . $labelKey . '.description',
                'icon'        => $icon,
                'group'       => 'nr_vault',
            ],
            [
                'label'       => $typeItem['label'] ?? null,
                'description' => $typeItem['description'] ?? null,
                'icon'        => $typeItem['icon'] ?? null,
                'group'       => $typeItem['group'] ?? null,
            ],
        );
    }
}
