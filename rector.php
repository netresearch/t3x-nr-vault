<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Privatization\Rector\Property\PrivatizeFinalClassPropertyRector;
use Ssch\TYPO3Rector\Set\Typo3LevelSetList;
use Ssch\TYPO3Rector\Set\Typo3SetList;

$configure = require_once __DIR__ . '/.Build/vendor/netresearch/typo3-ci-workflows/config/rector/rector.php';

return static function (RectorConfig $rectorConfig) use ($configure): void {
    // Shared org base config: code-quality sets, rule skips, phpstan-rector.neon
    $configure($rectorConfig, __DIR__);

    // paths() replaces the shared list — re-declared to keep Tests/ in scope,
    // which the shared $projectRoot default leaves out.
    $rectorConfig->paths(array_merge(
        [
            __DIR__ . '/Classes',
            __DIR__ . '/Configuration',
            __DIR__ . '/Resources',
            __DIR__ . '/Tests',
        ],
        glob(__DIR__ . '/ext_*.php') ?: [],
    ));

    $rectorConfig->sets([
        Typo3LevelSetList::UP_TO_TYPO3_14,
        Typo3SetList::CODE_QUALITY,
        Typo3SetList::GENERAL,
        Rector\Set\ValueObject\SetList::DEAD_CODE,
    ]);

    $rectorConfig->skip([
        // Scheduler tasks use unserialize() - constructor injection breaks them
        __DIR__ . '/Classes/Task/OrphanCleanupTask.php',
        // Factory is called via GeneralUtility::makeInstance without constructor args
        __DIR__ . '/Classes/Http/SecureHttpClientFactory.php',
        // The shared config enables SetList::PRIVATIZATION, whose
        // PrivatizeFinalClassPropertyRector narrows protected properties in final
        // classes to private. Two places here depend on the wider visibility and
        // Rector cannot see either contract:
        //
        // Classes/Task: TYPO3 13.4 stores a scheduler task as a serialized object
        // (tx_scheduler_task.serialized_task_object, restored by
        // Scheduler\Task\TaskSerializer::deserialize()), and PHP encodes property
        // visibility in the serialized key ("\0*\0prop" protected vs "\0FQCN\0prop"
        // private). Narrowing therefore orphans the stored value in every existing
        // task row: unserialize() leaves the typed property uninitialized and the
        // next read fails with "must not be accessed before initialization".
        //
        // Tests: Tests/Unit/TestCase.php pulls in TcaSchemaMockTrait, whose
        // mockTcaSchemaForTable() reads isset($this->tcaSchemaFactory) — a property
        // each final test class declares itself. From the base-class scope a private
        // child property is invisible, so isset() reports false and the helper
        // throws (50 unit tests failed on exactly that).
        PrivatizeFinalClassPropertyRector::class => [
            __DIR__ . '/Classes/Task',
            __DIR__ . '/Tests',
        ],
    ]);
};
