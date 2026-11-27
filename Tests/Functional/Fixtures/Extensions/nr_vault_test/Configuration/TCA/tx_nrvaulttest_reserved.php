<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use Netresearch\NrVault\TCA\VaultFieldHelper;

/*
 * Test-only record table whose vault field is named by an SQL reserved word.
 *
 * Doctrine DBAL keys `listTableColumns()` by the platform-QUOTED name of such
 * a column, so code comparing those keys with the plain field name treats the
 * column as unknown (#565). It also has enable fields and a delete flag, so
 * `vault:migrate-field` can be shown to migrate hidden and time-restricted
 * rows but not deleted ones, and a column too narrow for an identifier.
 */
return [
    'ctrl' => [
        'title'         => 'Vault test record with a reserved-word field',
        'label'         => 'title',
        'crdate'        => 'crdate',
        'tstamp'        => 'tstamp',
        'delete'        => 'deleted',
        'enablecolumns' => [
            'disabled'  => 'hidden',
            'starttime' => 'starttime',
        ],
        'rootLevel' => -1,
    ],
    'columns' => [
        'title' => [
            'label'  => 'Title',
            'config' => [
                'type' => 'input',
            ],
        ],
        'key' => VaultFieldHelper::getFieldConfig(['label' => 'Key']),
    ],
    'types' => [
        '0' => ['showitem' => 'title, key'],
    ],
];
