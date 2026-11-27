<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

/*
 * Test-only record table whose delete flag is not named `deleted`
 * (ctrl.delete = removed), so the migrations can be shown to follow the TCA
 * delete column (#565).
 */
return [
    'ctrl' => [
        'title'         => 'Vault test record with a custom delete column',
        'label'         => 'title',
        'crdate'        => 'crdate',
        'tstamp'        => 'tstamp',
        'delete'        => 'removed',
        'enablecolumns' => [
            'disabled' => 'hidden',
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
        'secret' => [
            'label'  => 'Secret',
            'config' => [
                'type' => 'input',
            ],
        ],
    ],
    'types' => [
        '0' => ['showitem' => 'title, secret'],
    ],
];
