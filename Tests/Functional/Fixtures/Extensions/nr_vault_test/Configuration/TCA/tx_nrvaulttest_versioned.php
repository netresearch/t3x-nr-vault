<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use Netresearch\NrVault\TCA\VaultFieldHelper;

/*
 * Test-only workspace-aware record table with one vault field.
 *
 * `versioningWS` makes core add the t3ver_* columns, so a row can be a
 * workspace version (`t3ver_oid` > 0). The orphan cleanup tests use it to
 * check that a secret created on a version is linked to the live record and
 * survives publishing (#565).
 */
return [
    'ctrl' => [
        'title'        => 'Vault test versioned record',
        'label'        => 'title',
        'crdate'       => 'crdate',
        'tstamp'       => 'tstamp',
        'versioningWS' => true,
        'rootLevel'    => -1,
    ],
    'columns' => [
        'title' => [
            'label'  => 'Title',
            'config' => [
                'type' => 'input',
            ],
        ],
        'api_key' => VaultFieldHelper::getFieldConfig(['label' => 'API key']),
    ],
    'types' => [
        '0' => ['showitem' => 'title, api_key'],
    ],
];
