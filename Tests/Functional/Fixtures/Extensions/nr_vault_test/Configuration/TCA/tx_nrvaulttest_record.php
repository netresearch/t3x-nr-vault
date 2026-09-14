<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use Netresearch\NrVault\TCA\VaultFieldHelper;

/*
 * Test-only record table with two vault secret fields.
 *
 * Registered at bootstrap through a fixture extension (not by writing to
 * $GLOBALS['TCA'] at runtime) so TcaSchemaFactory knows the table: both
 * DataHandler and VaultFieldResolver read the schema, not the raw array.
 * The fields use VaultFieldHelper, the helper integrators are told to use.
 */
return [
    'ctrl' => [
        'title' => 'Vault test record',
        'label' => 'title',
        'delete' => 'deleted',
        'crdate' => 'crdate',
        'tstamp' => 'tstamp',
        'rootLevel' => -1,
    ],
    'columns' => [
        'title' => [
            'label' => 'Title',
            'config' => [
                'type' => 'input',
            ],
        ],
        'api_key' => VaultFieldHelper::getFieldConfig(['label' => 'API key']),
        'api_secret' => VaultFieldHelper::getFieldConfig(['label' => 'API secret']),
    ],
    'types' => [
        '0' => ['showitem' => 'title, api_key, api_secret'],
    ],
];
