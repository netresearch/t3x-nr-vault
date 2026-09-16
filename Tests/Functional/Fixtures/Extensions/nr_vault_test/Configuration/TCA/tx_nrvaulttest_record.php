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
 *
 * The table is language aware and carries an inline child collection so the
 * DataHandler commands that duplicate a record through a nested datamap pass —
 * copy, localize, copyToLanguage, copying a page with its records, copying a
 * parent with its inline children — can be driven against real vault fields.
 */
return [
    'ctrl' => [
        'title' => 'Vault test record',
        'label' => 'title',
        'delete' => 'deleted',
        'crdate' => 'crdate',
        'tstamp' => 'tstamp',
        'sortby' => 'sorting',
        'languageField' => 'sys_language_uid',
        'transOrigPointerField' => 'l10n_parent',
        'translationSource' => 'l10n_source',
        'rootLevel' => -1,
    ],
    'columns' => [
        'sys_language_uid' => [
            'label' => 'Language',
            'config' => [
                'type' => 'language',
            ],
        ],
        'l10n_parent' => [
            'label' => 'Translation parent',
            'config' => [
                'type' => 'select',
                'renderType' => 'selectSingle',
                'default' => 0,
                'items' => [['label' => '', 'value' => 0]],
                'foreign_table' => 'tx_nrvaulttest_record',
                'foreign_table_where' => 'AND {#tx_nrvaulttest_record}.{#sys_language_uid} IN (-1,0)',
            ],
        ],
        'l10n_source' => [
            'config' => [
                'type' => 'passthrough',
            ],
        ],
        'title' => [
            'label' => 'Title',
            'config' => [
                'type' => 'input',
            ],
        ],
        'api_key' => VaultFieldHelper::getFieldConfig(['label' => 'API key']),
        'api_secret' => VaultFieldHelper::getFieldConfig(['label' => 'API secret']),
        // What integrators get from VaultFieldHelper::getSecureFieldConfig():
        // l10n_mode = exclude, which makes core's DataMapProcessor push the
        // default-language record's stored value into every translation's
        // data map on an ordinary update.
        'api_token' => VaultFieldHelper::getSecureFieldConfig('API token'),
        'children' => [
            'label' => 'Children',
            'config' => [
                'type' => 'inline',
                'foreign_table' => 'tx_nrvaulttest_child',
                'foreign_field' => 'parent',
            ],
        ],
    ],
    'types' => [
        '0' => ['showitem' => 'title, api_key, api_secret, api_token, children'],
    ],
];
