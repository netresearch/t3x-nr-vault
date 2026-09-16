<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use Netresearch\NrVault\TCA\VaultFieldHelper;

/*
 * Inline child of tx_nrvaulttest_record with its own vault secret field.
 *
 * DataHandler copies inline children through copyRecord() from within the
 * parent's field processing, so a child's secret travels the same nested
 * datamap pass as the parent's without any command of its own.
 */
return [
    'ctrl' => [
        'title' => 'Vault test child',
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
                'foreign_table' => 'tx_nrvaulttest_child',
                'foreign_table_where' => 'AND {#tx_nrvaulttest_child}.{#sys_language_uid} IN (-1,0)',
            ],
        ],
        'l10n_source' => [
            'config' => [
                'type' => 'passthrough',
            ],
        ],
        'parent' => [
            'label' => 'Parent',
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
    ],
    'types' => [
        '0' => ['showitem' => 'title, api_key'],
    ],
];
