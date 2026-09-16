<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use TYPO3\CMS\Core\Information\Typo3Version;

/*
 * Test-only record table with a FlexForm column that holds a vault secret and
 * is NOT translatable (`l10n_mode = exclude`), on a table without a `delete`
 * column.
 *
 * Both properties are needed to reach the FlexForm delete guard at all:
 * `processCmdmap_deleteAction()` only acts on a hard delete, and the secret it
 * must leave alone is one a translation shares with its default-language
 * record. `tt_content` soft-deletes, so no test against it can reach that
 * branch.
 */
$dataStructure = '<T3DataStructure>
    <sheets>
        <sDEF>
            <ROOT>
                <type>array</type>
                <el>
                    <apiKey>
                        <label>API Key</label>
                        <config>
                            <type>input</type>
                            <renderType>vaultSecret</renderType>
                        </config>
                    </apiKey>
                </el>
            </ROOT>
        </sDEF>
    </sheets>
</T3DataStructure>';

return [
    'ctrl' => [
        'title' => 'Vault test FlexForm record',
        'label' => 'title',
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
                'foreign_table' => 'tx_nrvaulttest_flex',
                'foreign_table_where' => 'AND {#tx_nrvaulttest_flex}.{#sys_language_uid} IN (-1,0)',
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
        'settings' => [
            'label' => 'Settings',
            // Top level, as TYPO3 reads it: the column is not translatable, so
            // every translation keeps the default record's XML — vault
            // identifiers included.
            'l10n_mode' => 'exclude',
            'config' => [
                'type' => 'flex',
                // v14 resolves a single data structure string per field, v13.4
                // requires the `ds` array with a `default` key.
                'ds' => (new Typo3Version())->getMajorVersion() >= 14
                    ? $dataStructure
                    : ['default' => $dataStructure],
            ],
        ],
    ],
    'types' => [
        '0' => ['showitem' => 'title, settings'],
    ],
];
