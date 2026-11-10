<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use Netresearch\NrVault\TCA\VaultFieldHelper;
use TYPO3\CMS\Core\Information\Typo3Version;

/*
 * Test-only record table that holds a vault secret in a plain TCA field AND in
 * a FlexForm field, on a table without a `delete` column.
 *
 * A hard delete is the only delete in which both hooks remove secrets: the
 * plain field through DataHandlerHook, the FlexForm field through
 * FlexFormVaultHook. The record-wide delete preflight is tested against it.
 * Kept apart from `tx_nrvaulttest_flex`, so the FlexForm-only tests never pass
 * through the plain-field hook.
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
        'title'     => 'Vault test record with plain and FlexForm secrets',
        'label'     => 'title',
        'crdate'    => 'crdate',
        'tstamp'    => 'tstamp',
        'rootLevel' => -1,
    ],
    'columns' => [
        'title' => [
            'label'  => 'Title',
            'config' => [
                'type' => 'input',
            ],
        ],
        'api_key'  => VaultFieldHelper::getFieldConfig(['label' => 'API key']),
        'settings' => [
            'label'  => 'Settings',
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
        '0' => ['showitem' => 'title, api_key, settings'],
    ],
];
