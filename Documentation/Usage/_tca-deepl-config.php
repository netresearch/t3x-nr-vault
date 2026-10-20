<?php

declare(strict_types=1);

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
return [
    'ctrl' => [
        'title' => 'DeepL Configuration',
        'label' => 'name',
        'delete' => 'deleted',
        'rootLevel' => 1,
        'security' => [
            'ignorePageTypeRestriction' => true,
        ],
    ],
    'columns' => [
        'name' => [
            'label' => 'Configuration Name',
            'config' => [
                'type' => 'input',
                'default' => 'Default',
            ],
        ],
        'api_key' => [
            'label' => 'DeepL API Key',
            'config' => [
                'type' => 'input',
                'renderType' => 'vaultSecret',
            ],
        ],
        'api_url' => [
            'label' => 'API URL',
            'config' => [
                'type' => 'input',
                'default' => 'https://api-free.deepl.com/v2',
            ],
        ],
    ],
    'types' => [
        '0' => ['showitem' => 'name, api_key, api_url'],
    ],
];
