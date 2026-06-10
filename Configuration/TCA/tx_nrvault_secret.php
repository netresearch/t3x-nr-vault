<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

/**
 * TCA configuration for tx_nrvault_secret.
 *
 * Provides FormEngine support for vault secrets with native TYPO3
 * group fields for owner, groups, and page selection.
 */
return [
    'ctrl' => [
        'title' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret',
        'label' => 'identifier',
        'label_alt' => 'description',
        'tstamp' => 'tstamp',
        'crdate' => 'crdate',
        'delete' => 'deleted',
        'default_sortby' => 'identifier ASC',
        // searchFields is ignored on v14 (option removed, see #106972 — the
        // backend derives searchable fields from per-column `searchable`
        // flags there) but enables backend live-search on v13.
        'searchFields' => 'identifier,description,context',
        'hideTable' => false,
        'enablecolumns' => [
            'disabled' => 'hidden',
        ],
        'iconfile' => 'EXT:nr_vault/Resources/Public/Icons/vault-secret.svg',
        'security' => [
            'ignorePageTypeRestriction' => true,
        ],
        'rootLevel' => -1,
    ],

    'columns' => [
        'hidden' => [
            'label' => 'LLL:EXT:core/Resources/Private/Language/locallang_general.xlf:LGL.enabled',
            'config' => [
                'type' => 'check',
                'renderType' => 'checkboxToggle',
                'default' => 0,
                'items' => [
                    [
                        'label' => '',
                        'invertStateDisplay' => true,
                    ],
                ],
            ],
        ],

        'identifier' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.identifier',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.identifier.description',
            'l10n_mode' => 'exclude',
            'config' => [
                'type' => 'input',
                'size' => 50,
                'max' => 255,
                'eval' => 'trim,alphanum_x',
                'placeholder' => 'my-api-key',
                'required' => true,
                'searchable' => true,
                // Identifier is immutable after creation - use readOnly in edit context
            ],
        ],

        'secret_input' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.secret_input',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.secret_input.description',
            'config' => [
                'type' => 'user',
                'renderType' => 'vaultSecretInput',
                'size' => 50,
            ],
        ],

        'description' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.description',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.description.description',
            'config' => [
                'type' => 'text',
                'rows' => 3,
                'cols' => 50,
                'max' => 1000,
                'searchable' => true,
            ],
        ],

        'owner_uid' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.owner_uid',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.owner_uid.description',
            'config' => [
                'type' => 'group',
                'allowed' => 'be_users',
                'relationship' => 'manyToOne',
                'size' => 1,
                'maxitems' => 1,
                'minitems' => 0,
                'suggestOptions' => [
                    'default' => [
                        'additionalSearchFields' => 'realName,email',
                    ],
                ],
            ],
        ],

        'allowed_groups' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.allowed_groups',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.allowed_groups.description',
            'config' => [
                'type' => 'group',
                'allowed' => 'be_groups',
                'size' => 5,
                'maxitems' => 20,
                'minitems' => 0,
                'MM' => 'tx_nrvault_secret_begroups_mm',
                'suggestOptions' => [
                    'default' => [
                        'additionalSearchFields' => 'description',
                    ],
                ],
            ],
        ],

        'write_groups' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.write_groups',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.write_groups.description',
            'config' => [
                'type' => 'group',
                'allowed' => 'be_groups',
                'size' => 5,
                'maxitems' => 20,
                'minitems' => 0,
                'MM' => 'tx_nrvault_secret_writegroups_mm',
                'suggestOptions' => [
                    'default' => [
                        'additionalSearchFields' => 'description',
                    ],
                ],
            ],
        ],

        'context' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.context',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.context.description',
            'config' => [
                'type' => 'input',
                'size' => 30,
                'max' => 50,
                'placeholder' => 'production',
                'searchable' => true,
            ],
        ],

        'frontend_accessible' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.frontend_accessible',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.frontend_accessible.description',
            'config' => [
                'type' => 'check',
                'renderType' => 'checkboxToggle',
                'default' => 0,
            ],
        ],

        'expires_at' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.expires_at',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.expires_at.description',
            'config' => [
                'type' => 'datetime',
                'format' => 'datetime',
                'default' => 0,
            ],
        ],

        'metadata' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.metadata',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.metadata.description',
            'config' => [
                'type' => 'text',
                'renderType' => 'codeEditor',
                'format' => 'json',
                'rows' => 5,
            ],
        ],

        'scope_pid' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.scope_pid',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.scope_pid.description',
            'config' => [
                'type' => 'group',
                'allowed' => 'pages',
                'relationship' => 'manyToOne',
                'size' => 1,
                'maxitems' => 1,
                'minitems' => 0,
            ],
        ],

        // Read-only info fields
        'version' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.version',
            'config' => [
                'type' => 'number',
                'readOnly' => true,
            ],
        ],

        'last_rotated_at' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.last_rotated_at',
            'config' => [
                'type' => 'datetime',
                'format' => 'datetime',
                'readOnly' => true,
            ],
        ],

        'read_count' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.read_count',
            'config' => [
                'type' => 'number',
                'readOnly' => true,
            ],
        ],

        'last_read_at' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.last_read_at',
            'config' => [
                'type' => 'datetime',
                'format' => 'datetime',
                'readOnly' => true,
            ],
        ],

        'adapter' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.adapter',
            'config' => [
                'type' => 'input',
                'readOnly' => true,
            ],
        ],

        // Written exclusively by the crypto layer (EncryptionService);
        // surfaced read-only so operators can see which AEAD algorithm a
        // secret's envelope uses (empty = legacy, host-derived at decrypt).
        'encryption_algorithm' => [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tx_nrvault_secret.encryption_algorithm',
            'config' => [
                'type' => 'input',
                'readOnly' => true,
            ],
        ],
    ],

    'types' => [
        '0' => [
            'showitem' => '
                --div--;core.form.tabs:general,
                    identifier,
                    secret_input,
                    description,
                --div--;LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tabs.access,
                    owner_uid,
                    allowed_groups,
                    write_groups,
                    frontend_accessible,
                --div--;LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tabs.settings,
                    context,
                    expires_at,
                    scope_pid,
                    metadata,
                --div--;LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:tabs.info,
                    version,
                    last_rotated_at,
                    read_count,
                    last_read_at,
                    adapter,
                    encryption_algorithm,
                --div--;core.form.tabs:access,
                    hidden,
            ',
        ],
    ],
];
