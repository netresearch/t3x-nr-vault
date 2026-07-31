<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use Netresearch\NrVault\Form\Element\VaultSecretElement;
use Netresearch\NrVault\Form\Element\VaultSecretInputElement;
use Netresearch\NrVault\Hook\DataHandlerHook;
use Netresearch\NrVault\Hook\FlexFormVaultHook;
use Netresearch\NrVault\Hook\SecretTcaHook;
use Netresearch\NrVault\Security\VaultPermission;

defined('TYPO3') || die();

(static function (): void {
    // Operation permissions as TYPO3 custom permission options, so
    // each one is grantable per backend user group in the Backend Users module
    // and checked via check('custom_options', 'tx_nrvault:<permission>').
    // Enum-driven: a new VaultPermission case is grantable without touching
    // this list. Labels/descriptions live in locallang_mod.xlf under
    // `permissions.<case value>` / `.description`.
    $permissionLabels = 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:permissions.';
    $permissionItems = [];
    foreach (VaultPermission::cases() as $permission) {
        $permissionItems[$permission->value] = [
            $permissionLabels . $permission->value,
            // No icon: the Backend Users module falls back to a neutral one.
            '',
            $permissionLabels . $permission->value . '.description',
        ];
    }

    $GLOBALS['TYPO3_CONF_VARS']['BE']['customPermOptions']['tx_nrvault'] = [
        'header' => $permissionLabels . 'header',
        'items' => $permissionItems,
    ];


    // Register vaultSecret form element type (for OTHER tables to reference vault secrets)
    $GLOBALS['TYPO3_CONF_VARS']['SYS']['formEngine']['nodeRegistry'][1735400000] = [
        'nodeName' => 'vaultSecret',
        'priority' => 40,
        'class' => VaultSecretElement::class,
    ];

    // Register vaultSecretInput form element type (for tx_nrvault_secret table direct input)
    $GLOBALS['TYPO3_CONF_VARS']['SYS']['formEngine']['nodeRegistry'][1735400001] = [
        'nodeName' => 'vaultSecretInput',
        'priority' => 40,
        'class' => VaultSecretInputElement::class,
    ];

    // DataHandler hooks for TCA vaultSecret field operations
    $GLOBALS['TYPO3_CONF_VARS']['SC_OPTIONS']['t3lib/class.t3lib_tcemain.php']['processDatamapClass'][]
        = DataHandlerHook::class;

    $GLOBALS['TYPO3_CONF_VARS']['SC_OPTIONS']['t3lib/class.t3lib_tcemain.php']['processCmdmapClass'][]
        = DataHandlerHook::class;

    // FlexForm vault field handling
    $GLOBALS['TYPO3_CONF_VARS']['SC_OPTIONS']['t3lib/class.t3lib_tcemain.php']['processDatamapClass'][]
        = FlexFormVaultHook::class;

    $GLOBALS['TYPO3_CONF_VARS']['SC_OPTIONS']['t3lib/class.t3lib_tcemain.php']['processCmdmapClass'][]
        = FlexFormVaultHook::class;

    // Hook for tx_nrvault_secret TCA operations (identifier immutability, audit logging)
    $GLOBALS['TYPO3_CONF_VARS']['SC_OPTIONS']['t3lib/class.t3lib_tcemain.php']['processDatamapClass'][]
        = SecretTcaHook::class;

    $GLOBALS['TYPO3_CONF_VARS']['SC_OPTIONS']['t3lib/class.t3lib_tcemain.php']['processCmdmapClass'][]
        = SecretTcaHook::class;
})();
