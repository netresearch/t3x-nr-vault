<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use Netresearch\NrVault\Task\AuditAnchorTask;
use Netresearch\NrVault\Task\AuditVerifyTask;
use Netresearch\NrVault\Task\OrphanCleanupTask;
use TYPO3\CMS\Core\Utility\ExtensionManagementUtility;

defined('TYPO3') || die();

if (is_array($GLOBALS['TCA'] ?? null) && isset($GLOBALS['TCA']['tx_scheduler_task'])) {
    // Add custom fields for the OrphanCleanupTask
    ExtensionManagementUtility::addTCAcolumns(
        'tx_scheduler_task',
        [
            'nr_vault_retention_days' => [
                'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:task.orphanCleanup.retentionDays',
                'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:task.orphanCleanup.retentionDays.description',
                'config' => [
                    'type' => 'number',
                    'size' => 5,
                    'range' => [
                        'lower' => 0,
                        'upper' => 365,
                    ],
                    'default' => 7,
                ],
            ],
            'nr_vault_table_filter' => [
                'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:task.orphanCleanup.tableFilter',
                'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:task.orphanCleanup.tableFilter.description',
                'config' => [
                    'type' => 'input',
                    'size' => 30,
                    'max' => 255,
                    'placeholder' => 'e.g., tx_myext_settings',
                ],
            ],
            'nr_vault_tamper_only' => [
                'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:task.auditVerify.tamperOnly',
                'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:task.auditVerify.tamperOnly.description',
                'config' => [
                    'type' => 'check',
                    'renderType' => 'checkboxToggle',
                    'default' => 0,
                ],
            ],
        ],
    );

    // Register the OrphanCleanupTask as a native TCA task type
    ExtensionManagementUtility::addRecordType(
        [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:task.orphanCleanup.title',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:task.orphanCleanup.description',
            'value' => OrphanCleanupTask::class,
            'icon' => 'actions-database-clean',
            'group' => 'nr_vault',
        ],
        '
            --div--;LLL:EXT:core/Resources/Private/Language/locallang_core.xlf:labels.generalTab,
                tasktype,
                task_group,
                description,
                nr_vault_retention_days,
                nr_vault_table_filter,
            --div--;LLL:EXT:scheduler/Resources/Private/Language/locallang.xlf:scheduler.form.palettes.timing,
                execution_details,
                nextexecution,
                --palette--;;lastexecution,
            --div--;LLL:EXT:core/Resources/Private/Language/locallang_core.xlf:labels.accessTab,
                disable,
            --div--;LLL:EXT:core/Resources/Private/Language/locallang_core.xlf:labels.extended,
        ',
        [],
        '',
        'tx_scheduler_task',
    );

    // Register the AuditAnchorTask — publishes the audit chain tip to the
    // external sinks. No task-specific fields: what it does is fully determined
    // by which audit sinks are enabled in the extension configuration.
    ExtensionManagementUtility::addRecordType(
        [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:task.auditAnchor.title',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:task.auditAnchor.description',
            'value' => AuditAnchorTask::class,
            'icon' => 'actions-lock',
            'group' => 'nr_vault',
        ],
        '
            --div--;LLL:EXT:core/Resources/Private/Language/locallang_core.xlf:labels.generalTab,
                tasktype,
                task_group,
                description,
            --div--;LLL:EXT:scheduler/Resources/Private/Language/locallang.xlf:scheduler.form.palettes.timing,
                execution_details,
                nextexecution,
                --palette--;;lastexecution,
            --div--;LLL:EXT:core/Resources/Private/Language/locallang_core.xlf:labels.accessTab,
                disable,
            --div--;LLL:EXT:core/Resources/Private/Language/locallang_core.xlf:labels.extended,
        ',
        [],
        '',
        'tx_scheduler_task',
    );

    // Register the AuditVerifyTask — verifies the hash chain against the
    // external anchor and dispatches integrity alerts.
    ExtensionManagementUtility::addRecordType(
        [
            'label' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:task.auditVerify.title',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:task.auditVerify.description',
            'value' => AuditVerifyTask::class,
            'icon' => 'actions-check',
            'group' => 'nr_vault',
        ],
        '
            --div--;LLL:EXT:core/Resources/Private/Language/locallang_core.xlf:labels.generalTab,
                tasktype,
                task_group,
                description,
                nr_vault_tamper_only,
            --div--;LLL:EXT:scheduler/Resources/Private/Language/locallang.xlf:scheduler.form.palettes.timing,
                execution_details,
                nextexecution,
                --palette--;;lastexecution,
            --div--;LLL:EXT:core/Resources/Private/Language/locallang_core.xlf:labels.accessTab,
                disable,
            --div--;LLL:EXT:core/Resources/Private/Language/locallang_core.xlf:labels.extended,
        ',
        [],
        '',
        'tx_scheduler_task',
    );
}
