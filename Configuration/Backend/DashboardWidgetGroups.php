<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

/**
 * Dashboard widget group for nr-vault widgets.
 *
 * Only evaluated when EXT:dashboard is installed — TYPO3 reads this file
 * from the dashboard extension's boot code, so no guard is needed here.
 */
return [
    'nrvault' => [
        'title' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_dashboard.xlf:widget_group.nrvault',
    ],
];
