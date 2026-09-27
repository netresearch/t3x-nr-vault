<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use TYPO3\CMS\Core\Information\Typo3Version;

defined('TYPO3') || die();

// TYPO3 v13 reads the backend search scope from `ctrl.searchFields` and ignores
// the per-column `searchable` flag the base TCA sets. TYPO3 v14 removed
// `searchFields` (#106972) and logs a deprecation for every table that still
// sets it, so it is set on v13 only. Remove this file with v13 support.
if ((new Typo3Version())->getMajorVersion() < 14
    && is_array($GLOBALS['TCA']['tx_nrvault_secret']['ctrl'] ?? null)
) {
    $GLOBALS['TCA']['tx_nrvault_secret']['ctrl']['searchFields'] = 'identifier,description,context';
}
