<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use TYPO3\CMS\Core\Imaging\IconProvider\SvgIconProvider;
use TYPO3\CMS\Core\Information\Typo3Version;

/**
 * Icon registry configuration.
 *
 * TYPO3 v14 ships a redesigned backend with light/dark mode: use the flat,
 * three-color icons (currentColor + teal accent) that adapt to the active
 * color scheme. v13 uses the colored (teal tile) legacy variants that match
 * the classic module menu.
 */
$suffix = (new Typo3Version())->getMajorVersion() >= 14 ? '.svg' : '.legacy.svg';

$icons = [];

foreach ([
    'module-vault',
    'module-vault-secrets',
    'module-vault-analytics',
    'module-vault-audit',
    'module-vault-migration',
    'vault-secret',
] as $identifier) {
    $icons[$identifier] = [
        'provider' => SvgIconProvider::class,
        'source' => 'EXT:nr_vault/Resources/Public/Icons/' . $identifier . $suffix,
    ];
}

return $icons;
