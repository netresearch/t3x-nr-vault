<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Widgets;

use TYPO3\CMS\Dashboard\Widgets\AdminOnlyWidgetInterface;
use TYPO3\CMS\Dashboard\Widgets\NumberWithIconWidget;

/**
 * Admin-only variant of the core NumberWithIcon widget.
 *
 * The core dashboard marks a widget as admin-only via the registered widget
 * CLASS: DashboardWidgetPass sets the `adminOnly` tag attribute from
 * `is_a($class, AdminOnlyWidgetInterface::class)`. The core widget classes do
 * not implement that marker interface, so this empty subclass exists solely
 * to add it — vault statistics must never be assignable to non-admin users,
 * matching the admin-scoped vault backend module (`'access' => 'admin'`).
 *
 * TYPO3 v14 only: AdminOnlyWidgetInterface does not exist in v13.4, so
 * Services.Dashboard.php registers this class only when the interface is
 * present (v13 falls back to the plain core widget class) and the file is
 * excluded from PHPStan analysis on the v13 matrix (see phpstan.neon).
 */
final class AdminOnlyNumberWithIconWidget extends NumberWithIconWidget implements AdminOnlyWidgetInterface {}
