<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Widgets;

use TYPO3\CMS\Dashboard\Widgets\AdminOnlyWidgetInterface;
use TYPO3\CMS\Dashboard\Widgets\BarChartWidget;

/**
 * Admin-only variant of the core BarChart widget.
 *
 * See {@see AdminOnlyNumberWithIconWidget} for why the marker interface has
 * to live on the registered widget class: DashboardWidgetPass derives the
 * `adminOnly` flag from the class of the tagged service, and the core widget
 * classes do not implement AdminOnlyWidgetInterface themselves.
 *
 * TYPO3 v14 only — see {@see AdminOnlyNumberWithIconWidget} for the v13.4
 * fallback and PHPStan exclusion rationale.
 */
final class AdminOnlyBarChartWidget extends BarChartWidget implements AdminOnlyWidgetInterface {}
