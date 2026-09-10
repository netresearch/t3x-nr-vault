<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

/*
 * PHPStan bootstrap — never loaded by TYPO3.
 *
 * TYPO3 14 moved the upgrade-wizard API from EXT:install
 * (`TYPO3\CMS\Install\Updates`) to EXT:core (`TYPO3\CMS\Core\Upgrades`);
 * TYPO3 13 has only the former. PHPStan runs once per TYPO3 major in CI, so
 * the run against 13 lacks the EXT:core API the TYPO3 14 wizard shell is
 * written against — a severe, non-baselineable error. Both majors also keep
 * the wizard registry the registration test reads under a different name.
 *
 * Instead of excluding the shell (and with it the test that reaches the
 * wizard through TYPO3's registry), the stub files declare each missing
 * symbol for the analysis only. Every declaration is guarded, so whatever
 * the installed major does provide is never shadowed.
 */

require __DIR__ . '/stubs/typo3-core-upgrades.php';
require __DIR__ . '/stubs/typo3-install-updates.php';
