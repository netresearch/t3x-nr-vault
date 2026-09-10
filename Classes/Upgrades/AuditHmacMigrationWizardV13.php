<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Upgrades;

use TYPO3\CMS\Install\Attribute\UpgradeWizard;
use TYPO3\CMS\Install\Updates\UpgradeWizardInterface;

/**
 * Offers {@see AuditHmacMigration} to the Install Tool and `upgrade:run` on
 * TYPO3 13, whose upgrade API lives in EXT:install.
 *
 * Registered by `Configuration/Services.php` only when that API exists; see
 * {@see AuditHmacMigrationWizardTrait} for why there are two shells. Remove
 * this class together with TYPO3 13 support.
 */
#[UpgradeWizard(AuditHmacMigration::IDENTIFIER)]
final class AuditHmacMigrationWizardV13 implements UpgradeWizardInterface
{
    use AuditHmacMigrationWizardTrait;
}
