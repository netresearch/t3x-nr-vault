<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use Netresearch\NrVault\Upgrades\AuditHmacMigrationWizard;
use Netresearch\NrVault\Upgrades\AuditHmacMigrationWizardV13;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use TYPO3\CMS\Core\Upgrades\UpgradeWizardInterface as CoreUpgradeWizardInterface;
use TYPO3\CMS\Dashboard\Widgets\WidgetInterface;
use TYPO3\CMS\Install\Updates\UpgradeWizardInterface as InstallUpgradeWizardInterface;

return static function (ContainerConfigurator $containerConfigurator, ContainerBuilder $containerBuilder): void {
    // The upgrade API moved from EXT:install (TYPO3 13) to EXT:core
    // (TYPO3 14), and neither major keeps the other's name. Register the
    // wizard shell for the running core; autoconfigure turns its
    // #[UpgradeWizard] attribute into the `install.upgradewizard` tag both
    // majors fill their registry from. The shells are excluded from the
    // Services.yaml resource glob, so nothing tries to load the other one.
    $upgradeWizard = match (true) {
        interface_exists(CoreUpgradeWizardInterface::class) => AuditHmacMigrationWizard::class,
        interface_exists(InstallUpgradeWizardInterface::class) => AuditHmacMigrationWizardV13::class,
        default => null,
    };
    if ($upgradeWizard !== null) {
        $containerConfigurator->services()
            ->defaults()->autowire()->autoconfigure()->private()
            ->set($upgradeWizard);
    }

    // Dashboard widgets ship only when typo3/cms-dashboard is installed
    // (composer "suggest", not a hard requirement). Guarding here keeps TYPO3
    // installs without the dashboard from blowing up on unresolvable class
    // references during container compile. WidgetInterface is an interface,
    // so the guard must use interface_exists() (class_exists() returns false
    // for interfaces). The imported file is PHP, not YAML, because the loader
    // handling Services.php cannot resolve a YAML import.
    if (interface_exists(WidgetInterface::class)) {
        $containerConfigurator->import(__DIR__ . '/Services.Dashboard.php');
    }
};
