<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Upgrades;

/**
 * The body both upgrade-wizard shells share: every method hands over to
 * {@see AuditHmacMigration}, which holds the logic and knows nothing about
 * TYPO3's upgrade API.
 *
 * TYPO3 13 declares that API in EXT:install (`TYPO3\CMS\Install\Updates`),
 * TYPO3 14 in EXT:core (`TYPO3\CMS\Core\Upgrades`), and neither major ships
 * the other's name. So each major gets a shell that implements its own
 * interface — {@see AuditHmacMigrationWizard} and
 * {@see AuditHmacMigrationWizardV13} — and `Configuration/Services.php`
 * registers only the one whose interface exists. The methods live here so
 * the shells cannot drift apart.
 */
trait AuditHmacMigrationWizardTrait
{
    public function __construct(
        private readonly AuditHmacMigration $migration,
    ) {}

    public function getTitle(): string
    {
        return $this->migration->getTitle();
    }

    public function getDescription(): string
    {
        return $this->migration->getDescription();
    }

    public function updateNecessary(): bool
    {
        return $this->migration->updateNecessary();
    }

    public function executeUpdate(): bool
    {
        return $this->migration->executeUpdate();
    }

    /**
     * @return string[]
     */
    public function getPrerequisites(): array
    {
        return [];
    }
}
