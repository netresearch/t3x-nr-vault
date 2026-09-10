<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

/*
 * The TYPO3 14 upgrade-wizard API (EXT:core), for PHPStan runs against
 * TYPO3 13, which does not ship it. Signatures copied from typo3/cms-core
 * 14.3; see ../typo3-upgrade-api.php for why this exists.
 */

namespace TYPO3\CMS\Core\Upgrades {
    if (!interface_exists(UpgradeWizardInterface::class)) {
        interface UpgradeWizardInterface
        {
            public function getTitle(): string;

            public function getDescription(): string;

            public function executeUpdate(): bool;

            public function updateNecessary(): bool;

            /**
             * @return string[]
             */
            public function getPrerequisites(): array;
        }
    }

    if (!class_exists(UpgradeWizardRegistry::class)) {
        /**
         * @internal
         */
        readonly class UpgradeWizardRegistry
        {
            public function hasUpgradeWizard(string $identifier): bool
            {
                return false;
            }

            public function getUpgradeWizard(string $identifier): UpgradeWizardInterface
            {
                throw new \UnexpectedValueException('PHPStan stub', 1757500001);
            }
        }
    }
}

namespace TYPO3\CMS\Core\Attribute {
    if (!class_exists(UpgradeWizard::class)) {
        #[\Attribute(\Attribute::TARGET_CLASS)]
        class UpgradeWizard
        {
            public const TAG_NAME = 'install.upgradewizard';

            public function __construct(
                public string $identifier,
            ) {}
        }
    }
}
