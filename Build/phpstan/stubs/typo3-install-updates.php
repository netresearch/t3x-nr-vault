<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

/*
 * The TYPO3 13 wizard registry (EXT:install), for PHPStan runs against
 * TYPO3 14. TYPO3 14 still ships the EXT:install interface and attribute
 * (deprecated, extending their EXT:core successors), but not this registry,
 * which the registration test reads on 13. Signatures copied from
 * typo3/cms-install 13.4; see ../typo3-upgrade-api.php for why this exists.
 */

namespace TYPO3\CMS\Install\Updates {
    if (!class_exists(UpgradeWizardRegistry::class)) {
        /**
         * @internal
         */
        class UpgradeWizardRegistry
        {
            public function hasUpgradeWizard(string $identifier): bool
            {
                return false;
            }

            public function getUpgradeWizard(string $identifier): UpgradeWizardInterface
            {
                throw new \UnexpectedValueException('PHPStan stub', 1757500002);
            }
        }
    }
}
