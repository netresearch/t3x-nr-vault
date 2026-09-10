<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Upgrades;

use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Traits\LegacyAuditEntryTrait;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Upgrades\UpgradeWizardRegistry as CoreUpgradeWizardRegistry;
use TYPO3\CMS\Install\Updates\UpgradeWizardRegistry as InstallUpgradeWizardRegistry;

/**
 * The HMAC migration must reach the Install Tool and `upgrade:run` on every
 * TYPO3 major composer.json promises — asked of the registry TYPO3 itself
 * reads, not of an instance built with `new`.
 *
 * Building the wizard by hand proves the migration logic and nothing about
 * whether TYPO3 ever offers it. The registry is the only place that answers
 * that: TYPO3 13 keeps it in EXT:install, TYPO3 14 in EXT:core, and both fill
 * it from the `install.upgradewizard` service tag.
 */
final class UpgradeWizardRegistrationTest extends AbstractVaultFunctionalTestCase
{
    use LegacyAuditEntryTrait;

    private const IDENTIFIER = 'nrVaultAuditHmacMigration';

    protected ?string $backendUserFixture = __DIR__ . '/../../Functional/Service/Fixtures/be_users.csv';

    /**
     * EXT:install is a system extension every real installation runs, and on
     * TYPO3 13 it owns the wizard registry — which the test instance does not
     * build unless the extension is loaded.
     *
     * @var list<string>
     */
    protected array $coreExtensionsToLoad = [
        'backend',
        'install',
    ];

    /**
     * The target epoch is configured before the container is built, so the
     * DI-resolved wizard sees it without a hand-built configuration object.
     *
     * @var array<string, mixed>
     */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 1,
    ];

    #[Test]
    public function theRegistryTypo3ReadsOffersTheWizard(): void
    {
        self::assertTrue(
            $this->registry()->hasUpgradeWizard(self::IDENTIFIER),
            \sprintf('TYPO3 does not offer the upgrade wizard "%s"; the Install Tool and upgrade:run cannot run it.', self::IDENTIFIER),
        );
    }

    #[Test]
    public function theRegisteredWizardMigratesALegacyChainThatThenVerifies(): void
    {
        $this->seedLegacyAuditEntry('registry/legacy/1', 'store');
        $this->seedLegacyAuditEntry('registry/legacy/2', 'retrieve');

        $wizard = $this->registry()->getUpgradeWizard(self::IDENTIFIER);

        self::assertTrue($wizard->updateNecessary(), 'Legacy epoch-0 rows under a configured epoch 1 must need the migration.');
        self::assertTrue($wizard->executeUpdate(), 'The registered wizard must complete the migration.');
        self::assertFalse($wizard->updateNecessary(), 'After the migration no row may remain below the configured epoch.');

        $verification = $this->get(AuditLogServiceInterface::class)->verifyHashChain();
        self::assertTrue(
            $verification->isValid(),
            'The migrated chain must verify: ' . implode(', ', $verification->errors),
        );
    }

    private function registry(): CoreUpgradeWizardRegistry|InstallUpgradeWizardRegistry
    {
        $registryClass = class_exists(CoreUpgradeWizardRegistry::class)
            ? CoreUpgradeWizardRegistry::class
            : InstallUpgradeWizardRegistry::class;

        $registry = $this->get($registryClass);
        self::assertInstanceOf($registryClass, $registry);

        return $registry;
    }
}
