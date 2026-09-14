<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Acceptance;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditChainAnchorStatus;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Command\VaultAuditVerifyCommand;
use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Acceptance\Fixtures\UpgradeFixture;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Upgrades\UpgradeWizardInterface as CoreUpgradeWizardInterface;
use TYPO3\CMS\Core\Upgrades\UpgradeWizardRegistry as CoreUpgradeWizardRegistry;
use TYPO3\CMS\Install\Updates\UpgradeWizardInterface as InstallUpgradeWizardInterface;
use TYPO3\CMS\Install\Updates\UpgradeWizardRegistry as InstallUpgradeWizardRegistry;

/**
 * Upgrading an installation that ran v0.16.0 to the current code.
 *
 * The database content comes from the released v0.16.0 classes, not from the
 * code under test: `Fixtures/UpgradeFixtureGenerator.php.dist` wrote both CSV data
 * sets against a `git archive v0.16.0` tree, and its docblock is the
 * regeneration recipe. It also names the release each row shape comes from.
 *
 *  - `upgrade_long_lived_v0.16.0.csv` — an installation that started before
 *    0.5.0 and was upgraded along the way: audit rows at epochs 0, 1 and 2, a
 *    version-1 secret without algorithm marker, then v0.16.0's own epoch-3
 *    writes and tip anchor on top. v0.16.0's wizard never reached TYPO3, so
 *    the lower epochs were never migrated.
 *  - `upgrade_plain_v0.16.0.csv` — an installation that only ever ran the
 *    epoch-3 default (0.10.1 and later).
 *
 * The wizard is taken from the registry TYPO3 itself fills — EXT:core's on 14,
 * EXT:install's on 13 — and run the way the Install Tool runs it:
 * `updateNecessary()`, `executeUpdate()`, `updateNecessary()`, and once more to
 * prove a repeated run changes nothing.
 *
 * The installation sets `preferXChaCha20`, as a pre-0.9.0 installation had to
 * for its version-1 secrets to be XChaCha20-Poly1305: version 1 carries no
 * algorithm marker and is decrypted with the host-derived algorithm.
 */
final class UpgradeFromPreviousReleaseTest extends AbstractVaultFunctionalTestCase
{
    private const WIZARD_IDENTIFIER = 'nrVaultAuditHmacMigration';

    private const ADMIN = 1;

    private const READER = 2;

    private const OUTSIDER = 3;

    /** @var list<string> */
    protected array $coreExtensionsToLoad = [
        'backend',
        'install',
    ];

    /** The fixture data sets carry their own users and groups. */
    protected ?int $backendUserUid = null;

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'masterKeyProvider' => 'file',
        'auditHmacEpoch' => 3,
        'preferXChaCha20' => 1,
    ];

    protected function setUp(): void
    {
        parent::setUp();

        // The fixture ciphertext and HMAC chain were sealed under this key.
        self::assertNotNull($this->masterKeyPath);
        file_put_contents($this->masterKeyPath, UpgradeFixture::masterKey());
        FileMasterKeyProvider::clearCachedKey();
    }

    #[Test]
    public function aLongLivedInstallationIsMigratedByTheRegisteredWizardAndKeepsWorking(): void
    {
        $this->importCSVDataSet(__DIR__ . '/Fixtures/upgrade_long_lived_v0.16.0.csv');
        $this->setUpBackendUser(self::ADMIN);

        $beforeUpgrade = $this->get(AuditLogServiceInterface::class)->verifyHashChain(minEpoch: 0);
        self::assertTrue($beforeUpgrade->isValid(), 'The v0.16.0 chain must verify under its stored epochs: ' . implode(', ', $beforeUpgrade->errors));
        self::assertSame(0, $beforeUpgrade->getMinEpoch(), 'The fixture must carry rows sealed before 0.5.0.');
        self::assertSame(3, $beforeUpgrade->getMaxEpoch());

        $wizard = $this->registeredWizard();
        self::assertTrue($wizard->updateNecessary(), 'Epoch 0-2 rows under a configured epoch 3 must offer the migration.');
        self::assertTrue($wizard->executeUpdate(), 'The registered wizard must complete the migration.');
        self::assertFalse($wizard->updateNecessary(), 'No row may remain below the configured epoch after the migration.');

        $afterFirstRun = $this->auditSnapshot();
        self::assertTrue($wizard->executeUpdate(), 'A repeated run must succeed.');
        self::assertSame($afterFirstRun, $this->auditSnapshot(), 'A repeated run must leave every hash byte-identical.');
        self::assertFalse($wizard->updateNecessary());
        self::assertSame([3], array_values(array_unique(array_column($afterFirstRun, 'hmac_key_epoch'))), 'Every row must be sealed at epoch 3.');

        $this->assertChainAndAnchorVerify();
        $this->assertEverySecretDecrypts(UpgradeFixture::LONG_LIVED_PLAINTEXTS);
        $this->assertAclHolds(['legacy_v1_reader_tier', 'modern_reader_tier', 'modern_owned_by_reader']);
    }

    #[Test]
    public function aPlainInstallationNeedsNoMigrationAndKeepsWorking(): void
    {
        $this->importCSVDataSet(__DIR__ . '/Fixtures/upgrade_plain_v0.16.0.csv');
        $this->setUpBackendUser(self::ADMIN);

        self::assertFalse($this->registeredWizard()->updateNecessary(), 'An epoch-3 installation must not be offered the migration.');

        $this->assertChainAndAnchorVerify();
        $this->assertEverySecretDecrypts(UpgradeFixture::PLAIN_PLAINTEXTS);
        $this->assertAclHolds(['modern_reader_tier', 'modern_owned_by_reader']);
    }

    private function assertChainAndAnchorVerify(): void
    {
        $chain = $this->get(AuditLogServiceInterface::class)->verifyHashChain();
        self::assertTrue($chain->isValid(), 'The upgraded chain must verify: ' . implode(', ', $chain->errors));
        self::assertSame(3, $chain->getMinEpoch(), 'No row may remain below the configured epoch.');
        self::assertSame(AuditChainAnchorStatus::Ok, $chain->anchorStatus, 'The v0.16.0 tip anchor must still match the chain.');

        $report = $this->get(ChainTipAnchorServiceInterface::class)->verify();
        self::assertTrue($report->isValid(), implode(', ', $report->getReasonCodes()));

        $command = $this->get(VaultAuditVerifyCommand::class);
        self::assertInstanceOf(Command::class, $command);
        $tester = new CommandTester($command);
        self::assertSame(Command::SUCCESS, $tester->execute([]), $tester->getDisplay());
    }

    /**
     * @param array<string, string> $plaintexts
     */
    private function assertEverySecretDecrypts(array $plaintexts): void
    {
        $this->setUpBackendUser(self::ADMIN);
        $vault = $this->get(VaultServiceInterface::class);
        foreach ($plaintexts as $identifier => $plaintext) {
            self::assertSame($plaintext, $vault->retrieve($identifier), \sprintf('"%s" must decrypt after the upgrade.', $identifier));
        }
    }

    /**
     * The reader holds the grant and sits in the group (or owns the secret);
     * the outsider holds the same operation permissions in another group.
     *
     * @param list<string> $identifiers
     */
    private function assertAclHolds(array $identifiers): void
    {
        $vault = $this->get(VaultServiceInterface::class);

        $this->setUpBackendUser(self::READER);
        foreach ($identifiers as $identifier) {
            self::assertNotNull($vault->retrieve($identifier), \sprintf('The reader must still reach "%s".', $identifier));
        }

        $this->setUpBackendUser(self::OUTSIDER);
        foreach ($identifiers as $identifier) {
            try {
                $vault->retrieve($identifier);
                self::fail(\sprintf('The outsider must not reach "%s".', $identifier));
            } catch (AccessDeniedException) {
                // expected
            }
        }

        $this->setUpBackendUser(self::ADMIN);
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function auditSnapshot(): array
    {
        return $this->getConnectionPool()->getConnectionForTable('tx_nrvault_audit_log')
            ->select(['uid', 'previous_hash', 'entry_hash', 'hmac_key_epoch'], 'tx_nrvault_audit_log', [], [], ['uid' => 'ASC'])
            ->fetchAllAssociative();
    }

    private function registeredWizard(): CoreUpgradeWizardInterface|InstallUpgradeWizardInterface
    {
        $registryClass = class_exists(CoreUpgradeWizardRegistry::class)
            ? CoreUpgradeWizardRegistry::class
            : InstallUpgradeWizardRegistry::class;

        $registry = $this->get($registryClass);
        self::assertInstanceOf($registryClass, $registry);
        self::assertTrue($registry->hasUpgradeWizard(self::WIZARD_IDENTIFIER), 'TYPO3 must offer the upgrade wizard.');

        return $registry->getUpgradeWizard(self::WIZARD_IDENTIFIER);
    }
}
