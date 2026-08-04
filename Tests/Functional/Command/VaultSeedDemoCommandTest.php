<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Command;

use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Command\VaultSeedDemoCommand;
use Netresearch\NrVault\Service\VaultServiceInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

#[CoversClass(VaultSeedDemoCommand::class)]
final class VaultSeedDemoCommandTest extends FunctionalTestCase
{
    protected array $testExtensionsToLoad = ['netresearch/nr-vault'];

    protected array $coreExtensionsToLoad = ['backend'];

    protected array $configurationToUseInTestInstance = [
        'EXTENSIONS' => ['nr_vault' => ['masterKeyProvider' => 'file']],
    ];

    private string $masterKeyPath = '';

    protected function setUp(): void
    {
        parent::setUp();
        $this->masterKeyPath = $this->instancePath . '/var/secrets/vault-master.key';
        $dir = \dirname($this->masterKeyPath);
        if (!is_dir($dir)) {
            mkdir($dir, 0o700, true);
        }

        file_put_contents($this->masterKeyPath, sodium_crypto_secretbox_keygen());
        chmod($this->masterKeyPath, 0o600);
        $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault']['masterKeySource'] = $this->masterKeyPath;
        $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault']['autoKeyPath'] = $this->masterKeyPath;
        $this->importCSVDataSet(__DIR__ . '/../Hook/Fixtures/be_users.csv');
        $this->setUpBackendUser(1);
    }

    #[Test]
    public function seedsHistoricDataWithValidChainAndDecryptableSecrets(): void
    {
        $tester = new CommandTester($this->get(VaultSeedDemoCommand::class));
        $exit = $tester->execute([]);
        self::assertSame(0, $exit, $tester->getDisplay());

        $vault = $this->get(VaultServiceInterface::class);
        self::assertTrue($vault->exists('stripe_live_key'));
        self::assertSame('sk_live_demo_4242', $vault->retrieve('stripe_live_key'));

        $row = $this->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_secret')
            ->select(['read_count', 'crdate'], 'tx_nrvault_secret', ['identifier' => 'stripe_test_old']);
        $secret = $row->fetchAssociative();
        self::assertSame(0, (int) $secret['read_count']);
        self::assertLessThan(time() - 200 * 86400, (int) $secret['crdate']);

        self::assertTrue($this->get(AuditLogServiceInterface::class)->verifyHashChain()->isValid());
    }

    #[Test]
    public function isIdempotentWithoutForce(): void
    {
        (new CommandTester($this->get(VaultSeedDemoCommand::class)))->execute([]);
        $countAfterFirst = $this->secretCount();

        $exit = (new CommandTester($this->get(VaultSeedDemoCommand::class)))->execute([]);
        self::assertSame(0, $exit);
        self::assertSame($countAfterFirst, $this->secretCount(), 'second run without --force must not add secrets');
    }

    #[Test]
    public function forceReseedKeepsCountStableAndChainValid(): void
    {
        (new CommandTester($this->get(VaultSeedDemoCommand::class)))->execute([]);
        $countAfterFirst = $this->secretCount();

        $exit = (new CommandTester($this->get(VaultSeedDemoCommand::class)))->execute(['--force' => true]);
        self::assertSame(0, $exit);
        self::assertSame($countAfterFirst, $this->secretCount(), 'force reseed must not change the active secret count');
        self::assertTrue(
            $this->get(AuditLogServiceInterface::class)->verifyHashChain()->isValid(),
            'audit chain must remain valid after a --force reseed (delete + re-append)',
        );
    }

    private function secretCount(): int
    {
        return (int) $this->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_secret')
            ->count('uid', 'tx_nrvault_secret', ['deleted' => 0]);
    }
}
