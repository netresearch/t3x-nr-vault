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

    /**
     * Without an owner the seeded secrets belong to uid 0 and the module prints
     * "User #0" on every row -- next to an owner filter with nothing to filter
     * by. The audit rows for those writes read "Unknown" for the same reason.
     *
     * TYPO3's own system accounts are excluded on purpose: picking `_cli_` as
     * the acting user puts that name in the Actor column, which is the thing
     * being fixed, and owning a credential is not something they do.
     */
    #[Test]
    public function seededSecretsBelongToRealBackendUsersAndTheWritesAreAttributed(): void
    {
        $this->importCSVDataSet(__DIR__ . '/Fixtures/be_users_seed_owners.csv');

        $tester = new CommandTester($this->get(VaultSeedDemoCommand::class));
        self::assertSame(0, $tester->execute([]), $tester->getDisplay());

        $connection = $this->get(ConnectionPool::class)->getConnectionForTable('tx_nrvault_secret');

        $owners = $connection
            ->select(['owner_uid'], 'tx_nrvault_secret', ['deleted' => 0])
            ->fetchFirstColumn();
        $owners = array_map(static fn (mixed $uid): int => (int) $uid, $owners);

        self::assertNotContains(0, $owners, 'no secret may belong to uid 0');
        self::assertNotContains(2, $owners, 'the _cli_ system account is not an owner');
        self::assertNotContains(4, $owners, 'a disabled user is not an owner');
        self::assertContains(1, $owners, 'the admin owns some of them');
        self::assertContains(3, $owners, 'ownership is spread over more than one user');

        $actors = $this->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_audit_log')
            ->select(['actor_username'], 'tx_nrvault_audit_log', ['action' => 'create'])
            ->fetchFirstColumn();

        self::assertNotSame([], $actors, 'the creates are recorded');
        foreach ($actors as $username) {
            self::assertNotSame('', (string) $username, 'every create names its actor');
            self::assertNotSame('_cli_', (string) $username, 'and it is not the CLI system account');
        }
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
