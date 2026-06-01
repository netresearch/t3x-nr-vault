<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Seeder;

use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Seeder\AuditChainSeeder;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

#[CoversClass(AuditChainSeeder::class)]
final class AuditChainSeederTest extends FunctionalTestCase
{
    protected array $testExtensionsToLoad = ['netresearch/nr-vault'];

    protected array $coreExtensionsToLoad = ['backend'];

    protected array $configurationToUseInTestInstance = [
        'EXTENSIONS' => [
            'nr_vault' => [
                'masterKeyProvider' => 'file',
                'enableCache' => false,
            ],
        ],
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
    }

    #[Test]
    public function seededChainVerifiesValid(): void
    {
        $seeder = $this->get(AuditChainSeeder::class);
        $now = time();
        $seeder->seed([
            ['secret_identifier' => 'demo_a', 'action' => 'create', 'success' => true, 'actor_uid' => 1, 'actor_type' => 'cli', 'actor_username' => '_cli_', 'crdate' => $now - 100 * 86400, 'context' => ['source' => 'demo-seed']],
            ['secret_identifier' => 'demo_a', 'action' => 'read', 'success' => true, 'actor_uid' => 0, 'actor_type' => 'api', 'actor_username' => '_cli_', 'crdate' => $now - 50 * 86400, 'context' => []],
            ['secret_identifier' => 'demo_a', 'action' => 'rotate', 'success' => true, 'actor_uid' => 1, 'actor_type' => 'backend', 'actor_username' => 'admin', 'crdate' => $now - 10 * 86400, 'context' => []],
        ]);

        $audit = $this->get(AuditLogServiceInterface::class);
        $result = $audit->verifyHashChain();
        self::assertTrue($result->isValid(), 'seeded chain must verify valid');

        $count = (int) $this->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_audit_log')
            ->createQueryBuilder()
            ->count('uid')
            ->from('tx_nrvault_audit_log')
            ->executeQuery()
            ->fetchOne();
        self::assertSame(3, $count);
    }
}
