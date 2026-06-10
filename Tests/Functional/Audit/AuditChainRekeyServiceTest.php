<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Audit;

use Netresearch\NrVault\Audit\AuditChainRekeyService;
use Netresearch\NrVault\Audit\AuditChainRekeyServiceInterface;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Functional tests for the audit-chain re-key on master-key rotation:
 * the chain HMAC key derives from the master key, so after a re-key the
 * chain must verify under the NEW key (and no longer under the old one),
 * per-row epochs must be preserved, and re-keying must be idempotent.
 */
#[CoversClass(AuditChainRekeyService::class)]
final class AuditChainRekeyServiceTest extends AbstractVaultFunctionalTestCase
{
    private const TABLE_NAME = 'tx_nrvault_audit_log';

    protected ?string $backendUserFixture = __DIR__ . '/../../Functional/Service/Fixtures/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'masterKeyProvider' => 'file',
        'auditHmacEpoch' => 2,
    ];

    #[Test]
    public function rekeyChainMakesChainVerifiableUnderNewMasterKey(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $rekeyService = $this->get(AuditChainRekeyServiceInterface::class);
        $connection = $this->getAuditConnection();

        // Seed a chain sealed under the ORIGINAL master key.
        $auditService->log('rekey_test_secret', 'create', true);
        $auditService->log('rekey_test_secret', 'read', true);
        $auditService->log('rekey_test_secret', 'rotate', true, null, 'value rotation');

        self::assertTrue($auditService->verifyHashChain()->isValid(), 'Chain must verify under the original key');

        // Re-key under a NEW master key, inside a transaction per contract.
        $newKey = sodium_crypto_secretbox_keygen();
        $connection->beginTransaction();
        $rewritten = $rekeyService->rekeyChain($connection, $newKey);
        $connection->commit();

        self::assertSame(3, $rewritten, 'All three HMAC-epoch rows must be rewritten');

        // Until the provider configuration is switched, verification uses
        // the OLD key and must now fail — this is the documented switch
        // window, mirroring the secrets being undecryptable until then.
        self::assertFalse(
            $auditService->verifyHashChain()->isValid(),
            'Chain must NOT verify under the old key after the re-key',
        );

        // Switch the provider to the new key (same mechanism as rotating the
        // key file in production), then the chain must verify again.
        $this->switchMasterKeyFile($newKey);

        self::assertTrue(
            $auditService->verifyHashChain()->isValid(),
            'Chain must verify under the new key after the provider switch',
        );
    }

    #[Test]
    public function rekeyChainPreservesEpochsAndLeavesKeylessPrefixUntouched(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $rekeyService = $this->get(AuditChainRekeyServiceInterface::class);
        $connection = $this->getAuditConnection();

        // Two legacy keyless (epoch 0) rows at the head of the chain — these
        // do not depend on the master key at all.
        $this->insertKeylessEntry($connection, 'legacy_secret', 'create');
        $this->insertKeylessEntry($connection, 'legacy_secret', 'read');

        // Two HMAC (epoch 2) rows chained on top, sealed under the original key.
        $auditService->log('rekey_epoch_secret', 'create', true);
        $auditService->log('rekey_epoch_secret', 'read', true);

        self::assertTrue($auditService->verifyHashChain()->isValid(), 'Mixed-epoch chain must verify before re-key');

        $epochsBefore = $this->fetchColumnByUid($connection, 'hmac_key_epoch');
        $hashesBefore = $this->fetchColumnByUid($connection, 'entry_hash');

        $newKey = sodium_crypto_secretbox_keygen();
        $connection->beginTransaction();
        $rewritten = $rekeyService->rekeyChain($connection, $newKey);
        $connection->commit();

        // Only the two HMAC rows change; the keyless prefix is untouched
        // because neither its payload nor its previous_hash links changed.
        self::assertSame(2, $rewritten);

        $epochsAfter = $this->fetchColumnByUid($connection, 'hmac_key_epoch');
        $hashesAfter = $this->fetchColumnByUid($connection, 'entry_hash');

        self::assertSame($epochsBefore, $epochsAfter, 'Per-row epochs must be preserved (key change, not format change)');

        $uids = array_keys($hashesBefore);
        self::assertSame($hashesBefore[$uids[0]], $hashesAfter[$uids[0]], 'Keyless row 1 must be unchanged');
        self::assertSame($hashesBefore[$uids[1]], $hashesAfter[$uids[1]], 'Keyless row 2 must be unchanged');
        self::assertNotSame($hashesBefore[$uids[2]], $hashesAfter[$uids[2]], 'HMAC row 1 must be re-keyed');
        self::assertNotSame($hashesBefore[$uids[3]], $hashesAfter[$uids[3]], 'HMAC row 2 must be re-keyed');

        $this->switchMasterKeyFile($newKey);
        self::assertTrue($auditService->verifyHashChain()->isValid(), 'Mixed-epoch chain must verify under the new key');
    }

    #[Test]
    public function rekeyChainIsIdempotent(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $rekeyService = $this->get(AuditChainRekeyServiceInterface::class);
        $connection = $this->getAuditConnection();

        $auditService->log('idempotency_secret', 'create', true);
        $auditService->log('idempotency_secret', 'read', true);

        $newKey = sodium_crypto_secretbox_keygen();

        $connection->beginTransaction();
        $firstRun = $rekeyService->rekeyChain($connection, $newKey);
        $connection->commit();

        $connection->beginTransaction();
        $secondRun = $rekeyService->rekeyChain($connection, $newKey);
        $connection->commit();

        self::assertSame(2, $firstRun, 'First run rewrites every HMAC row');
        self::assertSame(0, $secondRun, 'Second run with the same key must rewrite nothing');
    }

    private function getAuditConnection(): Connection
    {
        return $this->get(ConnectionPool::class)->getConnectionForTable(self::TABLE_NAME);
    }

    /**
     * Point the file master-key provider at a new key, as a production
     * operator does after `vault:rotate-master-key`.
     */
    private function switchMasterKeyFile(string $newKey): void
    {
        self::assertIsString($this->masterKeyPath);
        file_put_contents($this->masterKeyPath, $newKey);
        FileMasterKeyProvider::clearCachedKey();
    }

    /**
     * Insert a legacy keyless (epoch 0) chain row, mirroring the pre-HMAC
     * writer: reserve the uid, then seal the row with a plain SHA-256 over
     * the identity fields.
     */
    private function insertKeylessEntry(Connection $connection, string $secretIdentifier, string $action): void
    {
        $previousHash = $this->fetchLatestEntryHash($connection);
        $crdate = time();

        $connection->insert(self::TABLE_NAME, [
            'pid' => 0,
            'secret_identifier' => $secretIdentifier,
            'action' => $action,
            'success' => 1,
            'actor_uid' => 1,
            'actor_type' => 'backend',
            'previous_hash' => $previousHash,
            'crdate' => $crdate,
            'hmac_key_epoch' => 0,
            'context' => '{}',
        ]);
        $uid = (int) $connection->lastInsertId();

        $connection->update(
            self::TABLE_NAME,
            ['entry_hash' => AuditLogService::calculateHash($uid, $secretIdentifier, $action, 1, $crdate, $previousHash)],
            ['uid' => $uid],
        );
    }

    private function fetchLatestEntryHash(Connection $connection): string
    {
        $hash = $connection->createQueryBuilder()
            ->select('entry_hash')
            ->from(self::TABLE_NAME)
            ->orderBy('uid', 'DESC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchOne();

        return \is_string($hash) ? $hash : '';
    }

    /**
     * @return array<int, int|string> Column values keyed by uid, in uid order
     */
    private function fetchColumnByUid(Connection $connection, string $column): array
    {
        $rows = $connection->createQueryBuilder()
            ->select('uid', $column)
            ->from(self::TABLE_NAME)
            ->orderBy('uid', 'ASC')
            ->executeQuery()
            ->fetchAllAssociative();

        $values = [];
        foreach ($rows as $row) {
            $values[(int) $row['uid']] = is_numeric($row[$column]) && $column !== 'entry_hash'
                ? (int) $row[$column]
                : (string) $row[$column];
        }

        return $values;
    }
}
