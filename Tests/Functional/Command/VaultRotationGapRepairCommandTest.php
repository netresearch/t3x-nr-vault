<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Command;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditChainAnchorStatus;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\HashChainVerificationResult;
use Netresearch\NrVault\Audit\RotationGapScanner;
use Netresearch\NrVault\Command\VaultAuditMigrateCommand;
use Netresearch\NrVault\Command\VaultRotateMasterKeyCommand;
use Netresearch\NrVault\Command\VaultRotationGapRepairCommand;
use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Tester\CommandTester;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Writes between a master-key rotation and the configuration switch: secrets
 * wrapped and audit rows sealed under the previous key (#508, #509).
 */
#[CoversClass(VaultRotationGapRepairCommand::class)]
#[CoversClass(RotationGapScanner::class)]
final class VaultRotationGapRepairCommandTest extends AbstractVaultFunctionalTestCase
{
    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    private const GAP_IDENTIFIER = '__gap_probe__';

    /** Pseudo identifier of the master-key lifecycle audit rows. */
    private const MASTER_KEY_IDENTIFIER = '__master_key__';

    protected ?string $backendUserFixture = __DIR__ . '/../Hook/Fixtures/be_users.csv';

    /**
     * The base class rebuilds the runtime nr_vault configuration in setUp(),
     * so the provider is pinned here as well as in the settings file below.
     */
    protected array $extensionConfiguration = ['masterKeyProvider' => 'file'];

    protected array $configurationToUseInTestInstance = [
        'EXTENSIONS' => [
            'nr_vault' => [
                'masterKeyProvider' => 'file',
                'enableCache'       => false,
            ],
        ],
    ];

    private string $oldKeyPath = '';

    private string $newKeyPath = '';

    protected function setUp(): void
    {
        parent::setUp();

        self::assertIsString($this->masterKeyPath);
        $this->oldKeyPath = $this->instancePath . '/master-old.key';
        $this->newKeyPath = $this->instancePath . '/master-new.key';
        copy($this->masterKeyPath, $this->oldKeyPath);
        file_put_contents($this->newKeyPath, sodium_crypto_secretbox_keygen());

        $this->get(VaultServiceInterface::class)->store($this->generateUuidV7(), 'stored-before-the-rotation');
        $this->rotate();
    }

    protected function tearDown(): void
    {
        foreach ([$this->oldKeyPath, $this->newKeyPath] as $path) {
            if ($path !== '' && file_exists($path)) {
                // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
                unlink($path);
            }
        }

        parent::tearDown();
    }

    /**
     * #509 as reported: an audit row written after the rotation commit and
     * before the configuration switch is sealed under the old key, the chain
     * no longer verifies, and `vault:audit-migrate-hmac` cannot re-seal it.
     */
    #[Test]
    public function auditMigrateHmacCannotResealARowWrittenInTheGap(): void
    {
        $this->writeGapRow();
        $this->switchToNewKey();

        self::assertFalse($this->verifyChain()->isValid());

        $migrate = new CommandTester($this->get(VaultAuditMigrateCommand::class));
        self::assertSame(0, $migrate->execute([]));
        self::assertStringContainsString('Nothing to migrate', $migrate->getDisplay());
        self::assertFalse($this->verifyChain()->isValid(), 'vault:audit-migrate-hmac leaves the gap row unsealed');
    }

    #[Test]
    public function resealsAnAuditRowWrittenInTheGap(): void
    {
        $this->writeGapRow();
        $this->switchToNewKey();

        $repair = $this->runRepair($this->oldKeyPath);

        self::assertSame(0, $repair->getStatusCode(), $repair->getDisplay());
        self::assertStringContainsString('re-sealed 1 audit row(s)', $repair->getDisplay());

        $result = $this->verifyChain();
        self::assertTrue($result->isValid(), 'the repaired chain must verify under the new key');
        self::assertSame(AuditChainAnchorStatus::Ok, $result->anchorStatus);
        self::assertSame(1, $this->countAuditRows(AuditAction::AuditChainRekey->value, self::MASTER_KEY_IDENTIFIER, true, 'Re-sealed 1 audit row'));
    }

    /**
     * #508: a secret stored in the gap is wrapped under the old key and cannot
     * be read after the switch. The repair re-wraps it, audited per secret.
     */
    #[Test]
    public function reWrapsASecretStoredInTheGap(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier   = $this->generateUuidV7();
        $vaultService->store($identifier, 'refresh-token-written-in-the-gap');
        $this->switchToNewKey();

        self::assertFalse($this->canRetrieve($identifier), 'the gap secret is under the old key');

        $repair = $this->runRepair($this->oldKeyPath);

        self::assertSame(0, $repair->getStatusCode(), $repair->getDisplay());
        self::assertStringContainsString('Re-wrapped 1 secret(s)', $repair->getDisplay());
        self::assertSame('refresh-token-written-in-the-gap', $vaultService->retrieve($identifier));
        self::assertSame(1, $this->countAuditRows(AuditAction::MasterKeyRewrap->value, $identifier, true));
        self::assertTrue($this->verifyChain()->isValid());
    }

    #[Test]
    public function dryRunChangesNothing(): void
    {
        $identifier = $this->generateUuidV7();
        $this->get(VaultServiceInterface::class)->store($identifier, 'gap-value');
        $this->writeGapRow();
        $this->switchToNewKey();
        $rowsBefore = $this->countAuditRows();

        $repair = $this->runRepair($this->oldKeyPath, '--dry-run');

        self::assertSame(0, $repair->getStatusCode(), $repair->getDisplay());
        self::assertStringContainsString('Would re-wrap 1 secret(s) and re-seal', $repair->getDisplay());
        self::assertSame($rowsBefore, $this->countAuditRows());
        self::assertFalse($this->verifyChain()->isValid());
        self::assertFalse($this->canRetrieve($identifier));
    }

    #[Test]
    public function aWrongOldKeyChangesNothing(): void
    {
        $identifier = $this->generateUuidV7();
        $this->get(VaultServiceInterface::class)->store($identifier, 'gap-value');
        $this->writeGapRow();
        $this->switchToNewKey();

        $wrongKeyPath = $this->instancePath . '/master-wrong.key';
        file_put_contents($wrongKeyPath, sodium_crypto_secretbox_keygen());
        $repair = $this->runRepair($wrongKeyPath);
        // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
        unlink($wrongKeyPath);

        self::assertSame(1, $repair->getStatusCode());
        self::assertStringContainsString('verifies under neither', $repair->getDisplay());
        self::assertFalse($this->canRetrieve($identifier));
        self::assertSame(1, $this->countAuditRows(AuditAction::AuditChainRekey->value, self::MASTER_KEY_IDENTIFIER, false));
    }

    /**
     * A row that was altered after it was written matches neither key. A
     * re-seal would hide the alteration, so the repair refuses.
     */
    #[Test]
    public function refusesAGapRowThatWasAlteredAfterwards(): void
    {
        $this->writeGapRow();
        $this->switchToNewKey();
        $this->auditConnection()->update(self::AUDIT_TABLE, ['reason' => 'rewritten'], ['secret_identifier' => self::GAP_IDENTIFIER]);

        $repair = $this->runRepair($this->oldKeyPath);

        self::assertSame(1, $repair->getStatusCode());
        self::assertStringContainsString('verifies under neither', $repair->getDisplay());
        self::assertFalse($this->verifyChain()->isValid());
    }

    /**
     * Only rows after the last successful rotation can have been written in
     * its gap. An old-key row before it is not one.
     */
    #[Test]
    public function refusesAnOldKeyRowBeforeTheLastRotation(): void
    {
        $this->writeGapRow();
        $this->switchToNewKey();
        $this->get(AuditLogServiceInterface::class)->log(
            self::MASTER_KEY_IDENTIFIER,
            AuditAction::MasterKeyRotateEnd->value,
            true,
            null,
            'a later rotation end row',
        );

        $repair = $this->runRepair($this->oldKeyPath);

        self::assertSame(1, $repair->getStatusCode());
        self::assertStringContainsString('Entry hash mismatch', $repair->getDisplay());
        self::assertFalse($this->verifyChain()->isValid());
    }

    /**
     * A deleted gap row leaves a uid gap and a broken link behind it.
     */
    #[Test]
    public function refusesWhenAGapRowWasDeleted(): void
    {
        $this->writeGapRow();
        $this->writeGapRow();
        $this->switchToNewKey();

        $firstGapUid = $this->auditConnection()->createQueryBuilder()
            ->select('uid')
            ->from(self::AUDIT_TABLE)
            ->where('secret_identifier = ' . $this->auditConnection()->quote(self::GAP_IDENTIFIER))
            ->orderBy('uid', 'ASC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchOne();
        $this->auditConnection()->delete(self::AUDIT_TABLE, ['uid' => $firstGapUid]);

        $repair = $this->runRepair($this->oldKeyPath);

        self::assertSame(1, $repair->getStatusCode());
        self::assertStringContainsString('are missing', $repair->getDisplay());
    }

    /**
     * A worker that missed its restart keeps writing under the old key after
     * the switch, so old-key rows and new-key rows alternate. Each row is
     * checked against the stored link of the row before it.
     */
    #[Test]
    public function resealsOldKeyRowsInterleavedWithNewKeyRows(): void
    {
        $this->writeGapRow();
        $this->switchToNewKey();
        $this->writeGapRow();
        $this->useKey($this->oldKeyPath);
        $this->writeGapRow();
        $this->switchToNewKey();
        $this->writeGapRow();

        $repair = $this->runRepair($this->oldKeyPath);

        self::assertSame(0, $repair->getStatusCode(), $repair->getDisplay());
        self::assertStringContainsString('re-sealed 2 audit row(s)', $repair->getDisplay());
        $result = $this->verifyChain();
        self::assertTrue($result->isValid());
        self::assertSame(AuditChainAnchorStatus::Ok, $result->anchorStatus);
    }

    #[Test]
    public function reportsNothingToRepairAfterACleanSwitch(): void
    {
        $this->switchToNewKey();

        $repair = $this->runRepair($this->oldKeyPath);

        self::assertSame(0, $repair->getStatusCode(), $repair->getDisplay());
        self::assertStringContainsString('Nothing is left under the previous master key', $repair->getDisplay());
    }

    private function rotate(): void
    {
        $rotate   = new CommandTester($this->get(VaultRotateMasterKeyCommand::class));
        $exitCode = $rotate->execute([
            '--old-key' => $this->oldKeyPath,
            '--new-key' => $this->newKeyPath,
            '--confirm' => true,
        ]);
        self::assertSame(0, $exitCode, $rotate->getDisplay());
    }

    /**
     * The provider still returns the old key until switchToNewKey(), so this
     * row is sealed under the old key.
     */
    private function writeGapRow(): void
    {
        $this->get(AuditLogServiceInterface::class)->log(self::GAP_IDENTIFIER, 'read', true, null, 'written in the gap');
    }

    private function switchToNewKey(): void
    {
        $this->useKey($this->newKeyPath);
    }

    /**
     * Make the key in `$keyPath` the one the provider returns.
     */
    private function useKey(string $keyPath): void
    {
        self::assertIsString($this->masterKeyPath);
        copy($keyPath, $this->masterKeyPath);
        FileMasterKeyProvider::clearCachedKey();
    }

    /**
     * Run the repair with `$oldKeyPath` and `--confirm`, or with the mode given.
     */
    private function runRepair(string $oldKeyPath, string $mode = '--confirm'): CommandTester
    {
        $tester = new CommandTester($this->get(VaultRotationGapRepairCommand::class));
        $tester->execute(['--old-key' => $oldKeyPath, $mode => true]);

        return $tester;
    }

    private function verifyChain(): HashChainVerificationResult
    {
        return $this->get(AuditLogServiceInterface::class)->verifyHashChain();
    }

    private function canRetrieve(string $identifier): bool
    {
        try {
            return $this->get(VaultServiceInterface::class)->retrieve($identifier) !== null;
        } catch (Throwable) {
            return false;
        }
    }

    private function auditConnection(): Connection
    {
        return $this->get(ConnectionPool::class)->getConnectionForTable(self::AUDIT_TABLE);
    }

    private function countAuditRows(?string $action = null, ?string $identifier = null, ?bool $success = null, ?string $reasonPrefix = null): int
    {
        $queryBuilder = $this->auditConnection()->createQueryBuilder();
        $queryBuilder->count('uid')->from(self::AUDIT_TABLE);

        if ($action !== null) {
            $queryBuilder->andWhere($queryBuilder->expr()->eq('action', $queryBuilder->createNamedParameter($action)));
        }

        if ($identifier !== null) {
            $queryBuilder->andWhere($queryBuilder->expr()->eq('secret_identifier', $queryBuilder->createNamedParameter($identifier)));
        }

        if ($success !== null) {
            $queryBuilder->andWhere($queryBuilder->expr()->eq('success', $queryBuilder->createNamedParameter($success ? 1 : 0, Connection::PARAM_INT)));
        }

        if ($reasonPrefix !== null) {
            $queryBuilder->andWhere($queryBuilder->expr()->like('reason', $queryBuilder->createNamedParameter($reasonPrefix . '%')));
        }

        $count = $queryBuilder->executeQuery()->fetchOne();

        return is_numeric($count) ? (int) $count : 0;
    }
}
