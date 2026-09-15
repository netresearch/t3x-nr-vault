<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Acceptance;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditChainAnchorStatus;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Command\VaultAuditAnchorCommand;
use Netresearch\NrVault\Command\VaultAuditCommand;
use Netresearch\NrVault\Command\VaultAuditVerifyCommand;
use Netresearch\NrVault\Command\VaultDoctorCommand;
use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Traits\AuditSinkSandboxTrait;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * Backup and restore, following Documentation/Operations/BackupAndRestore.rst.
 *
 * Each test builds a vault through the public API — secrets of different
 * owners and group tiers, one rotation, reads, an external anchor — exports
 * the tables the backup covers, wipes them together with the in-database tip
 * anchor to model a fresh installation that holds the same master key and
 * configuration, imports the export again and runs the documented restore
 * verification: `vault:doctor`, a probe decrypt of every secret,
 * `vault:audit-verify`, re-anchoring both anchors, and the ACL.
 *
 * This is an in-instance model. The export and import are row copies inside
 * one test database, the "fresh installation" is the same TYPO3 instance with
 * emptied tables, and the key file never leaves the instance. It proves the
 * restored DATA is complete and self-consistent; it does not replace a manual
 * restore of a real dump onto a separately installed TYPO3.
 *
 * The export set is the table list the page names — `tx_nrvault_secret`,
 * `tx_nrvault_audit_log`, `be_groups` — plus the two MM tables that hold the
 * per-secret group tiers, `tx_nrvault_secret_begroups_mm` and
 * `tx_nrvault_secret_writegroups_mm`. The page does not name the MM tables.
 * Restoring only the three named tables brings back every secret and a
 * verifying chain but no group tier: the reader below is then refused with
 * "insufficient permissions", and neither `vault:doctor` nor
 * `vault:audit-verify` reports it.
 */
final class BackupRestoreTest extends AbstractVaultFunctionalTestCase
{
    use AuditSinkSandboxTrait;

    private const ADMIN = 1;

    private const READER = 2;

    private const OUTSIDER = 3;

    private const WRITER = 4;

    private const READER_GROUP = 10;

    private const WRITER_GROUP = 11;

    /** Tables Documentation/Operations/BackupAndRestore.rst names for the database backup. */
    private const DOCUMENTED_TABLES = [
        'tx_nrvault_secret',
        'tx_nrvault_audit_log',
        'be_groups',
    ];

    /** Tables the per-secret group tiers live in; `allowed_groups` on the secret row is only a count. */
    private const GROUP_TIER_TABLES = [
        'tx_nrvault_secret_begroups_mm',
        'tx_nrvault_secret_writegroups_mm',
    ];

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/restore_users.csv';

    protected ?int $backendUserUid = self::ADMIN;

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'masterKeyProvider' => 'file',
        'auditHmacEpoch' => 3,
    ];

    /**
     * Plaintext per identifier, as stored (after rotation, where rotated).
     *
     * @var array<string, string>
     */
    private array $plaintexts = [];

    protected function setUp(): void
    {
        $this->extensionConfiguration = $this->prepareAuditSinkSandbox($this->extensionConfiguration);

        parent::setUp();
    }

    protected function tearDown(): void
    {
        $this->cleanUpAuditSinkSandbox();

        parent::tearDown();
    }

    #[Test]
    public function aCompleteRestoreOntoAnEmptiedInstanceDecryptsVerifiesAndKeepsTheAcl(): void
    {
        $this->buildVault();
        $backup = $this->export([...self::DOCUMENTED_TABLES, ...self::GROUP_TIER_TABLES]);

        $this->simulateFreshInstallation();
        $this->import($backup);

        // The in-database anchor went with the fresh installation: before any
        // audit write re-arms it, the restored chain verifies but is unanchored.
        $restored = $this->get(AuditLogServiceInterface::class)->verifyHashChain();
        self::assertTrue($restored->isValid(), 'The restored chain must verify: ' . implode(', ', $restored->errors));
        self::assertSame(AuditChainAnchorStatus::Unanchored, $restored->anchorStatus);

        // Step 4: the provider resolves before any secret is touched.
        $doctor = $this->runCommand(VaultDoctorCommand::class, ['--format' => 'json']);
        $report = json_decode($doctor->getDisplay(), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($report);
        self::assertContains('provider.available', $this->findingIds($report, 'pass'), $doctor->getDisplay());
        self::assertContains('provider.master_key_readable', $this->findingIds($report, 'pass'), $doctor->getDisplay());

        // Step 5: probe-decrypt EVERY secret, not a sample.
        $this->assertEverySecretDecrypts();

        // Step 6: the audit chain verifies through the operator command.
        $verify = $this->runCommand(VaultAuditVerifyCommand::class);
        self::assertSame(Command::SUCCESS, $verify->getStatusCode(), $verify->getDisplay());

        // Step 7: re-anchor both anchors, then the chain verifies with an Ok anchor.
        $reset = $this->runCommand(VaultAuditCommand::class, ['--reset-anchor' => true, '--force' => true]);
        self::assertSame(Command::SUCCESS, $reset->getStatusCode(), $reset->getDisplay());
        $anchor = $this->runCommand(VaultAuditAnchorCommand::class);
        self::assertSame(Command::SUCCESS, $anchor->getStatusCode(), $anchor->getDisplay());

        $afterReanchor = $this->get(AuditLogServiceInterface::class)->verifyHashChain();
        self::assertTrue($afterReanchor->isValid(), implode(', ', $afterReanchor->errors));
        self::assertSame(AuditChainAnchorStatus::Ok, $afterReanchor->anchorStatus);
        self::assertTrue($this->get(ChainTipAnchorServiceInterface::class)->verify()->isValid());

        $this->assertAclIsUnchanged();
    }

    #[Test]
    public function aRestoreUnderADifferentMasterKeyFailsLoudly(): void
    {
        $this->buildVault();
        $backup = $this->export([...self::DOCUMENTED_TABLES, ...self::GROUP_TIER_TABLES]);

        $this->simulateFreshInstallation();
        $this->replaceMasterKey();
        $this->import($backup);

        $this->setUpBackendUser(self::ADMIN);
        foreach (array_keys($this->plaintexts) as $identifier) {
            try {
                $value = $this->get(VaultServiceInterface::class)->retrieve($identifier);
                self::fail(\sprintf('Secret "%s" came back under a foreign master key (%d bytes) instead of failing.', $identifier, \strlen((string) $value)));
            } catch (EncryptionException) {
                // expected: the AEAD tag on the DEK envelope does not verify
            }
        }

        $report = $this->get(ChainTipAnchorServiceInterface::class)->verify();
        self::assertFalse($report->isValid(), 'A chain restored under a foreign master key must not verify.');
        self::assertTrue($report->hasReason(AuditIntegrityReason::HashMismatch), implode(', ', $report->getReasonCodes()));
    }

    /**
     * A restore that leaves out the audit table is caught against the external
     * anchor the backup procedure tells the operator to keep.
     */
    #[Test]
    public function aRestoreWithoutTheAuditTableIsReportedAgainstTheExternalAnchor(): void
    {
        $this->buildVault();
        $backup = $this->export([...self::DOCUMENTED_TABLES, ...self::GROUP_TIER_TABLES]);
        unset($backup['tx_nrvault_audit_log']);

        $this->simulateFreshInstallation();
        $this->import($backup);

        $verify = $this->runCommand(VaultAuditVerifyCommand::class);
        self::assertSame(Command::FAILURE, $verify->getStatusCode(), $verify->getDisplay());
        self::assertStringContainsString(AuditIntegrityReason::TableReset->value, $verify->getDisplay());
    }

    /**
     * Stores four secrets under two owners and both group tiers, rotates one,
     * reads two, and publishes an external anchor — the evidence a backup
     * procedure is told to keep apart from the database.
     */
    private function buildVault(): void
    {
        $this->setUpBackendUser(self::ADMIN);
        $vault = $this->get(VaultServiceInterface::class);

        $this->plaintexts = [
            'acceptance_restore_reader_tier' => 'reader-tier-value-' . bin2hex(random_bytes(8)),
            'acceptance_restore_writer_tier' => 'writer-tier-value-' . bin2hex(random_bytes(8)),
            'acceptance_restore_owned_by_reader' => 'owner-value-' . bin2hex(random_bytes(8)),
            'acceptance_restore_rotated' => 'before-rotation-' . bin2hex(random_bytes(8)),
        ];

        $vault->store('acceptance_restore_reader_tier', $this->plaintexts['acceptance_restore_reader_tier'], [
            'groups' => [self::READER_GROUP],
            'context' => 'payment',
            'description' => 'Read tier granted to the reader group',
        ]);
        $vault->store('acceptance_restore_writer_tier', $this->plaintexts['acceptance_restore_writer_tier'], [
            'context' => 'email',
        ]);
        $vault->store('acceptance_restore_owned_by_reader', $this->plaintexts['acceptance_restore_owned_by_reader'], [
            'owner' => self::READER,
        ]);
        $vault->store('acceptance_restore_rotated', $this->plaintexts['acceptance_restore_rotated'], [
            'groups' => [self::READER_GROUP],
        ]);

        $this->plaintexts['acceptance_restore_rotated'] = 'after-rotation-' . bin2hex(random_bytes(8));
        $vault->rotate('acceptance_restore_rotated', $this->plaintexts['acceptance_restore_rotated'], 'acceptance rotation');

        // The write tier has no VaultService option: only FormEngine writes it,
        // through the same MM row shape SecretRepository::saveGroupsForSecret() uses.
        $writerTierUid = $this->secretUid('acceptance_restore_writer_tier');
        $this->getConnectionPool()->getConnectionForTable('tx_nrvault_secret_writegroups_mm')->insert(
            'tx_nrvault_secret_writegroups_mm',
            ['uid_local' => $writerTierUid, 'uid_foreign' => self::WRITER_GROUP, 'sorting' => 0, 'sorting_foreign' => 0],
        );

        $vault->retrieve('acceptance_restore_reader_tier');
        $vault->retrieve('acceptance_restore_rotated');

        $anchorService = $this->get(ChainTipAnchorServiceInterface::class);
        self::assertGreaterThan(0, $anchorService->publish($anchorService->capture()), 'The external anchor must reach the file sink.');

        $this->assertAclIsUnchanged();
    }

    /**
     * @param list<string> $tables
     *
     * @return array<string, list<array<string, mixed>>>
     */
    private function export(array $tables): array
    {
        $backup = [];
        foreach ($tables as $table) {
            $backup[$table] = $this->getConnectionPool()->getConnectionForTable($table)
                ->select(['*'], $table)
                ->fetchAllAssociative();
        }

        return $backup;
    }

    /**
     * Empties every nr-vault table, the permission groups and the in-database
     * tip anchor, and drops the request-lifetime key cache. The key file and
     * the extension configuration stay: the documented restore brings both
     * back before any secret is touched.
     */
    private function simulateFreshInstallation(): void
    {
        $pool = $this->getConnectionPool();
        foreach ([...self::DOCUMENTED_TABLES, ...self::GROUP_TIER_TABLES] as $table) {
            $pool->getConnectionForTable($table)->truncate($table);
        }

        $pool->getConnectionForTable('sys_registry')->delete('sys_registry', ['entry_namespace' => 'tx_nrvault_audit_anchor']);
        FileMasterKeyProvider::clearCachedKey();
    }

    /**
     * @param array<string, list<array<string, mixed>>> $backup
     */
    private function import(array $backup): void
    {
        foreach ($backup as $table => $rows) {
            $connection = $this->getConnectionPool()->getConnectionForTable($table);
            foreach ($rows as $row) {
                $connection->insert($table, $row);
            }
        }
    }

    private function replaceMasterKey(): void
    {
        self::assertNotNull($this->masterKeyPath);
        $foreignKey = sodium_crypto_secretbox_keygen();
        file_put_contents($this->masterKeyPath, $foreignKey);
        sodium_memzero($foreignKey);
        FileMasterKeyProvider::clearCachedKey();
    }

    private function assertEverySecretDecrypts(): void
    {
        $this->setUpBackendUser(self::ADMIN);
        $vault = $this->get(VaultServiceInterface::class);
        foreach ($this->plaintexts as $identifier => $plaintext) {
            self::assertSame($plaintext, $vault->retrieve($identifier), \sprintf('Probe decrypt of "%s" after the restore.', $identifier));
        }
    }

    /**
     * The reader reaches its group's secret and its own; the outsider holds the
     * same operation permissions and reaches neither — only the per-secret tier
     * separates them. The writer group's tier admits reads as well.
     */
    private function assertAclIsUnchanged(): void
    {
        $this->setUpBackendUser(self::READER);
        $vault = $this->get(VaultServiceInterface::class);
        self::assertSame($this->plaintexts['acceptance_restore_reader_tier'], $vault->retrieve('acceptance_restore_reader_tier'), 'The reader group tier must admit the reader.');
        self::assertSame($this->plaintexts['acceptance_restore_owned_by_reader'], $vault->retrieve('acceptance_restore_owned_by_reader'), 'Ownership must admit the owner.');

        $this->setUpBackendUser(self::OUTSIDER);
        $this->assertAccessDenied('acceptance_restore_reader_tier');
        $this->assertAccessDenied('acceptance_restore_owned_by_reader');

        $this->setUpBackendUser(self::WRITER);
        self::assertSame($this->plaintexts['acceptance_restore_writer_tier'], $vault->retrieve('acceptance_restore_writer_tier'), 'The writer group tier must admit the writer.');

        $this->setUpBackendUser(self::ADMIN);
    }

    private function assertAccessDenied(string $identifier): void
    {
        try {
            $this->get(VaultServiceInterface::class)->retrieve($identifier);
        } catch (AccessDeniedException) {
            return;
        }

        self::fail(\sprintf('"%s" must stay closed to a user outside its tiers.', $identifier));
    }

    private function secretUid(string $identifier): int
    {
        $uid = $this->getConnectionPool()->getConnectionForTable('tx_nrvault_secret')
            ->select(['uid'], 'tx_nrvault_secret', ['identifier' => $identifier])
            ->fetchOne();
        self::assertIsNumeric($uid);

        return (int) $uid;
    }

    /**
     * @param class-string<Command> $commandClass
     * @param array<string, mixed> $input
     */
    private function runCommand(string $commandClass, array $input = []): CommandTester
    {
        $command = $this->get($commandClass);
        self::assertInstanceOf(Command::class, $command);
        $tester = new CommandTester($command);
        $tester->execute($input, ['interactive' => false]);

        return $tester;
    }

    /**
     * @param array<mixed> $report `vault:doctor --format=json` output
     *
     * @return list<string>
     */
    private function findingIds(array $report, string $severity): array
    {
        $ids = [];
        $findings = \is_array($report['findings'] ?? null) ? $report['findings'] : [];
        foreach ($findings as $finding) {
            if (\is_array($finding) && \is_string($finding['id'] ?? null) && ($finding['severity'] ?? null) === $severity) {
                $ids[] = $finding['id'];
            }
        }

        return $ids;
    }
}
