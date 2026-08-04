<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Audit;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditChainAnchorStatus;
use Netresearch\NrVault\Audit\AuditChainAnchorStore;
use Netresearch\NrVault\Audit\AuditChainAnchorStoreInterface;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Command\VaultAuditCommand;
use Netresearch\NrVault\Command\VaultAuditMigrateCommand;
use Netresearch\NrVault\Command\VaultRotateMasterKeyCommand;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Seeder\AuditChainSeeder;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Finding F2 — the hash chain walk only ever inspects rows that are still
 * present, so removing the tail (or the whole table) leaves a self-consistent
 * chain that every pre-anchor tamper-evidence control reports as VALID.
 *
 * The first three tests are the demonstration of the fix: each one FAILS
 * against the pre-anchor code (`isValid()` returns true on a truncated log) and
 * passes with the anchor in place. The remainder are the false-alarm coverage —
 * the cases earlier attempts at this control died on.
 */
#[CoversClass(AuditChainAnchorStore::class)]
#[CoversClass(AuditLogService::class)]
final class AuditChainAnchorTest extends AbstractVaultFunctionalTestCase
{
    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    private const REGISTRY_TABLE = 'sys_registry';

    private const ENTRY_NAMESPACE = 'tx_nrvault_audit_anchor';

    private const ENTRY_KEY = 'auditChainTip';

    protected ?string $backendUserFixture = __DIR__ . '/../Service/Fixtures/be_users.csv';

    // =====================================================================
    // Demonstration — these FAIL without the anchor
    // =====================================================================

    #[Test]
    public function tailTruncationIsDetected(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 6);

        self::assertTrue($auditLogService->verifyHashChain()->isValid(), 'precondition: chain valid');

        $this->deleteEntriesAbove(3);

        $result = $auditLogService->verifyHashChain();

        self::assertFalse($result->isValid(), 'A tail truncation must invalidate the chain');
        self::assertSame(AuditChainAnchorStatus::Violated, $result->anchorStatus);
    }

    #[Test]
    public function fullWipeIsDetected(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 5);

        $this->truncateAuditLog();

        $result = $auditLogService->verifyHashChain();

        self::assertFalse($result->isValid(), 'A full wipe must invalidate the chain');
        self::assertSame(AuditChainAnchorStatus::Violated, $result->anchorStatus);
    }

    /**
     * The anchored HASH — not just the anchored uid — is what makes this
     * detectable. Once the auto-increment restarts, ordinary appends refill the
     * anchored uid and the refilled chain re-links perfectly, so an anchor that
     * only asserted existence would report VALID.
     *
     * Whether a wipe restarts the counter by itself is platform-specific:
     * MariaDB gets it from TRUNCATE, while on SQLite the platform emits
     * DELETE FROM and TYPO3 maps `uid` to INTEGER PRIMARY KEY AUTOINCREMENT,
     * whose sequence survives in `sqlite_sequence`. `truncateAuditLog()`
     * therefore resets both, so this test pins the anchor's behaviour rather
     * than the database's.
     */
    #[Test]
    public function truncateThenRefillIsDetected(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 5);
        $anchoredUid = $this->currentAnchorUid();

        $this->truncateAuditLog();
        // Refill past the anchored uid using the ordinary write path, so the
        // refilled chain is genuinely self-consistent and the walk alone cannot
        // catch it — the whole point of the anchor. The refilled events are
        // DIFFERENT events: replaying the byte-identical originals would
        // legitimately reproduce the same chain.
        $this->writeEntries($auditLogService, $anchoredUid + 1, 'refill');

        self::assertNotNull(
            $this->entryHashOf($anchoredUid),
            'precondition: the anchored uid must have been refilled by a NEW row',
        );

        $result = $auditLogService->verifyHashChain();

        self::assertFalse($result->isValid(), 'A truncate-then-refill must invalidate the chain');
        self::assertSame(AuditChainAnchorStatus::Violated, $result->anchorStatus);
    }

    /**
     * The two-statement version of the attack: remove the anchor FIRST, then
     * truncate, then let ordinary traffic (one audited read is enough at the
     * default `auditReads = 1`) append a row. If `advance()` treats "no anchor
     * row" as the bootstrap case, it mints a fresh, correctly MAC'd anchor on
     * the truncated chain and the installation reports `Ok` permanently —
     * silent AND attested, which is worse than the pre-anchor behaviour.
     *
     * `auditAnchorRequired` is the operator's assertion that this install is
     * already anchored, and it lives in a settings file a database-write
     * attacker cannot reach. Under it, an absent anchor on a populated chain
     * must never become a valid signed anchor by itself.
     */
    #[Test]
    public function aDeletedAnchorIsNotReArmedByAnAppendWhenAnchorRequiredIsEnabled(): void
    {
        // Arm the way the documented upgrade path does: ordinary writes with the
        // flag still off, then enable it.
        $this->writeEntries($this->get(AuditLogServiceInterface::class), 6);
        $subject = $this->serviceWithConfiguration($this->configurationStub(3, true));
        self::assertTrue($subject->verifyHashChain()->isValid(), 'precondition: chain valid and armed');

        $this->deleteAnchorRow();
        $this->deleteEntriesAbove(3);
        $this->writeEntries($subject, 1, 'ordinary-traffic');

        $result = $subject->verifyHashChain();

        self::assertNull($this->rawAnchorValue(), 'an ordinary append must not arm an anchor here');
        self::assertFalse($result->isValid(), 'a truncated chain must not verify after the anchor was deleted');
        self::assertSame(AuditChainAnchorStatus::Unanchored, $result->anchorStatus);
    }

    /**
     * The same attack spelled with a FULL wipe instead of a tail truncation —
     * and the reason no emptiness probe can guard this. An earlier revision
     * refused implicit arming only when a row still sat BELOW the tip being
     * anchored, to keep a genuinely fresh installation bootstrapping under the
     * flag. But at the moment `advance()` runs, the audit insert has just
     * written the one row the chain has, so an emptied log is byte-for-byte the
     * fresh-install case. The uid gap does not help either: the walk starts at
     * `previousUid = -1`, so a chain that now begins at uid 7 has no leading
     * gap. The attacker reaches the bypass by deleting MORE rows, which is
     * cheaper than deleting some.
     *
     * `DELETE` without a `WHERE`, deliberately, not `TRUNCATE`: it leaves the
     * auto-increment counter where it was, so the refill lands at uid 7 exactly
     * as in the reported reproduction.
     */
    #[Test]
    public function aFullWipeIsNotReArmedByAnAppendWhenAnchorRequiredIsEnabled(): void
    {
        $this->writeEntries($this->get(AuditLogServiceInterface::class), 6);
        $subject = $this->serviceWithConfiguration($this->configurationStub(3, true));
        self::assertTrue($subject->verifyHashChain()->isValid(), 'precondition: chain valid and armed');

        $this->deleteAnchorRow();
        $this->deleteAllEntries();
        $this->writeEntries($subject, 1, 'ordinary-traffic');

        $result = $subject->verifyHashChain();

        self::assertNull($this->rawAnchorValue(), 'an emptied chain must not mint a fresh signed anchor');
        self::assertFalse($result->isValid(), 'a wiped chain must not verify after the anchor was deleted');
        self::assertSame(AuditChainAnchorStatus::Unanchored, $result->anchorStatus);
    }

    /**
     * The one-statement version: `UPDATE sys_registry SET entry_value = NULL`
     * leaves the row in place, so "no anchor row" and "anchor blanked" must not
     * read back the same. A present row with an unusable value is an
     * `Unreadable` ERROR and is never repaired by an append — and it must not
     * be re-INSERTed either, which would collide with the `entry_identifier`
     * unique key and fail every audit write from then on.
     */
    #[Test]
    public function aNulledAnchorValueIsNeitherReArmedNorReInserted(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 5);

        $this->nullifyAnchorValue();
        $this->deleteEntriesAbove(2);
        $this->writeEntries($auditLogService, 1, 'ordinary-traffic');

        $result = $auditLogService->verifyHashChain();

        self::assertSame(1, $this->anchorRowCount(), 'the row must still be there, not re-inserted or dropped');
        self::assertNull($this->rawAnchorValue(), 'the blanked value must be left exactly as it is');
        self::assertFalse($result->isValid());
        self::assertSame(AuditChainAnchorStatus::Unreadable, $result->anchorStatus);
    }

    /**
     * The other half of the same rule: with the flag ON, implicit arming is
     * refused even here. The flag's meaning is "this installation is already
     * anchored", so nothing legitimate needs implicit arming while it is set —
     * and an installation that genuinely is fresh cannot be told apart from one
     * whose log was just emptied. The install is not wedged: it reports
     * `Unanchored` loudly, and `vault:audit --reset-anchor` arms it explicitly
     * (see the escape-hatch tests above).
     */
    #[Test]
    public function aFreshChainDoesNotArmImplicitlyWithAnchorRequiredEnabled(): void
    {
        $subject = $this->serviceWithConfiguration($this->configurationStub(3, true));

        $this->writeEntries($subject, 3);

        $result = $subject->verifyHashChain();

        self::assertNull($this->rawAnchorValue(), 'no anchor may be minted implicitly under the flag');
        self::assertFalse($result->isValid(), 'an unanchored install is an error while the flag is on');
        self::assertSame(AuditChainAnchorStatus::Unanchored, $result->anchorStatus);
    }

    /**
     * With the flag OFF — the shipped default, and the documented upgrade path
     * — bootstrap is unchanged: the first audit write arms the anchor and the
     * installation reports `Ok`.
     */
    #[Test]
    public function aFreshChainArmsImplicitlyWithTheFlagOff(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);

        $this->writeEntries($auditLogService, 3);

        $result = $auditLogService->verifyHashChain();

        self::assertNotNull($this->rawAnchorValue(), 'the first audit write must arm the anchor');
        self::assertTrue($result->isValid(), 'a fresh chain must arm the anchor');
        self::assertSame(AuditChainAnchorStatus::Ok, $result->anchorStatus);
    }

    // =====================================================================
    // Escape hatch — vault:audit --reset-anchor
    // =====================================================================

    /**
     * After a legitimate wipe the forward-only rule leaves the install
     * reporting a violation forever, so `--reset-anchor` is the only way out.
     * It opens a transaction around `log()`, which itself takes the audit lock
     * and opens a nested savepoint — exercise that, not just the anchor state.
     */
    #[Test]
    public function resetAnchorCommandClearsTheViolationAndRecordsTheReset(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 4);
        $this->truncateAuditLog();
        self::assertFalse($auditLogService->verifyHashChain()->isValid(), 'precondition: violated');

        $commandTester = new CommandTester($this->get(VaultAuditCommand::class));
        $exitCode = $commandTester->execute(['--reset-anchor' => true, '--force' => true]);

        self::assertSame(0, $exitCode, $commandTester->getDisplay());

        $result = $auditLogService->verifyHashChain();
        self::assertTrue($result->isValid(), $commandTester->getDisplay());
        self::assertSame(AuditChainAnchorStatus::Ok, $result->anchorStatus);
        self::assertSame(
            [AuditAction::AuditAnchorReset->value],
            $this->storedActions(),
            'the reset must be inside the chain, not performed invisibly',
        );
    }

    /**
     * The escape hatch has to work under the hardening flag too — that is
     * exactly the configuration in which `advance()` refuses to arm, so the
     * command must arm explicitly rather than rely on the audit write it makes.
     */
    #[Test]
    public function resetAnchorCommandReArmsWithAnchorRequiredEnabled(): void
    {
        $configuration = $this->configurationStub(3, true);
        $store = new AuditChainAnchorStore(
            $this->get(ConnectionPool::class),
            $this->get(MasterKeyProviderInterface::class),
            $configuration,
        );
        $subject = $this->serviceWithStore($store, $configuration);
        $this->writeEntries($subject, 4);
        $this->truncateAuditLog();

        $command = new VaultAuditCommand(
            $subject,
            $store,
            $this->get(ConnectionPool::class),
            $this->get(AccessControlServiceInterface::class),
        );
        $command->setName('vault:audit');
        $exitCode = (new CommandTester($command))->execute(['--reset-anchor' => true, '--force' => true]);

        self::assertSame(0, $exitCode);

        $result = $subject->verifyHashChain();
        self::assertTrue($result->isValid());
        self::assertSame(AuditChainAnchorStatus::Ok, $result->anchorStatus);
    }

    // =====================================================================
    // False-alarm coverage — these must pass BEFORE and AFTER
    // =====================================================================

    /**
     * The check asks an existence-and-equality question about one
     * already-committed row, so an append committed between the anchor read
     * and the row read cannot falsify it. This is what an earlier
     * count/max(uid)-based attempt got wrong.
     */
    #[Test]
    public function interleavedAppendsNeverFalseAlarm(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 3);

        $first = $auditLogService->verifyHashChain();
        $this->writeEntries($auditLogService, 1);
        $second = $auditLogService->verifyHashChain();
        $this->writeEntries($auditLogService, 2);
        $third = $auditLogService->verifyHashChain();

        foreach ([$first, $second, $third] as $index => $result) {
            self::assertTrue($result->isValid(), 'verification #' . ($index + 1) . ' must stay valid');
            self::assertSame(AuditChainAnchorStatus::Ok, $result->anchorStatus);
        }
    }

    /**
     * Existing installations upgrade into a populated chain with no anchor row.
     * That must be a WARNING, not an error — otherwise every install
     * false-alarms until its next audit write, and the pre-rotation gate plus
     * both re-seal gates start refusing.
     */
    #[Test]
    public function populatedChainWithoutAnchorStaysValid(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 3);
        $this->deleteAnchorRow();

        $result = $auditLogService->verifyHashChain();

        self::assertTrue($result->isValid());
        self::assertSame([], $result->errors);
        self::assertSame(AuditChainAnchorStatus::Unanchored, $result->anchorStatus);
        self::assertSame(1, $result->getWarningCount());
    }

    #[Test]
    public function missingAnchorIsAnErrorWhenAuditAnchorRequiredIsEnabled(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 3);
        $this->deleteAnchorRow();

        $result = $this->serviceWithConfiguration($this->configurationStub(3, true))->verifyHashChain();

        self::assertFalse($result->isValid());
        self::assertSame(AuditChainAnchorStatus::Unanchored, $result->anchorStatus);
    }

    #[Test]
    public function boundedRangeVerificationDoesNotCheckTheAnchor(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 4);
        $this->deleteEntriesAbove(2);

        $result = $auditLogService->verifyHashChain(1, 2);

        self::assertTrue($result->isValid(), 'a bounded sub-range may legitimately exclude the tip');
        self::assertSame(AuditChainAnchorStatus::NotChecked, $result->anchorStatus);
    }

    /**
     * At epoch 0 the chain is keyless, so there is nothing to anchor — and
     * arming the anchor there would add a brand-new master-key dependency to
     * the audit write path of installs that carry no tamper evidence at all.
     */
    #[Test]
    public function epochZeroDisablesTheAnchorAndStillWrites(): void
    {
        $subject = $this->serviceWithConfiguration($this->configurationStub(0, false));
        $this->writeEntries($subject, 3);

        $result = $subject->verifyHashChain();

        self::assertTrue($result->isValid());
        self::assertSame(AuditChainAnchorStatus::Disabled, $result->anchorStatus);
        self::assertNull($this->rawAnchorValue(), 'no anchor may be written at epoch 0');
    }

    /**
     * `sys_registry` on a different database connection: the anchor cannot
     * commit atomically with the audit row, so nothing is written and the
     * verifier warns. Audit writes must keep working — no wedge.
     */
    #[Test]
    public function foreignRegistryConnectionWritesNothingAndOnlyWarns(): void
    {
        $foreignPool = self::createStub(ConnectionPool::class);
        $foreignPool->method('getConnectionForTable')->willReturn(self::createStub(Connection::class));

        $store = new AuditChainAnchorStore(
            $foreignPool,
            $this->get(MasterKeyProviderInterface::class),
            $this->get(ExtensionConfigurationInterface::class),
        );
        $subject = $this->serviceWithStore($store, $this->get(ExtensionConfigurationInterface::class));

        $this->writeEntries($subject, 2);
        $result = $subject->verifyHashChain();

        self::assertTrue($result->isValid(), 'a split connection must not wedge verification');
        self::assertSame(AuditChainAnchorStatus::Unanchored, $result->anchorStatus);
        self::assertNull($this->rawAnchorValue(), 'nothing may be written across connections');
    }

    #[Test]
    public function demoSeederKeepsTheChainValid(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 2);

        $this->get(AuditChainSeeder::class)->seed([
            [
                'secret_identifier' => 'seeded-secret',
                'action' => 'read',
                'success' => true,
                'actor_uid' => 1,
                'actor_type' => 'cli',
                'actor_username' => '_cli_',
                'crdate' => time() - 3600,
                'context' => [],
            ],
        ]);

        $result = $auditLogService->verifyHashChain();

        self::assertTrue($result->isValid());
        self::assertSame(AuditChainAnchorStatus::Ok, $result->anchorStatus);
    }

    // =====================================================================
    // Re-seal paths — a forgotten re-seal false-alarms on every install
    // =====================================================================

    #[Test]
    public function hmacMigrationCommandResealsTheAnchor(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 3);
        $this->downgradeStoredEpochs();

        $commandTester = new CommandTester($this->get(VaultAuditMigrateCommand::class));
        self::assertSame(0, $commandTester->execute([]), $commandTester->getDisplay());

        $result = $auditLogService->verifyHashChain();

        self::assertTrue($result->isValid(), $commandTester->getDisplay());
        self::assertSame(AuditChainAnchorStatus::Ok, $result->anchorStatus);
    }

    #[Test]
    public function hmacMigrationDryRunLeavesTheAnchorUntouched(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 3);
        $this->downgradeStoredEpochs();
        $before = $this->rawAnchorValue();

        $commandTester = new CommandTester($this->get(VaultAuditMigrateCommand::class));
        self::assertSame(0, $commandTester->execute(['--dry-run' => true]), $commandTester->getDisplay());

        self::assertSame($before, $this->rawAnchorValue());
    }

    /**
     * The laundering route that needs no master key and no shell: truncate the
     * tail, then `UPDATE tx_nrvault_audit_log SET hmac_key_epoch = 0` — one
     * statement, no key. That makes `chainHasHmacRows()` count zero, which used
     * to skip the re-seal gate ENTIRELY (anchor check included), and it makes the
     * HMAC migration wizard advertise itself as pending in the Install Tool, so a
     * routine admin click finishes the job. The re-hash then re-sealed a fresh,
     * correctly MAC'd anchor over the shortened chain and the truncation became
     * permanently invisible.
     *
     * Two independent stops now: the gate still checks the anchor at epoch 0, and
     * `reseal()` refuses to sign when the anchored row is gone.
     */
    #[Test]
    public function anEpochDowngradeCannotLaunderATruncationThroughTheHmacMigration(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 7);
        self::assertTrue($auditLogService->verifyHashChain()->isValid(), 'precondition: chain valid and armed');

        $this->deleteEntriesAbove(3);
        self::assertSame(
            AuditChainAnchorStatus::Violated,
            $auditLogService->verifyHashChain()->anchorStatus,
            'precondition: the anchor is evidence at this point',
        );

        $this->downgradeStoredEpochs();

        $commandTester = new CommandTester($this->get(VaultAuditMigrateCommand::class));
        $exitCode = $commandTester->execute([]);

        self::assertSame(
            Command::FAILURE,
            $exitCode,
            'the re-seal gate must still check the anchor when no row carries an HMAC epoch',
        );

        $result = $auditLogService->verifyHashChain();
        self::assertFalse($result->isValid(), 'the truncated chain must stay invalid across the migration');
        self::assertSame(AuditChainAnchorStatus::Violated, $result->anchorStatus);
    }

    /**
     * Master-key rotation rewrites every entry hash under the NEW key, so the
     * anchor has to be re-signed with that key inside the same transaction.
     * Omitting the re-seal — or signing it with the old key — makes every
     * install report a chain violation right after a rotation.
     */
    #[Test]
    public function masterKeyRotationResealsTheAnchorUnderTheNewKey(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 3);

        self::assertIsString($this->masterKeyPath);
        $newKeyPath = $this->instancePath . '/master-rotated.key';
        file_put_contents($newKeyPath, sodium_crypto_secretbox_keygen());

        $commandTester = new CommandTester($this->get(VaultRotateMasterKeyCommand::class));
        $exitCode = $commandTester->execute([
            '--old-key' => $this->masterKeyPath,
            '--new-key' => $newKeyPath,
            '--confirm' => true,
        ]);
        self::assertSame(0, $exitCode, $commandTester->getDisplay());

        // The operator's next step: make the new key the configured one.
        self::assertIsString($this->masterKeyPath, 'the master key path is wired by the base test case');
        copy($newKeyPath, $this->masterKeyPath);
        FileMasterKeyProvider::clearCachedKey();

        $result = $auditLogService->verifyHashChain();

        self::assertTrue($result->isValid(), 'chain must verify under the new key');
        self::assertSame(AuditChainAnchorStatus::Ok, $result->anchorStatus);

        // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
        unlink($newKeyPath);
    }

    /**
     * The rotation-path companion to the migration-path test above (#283).
     * Rotation hands `reseal()` the NEW key, under which the stored anchor's
     * MAC can never verify — that parse failure used to skip the
     * anti-truncation guard on exactly the one path that passes a different
     * key, so a chain shortened between the rotate command's pre-flight
     * verification and the re-seal was signed anyway. The guard now
     * authenticates the stored anchor under the provider's current key.
     *
     * The rotation flow end-to-end (re-key, then the operator's key switch)
     * is covered in `AuditChainRekeyServiceTest`; this pins the store-level
     * guard itself.
     */
    #[Test]
    public function resealWithACallerSuppliedKeyCannotSignATruncatedChain(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 7);
        self::assertTrue($auditLogService->verifyHashChain()->isValid(), 'precondition: chain valid and armed');

        $this->deleteEntriesAbove(3);
        self::assertSame(
            AuditChainAnchorStatus::Violated,
            $auditLogService->verifyHashChain()->anchorStatus,
            'precondition: the anchor is evidence at this point',
        );
        $before = $this->rawAnchorValue();

        $newKey = sodium_crypto_secretbox_keygen();
        $this->get(AuditChainAnchorStoreInterface::class)->reseal($this->auditConnection(), $newKey);
        sodium_memzero($newKey);

        self::assertSame(
            $before,
            $this->rawAnchorValue(),
            'the anchor must not be re-signed onto the shortened chain',
        );

        $result = $auditLogService->verifyHashChain();
        self::assertFalse($result->isValid(), 'the truncation must stay detected after the refused re-seal');
        self::assertSame(AuditChainAnchorStatus::Violated, $result->anchorStatus);
    }

    // =====================================================================
    // Anchor tampering
    // =====================================================================

    /**
     * @return iterable<string, array{string}>
     */
    public static function hostileAnchorValueProvider(): iterable
    {
        yield 'flipped mac' => ['nrvault-audit-tip.v1|1|' . str_repeat('a', 64) . '|1700000000|' . str_repeat('b', 64)];
        yield 'malformed format' => ['not-an-anchor'];
        yield 'serialize payload' => ['O:8:"stdClass":0:{}'];
        yield 'empty value' => [''];
    }

    #[Test]
    public function hostileAnchorValuesAreRejectedWithoutUnserializing(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 3);

        foreach (self::hostileAnchorValueProvider() as $label => [$hostileValue]) {
            $this->overwriteAnchorValue($hostileValue);

            $result = $auditLogService->verifyHashChain();

            self::assertFalse($result->isValid(), $label . ' must invalidate');
            self::assertSame(AuditChainAnchorStatus::Unreadable, $result->anchorStatus, $label);
        }
    }

    /**
     * A corrupted anchor must NOT be silently repaired by the next append —
     * that repair would hand an attacker who truncates AND corrupts a clean
     * verdict back.
     */
    #[Test]
    public function anAppendDoesNotRepairACorruptedAnchor(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 2);
        $this->overwriteAnchorValue('not-an-anchor');

        $this->writeEntries($auditLogService, 1);

        self::assertSame('not-an-anchor', $this->rawAnchorValue());
        self::assertSame(AuditChainAnchorStatus::Unreadable, $auditLogService->verifyHashChain()->anchorStatus);
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private function writeEntries(
        AuditLogServiceInterface $auditLogService,
        int $count,
        string $prefix = 'anchor-test',
    ): void {
        for ($i = 0; $i < $count; $i++) {
            $auditLogService->log($prefix . '-' . $i, 'read', true, null, 'anchor test');
        }
    }

    private function auditConnection(): Connection
    {
        return $this->get(ConnectionPool::class)->getConnectionForTable(self::AUDIT_TABLE);
    }

    private function deleteEntriesAbove(int $uid): void
    {
        $connection = $this->auditConnection();
        $queryBuilder = $connection->createQueryBuilder();
        $queryBuilder
            ->delete(self::AUDIT_TABLE)
            ->where($queryBuilder->expr()->gt('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeStatement();
    }

    /**
     * Empty the table with `DELETE` and no `WHERE`, which — unlike `TRUNCATE` —
     * leaves the auto-increment counter alone, so the next append continues the
     * uid sequence exactly as in the reported reproduction.
     */
    private function deleteAllEntries(): void
    {
        $connection = $this->auditConnection();
        $connection->createQueryBuilder()
            ->delete(self::AUDIT_TABLE)
            ->executeStatement();
    }

    private function truncateAuditLog(): void
    {
        $connection = $this->auditConnection();
        $connection->executeStatement(
            $connection->getDatabasePlatform()->getTruncateTableSQL(self::AUDIT_TABLE),
        );

        // Reset the auto-increment as well, so a refill starts at uid 1 on every
        // platform. MariaDB gets that from TRUNCATE; SQLite does not, because
        // the platform emits DELETE FROM and TYPO3 maps `uid` to INTEGER PRIMARY
        // KEY AUTOINCREMENT, whose sequence lives in `sqlite_sequence` and
        // survives. The statement is meaningless elsewhere and that table does
        // not exist there, so a failure is the expected non-SQLite outcome.
        try {
            $connection->executeStatement(
                'DELETE FROM sqlite_sequence WHERE name = ' . $connection->quote(self::AUDIT_TABLE),
            );
        } catch (Throwable) {
            // Not SQLite: TRUNCATE already reset the counter.
        }
    }

    /**
     * Push every stored row below the configured epoch so the HMAC migration
     * has work to do.
     */
    private function downgradeStoredEpochs(): void
    {
        $connection = $this->auditConnection();
        $queryBuilder = $connection->createQueryBuilder();
        $queryBuilder
            ->update(self::AUDIT_TABLE)
            ->set('hmac_key_epoch', '0')
            ->executeStatement();
    }

    private function entryHashOf(int $uid): ?string
    {
        $connection = $this->auditConnection();
        $queryBuilder = $connection->createQueryBuilder();
        $hash = $queryBuilder
            ->select('entry_hash')
            ->from(self::AUDIT_TABLE)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();

        return \is_string($hash) ? $hash : null;
    }

    private function rawAnchorValue(): ?string
    {
        $connection = $this->get(ConnectionPool::class)->getConnectionForTable(self::REGISTRY_TABLE);
        $queryBuilder = $connection->createQueryBuilder();
        $value = $queryBuilder
            ->select('entry_value')
            ->from(self::REGISTRY_TABLE)
            ->where(
                $queryBuilder->expr()->eq('entry_namespace', $queryBuilder->createNamedParameter(self::ENTRY_NAMESPACE)),
                $queryBuilder->expr()->eq('entry_key', $queryBuilder->createNamedParameter(self::ENTRY_KEY)),
            )
            ->executeQuery()
            ->fetchOne();

        if (\is_resource($value)) {
            $contents = stream_get_contents($value);

            return \is_string($contents) ? $contents : null;
        }

        return \is_string($value) ? $value : null;
    }

    private function currentAnchorUid(): int
    {
        $raw = $this->rawAnchorValue();
        self::assertIsString($raw, 'the anchor must be armed at this point');
        $parts = explode('|', $raw);
        self::assertCount(5, $parts);

        return (int) $parts[1];
    }

    private function overwriteAnchorValue(string $value): void
    {
        $this->get(ConnectionPool::class)
            ->getConnectionForTable(self::REGISTRY_TABLE)
            ->update(
                self::REGISTRY_TABLE,
                ['entry_value' => $value],
                ['entry_namespace' => self::ENTRY_NAMESPACE, 'entry_key' => self::ENTRY_KEY],
                ['entry_value' => Connection::PARAM_LOB],
            );
    }

    /**
     * Blank the stored value without deleting the row — the cheapest form of
     * the attack, and the one that distinguishes "no row" from "no value".
     */
    private function nullifyAnchorValue(): void
    {
        $connection = $this->get(ConnectionPool::class)->getConnectionForTable(self::REGISTRY_TABLE);
        $queryBuilder = $connection->createQueryBuilder();
        $queryBuilder
            ->update(self::REGISTRY_TABLE)
            ->set('entry_value', 'NULL', false)
            ->where(
                $queryBuilder->expr()->eq('entry_namespace', $queryBuilder->createNamedParameter(self::ENTRY_NAMESPACE)),
                $queryBuilder->expr()->eq('entry_key', $queryBuilder->createNamedParameter(self::ENTRY_KEY)),
            )
            ->executeStatement();
    }

    private function anchorRowCount(): int
    {
        $connection = $this->get(ConnectionPool::class)->getConnectionForTable(self::REGISTRY_TABLE);

        return (int) $connection->count(
            'entry_key',
            self::REGISTRY_TABLE,
            ['entry_namespace' => self::ENTRY_NAMESPACE, 'entry_key' => self::ENTRY_KEY],
        );
    }

    /**
     * @return array<int, string>
     */
    private function storedActions(): array
    {
        $connection = $this->auditConnection();
        $queryBuilder = $connection->createQueryBuilder();

        return array_map(
            static fn (mixed $value): string => \is_scalar($value) ? (string) $value : '',
            $queryBuilder
                ->select('action')
                ->from(self::AUDIT_TABLE)
                ->orderBy('uid', 'ASC')
                ->executeQuery()
                ->fetchFirstColumn(),
        );
    }

    private function deleteAnchorRow(): void
    {
        $this->get(ConnectionPool::class)
            ->getConnectionForTable(self::REGISTRY_TABLE)
            ->delete(
                self::REGISTRY_TABLE,
                ['entry_namespace' => self::ENTRY_NAMESPACE, 'entry_key' => self::ENTRY_KEY],
            );
    }

    private function configurationStub(int $epoch, bool $anchorRequired): ExtensionConfigurationInterface
    {
        $stub = self::createStub(ExtensionConfigurationInterface::class);
        $stub->method('getAuditHmacEpoch')->willReturn($epoch);
        $stub->method('isAuditAnchorRequired')->willReturn($anchorRequired);
        $stub->method('isAuditReadsEnabled')->willReturn(true);

        return $stub;
    }

    private function serviceWithConfiguration(ExtensionConfigurationInterface $configuration): AuditLogServiceInterface
    {
        $store = new AuditChainAnchorStore(
            $this->get(ConnectionPool::class),
            $this->get(MasterKeyProviderInterface::class),
            $configuration,
        );

        return $this->serviceWithStore($store, $configuration);
    }

    private function serviceWithStore(
        AuditChainAnchorStoreInterface $store,
        ExtensionConfigurationInterface $configuration,
    ): AuditLogServiceInterface {
        return new AuditLogService(
            $this->get(ConnectionPool::class),
            $this->get(AccessControlServiceInterface::class),
            $this->get(MasterKeyProviderInterface::class),
            $configuration,
            $store,
        );
    }
}
