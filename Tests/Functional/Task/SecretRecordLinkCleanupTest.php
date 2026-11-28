<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Task;

use Doctrine\DBAL\Platforms\AbstractMySQLPlatform;
use Netresearch\NrVault\Command\VaultCleanupOrphansCommand;
use Netresearch\NrVault\Command\VaultMigrateFieldCommand;
use Netresearch\NrVault\Controller\MigrationController;
use Netresearch\NrVault\Domain\Dto\MigrationResult;
use Netresearch\NrVault\Domain\Dto\SecretRecordLink;
use Netresearch\NrVault\Hook\DataHandlerHook;
use Netresearch\NrVault\Hook\FlexFormVaultHook;
use Netresearch\NrVault\Service\FieldValueMigrator;
use Netresearch\NrVault\Service\OrphanReferenceChecker;
use Netresearch\NrVault\Service\OrphanReferenceCheckerInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Task\OrphanCleanupTask;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\NullLogger;
use ReflectionMethod;
use ReflectionProperty;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Utility\GeneralUtility;

use function json_decode;
use function json_encode;

/**
 * Orphan cleanup against secrets created the way production creates them:
 * through DataHandler and the vault field hooks, not through hand-written
 * `store()` options (#565).
 *
 * The orphan state is produced the way it arises in practice: the record row
 * disappears without DataHandler (a hard delete by SQL, a dropped extension
 * table, a published workspace version), so the hook that deletes a secret
 * together with its record never runs.
 */
#[CoversClass(OrphanCleanupTask::class)]
#[CoversClass(VaultCleanupOrphansCommand::class)]
#[CoversClass(VaultMigrateFieldCommand::class)]
#[CoversClass(MigrationController::class)]
#[CoversClass(FieldValueMigrator::class)]
#[CoversClass(OrphanReferenceChecker::class)]
#[CoversClass(DataHandlerHook::class)]
#[CoversClass(FlexFormVaultHook::class)]
final class SecretRecordLinkCleanupTest extends AbstractVaultFunctionalTestCase
{
    private const TABLE = 'tx_nrvaulttest_record';

    private const FLEX_TABLE = 'tx_nrvaulttest_flex';

    private const CUSTOM_DELETE_TABLE = 'tx_nrvaulttest_customdelete';

    private const RESERVED_TABLE = 'tx_nrvaulttest_reserved';

    /** @var list<string> */
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
        __DIR__ . '/../Fixtures/Extensions/nr_vault_test',
    ];

    /** @var list<string> */
    protected array $coreExtensionsToLoad = ['backend', 'frontend', 'scheduler'];

    protected ?string $backendUserFixture = __DIR__ . '/../Hook/Fixtures/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 1,
    ];

    protected function setUp(): void
    {
        parent::setUp();

        $this->importCSVDataSet(__DIR__ . '/../Hook/Fixtures/pages.csv');
    }

    #[Test]
    public function aTcaFieldSecretStoresItsRecordLinkUnderMetadata(): void
    {
        $uid        = $this->createRecord('link-' . bin2hex(random_bytes(8)));
        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');

        self::assertSame(
            ['source' => 'tca_field', 'table' => self::TABLE, 'field' => 'api_key', 'uid' => $uid],
            $this->storedMetadata($identifier),
        );
    }

    #[Test]
    public function theTaskDeletesATcaFieldSecretWhoseRecordIsGone(): void
    {
        $uid        = $this->createRecord('orphan-' . bin2hex(random_bytes(8)));
        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');

        $this->hardDeleteRow(self::TABLE, $uid);
        $this->runTask();

        self::assertFalse(
            $this->get(VaultServiceInterface::class)->exists($identifier),
            'A TCA field secret whose record is gone must be found and deleted by the cleanup task',
        );
    }

    #[Test]
    public function theCommandDeletesATcaFieldSecretWhoseRecordIsGone(): void
    {
        $uid        = $this->createRecord('orphan-cli-' . bin2hex(random_bytes(8)));
        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');

        $this->hardDeleteRow(self::TABLE, $uid);

        $this->backdateSecrets();
        $tester = new CommandTester($this->get(VaultCleanupOrphansCommand::class));
        $tester->setInputs(['yes']);
        $tester->execute([]);

        self::assertFalse(
            $this->get(VaultServiceInterface::class)->exists($identifier),
            'A TCA field secret whose record is gone must be found and deleted by vault:cleanup-orphans. Output: ' . $tester->getDisplay(),
        );
    }

    #[Test]
    public function theTaskKeepsATcaFieldSecretWhoseRecordExists(): void
    {
        $plaintext  = 'kept-' . bin2hex(random_bytes(8));
        $uid        = $this->createRecord($plaintext);
        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');

        $this->runTask();

        self::assertSame($plaintext, $this->get(VaultServiceInterface::class)->retrieve($identifier));
    }

    /**
     * The linked row is gone, but another row of the table still holds the
     * identifier — the shape a published workspace version, a translation
     * sharing a non-translatable field or a row restored under another uid
     * leaves behind. The secret is still in use and must survive.
     */
    #[Test]
    public function theTaskKeepsASecretAnotherRowStillHolds(): void
    {
        $plaintext  = 'shared-' . bin2hex(random_bytes(8));
        $uid        = $this->createRecord($plaintext);
        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');

        $this->insertRow(self::TABLE, ['pid' => 1, 'title' => 'Holder', 'api_key' => $identifier]);
        $this->hardDeleteRow(self::TABLE, $uid);
        $this->runTask();

        self::assertSame(
            $plaintext,
            $this->get(VaultServiceInterface::class)->retrieve($identifier),
            'A secret another row still references must not be deleted',
        );
    }

    #[Test]
    public function theCommandKeepsASecretAnotherRowStillHolds(): void
    {
        $plaintext  = 'shared-cli-' . bin2hex(random_bytes(8));
        $uid        = $this->createRecord($plaintext);
        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');

        $this->insertRow(self::TABLE, ['pid' => 1, 'title' => 'Holder', 'api_key' => $identifier]);
        $this->hardDeleteRow(self::TABLE, $uid);

        $this->backdateSecrets();
        $tester = new CommandTester($this->get(VaultCleanupOrphansCommand::class));
        $tester->setInputs(['yes']);
        $tester->execute([]);

        self::assertSame($plaintext, $this->get(VaultServiceInterface::class)->retrieve($identifier));
    }

    #[Test]
    public function theTaskDeletesAFlexFormSecretWhoseRecordIsGone(): void
    {
        $uid        = $this->createFlexRecord('flex-orphan-' . bin2hex(random_bytes(8)));
        $identifier = $this->flexIdentifier($uid);

        self::assertSame(
            ['source' => 'flexform_field', 'table' => self::FLEX_TABLE, 'flexField' => 'settings', 'uid' => $uid],
            array_intersect_key($this->storedMetadata($identifier), ['source' => 0, 'table' => 0, 'flexField' => 0, 'uid' => 0]),
        );

        $this->hardDeleteRow(self::FLEX_TABLE, $uid);
        $this->runTask();

        self::assertFalse($this->get(VaultServiceInterface::class)->exists($identifier));
    }

    #[Test]
    public function theTaskKeepsAFlexFormSecretAnotherRowsFlexFormStillHolds(): void
    {
        $plaintext  = 'flex-shared-' . bin2hex(random_bytes(8));
        $uid        = $this->createFlexRecord($plaintext);
        $identifier = $this->flexIdentifier($uid);

        $this->insertRow(self::FLEX_TABLE, ['pid' => 1, 'title' => 'Holder', 'settings' => $this->fetchField(self::FLEX_TABLE, $uid, 'settings')]);
        $this->hardDeleteRow(self::FLEX_TABLE, $uid);
        $this->runTask();

        self::assertSame($plaintext, $this->get(VaultServiceInterface::class)->retrieve($identifier));
    }

    /**
     * A link naming a column the table does not have cannot be checked for
     * other holders, so nothing proves the secret unused: it stays.
     */
    #[Test]
    public function theTaskKeepsASecretWhoseLinkNamesAnUnknownColumn(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier   = $this->generateUuidV7();
        $vaultService->store($identifier, 'unknown-column', [
            'metadata' => SecretRecordLink::forField(SecretRecordLink::SOURCE_TCA_FIELD, self::TABLE, 'no_such_column', 99999),
        ]);

        // Kept, and the run reports the secret it could not check.
        $this->runTask(expectSuccess: false);

        self::assertTrue($vaultService->exists($identifier));
    }

    /**
     * Same fail-closed rule for a table that does not exist (an uninstalled
     * extension, a table on another connection that is not configured).
     */
    #[Test]
    public function theCommandKeepsASecretWhoseLinkNamesAnUnknownTable(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier   = $this->generateUuidV7();
        $vaultService->store($identifier, 'unknown-table', [
            'metadata' => SecretRecordLink::forField(SecretRecordLink::SOURCE_TCA_FIELD, 'tx_no_such_table', 'api_key', 1),
        ]);

        $this->backdateSecrets();
        $tester = new CommandTester($this->get(VaultCleanupOrphansCommand::class));
        $tester->setInputs(['yes']);
        $tester->execute([]);

        self::assertTrue($vaultService->exists($identifier), $tester->getDisplay());

        // The kept secret is listed with its link after the progress bar, not
        // as a context-less warning inside it.
        $display = $tester->getDisplay();
        self::assertMatchesRegularExpression(
            '/100%.*Kept 1 secret\\(s\\) whose record link could not be checked.*' . preg_quote($identifier, '/') . '.*tx_no_such_table.*names an unknown table/s',
            $display,
        );
    }

    /**
     * The record still exists but no longer holds the identifier (its field
     * was overwritten without DataHandler): nothing references the secret, so
     * it is an orphan whether or not the linked uid exists.
     */
    #[Test]
    public function theTaskDeletesASecretItsRecordNoLongerHolds(): void
    {
        $uid        = $this->createRecord('replaced-' . bin2hex(random_bytes(8)));
        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');

        $this->getConnectionPool()->getConnectionForTable(self::TABLE)
            ->update(self::TABLE, ['api_key' => ''], ['uid' => $uid]);
        $this->runTask();

        self::assertFalse($this->get(VaultServiceInterface::class)->exists($identifier));
    }

    /**
     * DBAL keys listTableColumns() by the platform-quoted name of a reserved
     * word (`key` on SQLite and MariaDB). The checker must still recognise the
     * column, or the secret is never cleaned up.
     */
    #[Test]
    public function theTaskDeletesASecretOfAReservedWordFieldWhoseRecordIsGone(): void
    {
        $uid        = $this->runDataHandler(self::RESERVED_TABLE, ['pid' => 1, 'title' => 'Reserved', 'key' => 'reserved-' . bin2hex(random_bytes(8))]);
        $identifier = $this->fetchField(self::RESERVED_TABLE, $uid, 'key');

        self::assertSame(
            ['source' => 'tca_field', 'table' => self::RESERVED_TABLE, 'field' => 'key', 'uid' => $uid],
            $this->storedMetadata($identifier),
        );

        $this->hardDeleteRow(self::RESERVED_TABLE, $uid);
        $this->runTask();

        self::assertFalse(
            $this->get(VaultServiceInterface::class)->exists($identifier),
            'A secret of a reserved-word column must be cleaned up once no row holds it',
        );
    }

    /**
     * A FlexForm-sourced link that names its column under `field` (not
     * `flexField`) is still a FlexForm link: the identifier sits inside the
     * column's XML, so the holder check must search the XML.
     */
    #[Test]
    public function theTaskKeepsAFlexFormSecretLinkedUnderTheFieldKey(): void
    {
        $plaintext  = 'flex-field-key-' . bin2hex(random_bytes(8));
        $uid        = $this->createFlexRecord($plaintext);
        $identifier = $this->flexIdentifier($uid);

        $this->getConnectionPool()->getConnectionForTable('tx_nrvault_secret')->update(
            'tx_nrvault_secret',
            ['metadata' => json_encode(['source' => 'flexform_field', 'table' => self::FLEX_TABLE, 'field' => 'settings', 'uid' => $uid], JSON_THROW_ON_ERROR)],
            ['identifier' => $identifier],
        );
        $this->runTask();

        self::assertSame($plaintext, $this->get(VaultServiceInterface::class)->retrieve($identifier));
    }

    /**
     * vault:migrate-field replaces the plaintext with the identifier, as its
     * documentation says. A secret no row references would be an orphan.
     */
    #[Test]
    public function theMigrateFieldCommandReplacesThePlaintextWithTheIdentifier(): void
    {
        $plaintext = 'migrate-' . bin2hex(random_bytes(8));
        $this->insertRow(self::TABLE, ['pid' => 1, 'title' => 'Plaintext', 'api_key' => $plaintext]);
        $uid = (int) $this->getConnectionPool()->getConnectionForTable(self::TABLE)->lastInsertId();

        $tester = new CommandTester($this->get(VaultMigrateFieldCommand::class));
        $tester->setInputs(['yes']);

        $exitCode = $tester->execute(['table' => self::TABLE, 'field' => 'api_key']);
        self::assertSame(0, $exitCode, $tester->getDisplay());

        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');
        self::assertNotSame($plaintext, $identifier, 'The field must no longer hold the plaintext');
        self::assertSame($plaintext, $this->get(VaultServiceInterface::class)->retrieve($identifier));
        self::assertSame(
            ['source' => 'migration', 'table' => self::TABLE, 'field' => 'api_key', 'uid' => $uid],
            array_intersect_key($this->storedMetadata($identifier), ['source' => 0, 'table' => 0, 'field' => 0, 'uid' => 0]),
        );

        $this->runTask();
        self::assertSame($plaintext, $this->get(VaultServiceInterface::class)->retrieve($identifier), 'A migrated secret its record holds must survive the cleanup');
    }

    /**
     * A writer stores the secret first and writes its identifier into the row
     * right after. A cleanup running in between must keep the secret, even
     * with 0 retention days; once it is older than the minimum age and still
     * unreferenced, it goes (#565).
     */
    #[Test]
    public function theTaskKeepsASecretWhoseRowIsNotWrittenYet(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier   = $this->generateUuidV7();
        $vaultService->store($identifier, 'row-not-written-yet', [
            'metadata' => SecretRecordLink::forField(SecretRecordLink::SOURCE_RECORD_COPY, self::TABLE, 'api_key', 424242),
        ]);

        $this->runTask(backdate: false);
        self::assertTrue($vaultService->exists($identifier), 'A secret younger than the minimum age must survive the cleanup');

        $this->getConnectionPool()->getConnectionForTable('tx_nrvault_secret')->update(
            'tx_nrvault_secret',
            ['crdate' => time() - OrphanReferenceCheckerInterface::MINIMUM_AGE_SECONDS - 60],
            ['identifier' => $identifier],
        );
        $this->runTask(backdate: false);
        self::assertFalse($vaultService->exists($identifier), 'Past the minimum age an unreferenced secret is an orphan');
    }

    /**
     * vault:migrate-field --force on a field that already holds the identifier
     * of an existing secret must not wrap it in a new secret: the old one
     * would be unreferenced and deleted by the next cleanup (#565).
     */
    #[Test]
    public function theMigrateFieldCommandSkipsAnExistingVaultIdentifierEvenWithForce(): void
    {
        $plaintext  = 'already-migrated-' . bin2hex(random_bytes(8));
        $uid        = $this->createRecord($plaintext);
        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');
        $before     = $this->secretCount();

        $tester = new CommandTester($this->get(VaultMigrateFieldCommand::class));
        $tester->setInputs(['yes']);

        $exitCode = $tester->execute(['table' => self::TABLE, 'field' => 'api_key', '--force' => true]);

        self::assertSame(0, $exitCode, $tester->getDisplay());
        self::assertSame($identifier, $this->fetchField(self::TABLE, $uid, 'api_key'), 'The field must keep its identifier');
        self::assertSame($plaintext, $this->get(VaultServiceInterface::class)->retrieve($identifier));
        self::assertSame($before, $this->secretCount(), 'No secret may be created for an existing identifier');
        self::assertStringContainsString('Skipped UID ' . $uid, $tester->getDisplay());
    }

    /**
     * PostgreSQL returns a CHAR column padded to its length. The padding is
     * not a mismatch: the record migrates and its secret stays (#565). The
     * value is stored as the database returns it, which on PostgreSQL
     * includes that padding.
     */
    #[Test]
    public function theMigrateFieldCommandMigratesAFixedWidthColumn(): void
    {
        $this->insertRow(self::RESERVED_TABLE, ['pid' => 1, 'title' => 'Padded', 'padded' => 'char-secret']);
        $uid = (int) $this->getConnectionPool()->getConnectionForTable(self::RESERVED_TABLE)->lastInsertId();

        $tester = new CommandTester($this->get(VaultMigrateFieldCommand::class));
        $tester->setInputs(['yes']);

        $exitCode = $tester->execute(['table' => self::RESERVED_TABLE, 'field' => 'padded']);

        self::assertSame(0, $exitCode, $tester->getDisplay());
        $identifier = rtrim($this->fetchField(self::RESERVED_TABLE, $uid, 'padded'), ' ');
        self::assertSame('char-secret', rtrim((string) $this->get(VaultServiceInterface::class)->retrieve($identifier), ' '));
    }

    /**
     * A --uid-field whose value several rows share would write one identifier
     * into all of them. The command refuses before it stores or writes
     * anything (#565).
     */
    #[Test]
    public function theMigrateFieldCommandRefusesAUidFieldSeveralRowsShare(): void
    {
        $this->insertRow(self::RESERVED_TABLE, ['pid' => 7, 'title' => 'First', 'key' => 'first-plain']);
        $first = (int) $this->getConnectionPool()->getConnectionForTable(self::RESERVED_TABLE)->lastInsertId();
        $this->insertRow(self::RESERVED_TABLE, ['pid' => 7, 'title' => 'Second', 'key' => 'second-plain']);
        $second = (int) $this->getConnectionPool()->getConnectionForTable(self::RESERVED_TABLE)->lastInsertId();
        $before = $this->secretCount();

        $tester = new CommandTester($this->get(VaultMigrateFieldCommand::class));
        $tester->setInputs(['yes']);

        $exitCode = $tester->execute(['table' => self::RESERVED_TABLE, 'field' => 'key', '--uid-field' => 'pid']);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('is not unique', $tester->getDisplay());
        self::assertSame('first-plain', $this->fetchField(self::RESERVED_TABLE, $first, 'key'));
        self::assertSame('second-plain', $this->fetchField(self::RESERVED_TABLE, $second, 'key'));
        self::assertSame($before, $this->secretCount());
    }

    /**
     * A column too narrow for an identifier would truncate it (non-strict
     * SQL, and SQLite ignores the length) and leave the stored secret
     * unreferenced. The command refuses before storing anything (#565).
     */
    #[Test]
    public function theMigrateFieldCommandRefusesAColumnTooNarrowForAnIdentifier(): void
    {
        $this->insertRow(self::RESERVED_TABLE, ['pid' => 1, 'title' => 'Narrow', 'narrow' => 'short-secret']);
        $uid    = (int) $this->getConnectionPool()->getConnectionForTable(self::RESERVED_TABLE)->lastInsertId();
        $before = $this->secretCount();

        $tester = new CommandTester($this->get(VaultMigrateFieldCommand::class));
        $tester->setInputs(['yes']);

        $exitCode = $tester->execute(['table' => self::RESERVED_TABLE, 'field' => 'narrow']);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('cannot hold a vault identifier', $tester->getDisplay());
        self::assertSame('short-secret', $this->fetchField(self::RESERVED_TABLE, $uid, 'narrow'));
        self::assertSame($before, $this->secretCount());
    }

    /**
     * Hidden and time-restricted records hold plaintext secrets too; deleted
     * records stay out. The field is named by a reserved word, which the
     * command's own column check must also recognise (#565).
     */
    #[Test]
    public function theMigrateFieldCommandMigratesHiddenAndScheduledRecordsButNotDeletedOnes(): void
    {
        $connection = $this->getConnectionPool()->getConnectionForTable(self::RESERVED_TABLE);
        $connection->insert(self::RESERVED_TABLE, ['pid' => 1, 'title' => 'Hidden', 'key' => 'hidden-plain', 'hidden' => 1]);

        $hiddenUid = (int) $connection->lastInsertId();
        $connection->insert(self::RESERVED_TABLE, ['pid' => 1, 'title' => 'Scheduled', 'key' => 'scheduled-plain', 'starttime' => time() + 86400]);
        $scheduledUid = (int) $connection->lastInsertId();
        $connection->insert(self::RESERVED_TABLE, ['pid' => 1, 'title' => 'Deleted', 'key' => 'deleted-plain', 'deleted' => 1]);
        $deletedUid = (int) $connection->lastInsertId();

        $tester = new CommandTester($this->get(VaultMigrateFieldCommand::class));
        $tester->setInputs(['yes']);

        $exitCode = $tester->execute(['table' => self::RESERVED_TABLE, 'field' => 'key']);
        self::assertSame(0, $exitCode, $tester->getDisplay());

        $vaultService = $this->get(VaultServiceInterface::class);
        self::assertSame('hidden-plain', $vaultService->retrieve($this->fetchField(self::RESERVED_TABLE, $hiddenUid, 'key')));
        self::assertSame('scheduled-plain', $vaultService->retrieve($this->fetchField(self::RESERVED_TABLE, $scheduledUid, 'key')));
        self::assertSame('deleted-plain', $this->fetchField(self::RESERVED_TABLE, $deletedUid, 'key'), 'A deleted record must not be migrated');
    }

    /**
     * The backend migration wizard selects like the command: hidden and
     * time-restricted records are migrated, deleted ones are not (#565).
     */
    #[Test]
    public function theMigrationWizardMigratesHiddenAndScheduledRecordsButNotDeletedOnes(): void
    {
        $connection = $this->getConnectionPool()->getConnectionForTable(self::RESERVED_TABLE);
        $connection->insert(self::RESERVED_TABLE, ['pid' => 1, 'title' => 'Hidden', 'key' => 'hidden-plain', 'hidden' => 1]);

        $hiddenUid = (int) $connection->lastInsertId();
        $connection->insert(self::RESERVED_TABLE, ['pid' => 1, 'title' => 'Scheduled', 'key' => 'scheduled-plain', 'starttime' => time() + 86400]);
        $scheduledUid = (int) $connection->lastInsertId();
        $connection->insert(self::RESERVED_TABLE, ['pid' => 1, 'title' => 'Deleted', 'key' => 'deleted-plain', 'deleted' => 1]);
        $deletedUid = (int) $connection->lastInsertId();

        $controller = $this->get(MigrationController::class);
        $result     = (new ReflectionMethod(MigrationController::class, 'migrateColumn'))
            ->invoke($controller, self::RESERVED_TABLE, 'key', 'wizard_key_{uid}');
        self::assertInstanceOf(MigrationResult::class, $result);
        self::assertSame(2, $result->migrated, $result->error ?? '');

        $vaultService = $this->get(VaultServiceInterface::class);
        self::assertSame('hidden-plain', $vaultService->retrieve('wizard_key_' . $hiddenUid));
        self::assertSame('scheduled-plain', $vaultService->retrieve('wizard_key_' . $scheduledUid));
        self::assertSame('deleted-plain', $this->fetchField(self::RESERVED_TABLE, $deletedUid, 'key'), 'A deleted record must not be migrated');
    }

    /**
     * The delete flag follows TCA ctrl.delete, here `removed`: both
     * migrations skip a removed row and migrate a hidden one (#565).
     */
    #[Test]
    public function bothMigrationsFollowTheTcaDeleteColumn(): void
    {
        $connection = $this->getConnectionPool()->getConnectionForTable(self::CUSTOM_DELETE_TABLE);
        $connection->insert(self::CUSTOM_DELETE_TABLE, ['pid' => 1, 'title' => 'Hidden', 'secret' => 'hidden-plain', 'hidden' => 1]);

        $hiddenUid = (int) $connection->lastInsertId();
        $connection->insert(self::CUSTOM_DELETE_TABLE, ['pid' => 1, 'title' => 'Removed', 'secret' => 'removed-plain', 'removed' => 1]);
        $removedUid = (int) $connection->lastInsertId();

        $tester = new CommandTester($this->get(VaultMigrateFieldCommand::class));
        $tester->setInputs(['yes']);
        self::assertSame(0, $tester->execute(['table' => self::CUSTOM_DELETE_TABLE, 'field' => 'secret']), $tester->getDisplay());

        self::assertSame('hidden-plain', $this->get(VaultServiceInterface::class)->retrieve($this->fetchField(self::CUSTOM_DELETE_TABLE, $hiddenUid, 'secret')));
        self::assertSame('removed-plain', $this->fetchField(self::CUSTOM_DELETE_TABLE, $removedUid, 'secret'), 'The command must skip a removed record');

        $connection->insert(self::CUSTOM_DELETE_TABLE, ['pid' => 1, 'title' => 'Hidden 2', 'secret' => 'hidden-plain-2', 'hidden' => 1]);
        $hiddenUid2 = (int) $connection->lastInsertId();

        $result = (new ReflectionMethod(MigrationController::class, 'migrateColumn'))
            ->invoke($this->get(MigrationController::class), self::CUSTOM_DELETE_TABLE, 'secret', 'custom_delete_{uid}');
        self::assertInstanceOf(MigrationResult::class, $result);
        self::assertSame('hidden-plain-2', $this->get(VaultServiceInterface::class)->retrieve('custom_delete_' . $hiddenUid2));
        self::assertSame('removed-plain', $this->fetchField(self::CUSTOM_DELETE_TABLE, $removedUid, 'secret'), 'The module must skip a removed record');
    }

    /**
     * A field holding the identifier of a disabled secret is skipped, also
     * with --force: wrapping it would orphan the disabled secret (#565).
     */
    #[Test]
    public function theMigrateFieldCommandSkipsTheIdentifierOfADisabledSecret(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier   = $this->generateUuidV7();
        $vaultService->store($identifier, 'disabled-plain');
        $vaultService->setEnabled($identifier, false);
        $this->insertRow(self::RESERVED_TABLE, ['pid' => 1, 'title' => 'Disabled', 'key' => $identifier]);
        $uid    = (int) $this->getConnectionPool()->getConnectionForTable(self::RESERVED_TABLE)->lastInsertId();
        $before = $this->secretCount();

        $tester = new CommandTester($this->get(VaultMigrateFieldCommand::class));
        $tester->setInputs(['yes']);

        $exitCode = $tester->execute(['table' => self::RESERVED_TABLE, 'field' => 'key', '--force' => true]);

        self::assertSame(0, $exitCode, $tester->getDisplay());
        self::assertSame($identifier, $this->fetchField(self::RESERVED_TABLE, $uid, 'key'));
        self::assertSame($before, $this->secretCount(), 'No secret may wrap the identifier of a disabled secret');
    }

    /**
     * The command gets its checker from DI, so the checker logs through a
     * real logger instead of the NullLogger default (#565).
     */
    #[Test]
    public function theContainerInjectsACheckerWithARealLogger(): void
    {
        $checker = $this->get(OrphanReferenceCheckerInterface::class);
        self::assertInstanceOf(OrphanReferenceChecker::class, $checker);

        $logger = (new ReflectionProperty(OrphanReferenceChecker::class, 'logger'))->getValue($checker);
        self::assertNotInstanceOf(NullLogger::class, $logger);
    }

    /**
     * The database compares with its collation, PHP compares bytes. A row
     * holding the identifier in another case or with a trailing space still
     * resolves the secret where the collation matches it (MySQL and MariaDB
     * defaults), so there the secret must be kept; where the database does
     * not match it (SQLite, PostgreSQL), nothing resolves it and it goes. The
     * checker must follow the database, never its own comparison (#565).
     */
    #[Test]
    #[DataProvider('collationVariantProvider')]
    public function theCleanupFollowsTheDatabaseCollation(string $variant): void
    {
        $uid        = $this->createRecord('collation-' . bin2hex(random_bytes(8)));
        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');
        $held       = $variant === 'upper' ? strtoupper($identifier) : $identifier . ' ';

        $connection = $this->getConnectionPool()->getConnectionForTable(self::TABLE);
        $connection->update(self::TABLE, ['api_key' => $held], ['uid' => $uid]);

        $databaseMatches = $connection->count('*', self::TABLE, ['api_key' => $identifier]) > 0;

        if ($variant === 'upper' && $connection->getDatabasePlatform() instanceof AbstractMySQLPlatform) {
            self::assertTrue($databaseMatches, 'MySQL/MariaDB compare case-insensitively; the test would check nothing otherwise');
        }

        $this->runTask();

        self::assertSame(
            $databaseMatches,
            $this->get(VaultServiceInterface::class)->exists($identifier),
            $databaseMatches ? 'A secret the database still resolves must be kept' : 'A secret nothing resolves is an orphan',
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function collationVariantProvider(): iterable
    {
        yield 'upper case' => ['upper'];
        yield 'trailing space' => ['trailing space'];
    }

    private function createRecord(string $apiKey): int
    {
        return $this->runDataHandler(self::TABLE, [
            'pid'     => 1,
            'title'   => 'Linked record',
            'api_key' => $apiKey,
        ]);
    }

    private function createFlexRecord(string $plaintext): int
    {
        return $this->runDataHandler(self::FLEX_TABLE, [
            'pid'      => 1,
            'title'    => 'Linked FlexForm record',
            'settings' => [
                'data' => [
                    'sDEF' => [
                        'lDEF' => [
                            'apiKey' => [
                                'vDEF' => [
                                    'value'             => $plaintext,
                                    '_vault_identifier' => '',
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ]);
    }

    /**
     * Create one record through DataHandler and return its uid.
     *
     * @param array<string, mixed> $record
     */
    private function runDataHandler(string $table, array $record): int
    {
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start([$table => ['NEW1' => $record]], []);
        $dataHandler->process_datamap();

        $uid = $dataHandler->substNEWwithIDs['NEW1'] ?? null;
        self::assertIsInt($uid);

        return $uid;
    }

    private function backdateSecrets(): void
    {
        $this->getConnectionPool()->getConnectionForTable('tx_nrvault_secret')->update(
            'tx_nrvault_secret',
            ['crdate' => time() - 86400],
            [],
        );
    }

    private function secretCount(): int
    {
        return $this->getConnectionPool()->getConnectionForTable('tx_nrvault_secret')->count('*', 'tx_nrvault_secret', []);
    }

    private function runTask(bool $backdate = true, bool $expectSuccess = true): void
    {
        // The secrets were created a moment ago; the cleanup only deletes
        // what is older than the minimum age, even with 0 retention days.
        if ($backdate) {
            $this->backdateSecrets();
        }

        $task = new OrphanCleanupTask(
            $this->get(ConnectionPool::class),
            $this->get(VaultServiceInterface::class),
        );
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);

        self::assertSame($expectSuccess, $task->execute(), 'A secret kept unchecked fails the run, any other run succeeds');
    }

    /**
     * @param array<string, mixed> $row
     */
    private function insertRow(string $table, array $row): void
    {
        $this->getConnectionPool()->getConnectionForTable($table)->insert($table, $row);
    }

    private function hardDeleteRow(string $table, int $uid): void
    {
        $this->getConnectionPool()->getConnectionForTable($table)->delete($table, ['uid' => $uid], [Connection::PARAM_INT]);
    }

    private function fetchField(string $table, int $uid, string $field): string
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        $value = $queryBuilder
            ->select($field)
            ->from($table)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();
        self::assertIsString($value);
        self::assertNotSame('', $value);

        return $value;
    }

    private function flexIdentifier(int $uid): string
    {
        $xml = $this->fetchField(self::FLEX_TABLE, $uid, 'settings');
        self::assertSame(1, preg_match('/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/', $xml, $match), 'FlexForm must hold a vault identifier: ' . $xml);

        return $match[0];
    }

    /**
     * @return array<string, mixed>
     */
    private function storedMetadata(string $identifier): array
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable('tx_nrvault_secret');
        $queryBuilder->getRestrictions()->removeAll();

        $raw = $queryBuilder
            ->select('metadata')
            ->from('tx_nrvault_secret')
            ->where($queryBuilder->expr()->eq('identifier', $queryBuilder->createNamedParameter($identifier)))
            ->executeQuery()
            ->fetchOne();
        self::assertIsString($raw, 'Secret ' . $identifier . ' not found');

        $metadata = json_decode($raw, true);
        self::assertIsArray($metadata, 'metadata is not a JSON object: ' . json_encode($raw));

        $typed = [];
        foreach ($metadata as $key => $value) {
            $typed[(string) $key] = $value;
        }

        return $typed;
    }
}
