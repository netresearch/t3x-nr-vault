<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Controller;

use Doctrine\DBAL\Schema\Column;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Controller\MigrationController;
use Netresearch\NrVault\Domain\Dto\FieldMigrationOutcome;
use Netresearch\NrVault\Domain\Dto\MigrationResult;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Service\FieldValueMigrator;
use Netresearch\NrVault\Service\FieldValueMigratorInterface;
use Netresearch\NrVault\Service\SecretRecordLinkWriterInterface;
use Netresearch\NrVault\Service\VaultService;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\AbstractLogger;
use Psr\Log\LogLevel;
use ReflectionClass;
use ReflectionMethod;
use Stringable;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;
use TYPO3\CMS\Core\Messaging\FlashMessage;
use TYPO3\CMS\Core\Messaging\FlashMessageService;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;

use function array_filter;
use function array_intersect_key;
use function array_key_exists;
use function array_values;
use function in_array;
use function is_array;
use function is_numeric;
use function is_string;
use function json_decode;
use function sprintf;
use function str_contains;
use function substr_count;

/**
 * The migration links a secret to its record without the secret.rotate
 * permission: the link is metadata of the creation, written once and audited
 * as one Create (#565).
 */
#[CoversClass(FieldValueMigrator::class)]
#[CoversClass(VaultService::class)]
#[CoversClass(MigrationController::class)]
final class MigrationRecordLinkPermissionTest extends AbstractVaultFunctionalTestCase
{
    private const TABLE = 'tx_nrvaulttest_customdelete';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    /** Non-admin editor without secret.create. */
    private const EDITOR_WITHOUT_CREATE = 2;

    /** Non-admin editor holding secret.create but not secret.rotate. */
    private const EDITOR_WITH_CREATE = 4;

    protected ?string $backendUserFixture = __DIR__ . '/../Hook/Fixtures/be_users_create_permission.csv';

    protected ?int $backendUserUid = self::EDITOR_WITH_CREATE;

    /** @var list<string> */
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
        __DIR__ . '/../Fixtures/Extensions/nr_vault_test',
    ];

    #[Test]
    public function aCreatorWithoutTheRotatePermissionGetsTheRecordLink(): void
    {
        $connection = $this->getConnectionPool()->getConnectionForTable(self::TABLE);
        $connection->insert(self::TABLE, ['pid' => 1, 'secret' => 'creator-plaintext']);

        $uid        = (int) $connection->lastInsertId();
        $identifier = 'linkperm_' . $uid;

        $result = (new ReflectionMethod(MigrationController::class, 'migrateColumn'))
            ->invoke($this->get(MigrationController::class), self::TABLE, 'secret', 'linkperm_{uid}');
        self::assertInstanceOf(MigrationResult::class, $result);

        self::assertSame(1, $result->migrated, implode('; ', $result->failureReasons));
        $metadata = $this->metadataOf($identifier);
        self::assertSame(['migration', self::TABLE, 'secret', $uid], [
            $metadata['source'] ?? null,
            $metadata['table'] ?? null,
            $metadata['field'] ?? null,
            $metadata['uid'] ?? null,
        ]);
        self::assertSame(1, $this->countAuditEntries($identifier, AuditAction::Create->value), 'One Create entry');
        self::assertSame(0, $this->countAuditEntries($identifier, AuditAction::Update->value), 'No Update entry for the link');
        self::assertSame(1, $this->countAuditEntries($identifier, AuditAction::MetadataUpdate->value), 'The link is audited as one metadata update');
    }

    /**
     * A disabled secret is linked too: the metadata write finds it, and the
     * read-back confirms the link landed before it is audited (#565).
     */
    #[Test]
    public function aDisabledSecretIsLinked(): void
    {
        $this->setUpBackendUser(1);
        $identifier   = 'linkperm_disabled';
        $vaultService = $this->get(VaultServiceInterface::class);
        $vaultService->store($identifier, 'value', ['metadata' => ['migrated_at' => 1]]);
        $vaultService->setEnabled($identifier, false);

        $this->get(SecretRecordLinkWriterInterface::class)->linkCreatedSecret($identifier, ['migrated_at' => 1], ['source' => 'migration', 'table' => self::TABLE, 'field' => 'secret', 'uid' => 9]);

        self::assertSame(['migrated_at' => 1, 'source' => 'migration', 'table' => self::TABLE, 'field' => 'secret', 'uid' => 9], $this->metadataOf($identifier));
        self::assertSame(1, $this->countAuditEntries($identifier, AuditAction::MetadataUpdate->value) - 1, 'One metadata update for the link, besides the one for disabling');
    }

    /**
     * A create-only store refuses an identifier a secret already holds,
     * disabled ones included, instead of updating that secret (#565).
     */
    #[Test]
    public function aCreateOnlyStoreDoesNotUpdateAnExistingSecret(): void
    {
        $this->setUpBackendUser(1);
        $identifier   = 'linkperm_create_only';
        $vaultService = $this->get(VaultServiceInterface::class);
        $vaultService->store($identifier, 'first-run-value', ['metadata' => ['migrated_at' => 1]]);
        $vaultService->setEnabled($identifier, false);

        try {
            $vaultService->store($identifier, 'second-run-value', ['metadata' => ['migrated_at' => 2], 'createOnly' => true]);
            self::fail('A create-only store must not update an existing secret');
        } catch (ValidationException $e) {
            self::assertStringContainsString('already exists', $e->getMessage());
        }

        $vaultService->setEnabled($identifier, true);
        self::assertSame('first-run-value', $vaultService->retrieve($identifier));
        self::assertSame(['migrated_at' => 1], $this->metadataOf($identifier));
    }

    /**
     * The link writer refuses a secret whose metadata is no longer what its
     * creator stored, and audits nothing (#565).
     */
    #[Test]
    public function theLinkIsRefusedForASecretChangedSinceItWasStored(): void
    {
        $this->setUpBackendUser(1);
        $identifier = 'linkperm_changed';
        $this->get(VaultServiceInterface::class)->store($identifier, 'value', ['metadata' => ['migrated_at' => 1, 'note' => 'edited']]);

        try {
            $this->get(SecretRecordLinkWriterInterface::class)->linkCreatedSecret($identifier, ['migrated_at' => 1], ['source' => 'migration']);
            self::fail('A changed secret must not be linked');
        } catch (ValidationException $e) {
            self::assertStringContainsString('the secret changed after it was stored', $e->getMessage());
        }

        self::assertSame(['migrated_at' => 1, 'note' => 'edited'], $this->metadataOf($identifier));
        self::assertSame(0, $this->countAuditEntries($identifier, AuditAction::MetadataUpdate->value));
    }

    /**
     * Linking needs secret.create, the permission of the creation: an owner
     * without it is refused and the refusal is audited (#565).
     */
    #[Test]
    public function theLinkNeedsTheCreatePermission(): void
    {
        $this->setUpBackendUser(1);
        $identifier = 'linkperm_owner';
        $this->get(VaultServiceInterface::class)->store($identifier, 'value', ['metadata' => ['migrated_at' => 1], 'owner' => self::EDITOR_WITHOUT_CREATE]);

        $this->setUpBackendUser(self::EDITOR_WITHOUT_CREATE);

        try {
            $this->get(SecretRecordLinkWriterInterface::class)->linkCreatedSecret($identifier, ['migrated_at' => 1], ['source' => 'migration']);
            self::fail('An actor without secret.create must not link');
        } catch (AccessDeniedException $e) {
            self::assertStringContainsString('secret.create', $e->getMessage());
        }

        self::assertSame(['migrated_at' => 1], $this->metadataOf($identifier));
        self::assertSame(1, $this->countAuditEntries($identifier, AuditAction::AccessDenied->value));
    }

    /**
     * A row whose value moved into the vault but whose record link was
     * refused is reported once, with one label, as needing attention (#565).
     */
    #[Test]
    public function anUnlinkedRowIsReportedWithOneLabel(): void
    {
        $connection = $this->getConnectionPool()->getConnectionForTable(self::TABLE);
        $connection->insert(self::TABLE, ['pid' => 1, 'secret' => 'unlinked-plaintext']);

        $uid = (int) $connection->lastInsertId();

        $refusingWriter = new class implements SecretRecordLinkWriterInterface {
            public function linkCreatedSecret(string $identifier, array $createdMetadata, array $link): void
            {
                throw new AccessDeniedException('link refused for the test', 1795000201);
            }
        };
        $migrator   = $this->rebuild($this->get(FieldValueMigratorInterface::class), ['recordLinkWriter' => $refusingWriter]);
        $controller = $this->rebuild($this->get(MigrationController::class), ['fieldValueMigrator' => $migrator]);

        $result = (new ReflectionMethod(MigrationController::class, 'migrateColumn'))
            ->invoke($controller, self::TABLE, 'secret', 'linkunl_{uid}');
        self::assertInstanceOf(MigrationResult::class, $result);

        self::assertSame(1, $result->migrated);
        self::assertSame(1, $result->unlinked, 'The verify page shows the column as Partial');
        self::assertCount(1, $result->failureReasons);
        self::assertStringStartsWith(sprintf('uid %d: migrated, unlinked: the field holds the identifier', $uid), $result->failureReasons[0]);
        self::assertSame(1, substr_count($result->failureReasons[0], 'migrated, unlinked'), 'The label is printed once');
    }

    /**
     * Failed rows are capped in the report, unlinked rows are not: a re-run
     * skips them, so the report and one warning log entry per row are the
     * only places that name them (#565).
     */
    #[Test]
    public function everyUnlinkedRowIsReportedAndLogged(): void
    {
        $connection = $this->getConnectionPool()->getConnectionForTable(self::TABLE);
        $uids       = [];
        for ($row = 1; $row <= 12; ++$row) {
            $connection->insert(self::TABLE, ['pid' => 1, 'secret' => 'unlinked-plaintext-' . $row]);
            $uids[] = (int) $connection->lastInsertId();
        }

        $refusingWriter = new class implements SecretRecordLinkWriterInterface {
            public function linkCreatedSecret(string $identifier, array $createdMetadata, array $link): void
            {
                throw new AccessDeniedException('link refused for the test', 1795000203);
            }
        };
        $logger = new class extends AbstractLogger {
            /** @var list<array{mixed, string, array<mixed>}> */
            public array $records = [];

            public function log($level, string|Stringable $message, array $context = []): void
            {
                $this->records[] = [$level, (string) $message, $context];
            }
        };
        $migrator   = $this->rebuild($this->get(FieldValueMigratorInterface::class), ['recordLinkWriter' => $refusingWriter]);
        $controller = $this->rebuild($this->get(MigrationController::class), ['fieldValueMigrator' => $migrator, 'logger' => $logger]);

        $result = (new ReflectionMethod(MigrationController::class, 'migrateColumn'))
            ->invoke($controller, self::TABLE, 'secret', 'linkmany_{uid}');
        self::assertInstanceOf(MigrationResult::class, $result);

        self::assertSame(12, $result->unlinked);
        self::assertCount(12, $result->failureReasons, 'No cap for unlinked rows');
        $logged = array_values(array_filter($logger->records, static fn (array $record): bool => $record[0] === LogLevel::WARNING));
        self::assertCount(12, $logged, 'One warning per unlinked row');
        self::assertSame(
            ['identifier' => 'linkmany_' . $uids[11], 'table' => self::TABLE, 'field' => 'secret', 'uid' => $uids[11]],
            array_intersect_key($logged[11][2], ['identifier' => true, 'table' => true, 'field' => true, 'uid' => true]),
        );
    }

    /**
     * A failed row whose secret was kept as the possible only copy of its
     * value cannot be recovered by a re-run (its identifier is in use): every
     * one is listed after the ten ordinary failures and logged as a warning.
     * Ordinary failures, whose row still holds its value, stay capped (#565).
     */
    #[Test]
    public function everyRowWhoseSecretWasKeptIsReportedAndLogged(): void
    {
        $connection = $this->getConnectionPool()->getConnectionForTable(self::TABLE);
        $kept       = [];
        for ($row = 1; $row <= 24; ++$row) {
            $connection->insert(self::TABLE, ['pid' => 1, 'secret' => 'kept-plaintext-' . $row]);
            if ($row % 2 === 0) {
                $kept[] = (int) $connection->lastInsertId();
            }
        }

        $real     = $this->get(FieldValueMigratorInterface::class);
        $migrator = new class ($real, $kept) implements FieldValueMigratorInterface {
            /**
             * @param list<int> $kept
             */
            public function __construct(private readonly FieldValueMigratorInterface $real, private readonly array $kept) {}

            public function findColumn(string $table, string $field): ?Column
            {
                return $this->real->findColumn($table, $field);
            }

            public function columnProblem(Column $column, int $identifierLength): ?string
            {
                return $this->real->columnProblem($column, $identifierLength);
            }

            public function countRowsWithDuplicateKey(string $table, string $keyField): ?int
            {
                return $this->real->countRowsWithDuplicateKey($table, $keyField);
            }

            public function restrictToMigratableRows(QueryBuilder $queryBuilder, string $table): void
            {
                $this->real->restrictToMigratableRows($queryBuilder, $table);
            }

            public function identifierInUse(string $identifier): bool
            {
                return $this->real->identifierInUse($identifier);
            }

            public function migrate(string $table, string $field, string $keyField, string $key, string $value, string $identifier): FieldMigrationOutcome
            {
                return in_array((int) $key, $this->kept, true)
                    ? FieldMigrationOutcome::failedKeepingSecret('the field could not be read back; the secret ' . $identifier . ' was kept')
                    : FieldMigrationOutcome::failed('the value could not be stored');
            }
        };
        $logger = new class extends AbstractLogger {
            /** @var list<array{mixed, string, array<mixed>}> */
            public array $records = [];

            public function log($level, string|Stringable $message, array $context = []): void
            {
                $this->records[] = [$level, (string) $message, $context];
            }
        };
        $controller = $this->rebuild($this->get(MigrationController::class), ['fieldValueMigrator' => $migrator, 'logger' => $logger]);

        $result = (new ReflectionMethod(MigrationController::class, 'migrateColumn'))
            ->invoke($controller, self::TABLE, 'secret', 'linkkept_{uid}');
        self::assertInstanceOf(MigrationResult::class, $result);

        self::assertSame(24, $result->failed);
        self::assertCount(10 + 1 + 12, $result->failureReasons, 'Ten ordinary failures, the rest counted, every kept secret listed');
        self::assertSame('and 2 more failed rows', $result->failureReasons[10]);
        self::assertCount(12, array_filter($result->failureReasons, static fn (string $reason): bool => str_contains($reason, 'was kept')));
        $logged = array_values(array_filter($logger->records, static fn (array $record): bool => $record[0] === LogLevel::WARNING));
        self::assertCount(12, $logged, 'One warning per kept secret');
        self::assertSame(
            ['identifier' => 'linkkept_' . $kept[11], 'table' => self::TABLE, 'field' => 'secret', 'uid' => $kept[11]],
            array_intersect_key($logged[11][2], ['identifier' => true, 'table' => true, 'field' => true, 'uid' => true]),
        );
    }

    /**
     * The module carries the count of unlinked rows from the run to the
     * verify step and warns about them there (#565).
     */
    #[Test]
    public function theModuleWarnsAboutUnlinkedRowsOnTheVerifyStep(): void
    {
        $connection = $this->getConnectionPool()->getConnectionForTable(self::TABLE);
        $connection->insert(self::TABLE, ['pid' => 1, 'secret' => 'unlinked-plaintext']);

        $refusingWriter = new class implements SecretRecordLinkWriterInterface {
            public function linkCreatedSecret(string $identifier, array $createdMetadata, array $link): void
            {
                throw new AccessDeniedException('link refused for the test', 1795000202);
            }
        };
        $migrator        = $this->rebuild($this->get(FieldValueMigratorInterface::class), ['recordLinkWriter' => $refusingWriter]);
        $controller      = $this->rebuild($this->get(MigrationController::class), ['fieldValueMigrator' => $migrator]);
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->create('default');

        /** @phpstan-ignore new.internalClass, method.internalClass */
        $request = new ServerRequest('https://example.com/typo3/module/admin/vault/migration', 'POST');
        /** @phpstan-ignore method.internalClass */
        $request = $request->withParsedBody(['migrations' => [['table' => self::TABLE, 'column' => 'secret', 'identifierPattern' => 'linkflash_{uid}']]]);
        (new ReflectionMethod(MigrationController::class, 'executeAction'))->invoke($controller, $request);

        $session = $GLOBALS['BE_USER']->getSessionData('vault_migration_results');
        self::assertIsArray($session);
        self::assertSame(1, $session['totalUnlinked'] ?? null, 'The count reaches the verify step');

        $queue = $this->get(FlashMessageService::class)->getMessageQueueByIdentifier();
        $queue->getAllMessagesAndFlush();
        (new ReflectionMethod(MigrationController::class, 'addResultFlashMessages'))->invoke($controller, 1, 0, 1);
        $warnings = array_values(array_filter(
            $queue->getAllMessages(),
            /** @phpstan-ignore method.internal */
            static fn (FlashMessage $message): bool => $message->getSeverity() === ContextualFeedbackSeverity::WARNING,
        ));
        self::assertCount(1, $warnings);
        self::assertStringContainsString('1 secret(s) were migrated with their record link missing or of unknown state', $warnings[0]->getMessage());
    }

    #[Test]
    public function theContainerProvidesTheMigratorBehindItsInterface(): void
    {
        self::assertInstanceOf(FieldValueMigrator::class, $this->get(FieldValueMigratorInterface::class));
    }

    /**
     * A new instance of $service's class with the same constructor arguments,
     * except those named in $replace.
     *
     * @template T of object
     *
     * @param T                    $service
     * @param array<string, mixed> $replace
     *
     * @return T
     */
    private function rebuild(object $service, array $replace): object
    {
        $class     = new ReflectionClass($service);
        $arguments = [];
        foreach ($class->getConstructor()?->getParameters() ?? [] as $parameter) {
            $name             = $parameter->getName();
            $arguments[$name] = array_key_exists($name, $replace) ? $replace[$name] : $class->getProperty($name)->getValue($service);
        }

        return $class->newInstanceArgs($arguments);
    }

    /**
     * @return array<mixed>
     */
    private function metadataOf(string $identifier): array
    {
        // Disabled secrets included.
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable('tx_nrvault_secret');
        $queryBuilder->getRestrictions()->removeAll();
        $json = $queryBuilder
            ->select('metadata')
            ->from('tx_nrvault_secret')
            ->where($queryBuilder->expr()->eq('identifier', $queryBuilder->createNamedParameter($identifier)))
            ->executeQuery()
            ->fetchOne();
        self::assertTrue(is_string($json), 'The secret must exist');
        $metadata = json_decode($json, true);
        self::assertTrue(is_array($metadata));

        return $metadata;
    }

    private function countAuditEntries(string $identifier, string $action): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::AUDIT_TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $count = $queryBuilder
            ->count('uid')
            ->from(self::AUDIT_TABLE)
            ->where(
                $queryBuilder->expr()->eq('secret_identifier', $queryBuilder->createNamedParameter($identifier)),
                $queryBuilder->expr()->eq('action', $queryBuilder->createNamedParameter($action)),
            )
            ->executeQuery()
            ->fetchOne();

        return is_numeric($count) ? (int) $count : 0;
    }
}
