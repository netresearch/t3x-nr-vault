<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Controller;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Controller\MigrationController;
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
use ReflectionMethod;

use function is_array;
use function is_numeric;
use function is_string;
use function json_decode;

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

    #[Test]
    public function theContainerProvidesTheMigratorBehindItsInterface(): void
    {
        self::assertInstanceOf(FieldValueMigrator::class, $this->get(FieldValueMigratorInterface::class));
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
