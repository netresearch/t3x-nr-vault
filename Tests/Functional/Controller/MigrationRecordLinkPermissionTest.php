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
use Netresearch\NrVault\Service\FieldValueMigrator;
use Netresearch\NrVault\Service\FieldValueMigratorInterface;
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
#[CoversClass(MigrationController::class)]
final class MigrationRecordLinkPermissionTest extends AbstractVaultFunctionalTestCase
{
    private const TABLE = 'tx_nrvaulttest_customdelete';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

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
        $json = $this->getConnectionPool()->getConnectionForTable('tx_nrvault_secret')
            ->select(['metadata'], 'tx_nrvault_secret', ['identifier' => $identifier])
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
