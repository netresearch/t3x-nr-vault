<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Hook;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Hook\SecretTcaHook;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * The review's acceptance scenario for the FormEngine create path: a backend
 * user holding generic TABLE permissions on tx_nrvault_secret but NOT the
 * secret.create operation permission must not be able to store a secret value
 * through a direct DataHandler request — the secrets-module controller check
 * is UX, the enforcement lives in VaultService::store() behind the hook.
 *
 * The hook contract is driven directly (like SecretTcaHookDeleteAclTest):
 * core's own table-permission system would block the group-less editor before
 * the vault gate runs and mask the result under test.
 */
#[CoversClass(SecretTcaHook::class)]
final class SecretTcaHookCreateAclTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    /** Non-admin editor (uid 2), no vault operation permissions. */
    private const EDITOR_UID = 2;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_acl.csv';

    protected ?int $backendUserUid = self::EDITOR_UID;

    #[Test]
    public function editorWithoutSecretCreatePermissionCannotStoreViaDataHandler(): void
    {
        $identifier = 'op_create_' . bin2hex(random_bytes(4));

        $hook = $this->get(SecretTcaHook::class);
        self::assertInstanceOf(SecretTcaHook::class, $hook);

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->BE_USER = $GLOBALS['BE_USER'];

        // Simulate the FormEngine create: preProcess captures the pending
        // secret value, core writes the row, afterDatabaseOperations hands
        // the value to VaultService::store() — which must deny.
        $fieldArray = [
            'pid' => 0,
            'identifier' => $identifier,
            'secret_input' => 'must-not-be-stored',
        ];
        $hook->processDatamap_preProcessFieldArray($fieldArray, self::SECRET_TABLE, 'NEW1', $dataHandler);

        $connection = $this->getConnectionPool()->getConnectionForTable(self::SECRET_TABLE);
        $connection->insert(self::SECRET_TABLE, [
            'pid' => 0,
            'identifier' => $identifier,
            'owner_uid' => self::EDITOR_UID,
            'deleted' => 0,
        ]);
        $newUid = (int) $connection->lastInsertId();

        $dataHandler->substNEWwithIDs['NEW1'] = $newUid;
        $hook->processDatamap_afterDatabaseOperations('new', self::SECRET_TABLE, 'NEW1', $fieldArray, $dataHandler);

        // No encrypted value may have been persisted for the record.
        $row = $connection->select(
            ['encrypted_value'],
            self::SECRET_TABLE,
            ['uid' => $newUid],
        )->fetchAssociative();
        self::assertIsArray($row);
        $encryptedValue = $row['encrypted_value'] ?? '';
        self::assertIsString($encryptedValue);
        self::assertSame('', $encryptedValue, 'The denied create must not persist a secret value.');

        // The denial is recorded in the audit trail.
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::AUDIT_TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $denied = $queryBuilder
            ->count('uid')
            ->from(self::AUDIT_TABLE)
            ->where(
                $queryBuilder->expr()->eq('secret_identifier', $queryBuilder->createNamedParameter($identifier)),
                $queryBuilder->expr()->eq('action', $queryBuilder->createNamedParameter(AuditAction::AccessDenied->value)),
                $queryBuilder->expr()->eq('success', $queryBuilder->createNamedParameter(0, Connection::PARAM_INT)),
            )
            ->executeQuery()
            ->fetchOne();
        self::assertSame(1, is_numeric($denied) ? (int) $denied : 0, 'The denied create must be audited as access_denied.');

        // The DataHandler log carries the user-facing error.
        /** @phpstan-ignore property.internal */
        self::assertNotEmpty($dataHandler->errorLog, 'The denied create must surface in the DataHandler error log.');
    }
}
