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
 * Functional tests for SecretTcaHook against a SOFT-DELETED secret
 * (`deleted = 1`), and against a uid that has no row at all.
 *
 * Both of the hook's datamap write gates — the per-secret write ACL and the
 * privileged-column policy — resolve their target through a lookup that
 * excludes soft-deleted rows, and both used to treat "not found" as "allowed".
 * Core does not stop there on their behalf: it reads its datamap UPDATE target
 * with `BackendUtility::getRecord($table, $id, '*', '', false)`, delete clause
 * OFF, and skips only a row it cannot find at all. A tombstone therefore has a
 * pid and is processed — so the columns of a deleted secret were writable by
 * anyone core let near the table, with no per-secret tier, no policy gate and
 * no audit entry.
 *
 * ## Why these tests drive the real DataHandler
 *
 * The finding is about what core does when the hook declines to act, and a
 * direct call to the hook cannot show that. The actors therefore hold real
 * table-modify and page rights, so `process_datamap()` reaches core's own
 * update branch whenever the hook lets the record through — which is what
 * makes an unguarded write visible. Same reasoning, and the same fixture, as
 * {@see SecretTcaHookDisabledSecretTest}.
 */
#[CoversClass(SecretTcaHook::class)]
final class SecretTcaHookDeletedSecretTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    /** Page the secrets live on; both actors may edit and delete here. */
    private const PAGE_UID = 1;

    /**
     * Non-admin editor with table-modify rights and nothing else: not the
     * owner, in neither tier, holding no operation permission.
     */
    private const EDITOR_UID = 2;

    /** Non-admin who owns the seeded secrets, so canWrite() grants them. */
    private const OWNER_UID = 3;

    private const SEEDED_DESCRIPTION = 'seeded description';

    private const SEEDED_CONTEXT = 'production';

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_disabled_secret.csv';

    /** Logged in per test — the scenarios need different actors. */
    protected ?int $backendUserUid = null;

    /**
     * The finding itself, stated at its strongest: the OWNER submits the
     * change, so the per-secret tier would grant it on a live record. It must
     * still not land, because the vault no longer holds the record to
     * authorize the write against.
     */
    #[Test]
    public function aDatamapAgainstASoftDeletedSecretDoesNotLand(): void
    {
        $this->setUpBackendUser(self::OWNER_UID);
        [$uid, $identifier] = $this->seedSecret(deleted: true);

        $this->submitUpdate($uid, ['description' => 'rewritten on a tombstone']);

        self::assertSame(
            self::SEEDED_DESCRIPTION,
            $this->readDescription($uid),
            'A soft-deleted secret must not be rewritten through the datamap.',
        );
        self::assertSame(
            1,
            $this->countAudit($identifier, AuditAction::AccessDenied->value, 0),
            'The refusal must be recorded under the identifier it is about.',
        );
    }

    /**
     * The second gate, on a column only it protects. `context` is the one
     * privileged column the TCA does NOT mark `exclude`, so DataHandler's own
     * field-permission layer lets it through and the privileged-column policy
     * is the only thing standing in front of it — which is exactly what makes
     * it the honest subject here. (`frontend_accessible`, `owner_uid` and the
     * rest are excludefields, and this fixture's group holds no
     * `non_exclude_fields`, so a test on one of those would pass on core's
     * behalf whatever the policy did.)
     */
    #[Test]
    public function aPrivilegedColumnOfASoftDeletedSecretStaysUnchanged(): void
    {
        $this->setUpBackendUser(self::OWNER_UID);
        [$uid] = $this->seedSecret(deleted: true);

        $this->submitUpdate($uid, ['context' => 'staging']);

        self::assertSame(
            self::SEEDED_CONTEXT,
            $this->readContext($uid),
            'A soft-deleted secret must not be re-bucketed into another context.',
        );
    }

    /**
     * The refusal is a property of the record's state, not of the actor: an
     * editor with no vault standing at all is refused for the same reason and
     * gets no further than the owner did.
     */
    #[Test]
    public function anEditorWithoutVaultStandingCannotRewriteASoftDeletedSecret(): void
    {
        $this->setUpBackendUser(self::EDITOR_UID);
        [$uid] = $this->seedSecret(deleted: true);

        $this->submitUpdate($uid, ['description' => 'rewritten by someone else']);

        self::assertSame(
            self::SEEDED_DESCRIPTION,
            $this->readDescription($uid),
            'A soft-deleted secret must not be rewritten by an actor the vault never authorized.',
        );
    }

    /**
     * The regression guard the fix has to survive: an ordinary edit of a live
     * secret by its owner still lands, and is still audited as the metadata
     * update it is. Failing closed on an unresolvable record must not cost the
     * resolvable case anything.
     */
    #[Test]
    public function anOrdinaryUpdateOfALiveSecretStillLandsAndIsAudited(): void
    {
        $this->setUpBackendUser(self::OWNER_UID);
        [$uid, $identifier] = $this->seedSecret();

        $this->submitUpdate($uid, ['description' => 'edited by the owner']);

        self::assertSame(
            'edited by the owner',
            $this->readDescription($uid),
            'A live secret must still be editable by its owner.',
        );
        self::assertSame(
            1,
            $this->countAudit($identifier, AuditAction::MetadataUpdate->value, 1),
            'The landed edit must be audited as a metadata update.',
        );
        self::assertSame(
            0,
            $this->countAudit($identifier, AuditAction::AccessDenied->value, 0),
            'An authorized edit must not be recorded as a denial.',
        );
    }

    /**
     * Disabled is not deleted, and the boundary this change draws runs exactly
     * between them: the write gates resolve a disabled record through the
     * disabled-visible lookup, so its owner keeps every administrative edit
     * that last round established — while the tests above show a deleted one
     * is refused. A disabled secret stays administrable; a deleted one is gone.
     */
    #[Test]
    public function aDisabledSecretIsStillEditableByItsOwner(): void
    {
        $this->setUpBackendUser(self::OWNER_UID);
        [$uid, $identifier] = $this->seedSecret(hidden: true);

        $this->submitUpdate($uid, ['description' => 'edited while out of service']);

        self::assertSame(
            'edited while out of service',
            $this->readDescription($uid),
            'A disabled secret must stay administrable by its owner.',
        );
        self::assertSame(
            0,
            $this->countAudit($identifier, AuditAction::AccessDenied->value, 0),
            'Editing a disabled secret one owns is not a denial.',
        );
    }

    /**
     * A uid with no row at all is refused too, but it has no identifier — so
     * the refusal must not invent one. Nothing may enter the tamper-evident
     * chain under an empty or guessed identifier; the DataHandler log carries
     * the uid instead.
     */
    #[Test]
    public function anAbsentRecordIsRefusedWithoutWritingAnAnonymousAuditEntry(): void
    {
        $this->setUpBackendUser(self::OWNER_UID);
        $before = $this->countAllAudit();

        $this->submitUpdate(2147483647, ['description' => 'no such record']);

        self::assertSame(
            $before,
            $this->countAllAudit(),
            'A refusal with no identifier must not append to the audit chain.',
        );
    }

    /**
     * Run the update as FormEngine would, through the whole DataHandler —
     * core's own permission checks included, so that a hook which lets the
     * record through really does leave core to write it.
     *
     * @param array<string, mixed> $fields
     */
    private function submitUpdate(int $uid, array $fields): void
    {
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->BE_USER = $GLOBALS['BE_USER'];
        $dataHandler->start([self::SECRET_TABLE => [$uid => $fields]], []);
        $dataHandler->process_datamap();
    }

    /**
     * @return array{int, string} The new secret UID and its identifier
     */
    private function seedSecret(bool $deleted = false, bool $hidden = false): array
    {
        $identifier = 'tombstone_' . bin2hex(random_bytes(4));
        $connection = $this->getConnectionPool()->getConnectionForTable(self::SECRET_TABLE);
        $connection->insert(self::SECRET_TABLE, [
            'pid' => self::PAGE_UID,
            'identifier' => $identifier,
            'description' => self::SEEDED_DESCRIPTION,
            'context' => self::SEEDED_CONTEXT,
            'owner_uid' => self::OWNER_UID,
            'frontend_accessible' => 0,
            'hidden' => $hidden ? 1 : 0,
            'deleted' => $deleted ? 1 : 0,
        ]);

        return [(int) $connection->lastInsertId(), $identifier];
    }

    private function readDescription(int $uid): string
    {
        $description = $this->readColumn($uid, 'description');

        return \is_string($description) ? $description : '';
    }

    private function readContext(int $uid): string
    {
        $context = $this->readColumn($uid, 'context');

        return \is_string($context) ? $context : '';
    }

    private function readColumn(int $uid, string $column): mixed
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::SECRET_TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        return $queryBuilder
            ->select($column)
            ->from(self::SECRET_TABLE)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();
    }

    private function countAudit(string $identifier, string $action, int $success): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::AUDIT_TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $count = $queryBuilder
            ->count('uid')
            ->from(self::AUDIT_TABLE)
            ->where(
                $queryBuilder->expr()->eq('secret_identifier', $queryBuilder->createNamedParameter($identifier)),
                $queryBuilder->expr()->eq('action', $queryBuilder->createNamedParameter($action)),
                $queryBuilder->expr()->eq('success', $queryBuilder->createNamedParameter($success, Connection::PARAM_INT)),
            )
            ->executeQuery()
            ->fetchOne();

        return is_numeric($count) ? (int) $count : 0;
    }

    private function countAllAudit(): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::AUDIT_TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $count = $queryBuilder
            ->count('uid')
            ->from(self::AUDIT_TABLE)
            ->executeQuery()
            ->fetchOne();

        return is_numeric($count) ? (int) $count : 0;
    }
}
