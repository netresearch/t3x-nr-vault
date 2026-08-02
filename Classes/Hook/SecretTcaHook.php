<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Hook;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Throwable;
use TYPO3\CMS\Backend\Utility\BackendUtility;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\DataHandling\DataHandler;

/**
 * DataHandler hook for tx_nrvault_secret TCA operations.
 *
 * Handles:
 * - Identifier immutability (prevent changes after creation)
 * - Secret encryption on save (secret_input field)
 * - Audit logging for metadata changes
 * - FormEngine integration with VaultService
 */
final class SecretTcaHook
{
    private const TABLE = 'tx_nrvault_secret';

    /**
     * Scalar ACL columns whose submitted value is reverted to the stored
     * value for a non-owner, non-admin editor (CWE-639/CWE-269). These are
     * plain row columns, so the prior value can be read back and re-written.
     *
     * @var list<string>
     */
    private const PRIVILEGED_SCALAR_COLUMNS = [
        'owner_uid',
        'frontend_accessible',
        'scope_pid',
    ];

    /**
     * Privileged ACL columns backed by MM relation tables, mapped to the MM
     * table holding their relations. The row column only holds the relation
     * COUNT, so the effective ACL cannot be restored by writing that column
     * back — the MM rows themselves are the source of truth
     * (`SecretRepository::loadGroupsForSecret()`).
     *
     * Two consequences follow, and both are implemented below:
     *  - An unauthorized change is dropped from $fieldArray entirely
     *    (see enforcePrivilegedColumnPolicy()), leaving DataHandler to keep
     *    the existing MM relations rather than replacing them.
     *  - An authorized change that later fails its audit write is rolled
     *    back by restoring the snapshotted MM rows, not just the count
     *    column (see snapshotMmRelations()/restoreMmRelations()).
     *
     * The table names are duplicated from SecretRepository rather than read
     * from $GLOBALS['TCA'] so the rollback keeps working on the CLI/scheduler
     * paths, where the hook may run before TCA is fully built.
     *
     * @var array<string, string>
     */
    private const PRIVILEGED_MM_COLUMNS = [
        'allowed_groups' => 'tx_nrvault_secret_begroups_mm',
        'write_groups' => 'tx_nrvault_secret_writegroups_mm',
    ];

    /**
     * Pending secrets to store after database operations.
     *
     * @var array<string, mixed> Map of temporary ID => secret value
     */
    private array $pendingSecrets = [];

    /**
     * Record UIDs whose delete command was fully handled in
     * processCmdmap_preProcess() — either performed through
     * VaultService::delete() (ACL, operation permission and compensated audit
     * included) or refused. Both outcomes must make core skip its own
     * deleteAction in processCmdmap(). Entries are consumed (unset) when the
     * cancel is applied so a DI-shared hook instance cannot leak a stale
     * entry across DataHandler runs.
     *
     * @var array<int, true>
     */
    private array $handledDeletions = [];

    /**
     * Original values of the real columns a datamap UPDATE submits, captured
     * in processDatamap_preProcessFieldArray() keyed by record id. Used by
     * the compensating rollback when the metadata-update audit write fails:
     * the mutation and its audit entry are all-or-nothing (SEC-3), mirroring
     * VaultService::compensateAuditFailure().
     *
     * @var array<string, array<string, mixed>>
     */
    private array $originalMetadata = [];

    /**
     * Pre-change MM relation rows for every privileged MM column a datamap
     * UPDATE submits, keyed by record id and then by MM table. Captured in
     * processDatamap_preProcessFieldArray() — DataHandler writes the new MM
     * rows during checkValue(), i.e. before this hook's
     * afterDatabaseOperations() runs, so by rollback time the widened set is
     * already committed and only a snapshot taken beforehand can restore it.
     *
     * An entry with an empty row list is meaningful: it records "this tier
     * had no groups", which the rollback restores by deleting the rows the
     * failed change added.
     *
     * @var array<string, array<string, list<array{uid_foreign: int, sorting: int, sorting_foreign: int}>>>
     */
    private array $originalMmRelations = [];

    /**
     * UIDs whose record creation was rolled back because the creation audit
     * write failed, awaiting the MM purge in
     * processDatamap_afterAllOperations().
     *
     * For a 'new' record DataHandler defers the MM writes to
     * $dbAnalysisStore (the uid is unknown during checkValue) and flushes
     * them in dbAnalysisStoreExec() — after every afterDatabaseOperations()
     * hook has run. The row is therefore deleted BEFORE its MM rows are
     * written, and without this purge the reverted creation would leave
     * orphaned relation rows pointing at a uid that no longer exists.
     *
     * @var array<int, true>
     */
    private array $revertedCreations = [];

    public function __construct(
        private readonly VaultServiceInterface $vaultService,
        private readonly AuditLogServiceInterface $auditService,
        private readonly AccessControlServiceInterface $accessControlService,
        private readonly SecretRepositoryInterface $secretRepository,
        /**
         * Needed for the compensating rollback of a metadata change whose
         * audit write failed. Optional so pre-existing unit-test
         * constructions keep working; without it the rollback degrades to
         * logging the inconsistency in the DataHandler log.
         */
        private readonly ?ConnectionPool $connectionPool = null,
    ) {}

    /**
     * Called before database operations.
     * Prevents identifier changes on existing records.
     *
     * @param array<string, mixed> $fieldArray
     */
    public function processDatamap_preProcessFieldArray(// NOSONAR: TYPO3 DataHandler hook method name (fixed API contract)
        array &$fieldArray,
        string $table,
        string|int $id,
        DataHandler $dataHandler,
    ): void {
        if ($table !== self::TABLE) {
            return;
        }

        // Authorize privileged ACL columns BEFORE DataHandler persists them.
        // The VaultService coercion (resolveOwnerUid/resolveFrontendAccessible)
        // only runs on the programmatic store($options) path; the FormEngine
        // path writes the raw columns directly, so the gate must live here.
        $this->enforcePrivilegedColumnPolicy($fieldArray, $id, $dataHandler);

        // For existing records, prevent identifier changes
        if (!str_starts_with((string) $id, 'NEW') && isset($fieldArray['identifier'])) {
            // Get the original identifier
            $originalRecord = $this->readRecord((int) $id, ['identifier']);
            $originalIdentifier = \is_string($originalRecord['identifier'] ?? null) ? $originalRecord['identifier'] : '';
            if ($originalRecord !== null && $fieldArray['identifier'] !== $originalIdentifier) {
                // Identifier change attempted - revert to original
                /** @phpstan-ignore method.internal */
                $dataHandler->log(
                    self::TABLE,
                    (int) $id,
                    2,
                    null,
                    1,
                    'Vault secret identifier cannot be changed after creation',
                );
                $fieldArray['identifier'] = $originalIdentifier;
            }
        }

        // Handle owner_uid - convert group format to simple uid
        if (isset($fieldArray['owner_uid']) && \is_string($fieldArray['owner_uid'])) {
            // Format from group field: "be_users_123" or just "123"
            $fieldArray['owner_uid'] = $this->extractUidFromGroupValue($fieldArray['owner_uid']);
        }

        // Handle scope_pid - convert group format to simple uid
        if (isset($fieldArray['scope_pid']) && \is_string($fieldArray['scope_pid']) && str_contains($fieldArray['scope_pid'], 'pages')) {
            $fieldArray['scope_pid'] = $this->extractUidFromGroupValue($fieldArray['scope_pid']);
        }

        // Handle secret_input field - extract secret value for later processing
        // The actual encryption happens in afterDatabaseOperations when we have the identifier
        if (isset($fieldArray['secret_input']) && $fieldArray['secret_input'] !== '') {
            // Store the secret temporarily keyed by record id
            $this->pendingSecrets[(string) $id] = $fieldArray['secret_input'];
        }

        // Always remove secret_input from fieldArray - it's not a real database column
        unset($fieldArray['secret_input']);

        // Capture the pre-change state of everything this UPDATE submits, for
        // the compensating rollback should the metadata-update audit write
        // fail in afterDatabaseOperations (SEC-3 atomicity): the real column
        // values, plus the MM relation rows behind the privileged ACL columns
        // (whose column value is only a count). Both snapshots are taken here
        // because DataHandler has overwritten neither yet — checkValue() and
        // updateDB() both run after this hook.
        if (!str_starts_with((string) $id, 'NEW') && $fieldArray !== []) {
            $columns = $this->submittedColumns($fieldArray);
            if ($columns !== []) {
                $original = $this->readRecord((int) $id, $columns);
                if ($original !== null) {
                    $this->originalMetadata[(string) $id] = array_intersect_key(
                        $original,
                        array_flip($columns),
                    );
                }

                // Assigned unconditionally, empty result included: a save that
                // submits no ACL column must clear any snapshot a previous
                // save left behind on a DI-shared instance, never inherit it
                // and "restore" a state two edits old.
                $this->originalMmRelations[(string) $id] = $this->snapshotMmRelations((int) $id, $columns);
            }
        }
    }

    /**
     * Called after database operations.
     * Handles secret encryption and audit logging.
     *
     * @param array<string, mixed> $fieldArray
     */
    public function processDatamap_afterDatabaseOperations(// NOSONAR: TYPO3 DataHandler hook method name (fixed API contract)
        string $status,
        string $table,
        string|int $id,
        array $fieldArray,
        DataHandler $dataHandler,
    ): void {
        if ($table !== self::TABLE) {
            return;
        }

        // Get actual UID for new records
        $uidRaw = $id;
        $originalId = (string) $id;
        if ($status === 'new') {
            $uidRaw = $dataHandler->substNEWwithIDs[$id] ?? $id;
        }
        $uid = is_numeric($uidRaw) ? (int) $uidRaw : 0;

        // Get the secret identifier for operations
        $record = $this->readRecord($uid, ['identifier', 'owner_uid', 'allowed_groups', 'scope_pid']);
        if ($record === null) {
            return;
        }

        $identifier = \is_string($record['identifier'] ?? null) ? $record['identifier'] : '';
        $secretStored = false;

        // Handle pending secret encryption
        if (isset($this->pendingSecrets[$originalId])) {
            $secretValue = $this->pendingSecrets[$originalId];
            // Drop the property's copy; $secretValue keeps the only remaining
            // reference and is wiped with sodium_memzero() in the finally block
            // below, once it has been consumed. Wiping the property here would,
            // via copy-on-write, also zero $secretValue before it is stored —
            // so the cleartext is scrubbed (CWE-316) without corrupting it.
            unset($this->pendingSecrets[$originalId]);

            // Ensure secretValue is a string
            if (!\is_string($secretValue)) {
                $secretValue = '';
            }

            if ($secretValue !== '') {
                try {
                    // Owner/group/scope ACL is persisted via the tx_nrvault_secret
                    // TCA columns (owner_uid, allowed_groups, scope_pid) by DataHandler
                    // itself, so no store() options are needed here. (Previously this
                    // passed ownerUid/allowedGroups/scopePid keys that VaultService
                    // never reads — they read owner/groups/scope_pid — so they were
                    // silently dropped; removed to avoid the impression they apply.)
                    if ($status === 'new') {
                        // New record - store the secret
                        $this->vaultService->store($identifier, $secretValue);
                        $secretStored = true;
                    } else {
                        // Existing record - rotate the secret
                        $this->vaultService->rotate($identifier, $secretValue, 'FormEngine edit');
                        $secretStored = true;
                    }
                } catch (Throwable $e) {
                    /** @phpstan-ignore method.internal */
                    $dataHandler->log(
                        self::TABLE,
                        $uid,
                        2,
                        null,
                        1,
                        'Failed to store secret: ' . $e->getMessage(),
                    );
                } finally {
                    // Scrub the local plaintext copy (success or failure).
                    // $secretValue is a guaranteed non-empty string in this
                    // branch, so no emptiness guard is needed.
                    sodium_memzero($secretValue);
                }
            }
        }

        // Audit strategy: value mutations (the store()/rotate() above) are
        // audited by VaultService itself, with a compensating rollback when
        // the audit write fails — the hook must not add a second (or worse, a
        // premature "success") entry for them. The hook stays responsible for
        // what the service never sees: the creation of a value-less record
        // and metadata-only column changes. Both are all-or-nothing here as
        // well (SEC-3): if the audit write fails, the database change is
        // reverted so no mutation persists without a tamper-evident record.
        $originalMetadata = $this->originalMetadata[$originalId] ?? null;
        $originalMmRelations = $this->originalMmRelations[$originalId] ?? [];
        unset($this->originalMetadata[$originalId], $this->originalMmRelations[$originalId]);

        if ($status === 'new') {
            if (!$secretStored) {
                $this->auditRecordCreationOrCompensate($identifier, $uid, $fieldArray, $dataHandler);
            }

            return;
        }

        $changedColumns = $this->submittedColumns($fieldArray);
        if ($changedColumns === []) {
            return;
        }

        $this->auditMetadataUpdateOrCompensate(
            $identifier,
            $uid,
            $changedColumns,
            $originalMetadata,
            $originalMmRelations,
            $dataHandler,
        );
    }

    /**
     * Called once every datamap operation — including DataHandler's deferred
     * MM writes (dbAnalysisStoreExec()) — has finished. Purges the relation
     * rows those deferred writes just created for records whose creation this
     * hook rolled back, so a reverted create leaves no orphaned MM rows
     * behind (see $revertedCreations).
     *
     * Cleaning up here rather than filtering DataHandler's public-but-internal
     * $dbAnalysisStore keeps the fix on a documented extension point, and it
     * is idempotent: deleting by uid_local removes whatever was written for
     * that uid, in whichever order the store was flushed.
     *
     * Entries are consumed so a DI-shared hook instance cannot carry a stale
     * uid into a later DataHandler run (same discipline as $pendingSecrets).
     */
    public function processDatamap_afterAllOperations(DataHandler $dataHandler): void// NOSONAR: TYPO3 DataHandler hook method name (fixed API contract)
    {
        $revertedUids = array_keys($this->revertedCreations);
        $this->revertedCreations = [];

        foreach ($revertedUids as $uid) {
            if ($this->purgeMmRelations($uid)) {
                continue;
            }

            /** @phpstan-ignore method.internal */
            $dataHandler->log(
                self::TABLE,
                $uid,
                2,
                null,
                1,
                'Vault secret ACL relations of the reverted record creation could not be purged; '
                . 'manual reconciliation required.',
            );
        }
    }

    /**
     * Called before a command (here: delete) is processed. Enforces the vault
     * delete ACL (F5 / CWE-862) and records the audit entry.
     *
     * DataHandler's own table permissions are NOT the vault ACL, so the gate
     * lives here — mirroring VaultService::delete()'s canDelete() check (the
     * most restrictive tier: owner / admin / system maintainer only, ADR-005).
     * A denied delete is flagged for cancellation in processCmdmap() and logged
     * as access_denied; only an authorized delete records a delete success.
     *
     * The extra $value/$dataHandler parameters are supplied by core
     * (DataHandler passes six positional args); they are optional so the
     * pre-existing three-argument unit-test calls still bind.
     */
    public function processCmdmap_preProcess(// NOSONAR: TYPO3 DataHandler hook method name (fixed API contract)
        string $command,
        string $table,
        string|int $id,
        mixed $value = null,
        ?DataHandler $dataHandler = null,
    ): void {
        if ($table !== self::TABLE || $command !== 'delete') {
            return;
        }

        $uid = is_numeric($id) ? (int) $id : 0;
        $secret = $this->secretRepository->findByUid($uid);
        if (!$secret instanceof Secret) {
            return;
        }

        // The delete is performed THROUGH the service, so the per-secret tier
        // (owner / admin / system maintainer, CWE-862), the secret.delete
        // operation permission, the audit entry and its compensating rollback
        // (SEC-3: no delete may persist without an audit record) all apply
        // exactly as on the programmatic path. Core's own deleteAction is
        // skipped in processCmdmap() in every outcome: on success the service
        // already soft-deleted the record, on refusal it must survive.
        $this->handledDeletions[$uid] = true;

        try {
            $this->vaultService->delete($secret->getIdentifier(), 'Deleted via FormEngine');
        } catch (AccessDeniedException) {
            // The service audited the denial (access_denied entry).
            /** @phpstan-ignore method.internal */
            $dataHandler?->log(
                self::TABLE,
                $uid,
                2,
                null,
                1,
                'Vault secret deletion requires being its owner or an administrator AND holding the secret.delete permission',
            );
        } catch (Throwable $e) {
            // Audit-write failure (the service reverted the delete) or any
            // other vault error: the record is preserved.
            /** @phpstan-ignore method.internal */
            $dataHandler?->log(
                self::TABLE,
                $uid,
                2,
                null,
                1,
                'Vault delete failed: ' . $e->getMessage() . ' — the record was preserved.',
            );
        }
    }

    /**
     * Makes core skip its own deleteAction() for every delete command the
     * hook handled in processCmdmap_preProcess() — a successful service
     * delete already soft-deleted the record, a refused one must leave it
     * untouched. (DataHandler runs this hook before the command switch.)
     *
     * The flag is consumed so a DI-shared hook instance cannot leak a stale
     * entry into a later DataHandler run (same discipline as
     * $pendingSecrets).
     */
    public function processCmdmap(// NOSONAR: TYPO3 DataHandler hook method name (fixed API contract)
        string $command,
        string $table,
        string|int $id,
        mixed $value,
        bool &$commandIsProcessed,
        DataHandler $dataHandler,
        mixed $pasteUpdate,
    ): void {
        if ($table !== self::TABLE || $command !== 'delete') {
            return;
        }

        $uid = is_numeric($id) ? (int) $id : 0;
        if (($this->handledDeletions[$uid] ?? false) === true) {
            unset($this->handledDeletions[$uid]);
            $commandIsProcessed = true;
        }
    }

    /**
     * Audit the FormEngine creation of a record that carries no secret value
     * (a value-bearing create is audited by VaultService::store()). If the
     * audit write fails, the just-created row is removed again — a record
     * must not exist without its audit entry. Its ACL relation rows are
     * purged in processDatamap_afterAllOperations(), because DataHandler
     * writes them only after this hook has run.
     *
     * @param array<string, mixed> $fieldArray
     */
    private function auditRecordCreationOrCompensate(
        string $identifier,
        int $uid,
        array $fieldArray,
        DataHandler $dataHandler,
    ): void {
        try {
            $this->auditService->log(
                $identifier,
                AuditAction::Create->value,
                true,
                null,
                'FormEngine create: ' . implode(', ', $this->submittedColumns($fieldArray)),
            );
        } catch (Throwable $e) {
            $reverted = $this->revertRow($uid, null);
            if ($reverted) {
                // The deferred MM writes for this uid have not run yet; queue
                // the purge for after dbAnalysisStoreExec(). Only a genuinely
                // removed row gets queued — if the revert failed the record
                // still exists and its relations rightfully belong to it.
                $this->revertedCreations[$uid] = true;
            }

            /** @phpstan-ignore method.internal */
            $dataHandler->log(
                self::TABLE,
                $uid,
                1,
                null,
                1,
                'Vault audit logging failed: ' . $e->getMessage() . ' — the record creation was '
                . ($reverted ? 'reverted (no mutation may persist without an audit entry).' : 'NOT revertible; manual reconciliation required.'),
            );
        }
    }

    /**
     * Audit a metadata-only column change. If the audit write fails, the
     * captured pre-change state is written back so the change does not
     * persist unaudited: the scalar column values AND the MM relation rows
     * behind the privileged ACL columns.
     *
     * Restoring the count column alone would be worse than not reverting at
     * all — it would leave the row claiming the old number of groups while
     * the MM tables still granted the widened set, and the effective ACL is
     * read from the MM tables. The revert therefore only counts as done when
     * both halves succeeded; a partial result is reported as
     * "NOT revertible" so the inconsistency is surfaced, not hidden.
     *
     * @param list<string> $changedColumns
     * @param array<string, mixed>|null $originalMetadata
     * @param array<string, list<array{uid_foreign: int, sorting: int, sorting_foreign: int}>> $originalMmRelations
     */
    private function auditMetadataUpdateOrCompensate(
        string $identifier,
        int $uid,
        array $changedColumns,
        ?array $originalMetadata,
        array $originalMmRelations,
        DataHandler $dataHandler,
    ): void {
        try {
            $this->auditService->log(
                $identifier,
                AuditAction::MetadataUpdate->value,
                true,
                null,
                'FormEngine edit: ' . implode(', ', $changedColumns),
            );
        } catch (Throwable $e) {
            $reverted = $originalMetadata !== null
                && $originalMetadata !== []
                && $this->revertRow($uid, $originalMetadata);

            // Restore the relation rows even when the row revert failed, so
            // the effective ACL stops granting the unaudited widening either
            // way; $reverted stays false so the log reports the row half.
            if ($originalMmRelations !== [] && !$this->restoreMmRelations($uid, $originalMmRelations)) {
                $reverted = false;
            }

            // A changed ACL column whose tier is absent from the snapshot
            // means the pre-change read failed: the relations cannot be
            // restored, so the change must not be reported as reverted.
            foreach (self::PRIVILEGED_MM_COLUMNS as $column => $mmTable) {
                if (\in_array($column, $changedColumns, true) && !\array_key_exists($mmTable, $originalMmRelations)) {
                    $reverted = false;
                }
            }

            /** @phpstan-ignore method.internal */
            $dataHandler->log(
                self::TABLE,
                $uid,
                2,
                null,
                1,
                'Vault audit logging failed: ' . $e->getMessage() . ' — the metadata change was '
                . ($reverted ? 'reverted (no mutation may persist without an audit entry).' : 'NOT revertible; manual reconciliation required.'),
            );
        }
    }

    /**
     * The string column names a datamap submits. An explicit loop rather
     * than array_filter with a first-class callable: every PHPStan version
     * in the CI matrix narrows this form to list<string>.
     *
     * @param array<string, mixed> $fieldArray
     *
     * @return list<string>
     */
    private function submittedColumns(array $fieldArray): array
    {
        $columns = [];
        foreach (array_keys($fieldArray) as $column) {
            if (\is_string($column)) {
                $columns[] = $column;
            }
        }

        return $columns;
    }

    /**
     * Read the requested columns of one secret row, soft-deleted rows
     * excluded — the semantics of BackendUtility::getRecord(), but through
     * the injected ConnectionPool.
     *
     * The static call is avoided because its internals differ across the
     * supported TYPO3 range: v13 gates on `$GLOBALS['TCA'][$table]`, v14 on
     * a TcaSchemaFactory resolved through GeneralUtility. That made this
     * hook's record reads depend on which core version was installed. The
     * `deleted = 0` predicate is spelled out for the same reason — core's
     * DeletedRestriction resolves the schema on v14 as well; it matches the
     * restriction set getRecord() applies (removeAll() plus DeletedRestriction).
     *
     * Without a ConnectionPool (construction without DI) the static call is
     * kept so those callers keep working unchanged.
     *
     * @param list<string> $columns
     *
     * @return array<string, mixed>|null
     */
    private function readRecord(int $uid, array $columns): ?array
    {
        if ($uid < 1) {
            return null;
        }

        if (!$this->connectionPool instanceof ConnectionPool) {
            $record = BackendUtility::getRecord(self::TABLE, $uid, implode(',', $columns));
            if ($record === null) {
                return null;
            }

            // Core annotates the return as a bare `array`; re-key so the
            // string-keyed row this method promises is established rather
            // than assumed. An explicit loop, like submittedColumns().
            $row = [];
            foreach ($record as $column => $value) {
                $row[(string) $column] = $value;
            }

            return $row;
        }

        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(self::TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        $row = $queryBuilder
            ->select(...$columns)
            ->from(self::TABLE)
            ->where(
                $queryBuilder->expr()->eq(
                    'uid',
                    $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT),
                ),
                $queryBuilder->expr()->eq(
                    'deleted',
                    $queryBuilder->createNamedParameter(0, Connection::PARAM_INT),
                ),
            )
            ->executeQuery()
            ->fetchAssociative();

        return $row === false ? null : $row;
    }

    /**
     * Write the compensating revert: `null` removes the just-created row,
     * a value map restores the captured pre-change column values.
     *
     * @param array<string, mixed>|null $originalValues
     */
    private function revertRow(int $uid, ?array $originalValues): bool
    {
        if ($uid <= 0 || !$this->connectionPool instanceof ConnectionPool) {
            return false;
        }

        try {
            $connection = $this->connectionPool->getConnectionForTable(self::TABLE);
            if ($originalValues === null) {
                $connection->delete(self::TABLE, ['uid' => $uid]);

                return true;
            }
            if ($originalValues === []) {
                return false;
            }
            $connection->update(self::TABLE, $originalValues, ['uid' => $uid]);

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Read the current MM relation rows of every privileged ACL column among
     * $submittedColumns, so a failed audit write can restore them verbatim.
     *
     * `sorting` is carried along because it is what orders the group list in
     * the FormEngine field and in
     * `SecretRepository::loadGroupsForSecret()` — a rollback that restored
     * the same groups in a different order would still alter the record.
     *
     * @param list<string> $submittedColumns
     *
     * @return array<string, list<array{uid_foreign: int, sorting: int, sorting_foreign: int}>>
     */
    private function snapshotMmRelations(int $uid, array $submittedColumns): array
    {
        if ($uid <= 0 || !$this->connectionPool instanceof ConnectionPool) {
            return [];
        }

        $snapshot = [];

        foreach (self::PRIVILEGED_MM_COLUMNS as $column => $mmTable) {
            if (!\in_array($column, $submittedColumns, true)) {
                continue;
            }

            try {
                $queryBuilder = $this->connectionPool->getQueryBuilderForTable($mmTable);
                $rows = $queryBuilder
                    ->select('uid_foreign', 'sorting', 'sorting_foreign')
                    ->from($mmTable)
                    ->where($queryBuilder->expr()->eq(
                        'uid_local',
                        $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT),
                    ))
                    ->orderBy('sorting', 'ASC')
                    ->executeQuery()
                    ->fetchAllAssociative();
            } catch (Throwable) {
                // An unreadable tier cannot be restored. Skip it rather than
                // recording an empty snapshot, which the rollback would
                // "restore" by deleting the record's real relations.
                continue;
            }

            $snapshot[$mmTable] = array_map(
                static fn (array $row): array => [
                    'uid_foreign' => is_numeric($row['uid_foreign'] ?? null) ? (int) $row['uid_foreign'] : 0,
                    'sorting' => is_numeric($row['sorting'] ?? null) ? (int) $row['sorting'] : 0,
                    'sorting_foreign' => is_numeric($row['sorting_foreign'] ?? null) ? (int) $row['sorting_foreign'] : 0,
                ],
                $rows,
            );
        }

        return $snapshot;
    }

    /**
     * Write a snapshot taken by snapshotMmRelations() back: replace the
     * record's current relation rows in each snapshotted tier with the
     * captured ones. An empty captured list is honoured — it means the tier
     * held no groups before the change, so the rows the change added are
     * deleted and nothing is re-inserted.
     *
     * @param array<string, list<array{uid_foreign: int, sorting: int, sorting_foreign: int}>> $snapshot
     *
     * @return bool True only if every snapshotted tier was fully restored
     */
    private function restoreMmRelations(int $uid, array $snapshot): bool
    {
        if ($uid <= 0 || !$this->connectionPool instanceof ConnectionPool) {
            return false;
        }

        $restored = true;

        foreach ($snapshot as $mmTable => $rows) {
            try {
                $connection = $this->connectionPool->getConnectionForTable($mmTable);
                // Transactional per tier: without it, an insert failure after
                // the delete would leave the tier EMPTY — locking out the
                // legitimate groups, which is worse than the unaudited
                // widening the rollback set out to undo. On rollback the tier
                // keeps its current rows and the caller reports NOT revertible.
                $connection->transactional(static function () use ($connection, $mmTable, $uid, $rows): void {
                    $connection->delete($mmTable, ['uid_local' => $uid]);

                    foreach ($rows as $row) {
                        $connection->insert($mmTable, ['uid_local' => $uid, ...$row]);
                    }
                });
            } catch (Throwable) {
                // Keep going: restoring the remaining tiers narrows the
                // unaudited widening even when one tier cannot be repaired.
                $restored = false;
            }
        }

        return $restored;
    }

    /**
     * Delete every privileged ACL relation row pointing at $uid, in both
     * tiers. Used to clean up after a reverted record creation, whose MM
     * rows DataHandler writes only after the revert has already removed the
     * row they reference.
     *
     * @return bool True if both tiers were purged
     */
    private function purgeMmRelations(int $uid): bool
    {
        if ($uid <= 0 || !$this->connectionPool instanceof ConnectionPool) {
            return false;
        }

        $purged = true;

        foreach (self::PRIVILEGED_MM_COLUMNS as $mmTable) {
            try {
                $this->connectionPool
                    ->getConnectionForTable($mmTable)
                    ->delete($mmTable, ['uid_local' => $uid]);
            } catch (Throwable) {
                $purged = false;
            }
        }

        return $purged;
    }

    /**
     * Enforce that only the secret's owner (or an admin/system maintainer)
     * may set or change the privileged ACL columns: owner_uid,
     * frontend_accessible, scope_pid (scalar) and allowed_groups, write_groups
     * (MM relations). This is the write-path authorization layer for
     * CWE-639/CWE-269 — the TCA `exclude` flag is the complementary
     * form-permission layer.
     *
     * Policy (default-DENY for the ambiguous delegation case):
     *  - Admin / system maintainer: unrestricted (no coercion).
     *  - NEW record by a non-admin: owner_uid is forced to the current backend
     *    user (the submitted value is not trusted); the other privileged
     *    columns are left as submitted (a creator legitimately scopes the
     *    secret they own).
     *  - EXISTING record edited by the owner: unrestricted.
     *  - EXISTING record edited by a non-owner non-admin: every privileged
     *    column change is reverted (scalar columns) or dropped (MM columns),
     *    and the attempt is logged.
     *
     * @param array<string, mixed> $fieldArray
     */
    private function enforcePrivilegedColumnPolicy(
        array &$fieldArray,
        string|int $id,
        DataHandler $dataHandler,
    ): void {
        // Admins and system maintainers are trusted on this path. Non-backend
        // actors (CLI/scheduler/api) do not reach DataHandler form edits with a
        // BE user, so they are treated as non-privileged here and fall through
        // to the owner check (which yields actor UID 0 => not owner).
        if ($this->accessControlService->isCurrentActorAdmin()) {
            return;
        }

        $isNew = str_starts_with((string) $id, 'NEW');

        if ($isNew) {
            // A non-admin creator owns what they create: force owner_uid to the
            // current backend user. Set it unconditionally — owner_uid is an
            // excludefield, so a creator lacking that grant submits no value at
            // all, and a conditional set would leave the column 0 (ownerless),
            // locking the creator out of managing their own new secret.
            $fieldArray['owner_uid'] = $this->accessControlService->getCurrentActorUid();

            return;
        }

        $uid = is_numeric($id) ? (int) $id : 0;
        $original = $this->readRecord($uid, ['owner_uid', 'frontend_accessible', 'scope_pid']);
        if ($original === null) {
            return;
        }

        $storedOwner = is_numeric($original['owner_uid'] ?? null) ? (int) $original['owner_uid'] : 0;
        $actorUid = $this->accessControlService->getCurrentActorUid();

        // The owner may manage their own secret's ACL — but only while
        // holding the secret.manage_policy operation permission (separation
        // of duties: owning a secret and widening who may access it are
        // different privileges). An owner without the grant falls through to
        // the revert below, exactly like a non-owner.
        if ($actorUid !== 0 && $actorUid === $storedOwner
            && $this->accessControlService->isGranted(VaultPermission::SecretManagePolicy)
        ) {
            return;
        }

        // Non-owner, non-admin: revert any privileged change. Scalar columns
        // are restored to their stored value; MM columns are dropped so
        // DataHandler leaves the existing relation rows untouched.
        $reverted = false;

        foreach (self::PRIVILEGED_SCALAR_COLUMNS as $column) {
            if (!\array_key_exists($column, $fieldArray)) {
                continue;
            }
            // Group fields (owner_uid, scope_pid) arrive as "be_users_12" /
            // "pages_100" strings while the stored value is an int; normalise
            // before comparing so an unchanged ACL on an ordinary save by a
            // non-owner is not treated as tampering (which would revert it and
            // log a spurious warning). frontend_accessible is already 0/1.
            $submitted = $fieldArray[$column];
            $submittedStr = \is_scalar($submitted) ? (string) $submitted : '';
            $submittedUid = ($column === 'owner_uid' || $column === 'scope_pid')
                ? $this->extractUidFromGroupValue($submittedStr)
                : (int) $submittedStr;
            $storedUid = is_numeric($original[$column] ?? null) ? (int) $original[$column] : 0;
            if ($submittedUid === $storedUid) {
                continue;
            }
            $fieldArray[$column] = $original[$column] ?? null;
            $reverted = true;
        }

        foreach (array_keys(self::PRIVILEGED_MM_COLUMNS) as $column) {
            if (!\array_key_exists($column, $fieldArray)) {
                continue;
            }
            // MM-backed group field: the row column holds only the relation
            // count, so it cannot be reverted by writing a value back. Drop the
            // submitted value entirely — DataHandler then preserves the
            // existing MM relations instead of replacing them.
            unset($fieldArray[$column]);
            $reverted = true;
        }

        if ($reverted) {
            /** @phpstan-ignore method.internal */
            $dataHandler->log(
                self::TABLE,
                $uid,
                2,
                null,
                1,
                'Vault secret ACL columns can only be changed by an administrator or by the secret owner holding the secret.manage_policy permission',
            );
        }
    }

    /**
     * Extract UID from group field value format.
     *
     * @param string $value Value like "be_users_123" or "123"
     *
     * @return int The extracted UID
     */
    private function extractUidFromGroupValue(string $value): int
    {
        // Handle format: "table_uid" (e.g., "be_users_123")
        if (preg_match('/_(\d+)$/', $value, $matches)) {
            return (int) $matches[1];
        }

        // Handle simple numeric value
        return (int) $value;
    }
}
