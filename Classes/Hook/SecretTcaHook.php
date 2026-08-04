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
 * - Create authorization (secret.create, before the row is inserted)
 * - Update authorization (the per-secret write ACL, before anything is written),
 *   refusing outright a datamap whose target the vault cannot resolve — a
 *   soft-deleted secret or none at all (see refuseUnresolvableTarget())
 * - Identifier immutability (prevent changes after creation)
 * - Secret encryption on save (secret_input field)
 * - Audit logging for metadata changes
 * - Delete authorization (the vault delete ACL, performed through VaultService)
 * - Refusal of the cmdmap commands this table does not support (see
 *   REFUSED_COMMANDS: undelete, copy, move)
 * - FormEngine integration with VaultService
 */
final class SecretTcaHook
{
    private const TABLE = 'tx_nrvault_secret';

    /**
     * Privileged scalar columns submitted as a FormEngine group reference
     * ("be_users_12", "pages_100"), so the comparison against the stored
     * integer has to extract the uid first.
     *
     * @var list<string>
     */
    private const PRIVILEGED_GROUP_COLUMNS = [
        'owner_uid',
        'scope_pid',
    ];

    /**
     * The remaining privileged scalar columns. Kept apart from the group
     * references only because they normalise differently for the
     * change comparison (see normalizeForComparison()); the policy applied
     * to them is identical.
     *
     * Why each one is privileged — i.e. needs `secret.manage_policy` on top
     * of write access to the secret — rather than merely write-gated:
     *
     *  - `frontend_accessible` flips a secret from ACL-gated to readable by
     *    any frontend request.
     *  - `hidden` is the column `SecretsController::toggleAction()` already
     *    gates on secret.manage_policy; leaving the FormEngine path open
     *    would make that gate bypassable by editing the record instead of
     *    pressing the button.
     *  - `expires_at` is honoured at runtime (`Secret::isExpired()` →
     *    `VaultService` throws `SecretExpiredException`), so backdating it
     *    denies the secret to every consumer and zeroing it revives a
     *    deliberately retired one. Availability, not content.
     *  - `metadata` is machine-consumed provenance: `OrphanCleanupTask`
     *    reads table/field/uid straight out of it to decide whether a secret
     *    is an orphan it should DELETE. Editor-writable text must never be
     *    able to nominate a secret for deletion.
     *  - `context` is the weakest member of the set and is included on
     *    inventory-integrity grounds rather than access-control ones: it
     *    grants nothing, but it is the only `SecretFilters` dimension
     *    besides the identifier prefix and it drives the analytics
     *    distribution, so silently re-bucketing someone else's secret hides
     *    it from the filtered views its owner uses to review their
     *    inventory. Rotating a value never requires changing it.
     *
     * `description` is deliberately NOT here: it is free-text documentation
     * with no machine consumer, and someone trusted with write access to a
     * secret should be able to document it.
     *
     * @var list<string>
     */
    private const PRIVILEGED_VALUE_COLUMNS = [
        'frontend_accessible',
        'hidden',
        'expires_at',
        'metadata',
        'context',
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
     * Cmdmap commands refused outright for this table, mapped to the reason
     * the editor is shown. Core supports nine; the other six need no entry:
     *
     *  - `delete` is performed THROUGH VaultService further down, gates,
     *    audit entry and compensating rollback included.
     *  - `localize` and `copyToLanguage` both call DataHandler::localize(),
     *    which refuses a table whose schema is not language-aware
     *    ("Localization failed; languageField and transOrigPointerField must
     *    be defined"). The TCA declares neither, by design — a secret has no
     *    translations.
     *  - `inlineLocalizeSynchronize` acts on the children of an inline field;
     *    this table has none, and the command returns early for a language id
     *    of 0.
     *  - `discard` returns unless the schema is workspace-aware AND the actor
     *    is in a workspace; `version` logs "Versioning is not supported for
     *    this table". The TCA sets no `versioningWS`.
     *
     * That leaves three, refused here:
     *
     *  - `undelete` restored a soft-deleted secret with no vault check of any
     *    kind. Core's undeleteRecord() asks checkModifyAccessList() and
     *    checkRecordEditAccess(), and skips the page-permission branch
     *    entirely for a record at pid 0 — which every vault secret is
     *    (`rootLevel => -1`, and the module creates them there). Because the
     *    vault delete is a SOFT delete — SecretRepository::delete() writes
     *    only `deleted`/`tstamp` — the ciphertext, the wrapped DEK,
     *    `frontend_accessible`, `hidden` and both MM ACL tiers survive it and
     *    come back with the row. The vault has no restore operation, and the
     *    product tells the editor it cannot give a deleted secret back, so
     *    the TCA path must not quietly offer one.
     *  - `copy` cannot produce a working secret. The crypto columns
     *    (`encrypted_value`, `encrypted_dek`, both nonces, `value_checksum`)
     *    have no TCA definition, and DataHandler::fillInFieldArray() only
     *    processes fields the schema knows — so the clone is value-less. What
     *    it does carry is the ORIGINAL identifier, and
     *    SecretRepository::findByIdentifier() has no ORDER BY: the empty
     *    clone can win the lookup and make retrieve() fail for every
     *    consumer of a secret that is still perfectly intact.
     *  - `move` is the only command that can take a secret off the root level
     *    and into the page tree. A record on a page is deleted by
     *    DataHandler::deleteSpecificPage(), which calls deleteRecord()
     *    directly — that path never reaches this hook, so the per-secret ACL
     *    and the audit entry are both skipped. `pid` carries no vault meaning
     *    (the ACL scope is the separate `scope_pid` column), so the move buys
     *    nothing and costs the record its protection.
     *
     * @var array<string, string>
     */
    private const REFUSED_COMMANDS = [
        'undelete' => 'A deleted vault secret cannot be restored: the vault has no restore operation, '
            . 'and its delete is documented as not reversible.',
        'copy' => 'A vault secret cannot be copied: the copy would carry no encrypted value and would '
            . 'claim the original identifier, shadowing it.',
        'move' => 'A vault secret cannot be moved: it belongs on the root level, where no page '
            . 'operation can delete it unaudited.',
    ];

    /**
     * Pending secrets to store after database operations.
     *
     * @var array<string, mixed> Map of temporary ID => secret value
     */
    private array $pendingSecrets = [];

    /**
     * Commands fully handled in processCmdmap_preProcess(), keyed
     * "<command>:<uid>" — a `delete` performed through VaultService (ACL,
     * operation permission and compensated audit included) or refused by it,
     * and every command in REFUSED_COMMANDS. All of those must make core skip
     * its own branch of the cmdmap switch in processCmdmap(). Entries are
     * consumed (unset) when the cancel is applied so a DI-shared hook
     * instance cannot leak a stale entry across DataHandler runs.
     *
     * Keyed by command as well as uid because one cmdmap may legitimately
     * carry several commands for the same record; a uid-only key would let
     * the first of them cancel the second.
     *
     * @var array<string, true>
     */
    private array $handledCommands = [];

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
     * UIDs whose record creation was rolled back — because the creation audit
     * write failed, or because the submitted secret value was refused —
     * awaiting the MM purge in processDatamap_afterAllOperations().
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
     * Authorizes the creation of a new record, enforces the per-secret write
     * ACL on an existing one, and prevents identifier changes.
     *
     * @param array<string, mixed> $fieldArray
     *
     * @param-out array<string, mixed>|null $fieldArray `null` refuses the
     *            record: core skips it entirely (see both gates below)
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

        // Object ACL (CWE-862): DataHandler's tables_modify grant is a TABLE
        // permission, not the vault's per-secret one. Without this gate any
        // backend user who may edit tx_nrvault_secret at all could change
        // ANY secret's description, context, expiry or metadata — and the
        // hook would then audit it as a successful metadata_update in their
        // name. The gate covers every column, not just the privileged ones,
        // because "may this actor change this secret at all" precedes "which
        // columns may they change".
        if (!$this->isUpdateAuthorized($id, $dataHandler)) {
            // Aborting here rather than in afterDatabaseOperations() means
            // nothing is written in the first place, so there is no mutation
            // to compensate. `null` is what makes core skip the record — see
            // the create gate below for core's guard and why `[]` is not a
            // substitute.
            $fieldArray = null;

            return;
        }

        // Authorize the CREATION ITSELF before DataHandler inserts anything.
        // Both create gates (canCreate + secret.create) live inside
        // VaultService::store(), and a record saved with an empty
        // secret_input never calls store() — secret_input is optional, so
        // that is a plain FormEngine save, not an edge case. Without this
        // gate such a create bypassed secret.create entirely: the row landed,
        // owner_uid was forced to its unauthorized creator by
        // enforcePrivilegedColumnPolicy(), and a SUCCESS `create` entry went
        // into the tamper-evident chain for an operation nobody was allowed
        // to perform. The identifier stayed squatted, so the next legitimate
        // non-admin creator failed canWrite() against the row.
        //
        // Refusing here rather than compensating afterwards is the point: the
        // unauthorized row never exists, so there is nothing to squat, no MM
        // rows to purge and no audit entry to retract.
        if (str_starts_with((string) $id, 'NEW') && !$this->isCreationGranted($fieldArray, $dataHandler)) {
            // Invalidating the by-ref array is how a preProcessFieldArray
            // hook aborts one record: immediately after each hook call
            // DataHandler re-checks the argument it just passed by reference,
            //
            //     if (!is_array($incomingFieldArray)) { continue 2; }
            //
            // skipping the record before newFieldArray(), insertDB() and the
            // deferred MM queuing. Quoted as code rather than by line number,
            // which moves with every core patch release; the guard is present
            // verbatim in v12.4, v13.4 and v14.3 alike.
            //
            // `[]` is NOT a substitute — core's guard is is_array(), and
            // newFieldArray() would refill the TCA defaults and insert the row
            // anyway. Assigning null to a by-ref `array` parameter is legal:
            // PHP type-checks by-ref parameters at call time, not on
            // assignment inside the callee.
            $fieldArray = null;

            return;
        }

        // Authorize privileged ACL columns BEFORE DataHandler persists them.
        // The VaultService coercion (resolveOwnerUid/resolveFrontendAccessible)
        // only runs on the programmatic store($options) path; the FormEngine
        // path writes the raw columns directly, so the gate must live here.
        //
        // Normally the policy filters the record and it proceeds; it refuses
        // the record outright only when the target could not be resolved at
        // all, which the ACL gate above should already have caught — the two
        // resolve through different reads, so this closes the case where they
        // disagree rather than trusting one of them for both.
        if (!$this->enforcePrivilegedColumnPolicy($fieldArray, $id, $dataHandler)) {
            $fieldArray = null;

            return;
        }

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

        // Both flags are needed to tell the three creation outcomes apart:
        // "no value was stored" alone cannot distinguish a deliberately
        // value-less record from one whose value was refused (see
        // RecordCreationOutcome).
        $valueSubmitted = false;
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
                $valueSubmitted = true;

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
            $this->completeRecordCreation(
                RecordCreationOutcome::classify($valueSubmitted, $secretStored),
                $identifier,
                $uid,
                $fieldArray,
                $dataHandler,
            );

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
     * Called before a command is processed. Refuses the commands this table
     * does not support at all (see REFUSED_COMMANDS) and enforces the vault
     * delete ACL (F5 / CWE-862) on the one it does, recording the audit entry
     * either way.
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
     *
     * The target is resolved through the disabled-visible lookup. The
     * restricted one skips a disabled secret, and skipping here does not
     * refuse the delete — it hands the command back to core, which
     * soft-deletes the row with no per-secret ACL, no `secret.delete` and no
     * audit entry. Disabling a secret must not be the way to strip it of its
     * guard.
     */
    public function processCmdmap_preProcess(// NOSONAR: TYPO3 DataHandler hook method name (fixed API contract)
        string $command,
        string $table,
        string|int $id,
        mixed $value = null,
        ?DataHandler $dataHandler = null,
    ): void {
        if ($table !== self::TABLE) {
            return;
        }

        if (\array_key_exists($command, self::REFUSED_COMMANDS)) {
            $this->refuseCommand($command, $id, $dataHandler);

            return;
        }

        if ($command !== 'delete') {
            return;
        }

        $uid = is_numeric($id) ? (int) $id : 0;
        $secret = $this->secretRepository->findByUidIncludingDisabled($uid);
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
        $this->handledCommands[$command . ':' . $uid] = true;

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
     * Makes core skip its own branch of the cmdmap switch for every command
     * the hook handled in processCmdmap_preProcess() — a successful service
     * delete already soft-deleted the record, a refused delete must leave it
     * untouched, and a refused command must not be carried out at all.
     * (DataHandler runs this hook before the command switch.)
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
        if ($table !== self::TABLE) {
            return;
        }

        $uid = is_numeric($id) ? (int) $id : 0;
        $key = $command . ':' . $uid;
        if (($this->handledCommands[$key] ?? false) === true) {
            unset($this->handledCommands[$key]);
            $commandIsProcessed = true;
        }
    }

    /**
     * Refuse a command this table does not support: cancel it, tell the
     * editor why, and record the refusal in the tamper-evident chain.
     *
     * The refusal is unconditional — it is a property of the command on this
     * table, not of the actor or of the row. An admin exemption would make
     * "a vault delete cannot be undone" mean "unless an administrator says
     * otherwise", and the chain auditors read would carry a restore the vault
     * never performed. An operator who genuinely must resurrect a row still
     * can, at the database, where the change is visible as one.
     *
     * The record read includes soft-deleted rows: an `undelete` target is by
     * definition deleted, so the default read would find nothing and the
     * denial would land in the chain without the identifier it is about.
     * An unreadable row still gets refused — only its audit entry is
     * necessarily anonymous, and the DataHandler log carries the uid.
     */
    private function refuseCommand(string $command, string|int $id, ?DataHandler $dataHandler): void
    {
        $uid = is_numeric($id) ? (int) $id : 0;

        // Flagged before anything can fail, and for uid 0 as well: the
        // cancellation is what makes the refusal real, so it must not depend
        // on the record read or the audit write below succeeding.
        $this->handledCommands[$command . ':' . $uid] = true;

        $record = $this->readRecord($uid, ['identifier'], true);
        $identifier = \is_string($record['identifier'] ?? null) ? $record['identifier'] : '';
        if ($identifier !== '') {
            $this->auditDenial($identifier, 'Command refused: ' . $command);
        }

        /** @phpstan-ignore method.internal */
        $dataHandler?->log(
            self::TABLE,
            $uid,
            2,
            null,
            1,
            self::REFUSED_COMMANDS[$command],
        );
    }

    /**
     * Finish the FormEngine creation of a secret record according to how it
     * ended. Routing by RecordCreationOutcome rather than by "no value was
     * stored" is the point of this method: the value-less and the rejected
     * case are indistinguishable by that fact alone, yet one must keep its
     * row and be audited as a creation while the other must lose its row and
     * be audited as nothing.
     *
     * @param array<string, mixed> $fieldArray
     */
    private function completeRecordCreation(
        RecordCreationOutcome $outcome,
        string $identifier,
        int $uid,
        array $fieldArray,
        DataHandler $dataHandler,
    ): void {
        switch ($outcome) {
            case RecordCreationOutcome::ValueLess:
                $this->auditRecordCreationOrCompensate($identifier, $uid, $fieldArray, $dataHandler);
                break;
            case RecordCreationOutcome::Rejected:
                $this->revertRejectedCreation($uid, $dataHandler);
                break;
            case RecordCreationOutcome::Stored:
                // VaultService::store() wrote the create entry itself, with
                // its own compensating rollback. Nothing to add.
                break;
        }
    }

    /**
     * Remove the row DataHandler inserted for a creation whose submitted
     * secret value VaultService refused (per-secret ACL or operation
     * permission) or failed to store.
     *
     * No secret was created, so no row may be left behind. A surviving row
     * squats the identifier under an owner_uid that
     * enforcePrivilegedColumnPolicy() has just forced to the refused
     * creator, so every later legitimate non-admin create of that identifier
     * fails canWrite() against it. Its ACL relation rows are purged in
     * processDatamap_afterAllOperations(), which core calls after the
     * deferred MM writes (see $revertedCreations).
     *
     * No audit entry is written here: VaultService already recorded the
     * refusal as access_denied, and a success `create` entry for a creation
     * that never happened would put a verifiable-looking falsehood into the
     * tamper-evident HMAC chain, right next to the truthful denial.
     */
    private function revertRejectedCreation(int $uid, DataHandler $dataHandler): void
    {
        $reverted = $this->revertRow($uid, null);
        if ($reverted) {
            $this->revertedCreations[$uid] = true;
        }

        /** @phpstan-ignore method.internal */
        $dataHandler->log(
            self::TABLE,
            $uid,
            2,
            null,
            1,
            'The submitted secret value was not stored, so no vault secret was created — the record was '
            . ($reverted
                ? 'removed again.'
                : 'NOT removable; it holds no secret and must be deleted manually.'),
        );
    }

    /**
     * Audit the FormEngine creation of a record that carries no secret value
     * (a stored value is audited by VaultService::store(), a refused one is
     * reverted instead — see completeRecordCreation()). If the audit write
     * fails, the just-created row is removed again — a record must not exist
     * without its audit entry. Its ACL relation rows are purged in
     * processDatamap_afterAllOperations(), because DataHandler writes them
     * only after this hook has run.
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
     * $includeDeleted drops that predicate, for the one caller that needs a
     * soft-deleted row: refuseCommand() has to name the identifier of an
     * `undelete` target, which is deleted by definition.
     *
     * @param list<string> $columns
     *
     * @return array<string, mixed>|null
     */
    private function readRecord(int $uid, array $columns, bool $includeDeleted = false): ?array
    {
        if ($uid < 1) {
            return null;
        }

        if (!$this->connectionPool instanceof ConnectionPool) {
            $record = BackendUtility::getRecord(self::TABLE, $uid, implode(',', $columns), '', !$includeDeleted);
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

        // Built after select()/from() so the parameter binding keeps the
        // order the read has always had — the shape unit tests pin it.
        $query = $queryBuilder
            ->select(...$columns)
            ->from(self::TABLE);

        $predicates = [
            $queryBuilder->expr()->eq(
                'uid',
                $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT),
            ),
        ];

        if (!$includeDeleted) {
            $predicates[] = $queryBuilder->expr()->eq(
                'deleted',
                $queryBuilder->createNamedParameter(0, Connection::PARAM_INT),
            );
        }

        $row = $query
            ->where(...$predicates)
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
     * May the current actor change this existing secret at all?
     *
     * The per-secret write tier (owner / write-group member / admin /
     * system maintainer, ADR-005) asserted through the same
     * `canWrite()` the programmatic path uses in
     * `VaultService::assertWritePermission()`, so a FormEngine edit and a
     * `store()` on an existing secret answer to one authorization rule.
     *
     * A creation is not gated here: it has no existing secret to authorize
     * against, and its own gates (`canCreate()`, `secret.create`) live on
     * the VaultService path.
     *
     * The record is resolved through the disabled-visible lookup, for the
     * same reason as the delete gate: the restricted one cannot see a
     * disabled secret, and a gate that cannot see its subject does not refuse
     * the write — it lets core perform it without ever consulting
     * `canWrite()`. Disabling a secret must not be the way to strip it of its
     * guard.
     *
     * With that lookup in place, an unresolved uid no longer means "possibly
     * a disabled secret" — it means the vault holds no live record for this
     * uid, and the write is refused rather than waved through
     * (see refuseUnresolvableTarget() for what the two remaining causes are
     * and why both are refused).
     */
    private function isUpdateAuthorized(string|int $id, DataHandler $dataHandler): bool
    {
        if (str_starts_with((string) $id, 'NEW')) {
            return true;
        }

        $uid = is_numeric($id) ? (int) $id : 0;
        $secret = $this->secretRepository->findByUidIncludingDisabled($uid);
        if (!$secret instanceof Secret) {
            $this->refuseUnresolvableTarget($uid, 'Update', $dataHandler);

            return false;
        }

        if ($this->accessControlService->canWrite($secret)) {
            return true;
        }

        $this->auditDenial($secret->getIdentifier(), 'Update access denied');

        /** @phpstan-ignore method.internal */
        $dataHandler->log(
            self::TABLE,
            $uid,
            2,
            null,
            1,
            'Changing this vault secret requires being its owner, a member of one of its write groups, or an administrator',
        );

        return false;
    }

    /**
     * Refuse a datamap write whose target this hook could not resolve, and
     * say as precisely as the data allows what was not resolvable.
     *
     * Shared by both write gates — the per-secret ACL (isUpdateAuthorized())
     * and the privileged-column policy (enforcePrivilegedColumnPolicy()) —
     * because they guard the same write from two angles and must not disagree
     * about what "the record is not there" means. Both resolve through a
     * lookup that excludes soft-deleted rows, so both reach this method for
     * the same two causes:
     *
     *  - **Soft-deleted (a tombstone).** The live one. Core reads its datamap
     *    UPDATE target with `BackendUtility::getRecord($table, $id, '*', '',
     *    false)` — delete clause OFF — and skips only a row it cannot find at
     *    all, so it processes a deleted secret's datamap perfectly happily.
     *    The gates cannot see the row, so before this refusal the columns of a
     *    deleted secret were writable by anyone DataHandler let near the
     *    table, with no per-secret tier and no policy gate. `deleted` has no
     *    TCA column and this table refuses `undelete`, so the row cannot be
     *    resurrected that way — but rewriting a tombstone is still an
     *    unaudited, ungated write to vault state, and the identifier it
     *    carries is what a later legitimate creation collides with.
     *  - **Genuinely absent.** Core skips such a record itself, one guard
     *    further on. Refused here anyway rather than special-cased: the gate
     *    would otherwise have to prove core's later guard still exists to stay
     *    correct, and "the vault could not identify the record it is being
     *    asked to authorize" is a refusal on its own terms.
     *
     * Reported differently because they differ for the editor, and because
     * only one of them HAS an identifier: the deleted-inclusive probe below
     * is what tells them apart, and it runs only on this path — a resolvable
     * target never pays for it. A tombstone is audited as `access_denied`
     * under its identifier, exactly like the hook's other refusals; an absent
     * record has no identifier to audit under, so it is reported in the
     * DataHandler log alone (the same concession refuseCommand() makes for an
     * unreadable row).
     */
    private function refuseUnresolvableTarget(int $uid, string $gate, DataHandler $dataHandler): void
    {
        $record = $this->readRecord($uid, ['identifier'], true);
        $identifier = \is_string($record['identifier'] ?? null) ? $record['identifier'] : '';

        if ($identifier !== '') {
            $this->auditDenial($identifier, $gate . ' denied: the vault secret is deleted');
            $message = 'This vault secret is deleted and can no longer be changed; '
                . 'the vault has no restore operation.';
        } else {
            $message = 'No vault secret exists for this record, so the change cannot be authorized.';
        }

        /** @phpstan-ignore method.internal */
        $dataHandler->log(
            self::TABLE,
            $uid,
            2,
            null,
            1,
            $message,
        );
    }

    /**
     * Record a refused write as an `access_denied` audit entry, mirroring
     * `VaultService`'s denial entries so both paths land the same shape in
     * the tamper-evident chain.
     *
     * A failing audit write must not turn the refusal into a grant, so the
     * exception is swallowed: unlike the compensating rollbacks elsewhere in
     * this hook there is no mutation to undo — the change was already
     * refused, and the caller returns false either way.
     */
    private function auditDenial(string $identifier, string $reason): void
    {
        try {
            $this->auditService->log($identifier, AuditAction::AccessDenied->value, false, $reason);
        } catch (Throwable) {
            // Deliberately ignored — see the docblock.
        }
    }

    /**
     * Both create gates, evaluated before the record exists.
     *
     * Mirrors what VaultService::store() applies on the programmatic path —
     * the per-actor `canCreate()` tier and the `secret.create` operation
     * permission (separation of duties: being allowed to touch the vault at
     * all versus being allowed to perform this KIND of operation). The hook
     * cannot delegate to store(): the whole point of this gate is the create
     * that never reaches store() because it carries no value.
     *
     * Applied to EVERY actor, admins included. Neither gate is an
     * "is this a non-admin" question — `canCreate()` and `isGranted()` route
     * the admin decision through AccessControlService::adminBypassActive(),
     * the single seam the hardened profile can switch off. Short-circuiting
     * admins here would reintroduce the bypass this extension deliberately
     * keeps in one place.
     *
     * @param array<string, mixed> $fieldArray
     *
     * @return bool True when the creation may proceed
     */
    private function isCreationGranted(array $fieldArray, DataHandler $dataHandler): bool
    {
        if (!$this->accessControlService->canCreate()) {
            $this->refuseCreation($fieldArray, 'Create access denied', $dataHandler);

            return false;
        }

        if (!$this->accessControlService->isGranted(VaultPermission::SecretCreate)) {
            $this->refuseCreation(
                $fieldArray,
                'Create denied: missing ' . VaultPermission::SecretCreate->value . ' permission',
                $dataHandler,
            );

            return false;
        }

        return true;
    }

    /**
     * Record a refused creation: an `access_denied` audit entry (the same
     * shape VaultService writes when it refuses a create) plus a DataHandler
     * log line so FormEngine tells the editor why the save did nothing.
     *
     * No `create` entry is written, successful or otherwise — nothing was
     * created. The audit write is contained: a denial whose audit entry
     * cannot be written must still deny, so the failure is surfaced in the
     * DataHandler log rather than allowed to abort the refusal.
     *
     * @param array<string, mixed> $fieldArray
     */
    private function refuseCreation(array $fieldArray, string $errorMessage, DataHandler $dataHandler): void
    {
        $identifier = \is_string($fieldArray['identifier'] ?? null) ? $fieldArray['identifier'] : '';

        try {
            // Fourth positional argument is $errorMessage, not $reason —
            // same slot VaultService uses for its own denial entries, so the
            // two read alike in the audit trail.
            $this->auditService->log(
                $identifier,
                AuditAction::AccessDenied->value,
                false,
                $errorMessage,
            );
        } catch (Throwable $e) {
            /** @phpstan-ignore method.internal */
            $dataHandler->log(
                self::TABLE,
                0,
                1,
                null,
                1,
                'Vault audit logging of the refused secret creation failed: ' . $e->getMessage()
                . ' — the creation was refused regardless.',
            );
        }

        /** @phpstan-ignore method.internal */
        $dataHandler->log(
            self::TABLE,
            0,
            1,
            null,
            1,
            'Vault secret creation requires the ' . VaultPermission::SecretCreate->value
            . ' permission (' . $errorMessage . ') — the record was not created.',
        );
    }

    /**
     * Enforce that the privileged columns may only be changed by an
     * admin/system maintainer, or by the secret's owner while holding
     * `secret.manage_policy`. Runs on top of the per-secret write ACL
     * asserted in isUpdateAuthorized(): passing canWrite() buys the right to
     * rotate a value and document it, not to re-scope, re-own, expire, hide
     * or re-provenance the secret (separation of duties).
     *
     * This is the write-path authorization layer for CWE-639/CWE-269 — the
     * TCA `exclude` flag is the complementary form-permission layer.
     *
     * The remedy for an unauthorized change is to DROP the column from
     * $fieldArray rather than to write the stored value back. Dropping is
     * what the MM columns always required (their row column holds only a
     * relation count), and it is the safer primitive for the scalar columns
     * too: it needs no second write, and it preserves the stored value even
     * when the submitted value cannot be normalised confidently enough to
     * prove it changed. The comparison below therefore only decides whether
     * to REPORT an attempt, never whether the column is protected.
     *
     * Policy (default-DENY for the ambiguous delegation case):
     *  - Admin / system maintainer: unrestricted (no coercion).
     *  - NEW record by a non-admin: owner_uid is forced to the current backend
     *    user (the submitted value is not trusted); the other privileged
     *    columns are left as submitted (a creator legitimately scopes the
     *    secret they own).
     *  - EXISTING record edited by the owner holding secret.manage_policy:
     *    unrestricted.
     *  - Anyone else: every privileged column is dropped and, when it
     *    differed from the stored value, the attempt is logged and audited.
     *
     * Returns false when the record must be refused outright rather than
     * merely filtered — see refuseUnresolvableTarget(). Dropping the
     * privileged columns would NOT be the fail-closed answer there: the read
     * that failed is the same read that supplies the stored values, so the
     * policy cannot be applied at all, and letting the non-privileged columns
     * through would still be an ungated write to a record the vault cannot
     * identify. The caller nulls $fieldArray, because that is what makes core
     * skip a record and this method holds it only by reference.
     *
     * @param array<string, mixed> $fieldArray
     *
     * @return bool True when the record may proceed
     */
    private function enforcePrivilegedColumnPolicy(
        array &$fieldArray,
        string|int $id,
        DataHandler $dataHandler,
    ): bool {
        // Admins and system maintainers are trusted on this path. Non-backend
        // actors (CLI/scheduler/api) do not reach DataHandler form edits with a
        // BE user, so they are treated as non-privileged here and fall through
        // to the owner check (which yields actor UID 0 => not owner).
        if ($this->accessControlService->isCurrentActorAdmin()) {
            return true;
        }

        $isNew = str_starts_with((string) $id, 'NEW');

        if ($isNew) {
            // A non-admin creator owns what they create: force owner_uid to the
            // current backend user. Set it unconditionally — owner_uid is an
            // excludefield, so a creator lacking that grant submits no value at
            // all, and a conditional set would leave the column 0 (ownerless),
            // locking the creator out of managing their own new secret.
            $fieldArray['owner_uid'] = $this->accessControlService->getCurrentActorUid();

            return true;
        }

        $uid = is_numeric($id) ? (int) $id : 0;
        // `identifier` is read alongside the privileged columns — the denial
        // audit entry needs it — but it is NOT one of them: its immutability
        // is enforced separately, further down the calling method.
        $original = $this->readRecord($uid, [...$this->privilegedScalarColumns(), 'identifier']);
        if ($original === null) {
            $this->refuseUnresolvableTarget($uid, 'Policy change', $dataHandler);

            return false;
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
            return true;
        }

        // Not authorized to manage this secret's policy: drop every
        // privileged column so DataHandler writes none of them, and leaves
        // the MM relation rows alone rather than replacing them.
        $attempted = [];

        foreach ($this->privilegedScalarColumns() as $column) {
            if (!\array_key_exists($column, $fieldArray)) {
                continue;
            }

            // Compare before dropping, so an ordinary save that merely
            // round-trips the unchanged value does not report tampering.
            // A comparison that cannot prove equality counts as an attempt:
            // over-reporting costs a log line, under-reporting would hide one.
            if ($this->normalizeForComparison($column, $fieldArray[$column])
                !== $this->normalizeForComparison($column, $original[$column] ?? null)
            ) {
                $attempted[] = $column;
            }

            unset($fieldArray[$column]);
        }

        foreach (array_keys(self::PRIVILEGED_MM_COLUMNS) as $column) {
            if (!\array_key_exists($column, $fieldArray)) {
                continue;
            }

            // MM-backed group field: the row column holds only the relation
            // count, so the submitted value carries no comparable state —
            // its mere presence is the attempt.
            unset($fieldArray[$column]);
            $attempted[] = $column;
        }

        if ($attempted === []) {
            return true;
        }

        $identifier = \is_string($original['identifier'] ?? null) ? $original['identifier'] : '';
        if ($identifier !== '') {
            $this->auditDenial(
                $identifier,
                'Policy change denied: ' . implode(', ', $attempted),
            );
        }

        /** @phpstan-ignore method.internal */
        $dataHandler->log(
            self::TABLE,
            $uid,
            2,
            null,
            1,
            'Vault secret ACL columns can only be changed by an administrator or by the secret owner holding the secret.manage_policy permission',
        );

        // The unauthorized columns are gone; the rest of the save is a
        // legitimate edit by someone who passed canWrite(), so it proceeds.
        return true;
    }

    /**
     * Every privileged column stored directly on the secret row, in a stable
     * order. Assembled from the two lists so the policy has a single source
     * of truth and a column can never be protected in one loop and forgotten
     * in the record read that feeds it.
     *
     * @return list<string>
     */
    private function privilegedScalarColumns(): array
    {
        return [...self::PRIVILEGED_GROUP_COLUMNS, ...self::PRIVILEGED_VALUE_COLUMNS];
    }

    /**
     * Reduce a submitted and a stored value of the same column to comparable
     * strings, so "did this save actually change the column" can be answered
     * across the type differences the FormEngine introduces.
     *
     * Only ever used to decide whether to REPORT an attempt — the column is
     * dropped either way — so returning a value that compares unequal is the
     * safe direction when normalisation is uncertain.
     */
    private function normalizeForComparison(string $column, mixed $value): string
    {
        if (\in_array($column, self::PRIVILEGED_GROUP_COLUMNS, true)) {
            // "be_users_12" / "pages_100" from the group field vs an int in
            // the row.
            return (string) $this->extractUidFromGroupValue(\is_scalar($value) ? (string) $value : '');
        }

        if ($column === 'expires_at') {
            return (string) $this->normalizeTimestamp($value);
        }

        if ($column === 'frontend_accessible' || $column === 'hidden') {
            return \is_scalar($value) ? (string) (int) $value : '0';
        }

        // context, metadata, identifier: free text, compared verbatim.
        return \is_scalar($value) ? (string) $value : '';
    }

    /**
     * A datetime column reaches this hook as the raw form value — an ISO-8601
     * string on the FormEngine path, an integer on the programmatic one —
     * while the stored value is always a Unix timestamp, because DataHandler
     * only converts it later in checkValue(). Both are reduced to a timestamp
     * so an unchanged expiry is recognised as unchanged.
     *
     * An unparseable value yields -1, which matches no stored timestamp and
     * so counts as a change (see normalizeForComparison()).
     */
    private function normalizeTimestamp(mixed $value): int
    {
        if (is_numeric($value)) {
            return (int) $value;
        }

        if (!\is_string($value) || trim($value) === '') {
            return 0;
        }

        $timestamp = strtotime($value);

        return $timestamp === false ? -1 : $timestamp;
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
