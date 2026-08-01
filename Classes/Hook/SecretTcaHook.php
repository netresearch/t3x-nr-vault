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
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Throwable;
use TYPO3\CMS\Backend\Utility\BackendUtility;
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
     * Privileged ACL columns backed by MM relation tables. The row column
     * only holds the relation COUNT, so it cannot be reverted by writing a
     * value back — the submitted change is instead dropped from $fieldArray
     * entirely, leaving DataHandler to keep the existing MM relations.
     *
     * @var list<string>
     */
    private const PRIVILEGED_MM_COLUMNS = [
        'allowed_groups',
        'write_groups',
    ];

    /**
     * Pending secrets to store after database operations.
     *
     * @var array<string, mixed> Map of temporary ID => secret value
     */
    private array $pendingSecrets = [];

    /**
     * Record UIDs whose delete command failed the vault ACL in
     * processCmdmap_preProcess(), to be cancelled in processCmdmap(). Entries
     * are consumed (unset) when the cancel is applied so a DI-shared hook
     * instance cannot leak a stale denial across DataHandler runs.
     *
     * @var array<int, true>
     */
    private array $deniedDeletions = [];

    public function __construct(
        private readonly VaultServiceInterface $vaultService,
        private readonly AuditLogServiceInterface $auditService,
        private readonly AccessControlServiceInterface $accessControlService,
        private readonly SecretRepositoryInterface $secretRepository,
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
            $originalRecord = BackendUtility::getRecord(self::TABLE, (int) $id, 'identifier');
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
        $record = BackendUtility::getRecord(self::TABLE, $uid, 'identifier,owner_uid,allowed_groups,scope_pid');
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
                        $this->vaultService->rotate($identifier, $secretValue);
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

        // Determine what changed for audit context
        $changedFields = array_keys($fieldArray);
        if ($secretStored) {
            $changedFields[] = 'secret_input';
        }

        try {
            // Determine action type
            $action = AuditAction::MetadataUpdate->value;
            if ($status === 'new') {
                $action = AuditAction::Create->value;
            } elseif ($secretStored) {
                $action = AuditAction::Rotate->value;
            }

            // Log the operation
            $this->auditService->log(
                $identifier,
                $action,
                true,
                null,
                'FormEngine edit: ' . implode(', ', $changedFields),
            );
        } catch (Throwable $e) {
            // Don't fail the save if audit logging fails
            /** @phpstan-ignore method.internal */
            $dataHandler->log(
                self::TABLE,
                $uid,
                2,
                null,
                1,
                'Audit logging failed: ' . $e->getMessage(),
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

        $identifier = $secret->getIdentifier();

        // Write-path authorization (CWE-862): the per-secret tier (owner /
        // admin / system maintainer) AND the secret.delete operation
        // permission must both hold. A non-owner non-admin editor with
        // generic table-modify rights — or an owner lacking the delete
        // grant — must be stopped here.
        if (!$this->accessControlService->canDelete($secret)
            || !$this->accessControlService->isGranted(VaultPermission::SecretDelete)
        ) {
            $this->deniedDeletions[$uid] = true;

            try {
                $this->auditService->log(
                    $identifier,
                    AuditAction::AccessDenied->value,
                    false,
                    'Delete access denied',
                    'FormEngine delete denied',
                );
            } catch (Throwable) {
                // A failed audit write must not mask the denial.
            }

            /** @phpstan-ignore method.internal */
            $dataHandler?->log(
                self::TABLE,
                $uid,
                2,
                null,
                1,
                'Vault secret deletion requires being its owner or an administrator AND holding the secret.delete permission',
            );

            return;
        }

        // Authorized delete: record the audit entry now, while the identifier
        // is still resolvable (core removes the row afterwards).
        try {
            $this->auditService->log(
                $identifier,
                AuditAction::Delete->value,
                true,
                null,
                'Deleted via FormEngine',
            );
        } catch (Throwable) {
            // Don't fail the delete if audit logging fails
        }
    }

    /**
     * Cancels a delete command that failed the vault ACL in
     * processCmdmap_preProcess(). Setting $commandIsProcessed = true makes core
     * skip its own deleteAction() (DataHandler runs this hook before the
     * command switch), so the record is preserved.
     *
     * The denial flag is consumed so a DI-shared hook instance cannot leak a
     * stale denial into a later DataHandler run (same discipline as
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
        if (($this->deniedDeletions[$uid] ?? false) === true) {
            unset($this->deniedDeletions[$uid]);
            $commandIsProcessed = true;
        }
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
        $original = BackendUtility::getRecord(
            self::TABLE,
            $uid,
            'owner_uid,frontend_accessible,scope_pid',
        );
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

        foreach (self::PRIVILEGED_MM_COLUMNS as $column) {
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
