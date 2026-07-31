<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

/**
 * Operation-level vault permissions.
 *
 * These are *operation* permissions ("may this actor rotate secrets at all?"),
 * orthogonal to the *per-secret* ACL tiers of
 * {@see AccessControlServiceInterface::canRead()} / `canWrite()` / `canDelete()`
 * (owner / group / admin, ADR-005). Both gates apply: an actor needs the
 * operation permission AND per-secret access for the concrete secret.
 *
 * The carrier is a TYPO3 custom permission option registered in
 * `ext_localconf.php` under
 * `$GLOBALS['TYPO3_CONF_VARS']['BE']['customPermOptions']['tx_nrvault']`, so
 * every case is grantable per backend user group in the Backend Users module
 * and checked via `$backendUser->check('custom_options', 'tx_nrvault:<value>')`.
 * Case values are therefore part of the stored configuration — renaming one
 * silently revokes the grant and needs an upgrade wizard.
 */
enum VaultPermission: string
{
    /**
     * Consume a secret's plaintext programmatically.
     *
     * The permission every *non-display* read needs: FormEngine vault field
     * widgets, FlexForm / TCA placeholder resolution, site-configuration
     * processing, HTTP clients injecting a token. The plaintext flows into
     * machinery, never onto the operator's screen.
     *
     * Deliberately separate from {@see self::SecretReveal}: an integration
     * account (or an editor whose forms consume vault-backed credentials)
     * needs `secret.use` and must NOT thereby gain the right to read the
     * plaintext with their own eyes.
     */
    case SecretUse = 'secret.use';

    /**
     * Display a secret's plaintext to a human.
     *
     * Gates the interactive reveal surfaces (the `vault_reveal` AJAX endpoint
     * behind the secrets list / FormEngine widget, and `vault:retrieve` which
     * prints plaintext to a terminal). This is the permission that turns a
     * stored secret into something an operator can copy, screenshot, or leak.
     *
     * Does not imply {@see self::SecretUse}, and is not implied by it: a
     * non-admin needs BOTH granted for an end-to-end reveal, because the
     * reveal endpoint displays plaintext (`secret.reveal`) that it obtained
     * through the shared read path (`secret.use`).
     */
    case SecretReveal = 'secret.reveal';

    /**
     * Create new secrets in the vault.
     *
     * Covers the secrets module's create entry point and the underlying
     * `store()` of a not-yet-existing identifier. Creating a secret makes the
     * creator its owner, which grants full per-secret access — so this is a
     * privilege-widening operation, not a harmless write.
     */
    case SecretCreate = 'secret.create';

    /**
     * Replace the value of an existing secret (rotation).
     *
     * Rotation is destructive to the previous value while leaving the
     * identifier — and therefore every consumer referencing it — in place. A
     * bad rotation is an outage; a malicious one substitutes a credential the
     * operator's own systems then use.
     */
    case SecretRotate = 'secret.rotate';

    /**
     * Delete secrets from the vault.
     *
     * The per-secret tier for deletion is already the most restrictive
     * (owner / admin / system maintainer, no group tier). This operation
     * permission gates whether the actor may invoke deletion at all.
     */
    case SecretDelete = 'secret.delete';

    /**
     * Change a secret's access policy or availability.
     *
     * Enabling / disabling a secret and editing its `allowed_groups` /
     * `write_groups` tiers. Holding this permission means being able to widen
     * who can read or write a secret — the permission that governs the
     * permissions, so it belongs to vault administration rather than to
     * day-to-day secret handling.
     */
    case SecretManagePolicy = 'secret.manage_policy';

    /**
     * Read the tamper-evident audit log and verify its hash chain.
     *
     * Audit entries name who touched which secret when. That is a sensitive
     * derivative of the secrets themselves (it maps out the credential
     * topology), so reading it is a permission of its own rather than a
     * side effect of holding any secret permission.
     */
    case AuditView = 'audit.view';

    /**
     * Export the audit log to a file (JSON / CSV).
     *
     * Separate from {@see self::AuditView} because export removes the data
     * from the vault's own tamper-evident storage: the downloaded copy has no
     * hash chain, no retention policy, and no further access control. Viewing
     * in the module and walking off with the full history are different acts.
     */
    case AuditExport = 'audit.export';

    /**
     * Rotate the master key (re-encrypt every envelope).
     *
     * The single most powerful vault operation: it rewrites every stored
     * secret's key envelope in one transaction and rekeys the audit chain. A
     * failed or hostile rotation can render the entire vault unreadable.
     */
    case MasterKeyRotate = 'master_key.rotate';

    /**
     * Change vault configuration and run migration tooling.
     *
     * Gates the migration wizard (which scans the database for plaintext
     * secrets — a map of exactly where credentials sit unencrypted — and
     * moves values into the vault). Configuration changes decide where the
     * master key comes from and which contexts may read secrets, so this is
     * an administrative permission.
     */
    case VaultConfigure = 'vault.configure';

    /**
     * Every permission that governs handling of secrets themselves.
     *
     * Used as the "may this actor enter the secrets module at all?" set:
     * holding any one of them implies a legitimate reason to see the list.
     *
     * @return list<self>
     */
    public static function secretOperations(): array
    {
        return [
            self::SecretUse,
            self::SecretReveal,
            self::SecretCreate,
            self::SecretRotate,
            self::SecretDelete,
            self::SecretManagePolicy,
        ];
    }
}
