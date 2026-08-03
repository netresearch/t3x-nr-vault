<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service;

use Netresearch\NrVault\Domain\Dto\SecretDetails;
use Netresearch\NrVault\Domain\Dto\SecretMetadata;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Exception\SecretExpiredException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Http\VaultHttpClientInterface;
use SensitiveParameter;

/**
 * Primary interface for interacting with the vault.
 */
interface VaultServiceInterface
{
    /**
     * Store a secret.
     *
     * @param string $identifier Unique identifier for the secret
     * @param string $secret The secret value to store
     * @param array<string, mixed> $options Optional configuration:
     *                                      - owner: int - BE user UID who owns this secret
     *                                      - groups: int[] - BE user group UIDs allowed to access
     *                                      - context: string - Permission scoping
     *                                      - expiresAt: int|\DateTimeInterface|null - When secret expires
     *                                      - metadata: array - Custom metadata
     *                                      - description: string - Human-readable description
     *                                      - scopePid: int - Page ID for multi-site scoping
     *
     * @throws ValidationException If identifier is invalid
     * @throws EncryptionException If encryption fails
     */
    public function store(string $identifier, #[SensitiveParameter] string $secret, array $options = []): void;

    /**
     * Retrieve a secret value.
     *
     * @throws AccessDeniedException If current user lacks permission
     * @throws EncryptionException If decryption fails
     * @throws SecretExpiredException If secret has expired
     *
     * @return string|null The secret value, or null if not found
     */
    public function retrieve(string $identifier): ?string;

    /**
     * Retrieve a secret for rendering in the frontend.
     *
     * Frontend-scoped counterpart of `retrieve()`: only secrets flagged
     * `frontend_accessible` are resolvable here, and that requirement holds
     * for every caller — including a request that happens to carry a backend
     * session (`$GLOBALS['BE_USER']`), whose ambient privileges would
     * otherwise widen `retrieve()`'s access decision. Everything else
     * (expiry, decryption, audit logging, read statistics) behaves as in
     * `retrieve()`.
     *
     * @throws AccessDeniedException If the secret is not frontend-accessible, or the current actor lacks read permission
     * @throws EncryptionException If decryption fails
     * @throws SecretExpiredException If secret has expired
     *
     * @return string|null The secret value, or null if not found
     */
    public function retrieveForFrontend(string $identifier): ?string;

    /**
     * Check if a secret exists.
     */
    public function exists(string $identifier): bool;

    /**
     * Delete a secret permanently.
     *
     * @throws SecretNotFoundException If secret doesn't exist
     * @throws AccessDeniedException If current user lacks permission
     */
    public function delete(string $identifier, string $reason = ''): void;

    /**
     * Assert that {@see delete()} is permitted for this identifier — without deleting.
     *
     * Exists for callers that delete SEVERAL secrets as one logical unit (the
     * DataHandler record delete across multiple vault fields). A vault delete is
     * a hard delete with no restore, so a partially applied batch cannot be
     * compensated: the only way to keep such a batch all-or-nothing is to run
     * every permission gate up front and abort before the first deletion.
     *
     * A secret that does not exist returns without throwing — the goal state
     * ("no secret under this identifier") is already reached, so deleting it is
     * permitted in the only sense a caller can act on. Callers that need to
     * distinguish absent from present must ask {@see exists()}.
     *
     * The gates asserted here are exactly the ones {@see delete()} applies, and
     * the denial is audited the same way. Passing this check does NOT guarantee
     * the subsequent delete succeeds — an audit-write failure, or a permission
     * revoked in between, can still abort it.
     *
     * @throws AccessDeniedException If current user lacks permission
     */
    public function assertDeletable(string $identifier): void;

    /**
     * Rotate a secret.
     *
     * @throws SecretNotFoundException If secret doesn't exist
     * @throws AccessDeniedException If current user lacks permission
     * @throws EncryptionException If encryption fails
     */
    public function rotate(string $identifier, #[SensitiveParameter] string $newSecret, string $reason = ''): void;

    /**
     * Enable or disable a secret — the single write path for its availability.
     *
     * Disabling withdraws the secret from every read path at once (the record
     * carries TCA's `disabled` enable column, so a disabled secret resolves to
     * nothing in `retrieve()`, `retrieveForFrontend()` and every placeholder
     * that goes through them). That makes it an access-control decision, not a
     * display preference, and it is gated accordingly: the per-secret
     * `canWrite()` tier AND the `secret.manage_policy` operation permission,
     * exactly as `rotate()` and `delete()` gate theirs.
     *
     * The state is ABSOLUTE, not a toggle. Two concurrent toggles cancel out
     * and leave two audit entries claiming opposite outcomes; two concurrent
     * `setEnabled($id, false)` calls converge on the state their caller asked
     * for. Whether a button flips the state is the caller's concern.
     *
     * Setting the state a secret already has is a no-op: no write, and no
     * audit entry, because nothing changed. A refused call is still audited
     * (`access_denied`) whether or not it would have changed anything.
     *
     * The change and its audit entry are all-or-nothing (ADR-036): if the
     * audit write fails, the previous availability is restored and the
     * `AuditWriteException` surfaces. A revert that itself fails is logged at
     * CRITICAL for manual reconciliation.
     *
     * @param string $reason Operator-supplied justification, recorded in the
     *                       audit entry alongside the direction of the change
     *
     * @throws SecretNotFoundException If secret doesn't exist
     * @throws AccessDeniedException If current user lacks permission
     */
    public function setEnabled(string $identifier, bool $enabled, string $reason = ''): void;

    /**
     * List all accessible secrets with metadata.
     *
     * @param string|null $pattern Optional pattern to filter identifiers (supports * wildcard)
     * @param bool $includeDisabled Also return secrets that are currently
     *                              disabled. Off by default, so a consumer
     *                              asking "which secrets are available" keeps
     *                              the answer it had; the management surfaces
     *                              pass `true`, because a disabled secret that
     *                              never appears in a listing cannot be
     *                              re-enabled. Each entry reports its state in
     *                              `SecretMetadata::$enabled`.
     *
     * @return list<SecretMetadata>
     */
    public function list(?string $pattern = null, bool $includeDisabled = false): array;

    /**
     * Get detailed metadata about a secret.
     *
     * @throws SecretNotFoundException If secret doesn't exist
     * @throws AccessDeniedException If current user lacks permission
     */
    public function getMetadata(string $identifier): SecretDetails;

    /**
     * Get the Vault HTTP Client for making authenticated API calls.
     *
     * Returns a PSR-18 compatible client. Use withAuthentication() to configure
     * secret injection, then sendRequest() to make calls.
     *
     * @example
     *     // Configure authentication and send PSR-7 request
     *     $client = $vault->http()->withAuthentication('stripe_key', SecretPlacement::Bearer);
     *     $response = $client->sendRequest($request);
     *
     *     // OAuth 2.0
     *     $client = $vault->http()->withOAuth($oauthConfig);
     *     $response = $client->sendRequest($request);
     */
    public function http(): VaultHttpClientInterface;
}
