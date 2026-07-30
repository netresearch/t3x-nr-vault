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
     * Rotate a secret.
     *
     * @throws SecretNotFoundException If secret doesn't exist
     * @throws AccessDeniedException If current user lacks permission
     * @throws EncryptionException If encryption fails
     */
    public function rotate(string $identifier, #[SensitiveParameter] string $newSecret, string $reason = ''): void;

    /**
     * List all accessible secrets with metadata.
     *
     * @param string|null $pattern Optional pattern to filter identifiers (supports * wildcard)
     *
     * @return list<SecretMetadata>
     */
    public function list(?string $pattern = null): array;

    /**
     * Get detailed metadata about a secret.
     *
     * @throws SecretNotFoundException If secret doesn't exist
     * @throws AccessDeniedException If current user lacks permission
     */
    public function getMetadata(string $identifier): SecretDetails;

    /**
     * Clear the request-scoped cache of decrypted secrets.
     *
     * Securely wipes cached plaintext values from memory.
     */
    public function clearCache(): void;

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
