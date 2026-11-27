<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage\Aws;

use Netresearch\NrVault\Exception\AwsSecretsManagerException;

/**
 * What the AWS Secrets Manager adapter needs from the secret store.
 *
 * Deliberately free of SDK types, so the adapter and everything that injects it
 * load without the SDK installed.
 */
interface AwsSecretStoreInterface
{
    /**
     * Whether the SDK that talks to AWS is installed.
     */
    public function isSdkInstalled(): bool;

    /**
     * The stored fields of the secret, or null when it does not exist.
     *
     * @return array<string, mixed>|null
     *
     * @throws AwsSecretsManagerException
     */
    public function read(string $identifier): ?array;

    /**
     * The stored fields and the version id of AWSCURRENT, from one response,
     * or null when the secret does not exist. A rollback moves AWSCURRENT back
     * to that version, see {@see restoreIfCurrent()}.
     *
     * @return array{data: array<string, mixed>, versionId: string}|null
     *
     * @throws AwsSecretsManagerException
     */
    public function readWithVersion(string $identifier): ?array;

    /**
     * Create the secret, only when no secret of that name exists (CreateSecret
     * fails on an existing name, so there is no window). While a name that was
     * force-deleted is still being deleted, the create is retried with a short
     * back-off (a few seconds at most).
     *
     * @param array<string, mixed> $data
     *
     * @return string The version id created
     *
     * @throws AwsSecretsManagerException With code 1794500012 when the name exists
     */
    public function create(string $identifier, array $data): string;

    /**
     * Store the fields as a new current version, creating the secret when it
     * does not exist. Only for a secret nr-vault owns: it overwrites.
     *
     * @param array<string, mixed> $data
     *
     * @return string The version id created
     *
     * @throws AwsSecretsManagerException
     */
    public function write(string $identifier, array $data): string;

    /**
     * Take back a write of this call, but only while the current version is
     * still the given one.
     *
     * With the id of the version the write replaced, AWSCURRENT is moved back
     * to it with UpdateSecretVersionStage, which fails when AWSCURRENT is on
     * any other version: a concurrent writer keeps its value. Without that id,
     * or when the move is refused (no permission) or fails while the secret is
     * still at the given version, the fields are put back as a new version
     * after a read of the current id; AWS has no conditional put, so a write
     * landing in that gap is not detected.
     *
     * @param array<string, mixed> $data              The fields of the version the write replaced
     * @param string|null          $previousVersionId The id of that version, read together with $data
     *
     * @return bool False when somebody wrote since, or the secret is gone
     */
    public function restoreIfCurrent(string $identifier, array $data, string $versionId, ?string $previousVersionId = null): bool;

    /**
     * Delete the secret, but only while the current version is still the given
     * one, to take back a create of this call. The id is read immediately
     * before the delete; AWS has no conditional delete, so a write landing in
     * that gap is deleted with the secret.
     *
     * @return bool False when somebody wrote since, or the secret is gone
     */
    public function destroyIfCurrent(string $identifier, string $versionId): bool;

    /**
     * Delete the secret without a recovery window, so no version survives.
     * Succeeds when it does not exist.
     *
     * @throws AwsSecretsManagerException
     */
    public function destroy(string $identifier): void;

    /**
     * The location stored in the registry row's external reference.
     *
     * @throws AwsSecretsManagerException
     */
    public function reference(string $identifier): string;
}
