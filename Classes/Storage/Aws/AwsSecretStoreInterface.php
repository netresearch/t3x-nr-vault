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
     * Create the secret, only when no secret of that name exists (CreateSecret
     * fails on an existing name, so there is no window).
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
     * Put the fields back as a new version, but only while the current version
     * is still the given one, to take back a write of this call. The id is read
     * immediately before the write; AWS has no conditional put, so a write
     * landing in that gap is not detected.
     *
     * @param array<string, mixed> $data
     *
     * @return bool False when somebody wrote since, or the secret is gone
     */
    public function restoreIfCurrent(string $identifier, array $data, string $versionId): bool;

    /**
     * Delete the secret, but only while the current version is still the given
     * one, to take back a create of this call. Same gap as
     * {@see restoreIfCurrent()}.
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
