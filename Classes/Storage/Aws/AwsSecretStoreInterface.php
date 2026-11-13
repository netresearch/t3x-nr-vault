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
     * Store the fields as a new current version, creating the secret when it
     * does not exist.
     *
     * @param array<string, mixed> $data
     *
     * @throws AwsSecretsManagerException
     */
    public function write(string $identifier, array $data): void;

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
