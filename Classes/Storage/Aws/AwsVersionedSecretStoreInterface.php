<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage\Aws;

use Netresearch\NrVault\Exception\AwsSecretsManagerException;

/**
 * A secret store that can take a write back conditionally, by moving the
 * AWSCURRENT label back to the version the write replaced (#567).
 *
 * Separate from {@see AwsSecretStoreInterface}, so an existing implementation
 * of that interface keeps working: the adapter takes the conditional path only
 * when the injected store also implements this one, and otherwise the
 * read-then-write of {@see AwsSecretStoreInterface::restoreIfCurrent()}.
 */
interface AwsVersionedSecretStoreInterface
{
    /**
     * The stored fields and the version id of AWSCURRENT, from one response,
     * or null when the secret does not exist.
     *
     * @return array{data: array<string, mixed>, versionId: string}|null
     *
     * @throws AwsSecretsManagerException
     */
    public function readWithVersion(string $identifier): ?array;

    /**
     * Take back a write of this call by moving AWSCURRENT from the version the
     * write created back to the version it replaced, with
     * UpdateSecretVersionStage. AWS refuses the move when AWSCURRENT is on any
     * other version, so a writer that landed after the write keeps its value.
     *
     * When the move fails, nothing is written: it counts as applied only when
     * two consecutive reads show the version moved back to (the move applied
     * and its answer was lost), and as skipped otherwise. Only a refusal for
     * lack of the permission (AccessDeniedException, or a 403 without an error
     * code) falls back to {@see AwsSecretStoreInterface::restoreIfCurrent()}.
     *
     * @param array<string, mixed> $data The fields of the version the write replaced, for that fallback
     *
     * @return bool True when the write was taken back; false when it was skipped (somebody wrote since, the
     *              secret is gone, or the move failed and did not apply)
     *
     * @throws AwsSecretsManagerException When a read or the fallback fails
     */
    public function restoreToVersionIfCurrent(string $identifier, array $data, string $versionId, string $previousVersionId): bool;
}
