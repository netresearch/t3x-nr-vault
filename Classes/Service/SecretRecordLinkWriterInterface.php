<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service;

use Netresearch\NrVault\Exception\VaultException;

/**
 * Adds the record link to a secret its caller has just created.
 *
 * The migrations store a secret without its link and add the link only once
 * the row verifiably holds the identifier, so a secret kept after a failed
 * write is invisible to orphan cleanup. The link is metadata of that
 * creation: it needs the permission the creation needed (secret.create), not
 * the one an update of the value needs (secret.rotate).
 *
 * @internal the seam the field migration links its secrets through
 */
interface SecretRecordLinkWriterInterface
{
    /**
     * Merge $link into the metadata of the secret, audited as a metadata
     * update. Refused unless the actor may write the secret and holds
     * secret.create, and unless the secret's metadata is still exactly
     * $createdMetadata, i.e. the secret is as the caller created it.
     *
     * @param array<string, mixed> $createdMetadata
     * @param array<string, mixed> $link
     *
     * @throws VaultException
     */
    public function linkCreatedSecret(string $identifier, array $createdMetadata, array $link): void;
}
