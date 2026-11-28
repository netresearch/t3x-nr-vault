<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Adapter;

use Netresearch\NrVault\Domain\Model\Secret;

/**
 * An adapter that can return a secret's registry row (owner, groups,
 * metadata) without contacting the backend that holds its value.
 *
 * {@see \Netresearch\NrVault\Service\VaultService} uses it where only the row
 * matters, so that an unreachable HashiCorp Vault or AWS Secrets Manager does
 * not fail an operation on the row alone. Without it, the service falls back
 * to {@see VaultAdapterInterface::retrieveIncludingDisabled()}.
 *
 * @internal
 */
interface RegistryRowReaderInterface
{
    /**
     * The registry row of a secret, disabled ones included, never with its
     * value or envelope. A secret removed for good stays invisible.
     */
    public function retrieveRegistryRow(string $identifier): ?Secret;
}
