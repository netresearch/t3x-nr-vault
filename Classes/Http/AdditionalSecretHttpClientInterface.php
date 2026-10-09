<?php

/* Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later */
declare(strict_types=1);

namespace Netresearch\NrVault\Http;

use InvalidArgumentException;

/**
 * Additive calling capability: combine primary authentication with a
 * separately stored body credential inside one secured request (ADR-041).
 * Consumers feature-detect; existing implementations remain valid.
 */
interface AdditionalSecretHttpClientInterface extends VaultHttpClientInterface
{
    /**
     * Bind an additional Vault identifier to a simple body field.
     * Clones preserve bindings; duplicate/primary collisions and more than
     * eight fields are refused. Secrets never leave Vault's send boundary.
     *
     * @throws InvalidArgumentException For malformed or ambiguous bindings.
     */
    public function withAdditionalBodyField(
        string $secretIdentifier,
        string $bodyField,
    ): static;
}
