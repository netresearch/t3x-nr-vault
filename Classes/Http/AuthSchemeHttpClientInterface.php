<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Http;

/**
 * Additive calling capability: configure the primary authentication with an
 * `AuthScheme` value object instead of a placement and an options array
 * (ADR-056). Consumers feature-detect; existing implementations remain valid.
 */
interface AuthSchemeHttpClientInterface extends VaultHttpClientInterface
{
    /**
     * Create a new client instance whose requests carry the secret as the
     * scheme describes.
     *
     * Returns a new immutable instance - the original is unchanged. The audit
     * reason, timeout, pinned addresses and additional body credentials of
     * this instance carry over; an OAuth configuration does not.
     *
     * @param string     $secretIdentifier Vault identifier for the secret
     * @param AuthScheme $scheme           Placement and its options
     *
     * @return static New client instance with authentication configured
     */
    public function withAuthScheme(string $secretIdentifier, AuthScheme $scheme): static;
}
