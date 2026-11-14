<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage;

use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;

/**
 * A stable, non-reversible marker of this installation, derived from its master
 * key. The external-store adapters stamp it into what they write and take over
 * an existing object only when the stamp is this installation's, so two
 * installations that share a prefix or a path cannot adopt, and overwrite, each
 * other's secrets. Each installation should still have its own prefix or path.
 */
final readonly class InstallationMarker
{
    public function __construct(
        private MasterKeyProviderInterface $masterKeyProvider,
    ) {}

    public function value(): string
    {
        $masterKey = $this->masterKeyProvider->getMasterKey();

        try {
            return substr(hash_hmac('sha256', 'nr-vault:external-store-installation', $masterKey), 0, 32);
        } finally {
            sodium_memzero($masterKey);
        }
    }
}
