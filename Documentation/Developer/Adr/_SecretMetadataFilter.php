<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

use Netresearch\NrVault\Domain\Dto\SecretMetadata;
use Netresearch\NrVault\Service\VaultServiceInterface;

/**
 * Return a callable that filters accessible DTOs by application metadata.
 */
return static function (VaultServiceInterface $vault): array {
    $secrets = $vault->list();

    return array_values(
        array_filter(
            $secrets,
            static fn (
                SecretMetadata $secret,
            ): bool => ($secret->metadata['source'] ?? '') === 'tca_field',
        ),
    );
};
