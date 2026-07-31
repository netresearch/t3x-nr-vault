<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

/**
 * Thrown when extension configuration is invalid.
 */
final class ConfigurationException extends VaultException
{
    public static function invalidProvider(string $provider): self
    {
        return new self(
            \sprintf('Unknown master key provider: %s', $provider),
            1703800015,
        );
    }

    public static function invalidAdapter(string $adapter): self
    {
        return new self(
            \sprintf('Unknown vault adapter: %s', $adapter),
            1703800016,
        );
    }

    public static function missingConfiguration(string $key): self
    {
        return new self(
            \sprintf('Missing required configuration: %s', $key),
            1703800017,
        );
    }

    public static function invalidSecurityProfile(string $profile): self
    {
        return new self(
            \sprintf(
                'Unknown security profile "%s". Valid profiles: standard, hardened. '
                . 'Refusing to fall back to a weaker profile.',
                $profile,
            ),
            1753900001,
        );
    }

    public static function providerForbiddenInHardenedProfile(string $provider): self
    {
        return new self(
            \sprintf(
                'Master key provider "%s" is not permitted in the hardened security profile. '
                . 'Configure an explicit external provider (file, env) — the TYPO3 encryption '
                . 'key must not protect vault secrets in hardened deployments.',
                $provider,
            ),
            1753900002,
        );
    }
}
