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

    /**
     * Two master key providers answer to the same identifier.
     *
     * Fatal rather than resolved by precedence: whichever provider won would
     * decide which key source protects the vault, and that is an operator's
     * decision, not load order's. Both class names are named so the colliding
     * extension can be identified; neither carries key material.
     */
    public static function duplicateProviderIdentifier(
        string $identifier,
        string $registeredClass,
        string $conflictingClass,
    ): self {
        return new self(
            \sprintf(
                'Master key provider identifier "%s" is claimed by two providers: %s and %s. '
                . 'Refusing to choose between them — an identifier decides which key source protects '
                . 'the vault. Change the identifier of the extension-supplied provider, or remove it.',
                $identifier,
                $registeredClass,
                $conflictingClass,
            ),
            1789430001,
        );
    }

    /**
     * A registered master key provider returns a blank identifier.
     *
     * Refused because `masterKeyProvider` is a plain string setting: a provider
     * naming itself "" would be selected by an unset value, which is what an
     * installation has before anybody chooses a provider.
     */
    public static function blankProviderIdentifier(string $providerClass): self
    {
        return new self(
            \sprintf(
                'Master key provider %s returns a blank identifier. A provider must return a '
                . 'non-empty identifier from getIdentifier(); the empty value is what an '
                . 'unconfigured installation carries and must never select a provider.',
                $providerClass,
            ),
            1789430002,
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
