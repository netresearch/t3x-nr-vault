<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use Netresearch\NrVault\Exception\ConfigurationException;

/**
 * Look-up of master key providers by their identifier.
 *
 * Implementations collect every service tagged `nr_vault.master_key_provider`
 * and index it under {@see MasterKeyProviderInterface::getIdentifier()}, which
 * is the single source of truth for the name `masterKeyProvider` selects. This
 * interface is for CALLING, not for implementing: a consuming extension plugs
 * in a key source by implementing {@see MasterKeyProviderInterface} and
 * tagging it, never by replacing the registry.
 */
interface MasterKeyProviderRegistryInterface
{
    /**
     * The provider registered under `$identifier`.
     *
     * @throws ConfigurationException If no provider carries this identifier, or
     *                                if the registered set is ambiguous
     */
    public function get(string $identifier): MasterKeyProviderInterface;

    /**
     * Whether a provider is registered under `$identifier`.
     *
     * @throws ConfigurationException If the registered set is ambiguous
     */
    public function has(string $identifier): bool;

    /**
     * Every registered identifier, in registration order.
     *
     * @throws ConfigurationException If the registered set is ambiguous
     *
     * @return list<string>
     */
    public function getIdentifiers(): array;

    /**
     * Fail unless every registered provider carries a distinct, non-blank
     * identifier.
     *
     * Callers that swallow {@see ConfigurationException} to reach a fallback
     * MUST run this first: an ambiguous registration is a question about which
     * key source protects the vault, and answering it by falling back would
     * silently swap the master key.
     *
     * @throws ConfigurationException
     */
    public function assertNoIdentifierConflicts(): void;
}
