<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use Netresearch\NrVault\Exception\MasterKeyException;

/**
 * Base class for master key providers implementing the ADR-020
 * request-lifetime caching contract once, in a single place.
 *
 * Subclasses implement only loadRawKey() (the source-specific key load) plus
 * their getIdentifier()/isAvailable()/storeMasterKey()/generateMasterKey()
 * specifics. The security-critical cache lifecycle — caching, late-static-bound
 * per-class isolation, and sodium_memzero() on clear — lives here so a future
 * hardening change is made in exactly one file.
 *
 * The cache is keyed by static::class so each concrete provider keeps its own
 * slot: clearing the file provider's cache must not touch the environment
 * provider's. See ADR-020.
 *
 * Destructor-based wiping is intentionally NOT defined here: File/Env providers
 * declare their own __destruct() that calls clearCachedKey(), while the default
 * Typo3 provider deliberately has none (its static reference outlives individual
 * instances). See ADR-020.
 */
abstract class AbstractMasterKeyProvider implements MasterKeyProviderInterface
{
    /**
     * Request-lifetime cache, isolated per concrete provider class.
     *
     * @var array<class-string, string>
     */
    private static array $cachedKeys = [];

    final public function getMasterKey(): string
    {
        $class = static::class;

        if (isset(self::$cachedKeys[$class])) {
            return self::$cachedKeys[$class];
        }

        $key = $this->loadRawKey();
        self::$cachedKeys[$class] = $key;

        return $key;
    }

    public static function clearCachedKey(): void
    {
        $class = static::class;

        if (!isset(self::$cachedKeys[$class])) {
            return;
        }

        // Wipe a local copy by reference so the by-ref sodium_memzero() does not
        // operate on the typed array slot (which would widen its value type to
        // string|null), then drop the slot entirely.
        $key = self::$cachedKeys[$class];
        unset(self::$cachedKeys[$class]);
        sodium_memzero($key);
    }

    /**
     * Load the raw master key from the provider's source.
     *
     * Called at most once per request per concrete provider class; the result
     * is cached by getMasterKey(). Implementations must return the 32-byte raw
     * key (deriving/decoding as needed).
     *
     * @throws MasterKeyException
     */
    abstract protected function loadRawKey(): string;
}
