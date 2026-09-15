<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto\Fixtures;

use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use SensitiveParameter;

/**
 * Shared skeleton for the registry's test-only providers.
 *
 * Unlike {@see AbstractFakeMasterKeyProvider}, this one implements
 * {@see MasterKeyProviderInterface} directly rather than extending
 * `AbstractMasterKeyProvider`: the registry is reached by a consuming extension
 * through the published interface, and the tests say so by using nothing else.
 * The identifier is constructor-injected because the registry indexes by what
 * `getIdentifier()` returns, so a test names it per case.
 *
 * Two concrete subclasses exist — {@see FirstThirdPartyMasterKeyProvider} and
 * {@see SecondThirdPartyMasterKeyProvider} — and they exist for one reason: an
 * anonymous class is compiled once per DECLARATION site, so two calls to one
 * factory method yield the same class name. A collision test asserting that the
 * exception names both providers would then compare the identical string twice
 * and pass even if only one were named. Distinct classes make that assertion
 * load-bearing, and their names are readable where an anonymous class name
 * carries a NUL byte.
 */
abstract class AbstractThirdPartyMasterKeyProvider implements MasterKeyProviderInterface
{
    public function __construct(private readonly string $identifier) {}

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function isAvailable(): bool
    {
        return true;
    }

    public function getMasterKey(): string
    {
        return str_repeat('k', 32);
    }

    public function storeMasterKey(#[SensitiveParameter] string $key): void
    {
        // Deliberately does not persist: these providers are only ever asked
        // which identifier they claim, never to survive a rotation.
    }

    public function generateMasterKey(): string
    {
        return str_repeat('n', 32);
    }

    public static function clearCachedKey(): void
    {
        // Nothing is cached: getMasterKey() returns a constant, so there is no
        // request-lifetime slot to wipe.
    }
}
