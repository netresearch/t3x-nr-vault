<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use Netresearch\NrVault\Crypto\AbstractMasterKeyProvider;
use Netresearch\NrVault\Tests\Unit\Crypto\Fixtures\FirstFakeMasterKeyProvider;
use Netresearch\NrVault\Tests\Unit\Crypto\Fixtures\SecondFakeMasterKeyProvider;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(AbstractMasterKeyProvider::class)]
final class AbstractMasterKeyProviderTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        FirstFakeMasterKeyProvider::clearCachedKey();
        SecondFakeMasterKeyProvider::clearCachedKey();
    }

    protected function tearDown(): void
    {
        FirstFakeMasterKeyProvider::clearCachedKey();
        SecondFakeMasterKeyProvider::clearCachedKey();

        parent::tearDown();
    }

    #[Test]
    public function getMasterKeyDelegatesToLoadRawKey(): void
    {
        $provider = new FirstFakeMasterKeyProvider();

        self::assertSame(str_repeat("\xAA", 32), $provider->getMasterKey());
    }

    #[Test]
    public function getMasterKeyLoadsRawKeyOnlyOncePerRequest(): void
    {
        $provider = new FirstFakeMasterKeyProvider();

        $provider->getMasterKey();
        $provider->getMasterKey();
        $provider->getMasterKey();

        self::assertSame(1, $provider->loadCount, 'loadRawKey() must be invoked at most once while cached');
    }

    #[Test]
    public function cacheIsSharedAcrossInstancesOfSameClass(): void
    {
        $first = new FirstFakeMasterKeyProvider();
        $first->getMasterKey();

        // A fresh instance of the same class reuses the cached slot and must not
        // re-load the raw key.
        $second = new FirstFakeMasterKeyProvider();
        $second->getMasterKey();

        self::assertSame(0, $second->loadCount, 'second instance must hit the shared cache, not re-load');
    }

    #[Test]
    public function clearCachedKeyForcesReload(): void
    {
        $provider = new FirstFakeMasterKeyProvider();
        $provider->getMasterKey();
        self::assertSame(1, $provider->loadCount);

        FirstFakeMasterKeyProvider::clearCachedKey();

        $provider->getMasterKey();
        self::assertSame(2, $provider->loadCount, 'clearing the cache must force a reload');
    }

    #[Test]
    public function cacheSlotsAreIsolatedPerConcreteClass(): void
    {
        $first = new FirstFakeMasterKeyProvider();
        $second = new SecondFakeMasterKeyProvider();

        self::assertSame(str_repeat("\xAA", 32), $first->getMasterKey());
        self::assertSame(str_repeat("\xBB", 32), $second->getMasterKey());

        // Clearing one provider's cache must not affect the other's slot.
        FirstFakeMasterKeyProvider::clearCachedKey();

        self::assertSame(str_repeat("\xBB", 32), $second->getMasterKey());
    }
}
