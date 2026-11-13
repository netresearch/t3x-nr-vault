<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Storage\Aws;

use Netresearch\NrVault\Storage\Aws\AwsSecretStoreInterface;
use PHPUnit\Framework\Attributes\Test;

/**
 * Taking a write back is applied only while the secret is still at the version
 * the write created, against the Secrets Manager emulation.
 */
final class AwsVersionedRollbackTest extends AbstractAwsContainerTestCase
{
    #[Test]
    public function aRestoreOverAConcurrentWritersVersionChangesNothing(): void
    {
        $identifier = $this->newIdentifier();
        $store      = $this->get(AwsSecretStoreInterface::class);

        $store->create($identifier, ['data' => 'original']);

        $ours = $store->write($identifier, ['data' => 'ours']);
        $store->write($identifier, ['data' => 'theirs']);

        self::assertFalse($store->restoreIfCurrent($identifier, ['data' => 'original'], $ours), 'somebody wrote after our version');
        self::assertSame(['data' => 'theirs'], $this->server->storedData($identifier));
        self::assertSame(3, $this->server->versionCount($identifier));
    }

    #[Test]
    public function aRestoreWhileTheSecretIsStillAtOurVersionApplies(): void
    {
        $identifier = $this->newIdentifier();
        $store      = $this->get(AwsSecretStoreInterface::class);

        $store->create($identifier, ['b' => 'original', 'a' => 'first']);

        $ours = $store->write($identifier, ['data' => 'ours']);

        self::assertTrue($store->restoreIfCurrent($identifier, ['b' => 'original', 'a' => 'first'], $ours));
        self::assertEquals(['a' => 'first', 'b' => 'original'], $this->server->storedData($identifier), 'key order does not matter');
    }

    #[Test]
    public function aDestroyOfASecretThatSomebodyWroteToSinceChangesNothing(): void
    {
        $identifier = $this->newIdentifier();
        $store      = $this->get(AwsSecretStoreInterface::class);

        $created = $store->create($identifier, ['data' => 'ours']);
        $theirs  = $store->write($identifier, ['data' => 'theirs']);

        self::assertFalse($store->destroyIfCurrent($identifier, $created));
        self::assertSame(['data' => 'theirs'], $this->server->storedData($identifier));

        self::assertTrue($store->destroyIfCurrent($identifier, $theirs));
        self::assertFalse($this->server->exists($identifier));
    }

    #[Test]
    public function createRefusesAnExistingSecretAndLeavesItAlone(): void
    {
        $identifier = $this->newIdentifier();
        $this->server->createForeign($identifier, 'somebody-elses-value');

        $failure = $this->thrownBy(fn () => $this->get(AwsSecretStoreInterface::class)->create($identifier, ['data' => 'ours']));

        self::assertSame(1794500012, $failure->getCode());
        self::assertSame('somebody-elses-value', $this->server->rawValue($identifier));
    }
}
