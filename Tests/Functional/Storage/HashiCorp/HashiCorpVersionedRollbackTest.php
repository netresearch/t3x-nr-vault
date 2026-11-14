<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Storage\HashiCorp;

use Netresearch\NrVault\Storage\HashiCorp\HashiCorpKvClient;
use PHPUnit\Framework\Attributes\Test;

/**
 * The rollback is a check-and-set against the version a write created, against
 * a real Vault: nobody who wrote since is overwritten or deleted, and no
 * payload is compared.
 */
final class HashiCorpVersionedRollbackTest extends AbstractHashiCorpContainerTestCase
{
    #[Test]
    public function aRestoreOverAConcurrentWritersVersionChangesNothing(): void
    {
        $identifier = $this->newIdentifier();
        $client     = $this->get(HashiCorpKvClient::class);

        $original = $client->create($identifier, ['data' => 'original']);
        $ours     = $client->writeVersioned($identifier, ['data' => 'ours']);
        $theirs   = $client->writeVersioned($identifier, ['data' => 'theirs']);

        self::assertSame([1, 2, 3], [$original, $ours, $theirs]);
        self::assertFalse($client->restoreIfCurrent($identifier, ['data' => 'original'], $ours), 'somebody wrote after our version');
        self::assertSame(['data' => 'theirs'], $this->server->storedData($identifier));
        self::assertSame(3, $this->server->currentVersion($identifier));
    }

    #[Test]
    public function aRestoreWhileTheKeyIsStillAtOurVersionApplies(): void
    {
        $identifier = $this->newIdentifier();
        $client     = $this->get(HashiCorpKvClient::class);

        $client->create($identifier, ['b' => 'original', 'a' => 'first']);

        $ours = $client->writeVersioned($identifier, ['data' => 'ours']);

        self::assertTrue($client->restoreIfCurrent($identifier, ['b' => 'original', 'a' => 'first'], $ours));
        self::assertEquals(['a' => 'first', 'b' => 'original'], $this->server->storedData($identifier), 'key order does not matter');
    }

    #[Test]
    public function aDestroyOfAKeyThatSomebodyWroteToSinceChangesNothing(): void
    {
        $identifier = $this->newIdentifier();
        $client     = $this->get(HashiCorpKvClient::class);

        $created = $client->create($identifier, ['data' => 'ours']);
        $client->writeVersioned($identifier, ['data' => 'theirs']);

        self::assertFalse($client->destroyIfCurrent($identifier, $created));
        self::assertSame(['data' => 'theirs'], $this->server->storedData($identifier));

        self::assertTrue($client->destroyIfCurrent($identifier, 2));
        self::assertNull($this->server->storedData($identifier));
    }

    protected function authSettings(VaultDevServer $server): array
    {
        return [
            'authMethod'  => 'token',
            'token'       => $server->limitedToken(),
            'tokenEnvVar' => 'NR_VAULT_TEST_UNSET_VAULT_TOKEN',
        ];
    }
}
