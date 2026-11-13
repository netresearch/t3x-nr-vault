<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Storage\HashiCorp;

use Netresearch\NrVault\Adapter\HashiCorpAdapter;
use Netresearch\NrVault\Adapter\LocalEncryptionAdapter;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Exception\HashiCorpException;
use Netresearch\NrVault\Storage\HashiCorp\AtomicKvStoreInterface;
use Netresearch\NrVault\Storage\HashiCorp\HashiCorpKvClient;
use PHPUnit\Framework\Attributes\Test;

/**
 * A key that somebody else creates in the window between "the path is empty"
 * and the adapter's write, against a real Vault.
 */
final class HashiCorpCreateRaceTest extends AbstractHashiCorpContainerTestCase
{
    #[Test]
    public function aKeyCreatedJustBeforeTheAdaptersCreateIsRefusedNotOverwrittenAndNotDestroyed(): void
    {
        $identifier = $this->newIdentifier();
        $inner      = $this->get(HashiCorpKvClient::class);

        $racing = new class ($inner, $identifier) implements AtomicKvStoreInterface {
            public function __construct(private readonly HashiCorpKvClient $inner, private readonly string $identifier) {}

            public function read(string $identifier): ?array
            {
                return $this->inner->read($identifier);
            }

            public function write(string $identifier, array $data): void
            {
                $this->inner->write($identifier, $data);
            }

            public function create(string $identifier, array $data): void
            {
                // The competing writer wins the race: its key exists before
                // the adapter's create reaches Vault.
                $this->inner->write($this->identifier, ['theirs' => 'somebody-elses-value']);
                $this->inner->create($identifier, $data);
            }

            public function destroy(string $identifier): void
            {
                $this->inner->destroy($identifier);
            }

            public function reference(string $identifier): string
            {
                return $this->inner->reference($identifier);
            }
        };

        $adapter   = new HashiCorpAdapter($this->get(LocalEncryptionAdapter::class), $racing, $this->get(ExtensionConfigurationInterface::class));
        $encrypted = $this->get(EncryptionServiceInterface::class)->encrypt('new-value', $identifier);
        $secret    = (new Secret(identifier: $identifier, ownerUid: 1))->withValueRotation($encrypted, time());

        $failure = $this->thrownBy(static fn (): Secret => $adapter->store($secret));

        self::assertInstanceOf(HashiCorpException::class, $failure);
        self::assertSame(1794400012, $failure->getCode());
        self::assertSame(['theirs' => 'somebody-elses-value'], $this->server->storedData($identifier), 'the competing key is untouched and still there');
        self::assertSame(1, $this->server->currentVersion($identifier), 'no version was added and none removed');
        self::assertFalse($this->get(LocalEncryptionAdapter::class)->exists($identifier), 'no row was written');
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
