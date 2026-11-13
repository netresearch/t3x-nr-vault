<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Storage\HashiCorp;

use Netresearch\NrVault\Adapter\LocalEncryptionAdapter;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Exception\HashiCorpException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\ConnectionPool;

use function is_array;

/**
 * What the adapter refuses, and what it keeps out of every message.
 */
final class HashiCorpAdapterSafetyTest extends AbstractHashiCorpContainerTestCase
{
    private const WRONG_TOKEN = 'hvs.wrong-token-that-must-not-be-echoed';

    #[Test]
    public function aRejectedTokenFailsBeforeAnyRowIsWritten(): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);

        $failure = $this->thrownBy(static fn () => $service->store($identifier, 'must-not-persist'));

        self::assertInstanceOf(HashiCorpException::class, $failure);
        self::assertSame(1794400006, $failure->getCode());
        self::assertSame(0, $this->countRows($identifier), 'Vault is written first, so no row exists');
    }

    #[Test]
    public function neitherTheSecretNorTheTokenAppearsInTheFailure(): void
    {
        $plaintext  = 'plaintext-' . bin2hex(random_bytes(8));
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);

        $failure = $this->thrownBy(static fn () => $service->store($identifier, $plaintext));

        $text = $failure->getMessage() . $failure->getTraceAsString();
        self::assertStringNotContainsString($plaintext, $text);
        self::assertStringNotContainsString(self::WRONG_TOKEN, $text);
    }

    #[Test]
    public function aLoopbackAddressIsRefusedUnlessTheHostIsListed(): void
    {
        $this->changeHashiCorpSettings(['token' => $this->server->limitedToken()]);
        $this->setHttpConfiguration(['allowed_hosts' => []]);

        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);

        $failure = $this->thrownBy(static fn () => $service->store($identifier, 'value'));

        self::assertInstanceOf(HashiCorpException::class, $failure);
        self::assertSame(1794400007, $failure->getCode(), 'the secure client refuses the unlisted loopback address');
        self::assertSame(0, $this->countRows($identifier));
    }

    #[Test]
    public function plainHttpIsRefusedUnlessTheOperatorOptedIn(): void
    {
        $this->changeHashiCorpSettings(['allowInsecureHttp' => '0']);
        $service = $this->get(VaultServiceInterface::class);

        $failure = $this->thrownBy(fn () => $service->store($this->newIdentifier(), 'value'));

        self::assertInstanceOf(HashiCorpException::class, $failure);
        self::assertSame(1794400002, $failure->getCode());
    }

    #[Test]
    public function aSecretStoredLocallyBeforeTheSwitchStaysLocalAndNewOnesGoToVault(): void
    {
        $this->changeHashiCorpSettings(['token' => $this->server->limitedToken()]);

        $legacy    = $this->newIdentifier();
        $encrypted = $this->get(EncryptionServiceInterface::class)->encrypt('legacy-value', $legacy);
        $this->get(LocalEncryptionAdapter::class)->store(
            (new Secret(identifier: $legacy, ownerUid: 1))->withValueRotation($encrypted, time()),
        );

        $service = $this->get(VaultServiceInterface::class);

        self::assertSame('legacy-value', $service->retrieve($legacy));
        $service->rotate($legacy, 'legacy-rotated');

        self::assertSame('local', $this->row($legacy)['adapter']);
        self::assertSame('legacy-rotated', $service->retrieve($legacy));
        self::assertNull($this->server->storedData($legacy), 'a local secret never reaches Vault');

        $fresh = $this->newIdentifier();
        $service->store($fresh, 'fresh-value');

        self::assertSame('hashicorp', $this->row($fresh)['adapter']);
        self::assertNotNull($this->server->storedData($fresh));
    }

    protected function authSettings(VaultDevServer $server): array
    {
        return [
            'authMethod'  => 'token',
            'token'       => self::WRONG_TOKEN,
            'tokenEnvVar' => 'NR_VAULT_TEST_UNSET_VAULT_TOKEN',
        ];
    }

    private function countRows(string $identifier): int
    {
        return (int) $this->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_secret')
            ->count('*', 'tx_nrvault_secret', ['identifier' => $identifier]);
    }

    /**
     * @param array<string, mixed> $values
     */
    private function setHttpConfiguration(array $values): void
    {
        $confVars = $GLOBALS['TYPO3_CONF_VARS'];
        self::assertIsArray($confVars);
        $http = is_array($confVars['HTTP'] ?? null) ? $confVars['HTTP'] : [];

        $confVars['HTTP']           = array_replace($http, $values);
        $GLOBALS['TYPO3_CONF_VARS'] = $confVars;
    }
}
