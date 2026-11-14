<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Storage\Aws;

use Netresearch\NrVault\Adapter\LocalEncryptionAdapter;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Exception\AwsSecretsManagerException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Throwable;

/**
 * What the adapter refuses, and what it keeps out of every message.
 */
final class AwsSecretsManagerAdapterSafetyTest extends AbstractAwsContainerTestCase
{
    private const WRONG_SECRET = 'wrong-secret-access-key-that-must-not-be-echoed';

    private const UNKNOWN_KEY_ID = 'AKIAUNKNOWNKEYFORTEST';

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function wrongCredentials(): iterable
    {
        yield 'a known key id with the wrong secret' => ['known', self::WRONG_SECRET];
        yield 'an unknown key id' => [self::UNKNOWN_KEY_ID, self::WRONG_SECRET];
    }

    #[Test]
    #[DataProvider('wrongCredentials')]
    public function rejectedCredentialsFailBeforeAnyRowIsWrittenAndLeakNothing(string $keyId, string $secret): void
    {
        putenv(self::KEY_ID_VARIABLE . '=' . ($keyId === 'known' ? $this->server->keyId : $keyId));
        putenv(self::SECRET_VARIABLE . '=' . $secret);

        $plaintext  = 'plaintext-' . bin2hex(random_bytes(8));
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);

        $failure = $this->thrownBy(static fn () => $service->store($identifier, $plaintext));

        self::assertInstanceOf(AwsSecretsManagerException::class, $failure);
        self::assertSame(1794500006, $failure->getCode(), 'the request was rejected');
        self::assertStringContainsString('HTTP 403', $failure->getMessage());
        self::assertSame(0, $this->countRows($identifier), 'AWS is written first, so no row exists');
        self::assertNull($this->server->storedData($identifier));

        for ($e = $failure; $e instanceof Throwable; $e = $e->getPrevious()) {
            $text = $e->getMessage() . $e->getTraceAsString();
            self::assertStringNotContainsString($plaintext, $text);
            self::assertStringNotContainsString(base64_encode($plaintext), $text);
            self::assertStringNotContainsString(self::WRONG_SECRET, $text);
            self::assertStringNotContainsString($this->server->secretKey, $text);
            self::assertStringNotContainsString(self::UNKNOWN_KEY_ID, $text);
        }

        self::assertNotInstanceOf(Throwable::class, $failure->getPrevious(), 'the SDK exception, which holds the request, is not chained');
    }

    #[Test]
    public function aMissingCredentialIsReportedByNameWithoutAValue(): void
    {
        putenv(self::SECRET_VARIABLE);
        $service = $this->get(VaultServiceInterface::class);

        $failure = $this->thrownBy(fn () => $service->store($this->newIdentifier(), 'value'));

        self::assertInstanceOf(AwsSecretsManagerException::class, $failure);
        self::assertSame(1794500005, $failure->getCode());
        self::assertStringContainsString(self::SECRET_VARIABLE, $failure->getMessage());
    }

    #[Test]
    public function aLoopbackAddressIsRefusedUnlessTheHostIsListed(): void
    {
        $this->setHttpConfiguration(['allowed_hosts' => []]);

        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);

        $failure = $this->thrownBy(static fn () => $service->store($identifier, 'value'));

        self::assertInstanceOf(AwsSecretsManagerException::class, $failure);
        self::assertSame(1794500007, $failure->getCode(), 'the secure client refuses the unlisted loopback address');
        self::assertSame(0, $this->countRows($identifier));
        self::assertNull($this->server->storedData($identifier));
    }

    #[Test]
    public function plainHttpIsRefusedUnlessTheOperatorOptedIn(): void
    {
        $this->changeAwsSettings(['allowInsecureHttp' => '0']);
        $service = $this->get(VaultServiceInterface::class);

        $failure = $this->thrownBy(fn () => $service->store($this->newIdentifier(), 'value'));

        self::assertInstanceOf(AwsSecretsManagerException::class, $failure);
        self::assertSame(1794500003, $failure->getCode());
    }

    #[Test]
    public function aSecretStoredLocallyBeforeTheSwitchStaysLocalAndNewOnesGoToAws(): void
    {
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
        self::assertNull($this->server->storedData($legacy), 'a local secret never reaches AWS');

        $fresh = $this->newIdentifier();
        $service->store($fresh, 'fresh-value');

        self::assertSame('aws', $this->row($fresh)['adapter']);
        self::assertNotNull($this->server->storedData($fresh));
    }
}
