<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Storage\HashiCorp;

use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Exception\HashiCorpException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use PHPUnit\Framework\Attributes\Test;

/**
 * The cases every auth method must pass against a real Vault, through the real
 * VaultService and database. Each concrete class runs them under one method, so
 * "approle and kubernetes work" is a statement about the same behaviour token
 * auth has, not a lighter check.
 */
abstract class AbstractHashiCorpAuthMethodTestCase extends AbstractHashiCorpContainerTestCase
{
    #[Test]
    public function aSecretRoundTripsThroughVaultAndTheRowKeepsNoEnvelope(): void
    {
        $identifier = $this->newIdentifier();
        $plaintext  = 'correct-horse-' . bin2hex(random_bytes(8));

        $service = $this->get(VaultServiceInterface::class);
        $service->store($identifier, $plaintext);

        self::assertSame($plaintext, $service->retrieve($identifier));

        $row = $this->row($identifier);
        self::assertSame('hashicorp', $row['adapter']);
        self::assertSame('secret/data/typo3/' . $identifier, $row['external_reference']);
        self::assertContains($row['encrypted_value'], [null, ''], 'the database row holds no ciphertext');
        self::assertSame('', $row['encrypted_dek']);
        self::assertSame('', $row['value_checksum']);

        $stored = $this->server->storedData($identifier);
        self::assertNotNull($stored, 'Vault holds the key');
        $raw = (string) json_encode($stored);
        self::assertStringNotContainsString($plaintext, $raw, 'Vault holds ciphertext, not the secret');
        self::assertStringNotContainsString(base64_encode($plaintext), $raw);
        self::assertArrayHasKey('encrypted_value', $stored);
    }

    #[Test]
    public function everyOperationIsAuditedAndTheChainStaysValid(): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);
        $audit      = $this->get(AuditLogServiceInterface::class);

        $service->store($identifier, 'first-value');
        $service->retrieve($identifier);
        $service->rotate($identifier, 'second-value');
        $service->delete($identifier);

        self::assertGreaterThanOrEqual(4, $audit->count());
        self::assertTrue($audit->verifyHashChain()->isValid());
    }

    #[Test]
    public function rotatingWritesANewVaultVersion(): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);

        $service->store($identifier, 'first-value');
        $service->rotate($identifier, 'second-value');

        self::assertSame('second-value', $service->retrieve($identifier));
        self::assertSame(2, $this->server->currentVersion($identifier));
    }

    #[Test]
    public function deletingRemovesTheVaultKeyWithItsVersionsAndTheRow(): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);

        $service->store($identifier, 'first-value');
        $service->rotate($identifier, 'second-value');
        $service->delete($identifier);

        self::assertFalse($service->exists($identifier));
        self::assertSame(0, $this->server->currentVersion($identifier), 'no version survives in Vault');
    }

    #[Test]
    public function aDisabledSecretIsWithheldAndComesBackIntact(): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);
        $service->store($identifier, 'kept-value');

        $service->setEnabled($identifier, false);
        self::assertNull($service->retrieve($identifier));

        $service->setEnabled($identifier, true);
        self::assertSame('kept-value', $service->retrieve($identifier));
    }

    #[Test]
    public function aRowWhoseVaultKeyWasRemovedIsReportedAndCanBeRepaired(): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);
        $service->store($identifier, 'lost-value');

        $this->server->admin('DELETE', '/v1/secret/metadata/typo3/' . $identifier);

        $failure = $this->thrownBy(static fn () => $service->retrieve($identifier));
        self::assertInstanceOf(HashiCorpException::class, $failure, 'a row without its Vault key must not read as an empty secret');
        self::assertSame(1794400009, $failure->getCode());

        $service->rotate($identifier, 'restored-value');

        self::assertSame('restored-value', $service->retrieve($identifier));
    }

    #[Test]
    public function aRevokedTokenIsHandledAccordingToTheAuthMethod(): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);
        $service->store($identifier, 'kept-value');

        self::assertGreaterThan(0, $this->server->revokeAllExtensionTokens());

        if ($this->refreshesAfterRevocation()) {
            self::assertSame('kept-value', $service->retrieve($identifier), 'a new login replaces the revoked token');

            return;
        }

        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400006);

        $service->retrieve($identifier);
    }

    /**
     * Whether a revoked login token is replaced by a new login. Only a login
     * based method can do that; a configured token has nothing to fall back on.
     */
    abstract protected function refreshesAfterRevocation(): bool;
}
