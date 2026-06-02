<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Controller;

use Netresearch\NrVault\Controller\SecretsController;
use Netresearch\NrVault\Domain\Dto\SecretDetails;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

/**
 * Functional tests for SecretsController.
 *
 * Tests the backend module controller for secrets management.
 * These tests verify that the controller's dependencies are properly configured
 * and that the underlying services work correctly.
 */
#[CoversClass(SecretsController::class)]
final class SecretsControllerTest extends AbstractVaultFunctionalTestCase
{
    private const REASON_TEST_CLEANUP = 'Test cleanup';

    protected ?string $backendUserFixture = __DIR__ . '/../Hook/Fixtures/be_users.csv';

    #[Test]
    public function vaultServiceIsInjectable(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);

        self::assertInstanceOf(VaultServiceInterface::class, $vaultService);
    }

    #[Test]
    public function vaultServiceCanStoreAndRetrieveSecrets(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = $this->generateUuidV7();
        $secretValue = 'test-secret-value';

        $vaultService->store($identifier, $secretValue);
        $retrieved = $vaultService->retrieve($identifier);

        self::assertSame($secretValue, $retrieved);

        // Cleanup
        $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
    }

    #[Test]
    public function vaultServiceCanListSecrets(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier1 = $this->generateUuidV7();
        $identifier2 = $this->generateUuidV7();

        $vaultService->store($identifier1, 'secret-1');
        $vaultService->store($identifier2, 'secret-2');

        $list = $vaultService->list();

        self::assertIsArray($list);
        self::assertGreaterThanOrEqual(2, \count($list));

        // Cleanup
        $vaultService->delete($identifier1, self::REASON_TEST_CLEANUP);
        $vaultService->delete($identifier2, self::REASON_TEST_CLEANUP);
    }

    #[Test]
    public function vaultServiceCanDeleteSecrets(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = $this->generateUuidV7();

        $vaultService->store($identifier, 'to-be-deleted');
        self::assertTrue($vaultService->exists($identifier));

        $vaultService->delete($identifier, 'Test deletion');
        self::assertFalse($vaultService->exists($identifier));
    }

    #[Test]
    public function vaultServiceCanRotateSecrets(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = $this->generateUuidV7();

        $vaultService->store($identifier, 'original-secret');
        $vaultService->rotate($identifier, 'rotated-secret', 'Test rotation');

        $retrieved = $vaultService->retrieve($identifier);
        self::assertSame('rotated-secret', $retrieved);

        // Cleanup
        $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
    }

    #[Test]
    public function vaultServiceReturnsMetadata(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = $this->generateUuidV7();

        $vaultService->store($identifier, 'secret-with-metadata');

        $metadata = $vaultService->getMetadata($identifier);

        self::assertInstanceOf(SecretDetails::class, $metadata);
        self::assertSame($identifier, $metadata->identifier);
        self::assertSame(1, $metadata->version);

        // Cleanup
        $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
    }
}
