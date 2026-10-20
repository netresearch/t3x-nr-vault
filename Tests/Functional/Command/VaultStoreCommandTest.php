<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Command;

use Netresearch\NrVault\Command\VaultStoreCommand;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Tester\CommandTester;
use Throwable;

/**
 * Functional tests for VaultStoreCommand end-to-end via CommandTester.
 *
 * Each test wraps the store-then-assert-then-delete sequence in
 * `try { ... } finally { ... }` so cleanup runs even when an assertion
 * throws. Without that guarantee a failing test leaks the secret into
 * the next test's DB state and turns one red test into many.
 */
#[CoversClass(VaultStoreCommand::class)]
final class VaultStoreCommandTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../Fixtures/Users/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 1,
    ];

    #[Test]
    public function storeCommandPersistsSecretInVault(): void
    {
        $identifier   = 'cmd_store_test_' . bin2hex(random_bytes(4));
        $vaultService = $this->get(VaultServiceInterface::class);
        $command      = $this->get(VaultStoreCommand::class);
        $tester       = new CommandTester($command);

        try {
            $exitCode = $tester->execute([
                'identifier' => $identifier,
                '--value'    => 'my-stored-secret',
            ]);

            self::assertSame(0, $exitCode, $tester->getDisplay());

            // Verify it was actually stored
            $retrieved = $vaultService->retrieve($identifier);
            self::assertSame('my-stored-secret', $retrieved);
        } finally {
            $this->safeDelete($vaultService, $identifier);
        }
    }

    #[Test]
    public function storeCommandOutputsSuccessMessage(): void
    {
        $identifier   = 'cmd_store_sucmsg_' . bin2hex(random_bytes(4));
        $vaultService = $this->get(VaultServiceInterface::class);
        $command      = $this->get(VaultStoreCommand::class);
        $tester       = new CommandTester($command);

        try {
            $tester->execute([
                'identifier' => $identifier,
                '--value'    => 'success-message-test',
            ]);

            self::assertStringContainsString('stored successfully', $tester->getDisplay());
        } finally {
            $this->safeDelete($vaultService, $identifier);
        }
    }

    #[Test]
    public function storeCommandReturnsFailureWhenNoValueProvided(): void
    {
        $identifier = 'cmd_store_noval_' . bin2hex(random_bytes(4));
        $command    = $this->get(VaultStoreCommand::class);
        $tester     = new CommandTester($command);

        // Run with no --value and non-interactive (no prompt).
        // No cleanup needed — the command fails before storing anything.
        $exitCode = $tester->execute(
            ['identifier' => $identifier],
            ['interactive' => false],
        );

        self::assertSame(1, $exitCode, 'Command must fail when no secret value is provided');
    }

    #[Test]
    public function storeCommandWithMetadataStoresWithOptions(): void
    {
        $identifier   = 'cmd_store_withmeta_' . bin2hex(random_bytes(4));
        $vaultService = $this->get(VaultServiceInterface::class);
        $command      = $this->get(VaultStoreCommand::class);
        $tester       = new CommandTester($command);

        try {
            $exitCode = $tester->execute([
                'identifier' => $identifier,
                '--value'    => 'metadata-secret',
                '--metadata' => ['env=production', 'owner=ci'],
            ]);

            self::assertSame(0, $exitCode, $tester->getDisplay());

            // Verify the secret is retrievable
            $retrieved = $vaultService->retrieve($identifier);
            self::assertSame('metadata-secret', $retrieved);
        } finally {
            $this->safeDelete($vaultService, $identifier);
        }
    }

    #[Test]
    public function storeCommandReadsValueFromFile(): void
    {
        $secretFile = $this->instancePath . '/test-secret.txt';
        file_put_contents($secretFile, 'file-based-secret');
        chmod($secretFile, 0o600);

        $identifier   = 'cmd_store_fromfile_' . bin2hex(random_bytes(4));
        $vaultService = $this->get(VaultServiceInterface::class);
        $command      = $this->get(VaultStoreCommand::class);
        $tester       = new CommandTester($command);

        try {
            $exitCode = $tester->execute([
                'identifier' => $identifier,
                '--file'     => $secretFile,
            ]);

            self::assertSame(0, $exitCode, $tester->getDisplay());

            $retrieved = $vaultService->retrieve($identifier);
            self::assertSame('file-based-secret', $retrieved);
        } finally {
            $this->safeDelete($vaultService, $identifier);
            if (file_exists($secretFile)) {
                // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
                unlink($secretFile);
            }
        }
    }

    /**
     * Delete a secret by identifier; swallow failures so the cleanup path
     * stays idempotent even when the test failed before the secret was
     * stored. Any underlying error in delete() would mask the original
     * assertion failure, which is rarely useful.
     */
    private function safeDelete(VaultServiceInterface $vaultService, string $identifier): void
    {
        try {
            if ($vaultService->exists($identifier)) {
                $vaultService->delete($identifier, 'test cleanup');
            }
        } catch (Throwable) {
            // best-effort cleanup
        }
    }
}
