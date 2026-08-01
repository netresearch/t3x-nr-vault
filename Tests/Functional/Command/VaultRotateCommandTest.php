<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Command;

use Netresearch\NrVault\Command\VaultRotateCommand;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Tester\CommandTester;
use Throwable;

/**
 * Functional tests for VaultRotateCommand end-to-end via CommandTester.
 *
 * Each test wraps the store/assert/delete sequence in `try { ... } finally
 * { ... }` so cleanup runs even when an assertion throws.
 */
#[CoversClass(VaultRotateCommand::class)]
final class VaultRotateCommandTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../Fixtures/Users/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 1,
    ];

    #[Test]
    public function rotateCommandUpdatesSecretValue(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = 'cmd_rotate_update_' . bin2hex(random_bytes(4));
        $vaultService->store($identifier, 'original-value');

        try {
            $command = $this->get(VaultRotateCommand::class);
            $tester = new CommandTester($command);

            $exitCode = $tester->execute([
                'identifier' => $identifier,
                '--value' => 'rotated-value',
                '--reason' => 'Test rotation',
            ]);

            self::assertSame(0, $exitCode, $tester->getDisplay());

            // Verify the secret was updated
            $retrieved = $vaultService->retrieve($identifier);
            self::assertSame('rotated-value', $retrieved);
        } finally {
            $this->safeDelete($vaultService, $identifier);
        }
    }

    #[Test]
    public function rotateCommandOutputsSuccessMessage(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = 'cmd_rotate_sucmsg_' . bin2hex(random_bytes(4));
        $vaultService->store($identifier, 'original');

        try {
            $command = $this->get(VaultRotateCommand::class);
            $tester = new CommandTester($command);

            $tester->execute([
                'identifier' => $identifier,
                '--value' => 'new-value',
            ]);

            self::assertStringContainsString('rotated successfully', $tester->getDisplay());
        } finally {
            $this->safeDelete($vaultService, $identifier);
        }
    }

    #[Test]
    public function rotateCommandFailsForNonExistentSecret(): void
    {
        $command = $this->get(VaultRotateCommand::class);
        $tester = new CommandTester($command);

        $exitCode = $tester->execute([
            'identifier' => 'nonexistent_' . bin2hex(random_bytes(4)),
            '--value' => 'some-value',
        ]);

        self::assertSame(1, $exitCode, 'Rotate must fail for non-existent secret');
        self::assertStringContainsString('not found', $tester->getDisplay());
    }

    #[Test]
    public function rotateCommandFailsWhenNoValueProvided(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = 'cmd_rotate_noval_' . bin2hex(random_bytes(4));
        $vaultService->store($identifier, 'original');

        try {
            $command = $this->get(VaultRotateCommand::class);
            $tester = new CommandTester($command);

            $exitCode = $tester->execute(
                ['identifier' => $identifier],
                ['interactive' => false],
            );

            self::assertSame(1, $exitCode, 'Rotate must fail when no new value is provided');
        } finally {
            $this->safeDelete($vaultService, $identifier);
        }
    }

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
