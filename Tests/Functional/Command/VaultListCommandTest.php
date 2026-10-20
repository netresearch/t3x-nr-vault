<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Command;

use Netresearch\NrVault\Command\VaultListCommand;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Tester\CommandTester;
use Throwable;

use function count;

/**
 * Functional tests for VaultListCommand end-to-end via CommandTester.
 *
 * Each test wraps the store/assert/delete sequence in `try { ... } finally
 * { ... }` so cleanup runs even when an assertion throws.
 */
#[CoversClass(VaultListCommand::class)]
final class VaultListCommandTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../Fixtures/Users/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 1,
    ];

    #[Test]
    public function listCommandShowsStoredSecrets(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $prefix       = 'cmd_list_show_' . bin2hex(random_bytes(4));
        $id1          = $prefix . '_s1';
        $id2          = $prefix . '_s2';
        $vaultService->store($id1, 'value1');
        $vaultService->store($id2, 'value2');

        try {
            $command = $this->get(VaultListCommand::class);
            $tester  = new CommandTester($command);

            $exitCode = $tester->execute([]);

            self::assertSame(0, $exitCode, $tester->getDisplay());
            $output = $tester->getDisplay();
            self::assertStringContainsString($id1, $output);
            self::assertStringContainsString($id2, $output);
        } finally {
            $this->safeDelete($vaultService, $id1);
            $this->safeDelete($vaultService, $id2);
        }
    }

    #[Test]
    public function listCommandWithJsonFormatOutputsValidJson(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier   = 'cmd_list_json_' . bin2hex(random_bytes(4));
        $vaultService->store($identifier, 'json-list-value');

        try {
            $command = $this->get(VaultListCommand::class);
            $tester  = new CommandTester($command);

            $exitCode = $tester->execute(['--format' => 'json']);

            self::assertSame(0, $exitCode, $tester->getDisplay());
            $json = json_decode($tester->getDisplay(), true);
            self::assertIsArray($json, 'JSON output must be parseable');
        } finally {
            $this->safeDelete($vaultService, $identifier);
        }
    }

    #[Test]
    public function listCommandWithCsvFormatOutputsCsvHeader(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier   = 'cmd_list_csv_' . bin2hex(random_bytes(4));
        $vaultService->store($identifier, 'csv-list-value');

        try {
            $command = $this->get(VaultListCommand::class);
            $tester  = new CommandTester($command);

            $exitCode = $tester->execute(['--format' => 'csv']);

            self::assertSame(0, $exitCode, $tester->getDisplay());
            self::assertStringContainsString('identifier', $tester->getDisplay());
        } finally {
            $this->safeDelete($vaultService, $identifier);
        }
    }

    #[Test]
    public function listCommandOutputsInfoMessageWhenNoSecretsExist(): void
    {
        // No secrets stored in this test — nothing to clean up.
        $command = $this->get(VaultListCommand::class);
        $tester  = new CommandTester($command);

        $exitCode = $tester->execute([]);

        self::assertSame(0, $exitCode, 'Must succeed even with no secrets');
        // Output should contain some indication of empty list
        self::assertStringContainsString('No secrets found', $tester->getDisplay());
    }

    #[Test]
    public function listCommandRespectsLimitOption(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $prefix       = 'cmd_list_limit_' . bin2hex(random_bytes(4));
        $ids          = [];
        for ($i = 0; $i < 5; ++$i) {
            $id    = $prefix . '_s' . $i;
            $ids[] = $id;
            $vaultService->store($id, 'value' . $i);
        }

        try {
            $command = $this->get(VaultListCommand::class);
            $tester  = new CommandTester($command);

            $exitCode = $tester->execute(['--limit' => '2', '--format' => 'json']);

            self::assertSame(0, $exitCode, $tester->getDisplay());
            $json = json_decode($tester->getDisplay(), true);
            self::assertIsArray($json);
            self::assertLessThanOrEqual(2, count($json), 'Limit option must cap the number of results');
        } finally {
            foreach ($ids as $id) {
                $this->safeDelete($vaultService, $id);
            }
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
