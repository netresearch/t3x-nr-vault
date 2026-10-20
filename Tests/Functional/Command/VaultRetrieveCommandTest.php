<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Command;

use Netresearch\NrVault\Command\VaultRetrieveCommand;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Tester\CommandTester;
use Throwable;

/**
 * Functional tests for VaultRetrieveCommand end-to-end via CommandTester.
 *
 * Each test wraps the store/assert/delete sequence in `try { ... } finally
 * { ... }` so cleanup runs even when an assertion throws (see the sibling
 * `VaultStoreCommandTest` for the rationale).
 */
#[CoversClass(VaultRetrieveCommand::class)]
final class VaultRetrieveCommandTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../Fixtures/Users/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 1,
    ];

    #[Test]
    public function retrieveCommandOutputsSecretToStdout(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier   = 'cmd_retrieve_stdout_' . bin2hex(random_bytes(4));
        $vaultService->store($identifier, 'retrieve-me-value');

        try {
            $command = $this->get(VaultRetrieveCommand::class);
            $tester  = new CommandTester($command);

            $exitCode = $tester->execute(['identifier' => $identifier]);

            self::assertSame(0, $exitCode, $tester->getDisplay());
            self::assertStringContainsString('retrieve-me-value', $tester->getDisplay());
        } finally {
            $this->safeDelete($vaultService, $identifier);
        }
    }

    #[Test]
    public function retrieveCommandReturnsFailureForNonExistentSecret(): void
    {
        $command = $this->get(VaultRetrieveCommand::class);
        $tester  = new CommandTester($command);

        $exitCode = $tester->execute(['identifier' => 'nonexistent_secret_' . bin2hex(random_bytes(4))]);

        self::assertSame(1, $exitCode, 'Command must fail for non-existent secret');
        self::assertStringContainsString('not found', $tester->getDisplay());
    }

    #[Test]
    public function retrieveCommandWritesSecretToOutputFile(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier   = 'cmd_retrieve_tofile_' . bin2hex(random_bytes(4));
        $vaultService->store($identifier, 'file-output-secret');

        $outputFile = $this->instancePath . '/retrieved-secret.txt';

        try {
            $command = $this->get(VaultRetrieveCommand::class);
            $tester  = new CommandTester($command);

            $exitCode = $tester->execute([
                'identifier' => $identifier,
                '--output'   => $outputFile,
            ]);

            self::assertSame(0, $exitCode, $tester->getDisplay());
            self::assertFileExists($outputFile);
            self::assertSame('file-output-secret', file_get_contents($outputFile));
        } finally {
            $this->safeDelete($vaultService, $identifier);
            if (file_exists($outputFile)) {
                // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
                unlink($outputFile);
            }
        }
    }

    #[Test]
    public function retrieveCommandCreatesAuditLogEntry(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier   = 'cmd_retrieve_audit_' . bin2hex(random_bytes(4));
        $vaultService->store($identifier, 'audit-check-value');

        try {
            $command = $this->get(VaultRetrieveCommand::class);
            $tester  = new CommandTester($command);
            $tester->execute(['identifier' => $identifier]);

            // The retrieve operation should have written audit log entries.
            // False positive on opengrep — `$identifier` is bound via
            // createNamedParameter, not string-concatenated into the SQL.
            $connection = $this->getConnectionPool()->getConnectionForTable('tx_nrvault_audit_log');
            $qb         = $connection->createQueryBuilder();
            // nosemgrep: php.doctrine.security.audit.doctrine-orm-dangerous-query.doctrine-orm-dangerous-query
            $count = (int) $qb->count('uid')->from('tx_nrvault_audit_log')->where($qb->expr()->eq('secret_identifier', $qb->createNamedParameter($identifier)))->executeQuery()->fetchOne();

            self::assertGreaterThan(0, $count, 'Retrieve must write to audit log');
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
