<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Command;

use Doctrine\DBAL\Platforms\SQLitePlatform;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Command\VaultAuditVerifyCommand;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Traits\AuditSinkSandboxTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * End-to-end tests for `vault:audit-verify` through CommandTester.
 *
 * The exit code is the load-bearing contract here: the command is meant to be
 * wired straight into monitoring, so "found a problem" and "could not check" must
 * both be non-zero, and a clean chain must be zero.
 */
#[CoversClass(VaultAuditVerifyCommand::class)]
final class VaultAuditVerifyCommandTest extends AbstractVaultFunctionalTestCase
{
    use AuditSinkSandboxTrait;

    /** Non-admin whose group carries no vault permission at all. */
    private const NO_PERMISSIONS = 2;

    /** Non-admin holding `audit.view` only. */
    private const AUDIT_VIEWER = 3;

    /** Non-admin holding `vault.configure` only. */
    private const VAULT_CONFIGURATOR = 5;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_audit_permission.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 3,
    ];

    protected function setUp(): void
    {
        $this->extensionConfiguration = $this->prepareAuditSinkSandbox($this->extensionConfiguration);

        parent::setUp();
    }

    protected function tearDown(): void
    {
        $this->cleanUpAuditSinkSandbox();

        parent::tearDown();
    }

    #[Test]
    public function anIntactAnchoredChainExitsZero(): void
    {
        $this->seedChain(3);
        $this->publishAnchor();

        $tester = new CommandTester($this->get(VaultAuditVerifyCommand::class));
        $exitCode = $tester->execute([]);

        self::assertSame(Command::SUCCESS, $exitCode, $tester->getDisplay());
        self::assertStringContainsString('verified', $tester->getDisplay());
    }

    /**
     * The end-to-end version of the reset scenario: publish an anchor, wipe the
     * table, re-seed, and confirm the CLI both exits non-zero and names the code.
     */
    #[Test]
    public function aTableResetExitsNonZeroAndNamesTheReasonCode(): void
    {
        $this->seedChain(5);
        $this->publishAnchor();

        $this->resetAuditTable();
        $this->seedChain(2);

        $tester = new CommandTester($this->get(VaultAuditVerifyCommand::class));
        $exitCode = $tester->execute([]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString('TABLE_RESET', $tester->getDisplay());
    }

    #[Test]
    public function jsonOutputCarriesTheReasonCodesAndTheAnchor(): void
    {
        $this->seedChain(4);
        $this->publishAnchor();

        $this->resetAuditTable();
        $this->seedChain(1);

        $tester = new CommandTester($this->get(VaultAuditVerifyCommand::class));
        $exitCode = $tester->execute(['--format' => 'json']);

        self::assertSame(Command::FAILURE, $exitCode);

        $payload = json_decode($tester->getDisplay(), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($payload);
        self::assertFalse($payload['valid']);
        self::assertTrue($payload['tamperEvidence']);
        self::assertIsArray($payload['reasonCodes']);
        self::assertContains('TABLE_RESET', $payload['reasonCodes']);
        self::assertIsArray($payload['anchor']);
        self::assertSame(4, $payload['anchor']['sequence']);
        self::assertContains('file', $payload['enabledSinks']);
    }

    #[Test]
    public function aTamperedRowExitsNonZeroWithHashMismatch(): void
    {
        $this->seedChain(2);

        $this->getAuditConnection()->update(
            AuditLogService::TABLE_NAME,
            ['secret_identifier' => 'rewritten_by_attacker'],
            ['uid' => 1],
        );

        $tester = new CommandTester($this->get(VaultAuditVerifyCommand::class));
        $exitCode = $tester->execute([]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString('HASH_MISMATCH', $tester->getDisplay());
    }

    #[Test]
    public function aDeletedRowExitsNonZeroWithUidGap(): void
    {
        $this->seedChain(4);

        $this->getAuditConnection()->delete(AuditLogService::TABLE_NAME, ['uid' => 2]);

        $tester = new CommandTester($this->get(VaultAuditVerifyCommand::class));
        $exitCode = $tester->execute([]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString('UID_GAP', $tester->getDisplay());
    }

    /**
     * `--tamper-only` must NOT soften a real tamper finding — that would make the
     * flag a way to silence the alarm it exists to preserve.
     */
    #[Test]
    public function tamperOnlyStillFailsOnTamperEvidence(): void
    {
        $this->seedChain(4);
        $this->getAuditConnection()->delete(AuditLogService::TABLE_NAME, ['uid' => 2]);

        $tester = new CommandTester($this->get(VaultAuditVerifyCommand::class));
        $exitCode = $tester->execute(['--tamper-only' => true]);

        self::assertSame(Command::FAILURE, $exitCode);
    }

    /**
     * With no anchor and the standard profile there is nothing to compare against,
     * which is acceptable — sinks are opt-in outside the hardened profile.
     */
    #[Test]
    public function aChainWithoutAnAnchorExitsZeroUnderTheStandardProfile(): void
    {
        $this->seedChain(2);

        $tester = new CommandTester($this->get(VaultAuditVerifyCommand::class));
        $exitCode = $tester->execute([]);

        self::assertSame(Command::SUCCESS, $exitCode, $tester->getDisplay());
        self::assertStringContainsString('none available', $tester->getDisplay());
    }

    #[Test]
    public function outputListsTheEnabledSinks(): void
    {
        $this->seedChain(1);

        $tester = new CommandTester($this->get(VaultAuditVerifyCommand::class));
        $tester->execute([]);

        self::assertStringContainsString('file', $tester->getDisplay());
    }

    /**
     * The gate this pins: the wrapper checks strictly more than
     * `vault:audit --verify` — the external anchor as well as the chain — while
     * asserting nothing, which made the gate on the interactive command a
     * formality. A refusal must run no verification and must not be mistakable
     * for a clean result.
     */
    #[Test]
    public function verificationIsRefusedWithoutAuditView(): void
    {
        $this->seedChain(3);
        $this->publishAnchor();
        $this->setUpBackendUser(self::NO_PERMISSIONS);

        $tester = new CommandTester($this->get(VaultAuditVerifyCommand::class));
        $exitCode = $tester->execute([]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString(
            'Access denied: the "audit.view" permission is required to verify the audit log integrity.',
            $this->normalize($tester),
        );
        self::assertStringNotContainsString('verified', $tester->getDisplay());
    }

    /**
     * A monitor that only reads `valid` must see a refused verification as a
     * failed one, never as an intact chain.
     */
    #[Test]
    public function refusedJsonVerificationReportsInvalid(): void
    {
        $this->seedChain(3);
        $this->publishAnchor();
        $this->setUpBackendUser(self::NO_PERMISSIONS);

        $tester = new CommandTester($this->get(VaultAuditVerifyCommand::class));
        $exitCode = $tester->execute(['--format' => 'json']);

        self::assertSame(Command::FAILURE, $exitCode);

        $payload = json_decode($tester->getDisplay(), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($payload);
        self::assertFalse($payload['valid']);
        self::assertIsString($payload['error']);
        self::assertStringContainsString('audit.view', $payload['error']);
    }

    /**
     * `audit.view` is the whole grant: verification is a read of the chain, so
     * an actor who may see the audit log may also check it for tampering — the
     * same rule `AuditController::verifyChainAction()` applies in the module.
     */
    #[Test]
    public function verificationIsAllowedWithAuditViewPermission(): void
    {
        $this->seedChain(3);
        $this->publishAnchor();
        $this->setUpBackendUser(self::AUDIT_VIEWER);

        $tester = new CommandTester($this->get(VaultAuditVerifyCommand::class));
        $exitCode = $tester->execute([]);

        self::assertSame(Command::SUCCESS, $exitCode, $tester->getDisplay());
        self::assertStringContainsString('verified', $tester->getDisplay());
    }

    /**
     * And `vault.configure` is not a stand-in for it — the administrative
     * permission does not carry the read.
     */
    #[Test]
    public function verificationIsRefusedForAnActorHoldingOnlyVaultConfigure(): void
    {
        $this->seedChain(3);
        $this->publishAnchor();
        $this->setUpBackendUser(self::VAULT_CONFIGURATOR);

        $tester = new CommandTester($this->get(VaultAuditVerifyCommand::class));

        self::assertSame(Command::FAILURE, $tester->execute([]));
    }

    private function seedChain(int $entries): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        for ($i = 0; $i < $entries; $i++) {
            $auditService->log('verify_cmd_secret', 'read', true);
        }
    }

    /**
     * SymfonyStyle wraps its error block to the terminal width; collapsing
     * whitespace lets the assertions pin the whole refusal sentence.
     */
    private function normalize(CommandTester $tester): string
    {
        return (string) preg_replace('/\s+/', ' ', $tester->getDisplay());
    }

    private function publishAnchor(): void
    {
        $service = $this->get(ChainTipAnchorServiceInterface::class);
        $service->publish($service->capture());
    }

    private function getAuditConnection(): Connection
    {
        return $this->get(ConnectionPool::class)->getConnectionForTable(AuditLogService::TABLE_NAME);
    }

    /**
     * Wipe the table AND its auto-increment counter, so the next write starts a
     * fresh chain at uid 1 — the state a truncate-and-rebuild leaves behind.
     */
    private function resetAuditTable(): void
    {
        $connection = $this->getAuditConnection();
        $connection->executeStatement('DELETE FROM ' . AuditLogService::TABLE_NAME);

        if ($connection->getDatabasePlatform() instanceof SQLitePlatform) {
            $connection->executeStatement(
                "DELETE FROM sqlite_sequence WHERE name = '" . AuditLogService::TABLE_NAME . "'",
            );

            return;
        }

        $connection->executeStatement('ALTER TABLE ' . AuditLogService::TABLE_NAME . ' AUTO_INCREMENT = 1');
    }
}
