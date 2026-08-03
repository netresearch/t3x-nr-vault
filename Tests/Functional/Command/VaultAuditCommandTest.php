<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Command;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Command\VaultAuditCommand;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The operation-permission gate on `vault:audit`, end to end.
 *
 * The command used to assert nothing at all, while the same four capabilities
 * were gated in the backend module (`AuditController`). These tests drive the
 * real command through the container against real backend users whose groups
 * carry — or do not carry — the `tx_nrvault:<permission>` custom option, so
 * the verdict comes from `AccessControlService` reading actual group data
 * rather than from a mock.
 *
 * Every refusal case asserts BOTH halves of "fail closed": a non-zero exit and
 * the absence of the effect (no listing in the output, no export file, an
 * untouched anchor row) — plus an unchanged audit-row count, which pins the
 * decision that a refusal writes no `access_denied` entry here.
 */
#[CoversClass(VaultAuditCommand::class)]
final class VaultAuditCommandTest extends AbstractVaultFunctionalTestCase
{
    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    private const REGISTRY_TABLE = 'sys_registry';

    private const ANCHOR_NAMESPACE = 'tx_nrvault_audit_anchor';

    private const ANCHOR_KEY = 'auditChainTip';

    /** Admin — holds every permission through the admin bypass. */
    private const ADMIN = 1;

    /** Non-admin whose group carries no vault permission at all. */
    private const NO_PERMISSIONS = 2;

    /** Non-admin holding `audit.view` only. */
    private const AUDIT_VIEWER = 3;

    /** Non-admin holding `audit.export` only. */
    private const AUDIT_EXPORTER = 4;

    /** Non-admin holding `vault.configure` only. */
    private const VAULT_CONFIGURATOR = 5;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_audit_permission.csv';

    /** Each test logs in the actor it needs, after seeding as admin. */
    protected ?int $backendUserUid = null;

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        // Arms the in-DB tip anchor, so the --reset-anchor cases operate on a
        // real anchor row rather than on an absent one.
        'auditHmacEpoch' => 1,
    ];

    #[Test]
    public function listingIsRefusedWithoutAuditViewPermission(): void
    {
        $identifier = $this->seedAuditEntry();
        $this->setUpBackendUser(self::NO_PERMISSIONS);
        $entriesBefore = $this->countAuditEntries();

        $tester = $this->executeAudit([]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString(
            'Access denied: the "audit.view" permission is required to read the audit log.',
            $this->normalize($tester),
        );
        self::assertStringNotContainsString($identifier, $tester->getDisplay());
        self::assertSame($entriesBefore, $this->countAuditEntries());
    }

    #[Test]
    public function listingIsAllowedWithAuditViewPermission(): void
    {
        $identifier = $this->seedAuditEntry();
        $this->setUpBackendUser(self::AUDIT_VIEWER);

        $tester = $this->executeAudit(['--identifier' => $identifier]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::assertStringContainsString($identifier, $tester->getDisplay());
    }

    #[Test]
    public function listingIsUnchangedForAnAdmin(): void
    {
        $identifier = $this->seedAuditEntry();
        $this->setUpBackendUser(self::ADMIN);

        $tester = $this->executeAudit(['--identifier' => $identifier, '--format' => 'json']);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $decoded = json_decode($tester->getDisplay(), true);
        self::assertIsArray($decoded);
        self::assertCount(1, $decoded);
        $entry = $decoded[0];
        self::assertIsArray($entry);
        self::assertSame($identifier, $entry['secretIdentifier'] ?? null);
    }

    /**
     * `audit.view` is not `audit.export`: reading the log in the terminal and
     * carrying an unchained copy of it off the installation are different acts.
     */
    #[Test]
    public function exportIsRefusedForAnActorHoldingOnlyAuditView(): void
    {
        $this->seedAuditEntry();
        $this->setUpBackendUser(self::AUDIT_VIEWER);
        $entriesBefore = $this->countAuditEntries();
        $exportFile = $this->instancePath . '/refused-audit-export.json';

        $tester = $this->executeAudit(['--export' => $exportFile]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString(
            'Access denied: the "audit.export" permission is required to export audit entries to a file.',
            $this->normalize($tester),
        );
        self::assertFileDoesNotExist($exportFile);
        self::assertSame($entriesBefore, $this->countAuditEntries());
    }

    #[Test]
    public function exportIsAllowedWithAuditExportPermission(): void
    {
        $identifier = $this->seedAuditEntry();
        $this->setUpBackendUser(self::AUDIT_EXPORTER);
        $exportFile = $this->instancePath . '/audit-export.json';

        try {
            $tester = $this->executeAudit(['--identifier' => $identifier, '--export' => $exportFile]);

            self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
            self::assertFileExists($exportFile);
            self::assertStringContainsString($identifier, (string) file_get_contents($exportFile));
        } finally {
            if (file_exists($exportFile)) {
                // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
                unlink($exportFile);
            }
        }
    }

    #[Test]
    public function verifyIsRefusedWithoutAuditViewPermission(): void
    {
        $this->seedAuditEntry();
        $this->setUpBackendUser(self::NO_PERMISSIONS);
        $entriesBefore = $this->countAuditEntries();

        $tester = $this->executeAudit(['--verify' => true]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString(
            'Access denied: the "audit.view" permission is required to verify the audit hash chain.',
            $this->normalize($tester),
        );
        self::assertStringNotContainsString('Hash chain', $tester->getDisplay());
        self::assertSame($entriesBefore, $this->countAuditEntries());
    }

    /**
     * Verification recomputes and compares — it mutates nothing, so it is a
     * read of the chain and shares `audit.view` with the listing, exactly as
     * `AuditController::verifyChainAction()` does in the backend module. The
     * same operation must not answer differently depending on where it is
     * invoked from.
     */
    #[Test]
    public function verifyIsAllowedWithAuditViewPermission(): void
    {
        $this->seedAuditEntry();
        $this->setUpBackendUser(self::AUDIT_VIEWER);

        $tester = $this->executeAudit(['--verify' => true]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::assertStringContainsString('Hash chain is valid', $tester->getDisplay());
    }

    /**
     * The administrative permission is not a stand-in for the read: it gates
     * `--reset-anchor`, which mutates tamper evidence, and nothing else here.
     */
    #[Test]
    public function verifyIsRefusedForAnActorHoldingOnlyVaultConfigure(): void
    {
        $this->seedAuditEntry();
        $this->setUpBackendUser(self::VAULT_CONFIGURATOR);

        $tester = $this->executeAudit(['--verify' => true]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringNotContainsString('Hash chain', $tester->getDisplay());
    }

    #[Test]
    public function resetAnchorIsRefusedForAnActorHoldingOnlyAuditView(): void
    {
        $this->seedAuditEntry();
        $this->setUpBackendUser(self::AUDIT_VIEWER);

        $anchorBefore = $this->readAnchor();
        self::assertNotNull($anchorBefore, 'The seeded audit write must have armed the anchor.');
        $entriesBefore = $this->countAuditEntries();

        $tester = $this->executeAudit(['--reset-anchor' => true, '--force' => true]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString(
            'Access denied: the "vault.configure" permission is required to reset the audit chain tip anchor.',
            $this->normalize($tester),
        );
        self::assertSame($anchorBefore, $this->readAnchor(), 'A refused reset must leave the anchor untouched.');
        self::assertSame($entriesBefore, $this->countAuditEntries());
        self::assertSame(0, $this->countAuditEntries(AuditAction::AuditAnchorReset->value));
    }

    #[Test]
    public function resetAnchorIsAllowedWithVaultConfigurePermission(): void
    {
        $this->seedAuditEntry();
        $this->setUpBackendUser(self::VAULT_CONFIGURATOR);

        $tester = $this->executeAudit(['--reset-anchor' => true, '--force' => true]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::assertStringContainsString('Tip anchor reset', $tester->getDisplay());
        self::assertSame(
            1,
            $this->countAuditEntries(AuditAction::AuditAnchorReset->value),
            'The reset must be recorded in the chain it clears the anchor of.',
        );
    }

    /**
     * Write one audit entry as the admin and return the identifier it names.
     */
    private function seedAuditEntry(): string
    {
        $this->setUpBackendUser(self::ADMIN);
        $identifier = 'cmd_audit_gate_' . bin2hex(random_bytes(4));

        $this->get(AuditLogServiceInterface::class)->log(
            $identifier,
            AuditAction::Read->value,
            true,
            null,
            'Seeded by the vault:audit permission gate test',
        );

        return $identifier;
    }

    /**
     * @param array<string, string|bool> $arguments
     */
    private function executeAudit(array $arguments): CommandTester
    {
        $tester = new CommandTester($this->get(VaultAuditCommand::class));
        $tester->execute($arguments);

        return $tester;
    }

    private function countAuditEntries(?string $action = null): int
    {
        $connection = $this->getConnectionPool()->getConnectionForTable(self::AUDIT_TABLE);
        $queryBuilder = $connection->createQueryBuilder();
        $queryBuilder->count('uid')->from(self::AUDIT_TABLE);

        if ($action !== null) {
            $queryBuilder->where(
                $queryBuilder->expr()->eq('action', $queryBuilder->createNamedParameter($action)),
            );
        }

        return (int) $queryBuilder->executeQuery()->fetchOne();
    }

    /**
     * The raw, MAC-signed anchor value, or null when no anchor row exists.
     */
    private function readAnchor(): ?string
    {
        $connection = $this->getConnectionPool()->getConnectionForTable(self::REGISTRY_TABLE);
        $queryBuilder = $connection->createQueryBuilder();
        $value = $queryBuilder
            ->select('entry_value')
            ->from(self::REGISTRY_TABLE)
            ->where(
                $queryBuilder->expr()->eq(
                    'entry_namespace',
                    $queryBuilder->createNamedParameter(self::ANCHOR_NAMESPACE),
                ),
                $queryBuilder->expr()->eq(
                    'entry_key',
                    $queryBuilder->createNamedParameter(self::ANCHOR_KEY),
                ),
            )
            ->executeQuery()
            ->fetchOne();

        return \is_string($value) ? $value : null;
    }

    /**
     * SymfonyStyle wraps its error block to the terminal width; collapsing
     * whitespace lets the assertions pin the whole refusal sentence.
     */
    private function normalize(CommandTester $tester): string
    {
        return (string) preg_replace('/\s+/', ' ', $tester->getDisplay());
    }
}
