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
use TYPO3\CMS\Core\Authentication\CommandLineUserAuthentication;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * `vault:audit --as-audit-reader` from the shell a deployment really has: an
 * unauthenticated CLI user, `allowCliAccess` off, and a configured
 * `auditReaderBeUserUid` whose groups carry `tx_nrvault:audit.view` and
 * `tx_nrvault:audit.export`.
 */
#[CoversClass(VaultAuditCommand::class)]
final class VaultAuditCommandAuditReaderTest extends AbstractVaultFunctionalTestCase
{
    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    /** Admin, used only to seed the log. */
    private const ADMIN = 1;

    /** Non-admin holding `audit.view` and `audit.export` (groups 41 and 42 in the fixture). */
    private const READER = 6;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_audit_permission.csv';

    protected ?int $backendUserUid = null;

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch'       => 1,
        'auditReaderBeUserUid' => self::READER,
    ];

    private string $seededIdentifier = '';

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpBackendUser(self::ADMIN);
        $this->seededIdentifier = 'cmd_audit_reader_' . bin2hex(random_bytes(4));
        $this->get(AuditLogServiceInterface::class)->log(
            $this->seededIdentifier,
            AuditAction::Read->value,
            true,
            null,
            'Seeded by the vault:audit --as-audit-reader test',
        );

        $GLOBALS['BE_USER'] = GeneralUtility::makeInstance(CommandLineUserAuthentication::class);
    }

    #[Test]
    public function asAuditReaderListsTheLogFromAnUnauthenticatedShell(): void
    {
        $tester = $this->executeAudit(['--as-audit-reader' => true, '--format' => 'json']);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::assertStringContainsString($this->seededIdentifier, $tester->getDisplay());
    }

    /**
     * Configuring the reader grants nothing to the plain shell: without the
     * flag the listing is refused exactly as before.
     */
    #[Test]
    public function withoutTheFlagTheShellIsStillRefused(): void
    {
        $tester = $this->executeAudit(['--format' => 'json']);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('Access denied', $this->normalize($tester));
        self::assertStringNotContainsString($this->seededIdentifier, $tester->getDisplay());
    }

    /**
     * The reader is evaluated, not trusted: without `audit.view` on its
     * groups it is refused like any other user.
     */
    #[Test]
    public function aReaderWithoutAuditViewIsRefused(): void
    {
        $this->setReaderGroups('');

        $tester = $this->executeAudit(['--as-audit-reader' => true, '--format' => 'json']);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString(
            'Access denied: the "audit.view" permission is required to read the audit log.',
            $this->normalize($tester),
        );
        self::assertStringNotContainsString($this->seededIdentifier, $tester->getDisplay());
    }

    #[Test]
    public function asAuditReaderVerifiesTheHashChain(): void
    {
        $tester = $this->executeAudit(['--as-audit-reader' => true, '--verify' => true]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::assertStringContainsString('Tip anchor:', $tester->getDisplay());
        self::assertStringContainsString('Hash chain is valid', $tester->getDisplay());
    }

    #[Test]
    public function asAuditReaderExportsWhenTheReaderHoldsAuditExport(): void
    {
        $exportFile = $this->instancePath . '/reader-audit-export.json';

        try {
            $tester = $this->executeAudit([
                '--as-audit-reader' => true,
                '--identifier'      => $this->seededIdentifier,
                '--export'          => $exportFile,
            ]);

            self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
            self::assertFileExists($exportFile);
            self::assertStringContainsString($this->seededIdentifier, (string) file_get_contents($exportFile));
        } finally {
            if (file_exists($exportFile)) {
                // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
                unlink($exportFile);
            }
        }
    }

    /**
     * `audit.view` does not buy the export for the reader either.
     */
    #[Test]
    public function aReaderWithoutAuditExportCannotExport(): void
    {
        $this->setReaderGroups('41');
        $exportFile = $this->instancePath . '/refused-reader-audit-export.json';

        $tester = $this->executeAudit(['--as-audit-reader' => true, '--export' => $exportFile]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString(
            'Access denied: the "audit.export" permission is required to export audit entries to a file.',
            $this->normalize($tester),
        );
        self::assertFileDoesNotExist($exportFile);
    }

    /**
     * `--reset-anchor` writes into the chain, so it is never run as the reader,
     * even when the reader's groups would grant `vault.configure`.
     */
    #[Test]
    public function resetAnchorIsRefusedAsTheReaderEvenWithVaultConfigure(): void
    {
        $this->setReaderGroups('41,42,43');
        $entriesBefore = $this->countAuditEntries();

        $tester = $this->executeAudit(['--as-audit-reader' => true, '--reset-anchor' => true, '--force' => true]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('cannot be combined with --reset-anchor', $this->normalize($tester));
        self::assertStringNotContainsString('Tip anchor reset', $tester->getDisplay());
        self::assertSame($entriesBefore, $this->countAuditEntries());
        self::assertSame(0, $this->countAuditEntries(AuditAction::AuditAnchorReset->value));
    }

    #[Test]
    public function aDisabledReaderFails(): void
    {
        $this->get(ConnectionPool::class)->getConnectionForTable('be_users')
            ->update('be_users', ['disable' => 1], ['uid' => self::READER]);

        $tester = $this->executeAudit(['--as-audit-reader' => true, '--format' => 'json']);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('The audit reader cannot be used:', $this->normalize($tester));
        self::assertStringContainsString('disabled', $this->normalize($tester));
        self::assertStringNotContainsString($this->seededIdentifier, $tester->getDisplay());
    }

    private function setReaderGroups(string $groups): void
    {
        $this->get(ConnectionPool::class)->getConnectionForTable('be_users')
            ->update('be_users', ['usergroup' => $groups], ['uid' => self::READER]);
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
        $queryBuilder = $this->get(ConnectionPool::class)->getConnectionForTable(self::AUDIT_TABLE)->createQueryBuilder();
        $queryBuilder->count('uid')->from(self::AUDIT_TABLE);

        if ($action !== null) {
            $queryBuilder->where(
                $queryBuilder->expr()->eq('action', $queryBuilder->createNamedParameter($action)),
            );
        }

        return (int) $queryBuilder->executeQuery()->fetchOne();
    }

    private function normalize(CommandTester $tester): string
    {
        return (string) preg_replace('/\s+/', ' ', $tester->getDisplay());
    }
}
