<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Audit;

use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Http\ServerRequest;

/**
 * F8 — the audit row's `user_agent` and `request_id` are taken verbatim from
 * request headers a client fully controls and stored in fixed-width columns
 * (`varchar(500)` / `varchar(100)`).
 *
 * Against a real database this pins both halves of the failure the clip
 * prevents: an oversized header must not abort the INSERT (strict `sql_mode`),
 * and it must not be truncated by the database behind the entry hash's back —
 * which would turn every later verification of that row into a false tamper
 * alarm. Epoch 3 is used because that is the payload that binds `user_agent`
 * and `request_id` into the HMAC.
 */
#[CoversClass(AuditLogService::class)]
final class AuditRequestHeaderWidthTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../../Functional/Service/Fixtures/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 3,
    ];

    #[Test]
    public function oversizedRequestHeadersAreStoredClippedAndLeaveTheChainVerifiable(): void
    {
        $GLOBALS['TYPO3_REQUEST'] = (new ServerRequest('https://example.com/', 'GET'))
            ->withHeader('X-Request-Id', str_repeat('A', 200))
            ->withHeader('User-Agent', str_repeat('B', 900));

        $auditService = $this->get(AuditLogServiceInterface::class);
        $identifier = 'test_audit_header_width';

        $auditService->log($identifier, 'create', true);

        $row = $this->getConnectionPool()
            ->getConnectionForTable('tx_nrvault_audit_log')
            ->select(['request_id', 'user_agent'], 'tx_nrvault_audit_log', ['secret_identifier' => $identifier])
            ->fetchAssociative();

        self::assertIsArray($row, 'The audit write must succeed despite the oversized headers');
        self::assertSame(str_repeat('A', 100), $row['request_id'], 'request_id fits varchar(100)');
        self::assertSame(str_repeat('B', 500), $row['user_agent'], 'user_agent fits varchar(500)');

        self::assertTrue(
            $auditService->verifyHashChain()->isValid(),
            'The entry hash must cover the stored bytes — a database-side truncation would break verification',
        );
    }
}
