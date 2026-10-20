<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(AuditLogEntry::class)]
final class AuditLogEntryTest extends TestCase
{
    #[Test]
    public function fromDatabaseRowCreatesCorrectEntry(): void
    {
        $row = [
            'uid'               => 42,
            'secret_identifier' => 'api-key',
            'action'            => 'read',
            'success'           => 1,
            'error_message'     => '',
            'reason'            => 'API call',
            'actor_uid'         => 5,
            'actor_type'        => 'backend',
            'actor_username'    => 'admin',
            'actor_role'        => 'Administrator',
            'ip_address'        => '192.168.1.1',
            'user_agent'        => 'Mozilla/5.0',
            'request_id'        => 'req-123',
            'previous_hash'     => 'abc',
            'entry_hash'        => 'def',
            'hash_before'       => 'ghi',
            'hash_after'        => 'jkl',
            'crdate'            => 1704067200,
            'context'           => '{"service":"stripe"}',
        ];

        $entry = AuditLogEntry::fromDatabaseRow($row);

        self::assertEquals(42, $entry->uid);
        self::assertEquals('api-key', $entry->secretIdentifier);
        self::assertEquals('read', $entry->action);
        self::assertTrue($entry->success);
        self::assertNull($entry->errorMessage);
        self::assertEquals('API call', $entry->reason);
        self::assertEquals(5, $entry->actorUid);
        self::assertEquals('backend', $entry->actorType);
        self::assertEquals('admin', $entry->actorUsername);
        self::assertEquals('Administrator', $entry->actorRole);
        self::assertEquals('192.168.1.1', $entry->ipAddress);
        self::assertEquals('Mozilla/5.0', $entry->userAgent);
        self::assertEquals('req-123', $entry->requestId);
        self::assertEquals(['service' => 'stripe'], $entry->context);
    }

    #[Test]
    public function fromDatabaseRowHandlesEmptyContext(): void
    {
        $row = [
            'uid'     => 1,
            'context' => '',
        ];

        $entry = AuditLogEntry::fromDatabaseRow($row);

        self::assertEquals([], $entry->context);
    }

    #[Test]
    public function fromDatabaseRowHandlesInvalidJson(): void
    {
        $row = [
            'uid'     => 1,
            'context' => 'not-valid-json',
        ];

        $entry = AuditLogEntry::fromDatabaseRow($row);

        self::assertEquals([], $entry->context);
    }

    #[Test]
    public function fromDatabaseRowHandlesMissingFields(): void
    {
        $row = ['uid' => 1];

        $entry = AuditLogEntry::fromDatabaseRow($row);

        self::assertEquals(1, $entry->uid);
        self::assertEquals('', $entry->secretIdentifier);
        self::assertEquals('', $entry->action);
        self::assertFalse($entry->success);
        self::assertEquals(0, $entry->actorUid);
    }

    #[Test]
    public function jsonSerializeReturnsCorrectStructure(): void
    {
        $entry = new AuditLogEntry(
            uid: 1,
            secretIdentifier: 'test-secret',
            action: 'create',
            success: true,
            errorMessage: null,
            reason: 'test',
            actorUid: 5,
            actorType: 'backend',
            actorUsername: 'admin',
            actorRole: 'Admin',
            ipAddress: '127.0.0.1',
            userAgent: 'Test',
            requestId: 'req-1',
            previousHash: 'prev',
            entryHash: 'curr',
            hashBefore: 'before',
            hashAfter: 'after',
            crdate: 1704067200,
            context: ['key' => 'value'],
        );

        $json = $entry->jsonSerialize();

        self::assertEquals(1, $json['uid']);
        self::assertEquals('test-secret', $json['secretIdentifier']);
        self::assertEquals('create', $json['action']);
        self::assertTrue($json['success']);
        self::assertNull($json['errorMessage']);
        self::assertEquals('test', $json['reason']);
        self::assertEquals(5, $json['actorUid']);
        self::assertStringContainsString('2024-01-01', $json['timestamp']);
        self::assertEquals(['key' => 'value'], $json['context']);
    }

    #[Test]
    public function fromDatabaseRowHandlesErrorMessage(): void
    {
        $row = [
            'uid'           => 1,
            'success'       => 0,
            'error_message' => 'Access denied',
        ];

        $entry = AuditLogEntry::fromDatabaseRow($row);

        self::assertFalse($entry->success);
        self::assertEquals('Access denied', $entry->errorMessage);
    }
}
