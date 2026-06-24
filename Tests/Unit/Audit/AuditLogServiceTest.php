<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use ArrayIterator;
use DateTimeImmutable;
use Doctrine\DBAL\Result;
use Iterator;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\AuditLogFilter;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\GenericContext;
use Netresearch\NrVault\Audit\HashChainVerificationResult;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Exception\AuditWriteException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use RuntimeException;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

#[CoversClass(AuditLogService::class)]
#[CoversClass(AuditLogEntry::class)]
#[AllowMockObjectsWithoutExpectations]
final class AuditLogServiceTest extends TestCase
{
    private const SHA256_HEX_PATTERN = '/^[a-f0-9]{64}$/';

    private const IP_ADDRESS = '10.0.0.5';

    private const USER_AGENT = 'curl/8';

    private ?AuditLogService $subject = null;

    private ?MockObject $connectionPool = null;

    private ?MockObject $accessControlService = null;

    private ?MockObject $masterKeyProvider = null;

    private ?MockObject $extensionConfiguration = null;

    private ?MockObject $queryBuilder = null;

    private ?MockObject $connection = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->connectionPool = $this->createMock(ConnectionPool::class);
        $this->accessControlService = $this->createMock(AccessControlServiceInterface::class);
        $this->masterKeyProvider = $this->createMock(MasterKeyProviderInterface::class);
        $this->extensionConfiguration = $this->createMock(ExtensionConfigurationInterface::class);
        $this->queryBuilder = $this->createMock(QueryBuilder::class);
        $this->connection = $this->createMock(Connection::class);

        $this->accessControlService
            ->method('getCurrentActorUid')
            ->willReturn(1);
        $this->accessControlService
            ->method('getCurrentActorType')
            ->willReturn('backend');
        $this->accessControlService
            ->method('getCurrentActorUsername')
            ->willReturn('admin');
        $this->accessControlService
            ->method('getCurrentUserGroups')
            ->willReturn([]);

        // Default: epoch 1 (HMAC mode)
        $this->extensionConfiguration
            ->method('getAuditHmacEpoch')
            ->willReturn(1);

        // Provide a stable 32-byte master key for tests
        $this->masterKeyProvider
            ->method('getMasterKey')
            ->willReturn(str_repeat("\x01", 32));

        self::assertNotNull($this->connectionPool);
        self::assertNotNull($this->accessControlService);
        $this->subject = new AuditLogService(
            $this->connectionPool,
            $this->accessControlService,
            $this->masterKeyProvider,
            $this->extensionConfiguration,
        );
    }

    #[Test]
    public function logCreatesAuditEntryForCreateAction(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['action'] === 'create'
                    && $data['secret_identifier'] === 'test_secret'
                    && $data['actor_uid'] === 1
                    && $data['actor_type'] === 'backend'),
            );

        $this->getSubject()->log('test_secret', 'create', true, null, 'Test secret stored');
    }

    #[Test]
    public function logCreatesAuditEntryForReadAction(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['action'] === 'read'
                    && $data['secret_identifier'] === 'api_key'),
            );

        $this->getSubject()->log('api_key', 'read', true);
    }

    #[Test]
    public function logCreatesAuditEntryForDeleteAction(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['action'] === 'delete'
                    && $data['secret_identifier'] === 'old_secret'),
            );

        $this->getSubject()->log('old_secret', 'delete', true, null, 'Cleanup');
    }

    #[Test]
    public function logCreatesAuditEntryForRotateAction(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['action'] === 'rotate'
                    && $data['secret_identifier'] === 'rotated_secret'),
            );

        $this->getSubject()->log('rotated_secret', 'rotate', true, null, 'Annual rotation');
    }

    #[Test]
    public function logCreatesAuditEntryForAccessDenied(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['action'] === 'access_denied'
                    && $data['secret_identifier'] === 'restricted_secret'
                    && $data['success'] === 0),
            );

        $this->getSubject()->log('restricted_secret', 'access_denied', false, 'Permission denied');
    }

    #[Test]
    public function auditLogEntryContainsRequestContext(): void
    {
        $this->setupDatabaseMocks();

        // Set up server globals for request context
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';
        $_SERVER['HTTP_USER_AGENT'] = 'PHPUnit Test';

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => isset($data['ip_address'])
                    && isset($data['user_agent'], $data['request_id'])),
            );

        $this->getSubject()->log('context_test', 'create', true, null, 'Testing context');

        // Cleanup
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT']);
    }

    #[Test]
    public function hashChainLinksToLastEntry(): void
    {
        // Override the default getLatestHash() return so this test exercises
        // the "chain continues from previous_hash_abc123" path.
        $this->setupDatabaseMocks('previous_hash_abc123');

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['previous_hash'] === 'previous_hash_abc123'),
            );

        $this->getSubject()->log('chained_secret', 'create', true, null, 'Testing hash chain');
    }

    #[Test]
    public function queryReturnsAuditLogEntries(): void
    {
        $this->setupQueryMocks([
            [
                'uid' => 1,
                'pid' => 0,
                'secret_identifier' => 'test_secret',
                'action' => 'create',
                'success' => 1,
                'error_message' => '',
                'reason' => 'Test',
                'actor_uid' => 1,
                'actor_type' => 'backend',
                'actor_username' => 'admin',
                'actor_role' => 'backend',
                'ip_address' => '127.0.0.1',
                'user_agent' => 'PHPUnit',
                'request_id' => 'abc123',
                'previous_hash' => '',
                'entry_hash' => 'hash123',
                'hash_before' => '',
                'hash_after' => 'newhash',
                'crdate' => time(),
                'context' => '{}',
            ],
        ]);

        $entries = $this->getSubject()->query();

        self::assertCount(1, $entries);
        self::assertInstanceOf(AuditLogEntry::class, $entries[0]);
        self::assertSame('test_secret', $entries[0]->secretIdentifier);
    }

    #[Test]
    public function queryWithFilterAppliesSecretIdentifierFilter(): void
    {
        $filter = new AuditLogFilter(secretIdentifier: 'specific_secret');

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->expects(self::once())
            ->method('eq')
            ->with('secret_identifier', self::anything())
            ->willReturn('secret_identifier = ?');

        $this->setupQueryMocksWithFilter($expressionBuilder, []);

        $this->queryBuilder
            ->expects(self::atLeastOnce())
            ->method('andWhere')
            ->with('secret_identifier = ?')
            ->willReturnSelf();

        $this->getSubject()->query($filter);
    }

    #[Test]
    public function queryWithFilterAppliesActionFilter(): void
    {
        $filter = new AuditLogFilter(action: 'read');

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->expects(self::once())
            ->method('eq')
            ->with('action', self::anything())
            ->willReturn('action = ?');

        $this->setupQueryMocksWithFilter($expressionBuilder, []);

        $this->queryBuilder
            ->expects(self::atLeastOnce())
            ->method('andWhere')
            ->with('action = ?')
            ->willReturnSelf();

        $this->getSubject()->query($filter);
    }

    #[Test]
    public function queryWithFilterAppliesSuccessFilter(): void
    {
        $filter = new AuditLogFilter(success: true);

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->expects(self::once())
            ->method('eq')
            ->with('success', self::anything())
            ->willReturn('success = 1');

        $this->setupQueryMocksWithFilter($expressionBuilder, []);

        $this->queryBuilder
            ->expects(self::atLeastOnce())
            ->method('andWhere')
            ->with('success = 1')
            ->willReturnSelf();

        $this->getSubject()->query($filter);
    }

    #[Test]
    public function queryWithFilterAppliesDateRangeFilters(): void
    {
        $since = new DateTimeImmutable('2024-01-01');
        $until = new DateTimeImmutable('2024-12-31');
        $filter = new AuditLogFilter(since: $since, until: $until);

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->expects(self::once())
            ->method('gte')
            ->willReturn('crdate >= ?');
        $expressionBuilder->expects(self::once())
            ->method('lte')
            ->willReturn('crdate <= ?');

        $this->setupQueryMocksWithFilter($expressionBuilder, []);

        $this->queryBuilder
            ->expects(self::atLeastOnce())
            ->method('andWhere')
            ->willReturnSelf();

        $this->getSubject()->query($filter);
    }

    #[Test]
    public function countReturnsNumberOfEntries(): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn(42);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder
            ->method('count')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('from')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('executeQuery')
            ->willReturn($result);

        self::assertSame(42, $this->getSubject()->count());
    }

    #[Test]
    public function countWithFilterAppliesFilter(): void
    {
        $filter = new AuditLogFilter(actorUid: 5);

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->expects(self::once())
            ->method('eq')
            ->with('actor_uid', self::anything())
            ->willReturn('actor_uid = 5');

        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn(10);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder
            ->method('expr')
            ->willReturn($expressionBuilder);

        $this->queryBuilder
            ->method('count')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('from')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('andWhere')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('createNamedParameter')
            ->willReturn('5');

        $this->queryBuilder
            ->method('executeQuery')
            ->willReturn($result);

        self::assertSame(10, $this->getSubject()->count($filter));
    }

    #[Test]
    public function exportReturnsAllEntries(): void
    {
        $this->setupQueryMocks([]);

        $entries = $this->getSubject()->export();

        self::assertIsArray($entries);
    }

    #[Test]
    public function getLatestHashReturnsNullWhenEmpty(): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn(false);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder
            ->method('select')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('from')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('orderBy')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('setMaxResults')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('executeQuery')
            ->willReturn($result);

        self::assertNull($this->getSubject()->getLatestHash());
    }

    #[Test]
    public function getLatestHashReturnsHashWhenExists(): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn('abc123hash');

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder
            ->method('select')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('from')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('orderBy')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('setMaxResults')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('executeQuery')
            ->willReturn($result);

        self::assertSame('abc123hash', $this->getSubject()->getLatestHash());
    }

    #[Test]
    public function verifyHashChainReturnsValidWhenEmpty(): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturn([]);
        $result->method('iterateAssociative')->willReturnCallback(static fn (): Iterator => new ArrayIterator($result->fetchAllAssociative()));

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder
            ->method('select')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('from')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('orderBy')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('executeQuery')
            ->willReturn($result);

        $verification = $this->getSubject()->verifyHashChain();

        self::assertTrue($verification->valid);
        self::assertEmpty($verification->errors);
    }

    #[Test]
    public function verifyHashChainWithRangeAppliesFilters(): void
    {
        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->method('gte')->willReturn('uid >= 10');
        $expressionBuilder->method('lte')->willReturn('uid <= 50');

        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturn([]);
        $result->method('iterateAssociative')->willReturnCallback(static fn (): Iterator => new ArrayIterator($result->fetchAllAssociative()));

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder
            ->method('expr')
            ->willReturn($expressionBuilder);

        $this->queryBuilder
            ->method('select')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('from')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('orderBy')
            ->willReturnSelf();

        $this->queryBuilder
            ->expects(self::exactly(2))
            ->method('andWhere')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('createNamedParameter')
            ->willReturn('?');

        $this->queryBuilder
            ->method('executeQuery')
            ->willReturn($result);

        $verification = $this->getSubject()->verifyHashChain(10, 50);

        self::assertTrue($verification->valid);
    }

    #[Test]
    public function logRecordsHashBeforeAndAfter(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['hash_before'] === 'before_hash'
                    && $data['hash_after'] === 'after_hash'),
            );

        $this->getSubject()->log(
            'test_secret',
            'update',
            true,
            null,
            'Updated secret',
            'before_hash',
            'after_hash',
        );
    }

    #[Test]
    public function logRecordsContext(): void
    {
        $this->setupDatabaseMocks();

        $context = new GenericContext(['key' => 'value']);

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static function (array $data) use ($context): bool {
                    $decodedContext = json_decode((string) $data['context'], true);

                    return $decodedContext === $context->toArray();
                }),
            );

        $this->getSubject()->log('test_secret', 'create', true, null, null, null, null, $context);
    }

    #[Test]
    public function logRecordsActorRole(): void
    {
        // Set up access control service to return groups
        $accessControlService = $this->createMock(AccessControlServiceInterface::class);
        $accessControlService->method('getCurrentActorUid')->willReturn(1);
        $accessControlService->method('getCurrentActorType')->willReturn('backend');
        $accessControlService->method('getCurrentActorUsername')->willReturn('admin');
        $accessControlService->method('getCurrentUserGroups')->willReturn([1, 2, 3]);

        $subject = new AuditLogService($this->connectionPool, $accessControlService, $this->masterKeyProvider, $this->extensionConfiguration);

        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['actor_role'] === 'groups:1,2,3'),
            );

        $subject->log('test_secret', 'read', true);
    }

    #[Test]
    public function logUsesTransactionForAtomicWrite(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('beginTransaction');

        $this->connection
            ->expects(self::once())
            ->method('commit');

        $this->connection
            ->expects(self::never())
            ->method('rollBack');

        $this->getSubject()->log('test_secret', 'create', true);
    }

    #[Test]
    public function logRollsBackTransactionOnInsertFailure(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->method('insert')
            ->willThrowException(new RuntimeException('Insert failed'));

        $this->connection
            ->expects(self::once())
            ->method('rollBack');

        $this->connection
            ->expects(self::never())
            ->method('commit');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Insert failed');

        $this->getSubject()->log('test_secret', 'create', true);
    }

    #[Test]
    public function logUpdatesEntryHashAfterInsert(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->method('lastInsertId')
            ->willReturn('42');

        $this->connection
            ->expects(self::once())
            ->method('update')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => isset($data['entry_hash']) && $data['entry_hash'] !== ''),
                ['uid' => 42],
            );

        $this->getSubject()->log('test_secret', 'create', true);
    }

    #[Test]
    public function hmacHashProducesDifferentOutputThanSha256(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->method('lastInsertId')
            ->willReturn('1');

        // Capture the entry_hash and crdate written during insert/update
        $hmacHash = '';
        $capturedCrdate = 0;
        $this->connection
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static function (array $data) use (&$capturedCrdate): bool {
                    $capturedCrdate = $data['crdate'];

                    return true;
                }),
            );

        $this->connection
            ->method('update')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static function (array $data) use (&$hmacHash): bool {
                    $hmacHash = $data['entry_hash'] ?? '';

                    return true;
                }),
                self::anything(),
            );

        $this->getSubject()->log('test_secret', 'create', true);

        // Calculate the legacy SHA-256 hash for the same payload using the captured crdate
        $payload = json_encode([
            'uid' => 1,
            'secret_identifier' => 'test_secret',
            'action' => 'create',
            'actor_uid' => 1,
            'crdate' => $capturedCrdate,
            'previous_hash' => '',
        ], JSON_THROW_ON_ERROR);

        // The HMAC hash should not be empty and should be a valid hex string
        self::assertNotEmpty($hmacHash);
        self::assertMatchesRegularExpression(self::SHA256_HEX_PATTERN, $hmacHash);

        // The HMAC hash should differ from a plain SHA-256 of the same payload
        $legacySha256 = hash('sha256', $payload);
        self::assertNotSame($legacySha256, $hmacHash);
    }

    #[Test]
    public function logSetsHmacKeyEpochInInsertData(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => isset($data['hmac_key_epoch']) && $data['hmac_key_epoch'] === 1),
            );

        $this->getSubject()->log('test_secret', 'create', true);
    }

    #[Test]
    public function legacyEpoch0VerificationUsesPlainSha256(): void
    {
        // Create a subject with epoch 0 (legacy mode)
        $extensionConfig = $this->createMock(ExtensionConfigurationInterface::class);
        $extensionConfig->method('getAuditHmacEpoch')->willReturn(0);

        $subject = new AuditLogService(
            $this->connectionPool,
            $this->accessControlService,
            $this->masterKeyProvider,
            $extensionConfig,
        );

        // Build a row with epoch 0 and valid SHA-256 hash
        $previousHash = '';
        $payload = json_encode([
            'uid' => 1,
            'secret_identifier' => 'test',
            'action' => 'create',
            'actor_uid' => 1,
            'crdate' => 1704067200,
            'previous_hash' => $previousHash,
        ], JSON_THROW_ON_ERROR);
        $legacyHash = hash('sha256', $payload);

        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturn([
            [
                'uid' => 1,
                'secret_identifier' => 'test',
                'action' => 'create',
                'actor_uid' => 1,
                'crdate' => 1704067200,
                'previous_hash' => '',
                'entry_hash' => $legacyHash,
                'hmac_key_epoch' => 0,
            ],
        ]);
        $result->method('iterateAssociative')->willReturnCallback(static fn (): Iterator => new ArrayIterator($result->fetchAllAssociative()));

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder->method('select')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('orderBy')->willReturnSelf();
        $this->queryBuilder->method('executeQuery')->willReturn($result);

        $verification = $subject->verifyHashChain();

        self::assertTrue($verification->isValid());
    }

    #[Test]
    public function epochBoundaryGeneratesWarning(): void
    {
        // Build rows where epoch changes from 0 to 1
        $previousHash = '';
        $payload1 = json_encode([
            'uid' => 1,
            'secret_identifier' => 'test',
            'action' => 'create',
            'actor_uid' => 1,
            'crdate' => 1704067200,
            'previous_hash' => $previousHash,
        ], JSON_THROW_ON_ERROR);
        $hash1 = hash('sha256', $payload1);

        // Second entry uses HMAC (epoch 1)
        $masterKey = str_repeat("\x01", 32);
        $hmacKey = hash_hkdf('sha256', $masterKey, 32, 'nr-vault-audit-hmac-v1');
        $payload2 = json_encode([
            'uid' => 2,
            'secret_identifier' => 'test2',
            'action' => 'read',
            'actor_uid' => 1,
            'crdate' => 1704153600,
            'previous_hash' => $hash1,
        ], JSON_THROW_ON_ERROR);
        $hash2 = hash_hmac('sha256', $payload2, $hmacKey);

        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturn([
            [
                'uid' => 1,
                'secret_identifier' => 'test',
                'action' => 'create',
                'actor_uid' => 1,
                'crdate' => 1704067200,
                'previous_hash' => '',
                'entry_hash' => $hash1,
                'hmac_key_epoch' => 0,
            ],
            [
                'uid' => 2,
                'secret_identifier' => 'test2',
                'action' => 'read',
                'actor_uid' => 1,
                'crdate' => 1704153600,
                'previous_hash' => $hash1,
                'entry_hash' => $hash2,
                'hmac_key_epoch' => 1,
            ],
        ]);
        $result->method('iterateAssociative')->willReturnCallback(static fn (): Iterator => new ArrayIterator($result->fetchAllAssociative()));

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder->method('select')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('orderBy')->willReturnSelf();
        $this->queryBuilder->method('executeQuery')->willReturn($result);

        $verification = $this->getSubject()->verifyHashChain();

        self::assertTrue($verification->isValid());
        self::assertNotEmpty($verification->warnings);
        self::assertArrayHasKey(2, $verification->warnings);
        self::assertStringContainsString('epoch boundary', $verification->warnings[2]);
    }

    #[Test]
    public function verifyHashChainWithMixedEpochsValidatesChainIntegrity(): void
    {
        // Build a chain with epoch-0 entries followed by epoch-1 entries
        $masterKey = str_repeat("\x01", 32);
        $hmacKey = hash_hkdf('sha256', $masterKey, 32, 'nr-vault-audit-hmac-v1');

        // Entry 1: epoch 0 (SHA-256)
        $hash1 = AuditLogService::calculateHash(1, 'secret-a', 'create', 1, 1704067200, '');
        // Entry 2: epoch 0 (SHA-256)
        $hash2 = AuditLogService::calculateHash(2, 'secret-b', 'read', 1, 1704153600, $hash1);
        // Entry 3: epoch 1 (HMAC) - epoch boundary
        $hash3 = AuditLogService::calculateHash(3, 'secret-c', 'update', 2, 1704240000, $hash2, $hmacKey);
        // Entry 4: epoch 1 (HMAC)
        $hash4 = AuditLogService::calculateHash(4, 'secret-d', 'delete', 2, 1704326400, $hash3, $hmacKey);

        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturn([
            [
                'uid' => 1,
                'secret_identifier' => 'secret-a',
                'action' => 'create',
                'actor_uid' => 1,
                'crdate' => 1704067200,
                'previous_hash' => '',
                'entry_hash' => $hash1,
                'hmac_key_epoch' => 0,
            ],
            [
                'uid' => 2,
                'secret_identifier' => 'secret-b',
                'action' => 'read',
                'actor_uid' => 1,
                'crdate' => 1704153600,
                'previous_hash' => $hash1,
                'entry_hash' => $hash2,
                'hmac_key_epoch' => 0,
            ],
            [
                'uid' => 3,
                'secret_identifier' => 'secret-c',
                'action' => 'update',
                'actor_uid' => 2,
                'crdate' => 1704240000,
                'previous_hash' => $hash2,
                'entry_hash' => $hash3,
                'hmac_key_epoch' => 1,
            ],
            [
                'uid' => 4,
                'secret_identifier' => 'secret-d',
                'action' => 'delete',
                'actor_uid' => 2,
                'crdate' => 1704326400,
                'previous_hash' => $hash3,
                'entry_hash' => $hash4,
                'hmac_key_epoch' => 1,
            ],
        ]);
        $result->method('iterateAssociative')->willReturnCallback(static fn (): Iterator => new ArrayIterator($result->fetchAllAssociative()));

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder->method('select')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('orderBy')->willReturnSelf();
        $this->queryBuilder->method('executeQuery')->willReturn($result);

        $verification = $this->getSubject()->verifyHashChain();

        self::assertTrue($verification->isValid(), 'Mixed epoch chain should be valid');
        self::assertNotEmpty($verification->warnings, 'Should have epoch boundary warning');
        self::assertArrayHasKey(3, $verification->warnings, 'Warning should be on entry 3 (epoch boundary)');
        self::assertCount(1, $verification->warnings, 'Should have exactly one epoch boundary warning');
    }

    // =========================================================================
    // Epoch 2 — extended hash payload covering forensic fields.
    //
    // The v1 hash binds only identity fields (uid / secret_identifier /
    // action / actor_uid / crdate / previous_hash). An attacker with
    // DB-write privileges could flip `success: false → true` or rewrite
    // `error_message` / `reason` / `ip_address` / `user_agent` without
    // breaking the chain. Epoch 2 extends the HMAC payload to cover those
    // fields too.
    // =========================================================================

    #[Test]
    public function calculateHashV2DiffersForDifferentSuccess(): void
    {
        $hmacKey = str_repeat("\xAA", 32);
        $base = $this->makeV2Row(success: 1);
        $tampered = $this->makeV2Row(success: 0);

        $h1 = AuditLogService::calculateHashV2($base, '', $hmacKey);
        $h2 = AuditLogService::calculateHashV2($tampered, '', $hmacKey);

        self::assertNotSame($h1, $h2, 'Flipping `success` must change the chain hash');
    }

    #[Test]
    public function calculateHashV2DiffersForDifferentErrorMessage(): void
    {
        $hmacKey = str_repeat("\xAA", 32);
        $base = $this->makeV2Row(errorMessage: 'access denied');
        $tampered = $this->makeV2Row(errorMessage: '');

        $h1 = AuditLogService::calculateHashV2($base, '', $hmacKey);
        $h2 = AuditLogService::calculateHashV2($tampered, '', $hmacKey);

        self::assertNotSame($h1, $h2, 'Rewriting `error_message` must change the chain hash');
    }

    #[Test]
    public function calculateHashV2DiffersForDifferentIpAddress(): void
    {
        $hmacKey = str_repeat("\xAA", 32);
        $base = $this->makeV2Row(ipAddress: self::IP_ADDRESS);
        $tampered = $this->makeV2Row(ipAddress: '192.168.1.1');

        $h1 = AuditLogService::calculateHashV2($base, '', $hmacKey);
        $h2 = AuditLogService::calculateHashV2($tampered, '', $hmacKey);

        self::assertNotSame($h1, $h2, 'Rewriting `ip_address` must change the chain hash');
    }

    #[Test]
    public function verifyHashChainEpoch2DetectsForensicTampering(): void
    {
        $masterKey = str_repeat("\x01", 32);
        $hmacKey = hash_hkdf('sha256', $masterKey, 32, 'nr-vault-audit-hmac-v1');

        $row = [
            'uid' => 1,
            'secret_identifier' => 'sek',
            'action' => 'access_denied',
            'success' => 0,
            'actor_uid' => 1,
            'crdate' => 1704067200,
            'error_message' => 'access denied',
            'reason' => 'group not in allowlist',
            'ip_address' => self::IP_ADDRESS,
            'user_agent' => self::USER_AGENT,
            'hash_before' => '',
            'hash_after' => '',
            'context' => '{}',
        ];
        $validHash = AuditLogService::calculateHashV2($row, '', $hmacKey);

        // Attacker flips `success` from 0 to 1 in storage, but the stored
        // entry_hash still binds the original `success: 0` payload.
        $tamperedRow = array_merge($row, [
            'success' => 1,
            'previous_hash' => '',
            'entry_hash' => $validHash,
            'hmac_key_epoch' => 2,
        ]);

        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturn([$tamperedRow]);
        $result->method('iterateAssociative')->willReturnCallback(static fn (): Iterator => new ArrayIterator($result->fetchAllAssociative()));

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);
        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);
        $this->queryBuilder->method('select')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('orderBy')->willReturnSelf();
        $this->queryBuilder->method('executeQuery')->willReturn($result);

        $verification = $this->getSubject()->verifyHashChain();

        self::assertFalse(
            $verification->isValid(),
            'verifyHashChain MUST detect tampering of forensic fields when epoch=2',
        );
    }

    // =========================================================================
    // Epoch 3 — also binds the algorithm selector (hmac_key_epoch) and the
    // human-readable attribution fields (actor_type / actor_username /
    // actor_role / request_id).
    //
    // Finding audit-integrity-1 (epoch-downgrade forgery): the per-row
    // hmac_key_epoch selects the verifying algorithm but was itself
    // unauthenticated, so a DB-write attacker could downgrade the tail row to
    // keyless epoch-0 SHA-256 and re-sign it without the HMAC key.
    // Finding audit-integrity-2 (attribution forgery): actor_username/role/
    // type and request_id were excluded from the v2 HMAC payload.
    // =========================================================================

    #[Test]
    public function verifyHashChainRejectsTailRowDowngradedToEpochZeroAndKeylessResigned(): void
    {
        // A two-row chain: row 1 stays epoch-3 HMAC-protected; the attacker
        // takes the tail row, sets hmac_key_epoch=0, rewrites identity fields,
        // and recomputes a VALID keyless SHA-256 entry_hash WITHOUT the HMAC
        // key. The downgrade (3 -> 0) MUST be reported as invalid, not merely
        // warned — otherwise the keyless tail-row forgery succeeds silently.
        $masterKey = str_repeat("\x01", 32);
        $hmacKey = hash_hkdf('sha256', $masterKey, 32, 'nr-vault-audit-hmac-v1');

        $row1 = $this->makeV3Row(uid: 1, secretIdentifier: 'secret-a', action: 'create');
        $hash1 = AuditLogService::calculateHashV3($row1, '', $hmacKey);

        // Attacker's forged tail row: downgraded to epoch 0, keyless re-sign.
        $forgedPrevHash = $hash1;
        $forgedEntryHash = AuditLogService::calculateHash(
            2,
            'attacker-rewritten',
            'read',
            999,
            1704153600,
            $forgedPrevHash,
        );

        $rows = [
            array_merge($row1, [
                'previous_hash' => '',
                'entry_hash' => $hash1,
                'hmac_key_epoch' => 3,
            ]),
            [
                'uid' => 2,
                'secret_identifier' => 'attacker-rewritten',
                'action' => 'read',
                'actor_uid' => 999,
                'crdate' => 1704153600,
                'previous_hash' => $forgedPrevHash,
                'entry_hash' => $forgedEntryHash,
                'hmac_key_epoch' => 0,
            ],
        ];

        $verification = $this->runVerifyOverRows($rows);

        self::assertFalse(
            $verification->isValid(),
            'A tail row downgraded to epoch 0 and keyless-resigned MUST be reported INVALID, not just warned',
        );
        self::assertArrayHasKey(2, $verification->errors, 'The downgrade error must be recorded against the forged tail row');
        self::assertStringContainsString('downgrade', $verification->errors[2]);
    }

    #[Test]
    public function verifyHashChainEpoch3DetectsActorUsernameTampering(): void
    {
        // The entry_hash binds the original actor_username; the attacker
        // rewrites the stored column to reassign blame but cannot recompute the
        // HMAC. verifyHashChain() MUST flag the entry hash mismatch.
        $masterKey = str_repeat("\x01", 32);
        $hmacKey = hash_hkdf('sha256', $masterKey, 32, 'nr-vault-audit-hmac-v1');

        $row = $this->makeV3Row(actorUsername: 'alice');
        $validHash = AuditLogService::calculateHashV3($row, '', $hmacKey);

        $tamperedRow = array_merge($row, [
            'actor_username' => 'bob',
            'previous_hash' => '',
            'entry_hash' => $validHash,
            'hmac_key_epoch' => 3,
        ]);

        $verification = $this->runVerifyOverRows([$tamperedRow]);

        self::assertFalse(
            $verification->isValid(),
            'verifyHashChain MUST detect actor_username tampering when epoch=3',
        );
    }

    #[Test]
    public function calculateHashV2AndV3ProduceStableGoldenHashes(): void
    {
        // Golden-hash guard: pins the exact byte serialisation of the v2 and v3
        // HMAC payloads. If a future refactor (e.g. of the shared
        // forensicPayloadV2 builder) changes key order or casting, the hash of
        // every already-stored audit row would change and the chain would fail
        // to verify after deployment. Captured from the pre-refactor code.
        $key = str_repeat("\x02", 32);
        $row = [
            'uid' => 1, 'secret_identifier' => 'göld/en', 'action' => 'read',
            'success' => 1, 'actor_uid' => 7, 'crdate' => 1704067200,
            'error_message' => 'e', 'reason' => 'r', 'ip_address' => 'ip-test',
            'user_agent' => 'ua', 'hash_before' => 'hb', 'hash_after' => 'ha',
            'context' => '{"k":"v"}', 'hmac_key_epoch' => 3, 'actor_type' => 'backend',
            'actor_username' => 'alice', 'actor_role' => 'groups:1', 'request_id' => 'req-1',
        ];

        self::assertSame(
            'fca84c88f4120f3b3cc534913d61afe33ce2ecce84993b52c5f5969ec65f05a4',
            AuditLogService::calculateHashV2(AuditLogService::extractV2HashRow($row), 'PREVHASH', $key),
            'v2 payload serialisation changed - existing epoch-2 rows would no longer verify',
        );
        self::assertSame(
            'a6d2b90cfcedcb39d46bef63401b96257319988b0540fc66982f114c66a8a569',
            AuditLogService::calculateHashV3(AuditLogService::extractV3HashRow($row), 'PREVHASH', $key),
            'v3 payload serialisation changed',
        );
    }

    #[Test]
    public function verifyHashChainEpoch3RoundTripIsValid(): void
    {
        // Backward-compat/forward-compat sanity: an untampered epoch-3 chain
        // verifies valid.
        $masterKey = str_repeat("\x01", 32);
        $hmacKey = hash_hkdf('sha256', $masterKey, 32, 'nr-vault-audit-hmac-v1');

        $row1 = $this->makeV3Row(uid: 1, secretIdentifier: 'secret-a', action: 'create');
        $hash1 = AuditLogService::calculateHashV3($row1, '', $hmacKey);
        $row2 = $this->makeV3Row(uid: 2, secretIdentifier: 'secret-b', action: 'read', crdate: 1704153600);
        $hash2 = AuditLogService::calculateHashV3($row2, $hash1, $hmacKey);

        $rows = [
            array_merge($row1, ['previous_hash' => '', 'entry_hash' => $hash1, 'hmac_key_epoch' => 3]),
            array_merge($row2, ['previous_hash' => $hash1, 'entry_hash' => $hash2, 'hmac_key_epoch' => 3]),
        ];

        $verification = $this->runVerifyOverRows($rows);

        self::assertTrue($verification->isValid(), 'An untampered epoch-3 chain must verify valid');
        self::assertSame([], $verification->errors);
    }

    #[Test]
    public function verifyHashChainAllowsMonotonicEpochIncrease(): void
    {
        // A partially-migrated chain (epoch 2 row followed by an epoch 3 row)
        // is a legitimate INCREASE and must stay valid — only the increase
        // warning is recorded, never an error.
        $masterKey = str_repeat("\x01", 32);
        $hmacKey = hash_hkdf('sha256', $masterKey, 32, 'nr-vault-audit-hmac-v1');

        $row1 = $this->makeV3Row(uid: 1, secretIdentifier: 'secret-a', action: 'create');
        $hash1 = AuditLogService::calculateHashV2(AuditLogService::extractV2HashRow($row1), '', $hmacKey);
        $row2 = $this->makeV3Row(uid: 2, secretIdentifier: 'secret-b', action: 'read', crdate: 1704153600);
        $hash2 = AuditLogService::calculateHashV3($row2, $hash1, $hmacKey);

        $rows = [
            array_merge($row1, ['previous_hash' => '', 'entry_hash' => $hash1, 'hmac_key_epoch' => 2]),
            array_merge($row2, ['previous_hash' => $hash1, 'entry_hash' => $hash2, 'hmac_key_epoch' => 3]),
        ];

        $verification = $this->runVerifyOverRows($rows);

        self::assertTrue($verification->isValid(), 'A monotonically increasing epoch chain (2 -> 3) must stay valid');
        self::assertArrayHasKey(2, $verification->warnings, 'The increase must still be reported as a (non-fatal) warning');
    }

    #[Test]
    public function extractV2HashRowAcceptsBooleanSuccess(): void
    {
        // PostgreSQL via Doctrine returns smallint columns as PHP bool.
        // Regression: is_numeric(true) is false, so a naive extractor would
        // coerce a valid `true` to 0 and break verification.
        $rowTrue = ['success' => true] + $this->makeRawRow();
        $rowFalse = ['success' => false] + $this->makeRawRow();

        $extractedTrue = AuditLogService::extractV2HashRow($rowTrue);
        $extractedFalse = AuditLogService::extractV2HashRow($rowFalse);

        self::assertSame(1, $extractedTrue['success'], 'bool(true) must extract to int(1)');
        self::assertSame(0, $extractedFalse['success'], 'bool(false) must extract to int(0)');
    }

    #[Test]
    public function extractV2HashRowAcceptsNumericStringSuccess(): void
    {
        // Doctrine with PDO::ATTR_EMULATE_PREPARES=true returns ints as strings.
        $row = ['success' => '1'] + $this->makeRawRow();

        $extracted = AuditLogService::extractV2HashRow($row);

        self::assertSame(1, $extracted['success'], 'numeric-string success must extract to int(1)');
    }

    #[Test]
    public function calculateHashV2SurvivesInvalidUtf8InFreeFormFields(): void
    {
        // A malicious or buggy client may submit a User-Agent / error_message
        // containing invalid UTF-8 (e.g. a lone continuation byte). Hashing
        // must NOT throw — that would crash audit logging and break the chain.
        $hmacKey = str_repeat("\xAA", 32);
        $invalidUtf8 = "valid prefix \xC3\x28 broken sequence";

        $hash = AuditLogService::calculateHashV2(
            $this->makeV2Row(errorMessage: $invalidUtf8, userAgent: $invalidUtf8),
            '',
            $hmacKey,
        );

        self::assertSame(64, \strlen($hash), 'hash_hmac sha256 hex output is 64 chars');
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    // =========================================================================
    // Strict-assertion tests — kill IncrementInteger/DecrementInteger/CastInt/
    // Coalesce/MethodCallRemoval/ConcatOperandRemoval mutators on AuditLogService.
    // =========================================================================

    /**
     * Kills ArrayItem mutation on `pid => 0` and IncrementInteger mutation.
     */
    #[Test]
    public function insertedRowHasPidZeroExactly(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => \array_key_exists('pid', $data) && $data['pid'] === 0),
            );

        $this->getSubject()->log('test_secret', 'create', true);
    }

    /**
     * Kill IncrementInteger on `success ? 1 : 0` ternary.
     */
    #[Test]
    public function successTrueMapsToExactlyOne(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['success'] === 1),
            );

        $this->getSubject()->log('s', 'create', true);
    }

    #[Test]
    public function successFalseMapsToExactlyZero(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['success'] === 0),
            );

        $this->getSubject()->log('s', 'access_denied', false);
    }

    /**
     * Kill Coalesce mutation on `errorMessage ?? ''` fallback.
     */
    #[Test]
    public function nullErrorMessageBecomesEmptyString(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['error_message'] === ''),
            );

        $this->getSubject()->log('s', 'create', true);
    }

    #[Test]
    public function nonNullErrorMessageIsStoredExactly(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['error_message'] === 'permission denied'),
            );

        $this->getSubject()->log('s', 'access_denied', false, 'permission denied');
    }

    /**
     * Kill Coalesce on `reason ?? ''` fallback.
     */
    #[Test]
    public function nullReasonBecomesEmptyString(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['reason'] === ''),
            );

        $this->getSubject()->log('s', 'create', true);
    }

    #[Test]
    public function nullHashBeforeAndAfterBecomeEmptyStrings(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['hash_before'] === ''
                    && $data['hash_after'] === ''),
            );

        $this->getSubject()->log('s', 'create', true);
    }

    /**
     * Kill ArrayItemRemoval on any of the many keys in the insert payload.
     */
    #[Test]
    public function insertedRowIncludesAllRequiredKeys(): void
    {
        $this->setupDatabaseMocks();

        $capturedData = null;
        $this->connection
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static function (array $data) use (&$capturedData): bool {
                    $capturedData = $data;

                    return true;
                }),
            );

        $this->getSubject()->log('s', 'create', true);

        self::assertIsArray($capturedData);

        $expectedKeys = [
            'pid',
            'secret_identifier',
            'action',
            'success',
            'error_message',
            'reason',
            'actor_uid',
            'actor_type',
            'actor_username',
            'actor_role',
            'ip_address',
            'user_agent',
            'request_id',
            'previous_hash',
            'hash_before',
            'hash_after',
            'crdate',
            'hmac_key_epoch',
            'context',
        ];

        foreach ($expectedKeys as $key) {
            self::assertArrayHasKey(
                $key,
                $capturedData,
                "Missing key '{$key}' in insert payload",
            );
        }
    }

    /**
     * Kill DecrementInteger/IncrementInteger + CastInt on `->setMaxResults(1)`
     * in getLatestHash() — result is always exactly the one row.
     */
    #[Test]
    public function getLatestHashReturnsExactStringHash(): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn('0000000000000000000000000000000000000000000000000000000000000042');

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder->method('select')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('orderBy')->willReturnSelf();
        $this->queryBuilder->method('setMaxResults')->willReturnSelf();
        $this->queryBuilder->method('executeQuery')->willReturn($result);

        self::assertSame(
            '0000000000000000000000000000000000000000000000000000000000000042',
            $this->getSubject()->getLatestHash(),
        );
    }

    /**
     * Kill CastInt + Coalesce on `count()` return — result must be strict int.
     */
    #[Test]
    public function countReturnsStrictIntegerZeroWhenEmpty(): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn('0');

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder->method('count')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('executeQuery')->willReturn($result);

        // assertSame(0, ...) catches CastInt mutation where result is '0' (string).
        self::assertSame(0, $this->getSubject()->count());
    }

    #[Test]
    public function countReturnsExactInt42(): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn('42');

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder->method('count')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('executeQuery')->willReturn($result);

        // Kills CastInt — string '42' becomes int 42.
        self::assertSame(42, $this->getSubject()->count());
    }

    #[Test]
    public function countReturnsZeroWhenResultIsNonNumeric(): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn(false);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder->method('count')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('executeQuery')->willReturn($result);

        // Kills Decrement/Increment on the fallback 0.
        self::assertSame(0, $this->getSubject()->count());
    }

    /**
     * Kill IncrementInteger/DecrementInteger on `query()` default `$limit = 100`.
     */
    #[Test]
    public function queryDefaultLimitIs100(): void
    {
        $this->setupQueryMocks([]);

        $this->queryBuilder
            ->expects(self::once())
            ->method('setMaxResults')
            ->with(100)
            ->willReturnSelf();

        $this->getSubject()->query();
    }

    /**
     * Kill IncrementInteger/DecrementInteger on `query()` default `$offset = 0`.
     */
    #[Test]
    public function queryDefaultOffsetIsZero(): void
    {
        $this->setupQueryMocks([]);

        $this->queryBuilder
            ->expects(self::once())
            ->method('setFirstResult')
            ->with(0)
            ->willReturnSelf();

        $this->getSubject()->query();
    }

    /**
     * Kill MethodCallRemoval on `setMaxResults` / `setFirstResult`.
     */
    #[Test]
    public function queryWithCustomLimitAndOffsetAreUsedLiterally(): void
    {
        $this->setupQueryMocks([]);

        $this->queryBuilder
            ->expects(self::once())
            ->method('setMaxResults')
            ->with(25)
            ->willReturnSelf();

        $this->queryBuilder
            ->expects(self::once())
            ->method('setFirstResult')
            ->with(50)
            ->willReturnSelf();

        $this->getSubject()->query(null, 25, 50);
    }

    /**
     * Kill MethodCallRemoval on `export()` — streams bounded chunks from
     * offset 0 instead of a single PHP_INT_MAX fetch (avoids OOM on large
     * audit tables). An empty first chunk terminates the loop, so exactly one
     * query runs with a finite chunk size as the limit and offset 0.
     */
    #[Test]
    public function exportStreamsBoundedChunksFromZeroOffset(): void
    {
        $this->setupQueryMocks([]);

        $this->queryBuilder
            ->expects(self::once())
            ->method('setMaxResults')
            ->with(self::lessThan(PHP_INT_MAX))
            ->willReturnSelf();

        $this->queryBuilder
            ->expects(self::once())
            ->method('setFirstResult')
            ->with(0)
            ->willReturnSelf();

        self::assertSame([], $this->getSubject()->export());
    }

    // =========================================================================
    // calculateHash() strict tests — kill CastInt/Increment/Decrement/
    // ConcatOperandRemoval on the hash payload.
    // =========================================================================

    #[Test]
    public function calculateHashLegacyProducesExactly64HexChars(): void
    {
        $hash = AuditLogService::calculateHash(1, 'identifier', 'create', 42, 1704067200, '');

        self::assertSame(64, \strlen($hash));
        self::assertMatchesRegularExpression(self::SHA256_HEX_PATTERN, $hash);
    }

    #[Test]
    public function calculateHashHmacProducesExactly64HexChars(): void
    {
        $hmacKey = str_repeat("\x42", 32);
        $hash = AuditLogService::calculateHash(1, 'id', 'create', 42, 1704067200, '', $hmacKey);

        self::assertSame(64, \strlen($hash));
        self::assertMatchesRegularExpression(self::SHA256_HEX_PATTERN, $hash);
    }

    #[Test]
    public function calculateHashLegacyIsDeterministic(): void
    {
        $hash1 = AuditLogService::calculateHash(1, 'id', 'create', 42, 1704067200, 'prev');
        $hash2 = AuditLogService::calculateHash(1, 'id', 'create', 42, 1704067200, 'prev');

        // Kills IncrementInteger/DecrementInteger/ConcatOperandRemoval
        // in the JSON payload construction.
        self::assertSame($hash1, $hash2);
    }

    /**
     * Kill IncrementInteger on $uid — changing uid changes the hash output.
     */
    #[Test]
    public function calculateHashDependsOnUid(): void
    {
        $h1 = AuditLogService::calculateHash(1, 'id', 'create', 42, 1704067200, '');
        $h2 = AuditLogService::calculateHash(2, 'id', 'create', 42, 1704067200, '');
        $h3 = AuditLogService::calculateHash(0, 'id', 'create', 42, 1704067200, '');

        self::assertNotSame($h1, $h2);
        self::assertNotSame($h1, $h3);
        self::assertNotSame($h2, $h3);
    }

    /**
     * Kill IncrementInteger on $actorUid — changing actor changes hash output.
     */
    #[Test]
    public function calculateHashDependsOnActorUid(): void
    {
        $h1 = AuditLogService::calculateHash(1, 'id', 'create', 42, 1704067200, '');
        $h2 = AuditLogService::calculateHash(1, 'id', 'create', 43, 1704067200, '');

        self::assertNotSame($h1, $h2);
    }

    /**
     * Kill IncrementInteger/DecrementInteger on $crdate.
     */
    #[Test]
    public function calculateHashDependsOnCrdate(): void
    {
        $h1 = AuditLogService::calculateHash(1, 'id', 'create', 42, 1704067200, '');
        $h2 = AuditLogService::calculateHash(1, 'id', 'create', 42, 1704067201, '');
        $h3 = AuditLogService::calculateHash(1, 'id', 'create', 42, 1704067199, '');

        self::assertNotSame($h1, $h2);
        self::assertNotSame($h1, $h3);
    }

    /**
     * Kill ConcatOperandRemoval on the action string — different actions → different hash.
     */
    #[Test]
    public function calculateHashDependsOnAction(): void
    {
        $h1 = AuditLogService::calculateHash(1, 'id', 'create', 42, 1704067200, '');
        $h2 = AuditLogService::calculateHash(1, 'id', 'read', 42, 1704067200, '');
        $h3 = AuditLogService::calculateHash(1, 'id', 'delete', 42, 1704067200, '');

        self::assertNotSame($h1, $h2);
        self::assertNotSame($h1, $h3);
        self::assertNotSame($h2, $h3);
    }

    /**
     * Kill ConcatOperandRemoval on the secret identifier.
     */
    #[Test]
    public function calculateHashDependsOnSecretIdentifier(): void
    {
        $h1 = AuditLogService::calculateHash(1, 'id_a', 'create', 42, 1704067200, '');
        $h2 = AuditLogService::calculateHash(1, 'id_b', 'create', 42, 1704067200, '');

        self::assertNotSame($h1, $h2);
    }

    /**
     * Kill ConcatOperandRemoval on previous_hash — chaining depends on it.
     */
    #[Test]
    public function calculateHashDependsOnPreviousHash(): void
    {
        $h1 = AuditLogService::calculateHash(1, 'id', 'create', 42, 1704067200, '');
        $h2 = AuditLogService::calculateHash(1, 'id', 'create', 42, 1704067200, 'prev');

        self::assertNotSame($h1, $h2);
    }

    /**
     * Kill boundary mutations on boundary values: uid=0, actorUid=0, crdate=0, PHP_INT_MAX.
     */
    #[Test]
    public function calculateHashWorksAtEpochZeroAndMaxInt(): void
    {
        $h0 = AuditLogService::calculateHash(0, '', '', 0, 0, '');
        $hMax = AuditLogService::calculateHash(PHP_INT_MAX, 'max', 'max', PHP_INT_MAX, PHP_INT_MAX, '');

        self::assertMatchesRegularExpression(self::SHA256_HEX_PATTERN, $h0);
        self::assertMatchesRegularExpression(self::SHA256_HEX_PATTERN, $hMax);
        self::assertNotSame($h0, $hMax);
    }

    /**
     * Explicitly test the canonical empty-chain first entry.
     */
    #[Test]
    public function calculateHashFirstEntryMatchesCanonicalPayload(): void
    {
        // Exact canonical SHA-256 of the JSON payload — kills ConcatOperandRemoval.
        $hash = AuditLogService::calculateHash(1, 'test', 'create', 1, 1704067200, '');

        $payload = json_encode([
            'uid' => 1,
            'secret_identifier' => 'test',
            'action' => 'create',
            'actor_uid' => 1,
            'crdate' => 1704067200,
            'previous_hash' => '',
        ], JSON_THROW_ON_ERROR);

        self::assertSame(hash('sha256', $payload), $hash);
    }

    /**
     * Kill DecrementInteger/IncrementInteger on the HMAC key size (32 bytes).
     */
    #[Test]
    public function deriveHmacKeyReturnsExactly32Bytes(): void
    {
        $mkp = $this->createMock(MasterKeyProviderInterface::class);
        $mkp->method('getMasterKey')->willReturn(str_repeat("\x01", 32));

        $key = AuditLogService::deriveHmacKey($mkp);

        self::assertSame(32, \strlen($key));
    }

    /**
     * Kill ConcatOperandRemoval on the HKDF info string 'nr-vault-audit-hmac-v1'.
     */
    #[Test]
    public function deriveHmacKeyIsDeterministicForSameMasterKey(): void
    {
        $mkp = $this->createMock(MasterKeyProviderInterface::class);
        $mkp->method('getMasterKey')->willReturn(str_repeat("\x01", 32));

        $key1 = AuditLogService::deriveHmacKey($mkp);
        $key2 = AuditLogService::deriveHmacKey($mkp);

        self::assertSame($key1, $key2);
    }

    /**
     * Kill ConcatOperandRemoval on the HKDF info string — different master key → different HMAC key.
     */
    #[Test]
    public function deriveHmacKeyDiffersForDifferentMasterKeys(): void
    {
        $mkp1 = $this->createMock(MasterKeyProviderInterface::class);
        $mkp1->method('getMasterKey')->willReturn(str_repeat("\x01", 32));

        $mkp2 = $this->createMock(MasterKeyProviderInterface::class);
        $mkp2->method('getMasterKey')->willReturn(str_repeat("\x02", 32));

        self::assertNotSame(
            AuditLogService::deriveHmacKey($mkp1),
            AuditLogService::deriveHmacKey($mkp2),
        );
    }

    /**
     * Kill ConcatOperandRemoval on the actor-role 'groups:' prefix.
     */
    #[Test]
    public function actorRoleWithGroupsUsesExactGroupsPrefix(): void
    {
        $accessControlService = $this->createMock(AccessControlServiceInterface::class);
        $accessControlService->method('getCurrentActorUid')->willReturn(1);
        $accessControlService->method('getCurrentActorType')->willReturn('backend');
        $accessControlService->method('getCurrentActorUsername')->willReturn('u');
        $accessControlService->method('getCurrentUserGroups')->willReturn([7, 8, 9]);

        $subject = new AuditLogService(
            $this->connectionPool,
            $accessControlService,
            $this->masterKeyProvider,
            $this->extensionConfiguration,
        );

        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['actor_role'] === 'groups:7,8,9'),
            );

        $subject->log('s', 'read', true);
    }

    /**
     * When no groups are present, actor_role falls back to actor_type exactly.
     */
    #[Test]
    public function actorRoleWithoutGroupsFallsBackToActorType(): void
    {
        $this->setupDatabaseMocks();

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['actor_role'] === 'backend'),
            );

        $this->getSubject()->log('s', 'read', true);
    }

    /**
     * If GET_LOCK returns 0 (timeout) or NULL (DB error), `log()` must throw
     * AuditWriteException and NOT insert anything. The previous implementation
     * silently fell through and wrote the audit row unprotected.
     */
    #[Test]
    public function logThrowsWhenLockAcquisitionFails(): void
    {
        $lockResult = $this->createMock(Result::class);
        $lockResult->method('fetchOne')->willReturn(0); // 0 = timeout

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('executeQuery')
            ->willReturn($lockResult);
        $this->connection
            ->expects(self::never())
            ->method('insert');
        $this->connection
            ->expects(self::never())
            ->method('beginTransaction');

        $this->expectException(AuditWriteException::class);
        $this->expectExceptionMessageMatches('/GET_LOCK returned 0/');

        $this->getSubject()->log('s', 'read', true);
    }

    /**
     * If `beginTransaction()` throws AFTER `GET_LOCK` returned 1, the named
     * lock must be released before the exception propagates — otherwise the
     * lock remains held for the connection's lifetime and blocks every
     * subsequent audit-log writer (caught by gemini-code-assist and
     * copilot-pull-request-reviewer on PR #134).
     */
    #[Test]
    public function logReleasesLockWhenBeginTransactionFails(): void
    {
        $lockResult = $this->createMock(Result::class);
        $lockResult->method('fetchOne')->willReturn(1); // 1 = acquired

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        // GET_LOCK and the subsequent RELEASE_LOCK both go through executeQuery
        // / executeStatement; track RELEASE_LOCK was called by recording all
        // executeStatement invocations.
        $executeStatementCalls = [];
        $this->connection
            ->method('executeStatement')
            ->willReturnCallback(function (string $sql) use (&$executeStatementCalls): int {
                $executeStatementCalls[] = $sql;

                return 0;
            });
        $this->connection
            ->method('executeQuery')
            ->willReturn($lockResult);
        $this->connection
            ->method('beginTransaction')
            ->willThrowException(new RuntimeException('simulated DB failure mid-transaction-start'));
        $this->connection
            ->expects(self::never())
            ->method('insert');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('simulated DB failure');

        try {
            $this->getSubject()->log('s', 'read', true);
        } finally {
            // RELEASE_LOCK must have been called even though the exception
            // propagates out of log().
            self::assertContains(
                'SELECT RELEASE_LOCK("nr_vault_audit")',
                $executeStatementCalls,
                'Named lock must be released when beginTransaction() throws',
            );
        }
    }

    /**
     * Kills Increment/Decrement on `setMaxResults(1)` in getPreviousHash (log flow).
     */
    #[Test]
    public function previousHashLookupAppliesExactMaxOneResult(): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn(false);

        // GET_LOCK lock-acquisition stub
        $lockResult = $this->createMock(Result::class);
        $lockResult->method('fetchOne')->willReturn(1);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->connection
            ->method('executeQuery')
            ->willReturn($lockResult);

        $this->queryBuilder->method('select')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('orderBy')->willReturnSelf();

        // Record the setMaxResults argument and verify it's exactly 1.
        $maxResults = null;
        $this->queryBuilder
            ->method('setMaxResults')
            ->willReturnCallback(function ($n) use (&$maxResults): QueryBuilder {
                $maxResults = $n;

                return $this->queryBuilder;
            });

        $this->queryBuilder->method('executeQuery')->willReturn($result);

        $this->getSubject()->log('s', 'create', true);

        self::assertSame(1, $maxResults);
    }

    /**
     * Kill DecrementInteger on `previousEpoch = -1` initial value — it must be -1
     * so the first-entry check `>= 0` correctly skips the warning.
     */
    #[Test]
    public function verifyHashChainSingleEntryProducesNoEpochWarning(): void
    {
        $payload = json_encode([
            'uid' => 1,
            'secret_identifier' => 's',
            'action' => 'create',
            'actor_uid' => 1,
            'crdate' => 100,
            'previous_hash' => '',
        ], JSON_THROW_ON_ERROR);
        $hash = hash('sha256', $payload);

        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturn([
            [
                'uid' => 1,
                'secret_identifier' => 's',
                'action' => 'create',
                'actor_uid' => 1,
                'crdate' => 100,
                'previous_hash' => '',
                'entry_hash' => $hash,
                'hmac_key_epoch' => 0,
            ],
        ]);
        $result->method('iterateAssociative')->willReturnCallback(static fn (): Iterator => new ArrayIterator($result->fetchAllAssociative()));

        $this->connectionPool->method('getConnectionForTable')->willReturn($this->connection);
        $this->connection->method('createQueryBuilder')->willReturn($this->queryBuilder);
        $this->queryBuilder->method('select')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('orderBy')->willReturnSelf();
        $this->queryBuilder->method('executeQuery')->willReturn($result);

        $extensionConfig = $this->createMock(ExtensionConfigurationInterface::class);
        $extensionConfig->method('getAuditHmacEpoch')->willReturn(0);

        $subject = new AuditLogService(
            $this->connectionPool,
            $this->accessControlService,
            $this->masterKeyProvider,
            $extensionConfig,
        );

        $verification = $subject->verifyHashChain();

        self::assertTrue($verification->valid);
        // Kills DecrementInteger mutation on `$previousEpoch = -1`: with initial -1,
        // the `>= 0` check skips epoch comparison on the first entry, so no warning.
        self::assertCount(0, $verification->warnings);
    }

    /**
     * Kill DecrementInteger/IncrementInteger mutation on the uid-gap detection:
     * the condition `$uid - $previousUid > 1` means consecutive UIDs (1, 2, 3) are fine,
     * but a gap (1, 3) produces an error.
     */
    #[Test]
    public function verifyHashChainConsecutiveUidsProduceNoErrors(): void
    {
        // Build 3 consecutive entries with correct hashes.
        $hash1 = AuditLogService::calculateHash(1, 'a', 'create', 1, 100, '');
        $hash2 = AuditLogService::calculateHash(2, 'b', 'read', 1, 200, $hash1);
        $hash3 = AuditLogService::calculateHash(3, 'c', 'delete', 1, 300, $hash2);

        $rows = [
            ['uid' => 1, 'secret_identifier' => 'a', 'action' => 'create', 'actor_uid' => 1, 'crdate' => 100, 'previous_hash' => '', 'entry_hash' => $hash1, 'hmac_key_epoch' => 0],
            ['uid' => 2, 'secret_identifier' => 'b', 'action' => 'read', 'actor_uid' => 1, 'crdate' => 200, 'previous_hash' => $hash1, 'entry_hash' => $hash2, 'hmac_key_epoch' => 0],
            ['uid' => 3, 'secret_identifier' => 'c', 'action' => 'delete', 'actor_uid' => 1, 'crdate' => 300, 'previous_hash' => $hash2, 'entry_hash' => $hash3, 'hmac_key_epoch' => 0],
        ];

        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturn($rows);
        $result->method('iterateAssociative')->willReturnCallback(static fn (): Iterator => new ArrayIterator($result->fetchAllAssociative()));

        $this->connectionPool->method('getConnectionForTable')->willReturn($this->connection);
        $this->connection->method('createQueryBuilder')->willReturn($this->queryBuilder);
        $this->queryBuilder->method('select')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('orderBy')->willReturnSelf();
        $this->queryBuilder->method('executeQuery')->willReturn($result);

        $extensionConfig = $this->createMock(ExtensionConfigurationInterface::class);
        $extensionConfig->method('getAuditHmacEpoch')->willReturn(0);

        $subject = new AuditLogService(
            $this->connectionPool,
            $this->accessControlService,
            $this->masterKeyProvider,
            $extensionConfig,
        );

        $verification = $subject->verifyHashChain();

        self::assertTrue($verification->valid);
        self::assertCount(0, $verification->errors);
    }

    /**
     * Kills GreaterThan mutation on `$uid - $previousUid > 1` (gap detection).
     * Missing uid=2 between 1 and 3 must surface as an error.
     */
    #[Test]
    public function verifyHashChainUidGapProducesErrorWithExactMissingUids(): void
    {
        $hash1 = AuditLogService::calculateHash(1, 'a', 'create', 1, 100, '');
        $hash3 = AuditLogService::calculateHash(3, 'c', 'delete', 1, 300, $hash1);

        $rows = [
            ['uid' => 1, 'secret_identifier' => 'a', 'action' => 'create', 'actor_uid' => 1, 'crdate' => 100, 'previous_hash' => '', 'entry_hash' => $hash1, 'hmac_key_epoch' => 0],
            ['uid' => 3, 'secret_identifier' => 'c', 'action' => 'delete', 'actor_uid' => 1, 'crdate' => 300, 'previous_hash' => $hash1, 'entry_hash' => $hash3, 'hmac_key_epoch' => 0],
        ];

        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturn($rows);
        $result->method('iterateAssociative')->willReturnCallback(static fn (): Iterator => new ArrayIterator($result->fetchAllAssociative()));

        $this->connectionPool->method('getConnectionForTable')->willReturn($this->connection);
        $this->connection->method('createQueryBuilder')->willReturn($this->queryBuilder);
        $this->queryBuilder->method('select')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('orderBy')->willReturnSelf();
        $this->queryBuilder->method('executeQuery')->willReturn($result);

        $extensionConfig = $this->createMock(ExtensionConfigurationInterface::class);
        $extensionConfig->method('getAuditHmacEpoch')->willReturn(0);

        $subject = new AuditLogService(
            $this->connectionPool,
            $this->accessControlService,
            $this->masterKeyProvider,
            $extensionConfig,
        );

        $verification = $subject->verifyHashChain();

        self::assertFalse($verification->valid);
        self::assertCount(1, $verification->errors);
        self::assertArrayHasKey(3, $verification->errors);
        self::assertStringContainsString('gap', $verification->errors[3]);
        // Missing uid list is exactly [2].
        self::assertSame([2], $verification->missingUids);
    }

    /**
     * Kill DecrementInteger/IncrementInteger on the gap-boundary (`gapStart = previousUid + 1`,
     * `gapEnd = uid - 1`).
     */
    #[Test]
    public function verifyHashChainTwoEntryGapListsAllMissingUids(): void
    {
        $hash1 = AuditLogService::calculateHash(1, 'a', 'create', 1, 100, '');
        $hash5 = AuditLogService::calculateHash(5, 'e', 'delete', 1, 500, $hash1);

        $rows = [
            ['uid' => 1, 'secret_identifier' => 'a', 'action' => 'create', 'actor_uid' => 1, 'crdate' => 100, 'previous_hash' => '', 'entry_hash' => $hash1, 'hmac_key_epoch' => 0],
            ['uid' => 5, 'secret_identifier' => 'e', 'action' => 'delete', 'actor_uid' => 1, 'crdate' => 500, 'previous_hash' => $hash1, 'entry_hash' => $hash5, 'hmac_key_epoch' => 0],
        ];

        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturn($rows);
        $result->method('iterateAssociative')->willReturnCallback(static fn (): Iterator => new ArrayIterator($result->fetchAllAssociative()));

        $this->connectionPool->method('getConnectionForTable')->willReturn($this->connection);
        $this->connection->method('createQueryBuilder')->willReturn($this->queryBuilder);
        $this->queryBuilder->method('select')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('orderBy')->willReturnSelf();
        $this->queryBuilder->method('executeQuery')->willReturn($result);

        $extensionConfig = $this->createMock(ExtensionConfigurationInterface::class);
        $extensionConfig->method('getAuditHmacEpoch')->willReturn(0);

        $subject = new AuditLogService(
            $this->connectionPool,
            $this->accessControlService,
            $this->masterKeyProvider,
            $extensionConfig,
        );

        $verification = $subject->verifyHashChain();

        // Kills increments / decrements on gapStart and gapEnd computations.
        self::assertSame([2, 3, 4], $verification->missingUids);
    }

    /**
     * Build a raw DB row (snake_case keys, mixed types) suitable for
     * extractV2HashRow() input. Used by tests that exercise the extractor
     * directly without going through the V2 fixture.
     *
     * @return array<string, mixed>
     */
    private function makeRawRow(): array
    {
        return [
            'uid' => 1,
            'secret_identifier' => 'sek',
            'action' => 'read',
            'actor_uid' => 1,
            'crdate' => 1704067200,
            'error_message' => '',
            'reason' => '',
            'ip_address' => self::IP_ADDRESS,
            'user_agent' => self::USER_AGENT,
            'hash_before' => '',
            'hash_after' => '',
            'context' => '{}',
        ];
    }

    /**
     * Build a v2 hash row with sensible defaults; override individual fields
     * via named parameters.
     *
     * @return array{
     *     uid: int, secret_identifier: string, action: string, success: int,
     *     actor_uid: int, crdate: int, error_message: string, reason: string,
     *     ip_address: string, user_agent: string, hash_before: string,
     *     hash_after: string, context: string,
     * }
     */
    private function makeV2Row(
        int $uid = 1,
        string $secretIdentifier = 'sek',
        string $action = 'read',
        int $success = 1,
        int $actorUid = 1,
        int $crdate = 1704067200,
        string $errorMessage = '',
        string $reason = '',
        string $ipAddress = self::IP_ADDRESS,
        string $userAgent = self::USER_AGENT,
        string $hashBefore = '',
        string $hashAfter = '',
        string $context = '{}',
    ): array {
        return [
            'uid' => $uid,
            'secret_identifier' => $secretIdentifier,
            'action' => $action,
            'success' => $success,
            'actor_uid' => $actorUid,
            'crdate' => $crdate,
            'error_message' => $errorMessage,
            'reason' => $reason,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'hash_before' => $hashBefore,
            'hash_after' => $hashAfter,
            'context' => $context,
        ];
    }

    /**
     * Build a v3 hash row (v2 fields plus the epoch selector and the four
     * attribution fields) with sensible defaults; override individual fields
     * via named parameters.
     *
     * @return array{
     *     uid: int, secret_identifier: string, action: string, success: int,
     *     actor_uid: int, crdate: int, error_message: string, reason: string,
     *     ip_address: string, user_agent: string, hash_before: string,
     *     hash_after: string, context: string, hmac_key_epoch: int,
     *     actor_type: string, actor_username: string, actor_role: string,
     *     request_id: string,
     * }
     */
    private function makeV3Row(
        int $uid = 1,
        string $secretIdentifier = 'sek',
        string $action = 'read',
        int $success = 1,
        int $actorUid = 1,
        int $crdate = 1704067200,
        string $actorType = 'backend',
        string $actorUsername = 'admin',
        string $actorRole = 'groups:1',
        string $requestId = 'req-0001',
    ): array {
        return $this->makeV2Row(
            uid: $uid,
            secretIdentifier: $secretIdentifier,
            action: $action,
            success: $success,
            actorUid: $actorUid,
            crdate: $crdate,
        ) + [
            'hmac_key_epoch' => 3,
            'actor_type' => $actorType,
            'actor_username' => $actorUsername,
            'actor_role' => $actorRole,
            'request_id' => $requestId,
        ];
    }

    /**
     * Wire the verify-path query mocks over the given rows and run
     * verifyHashChain() on the default subject.
     *
     * @param array<int, array<string, mixed>> $rows
     */
    private function runVerifyOverRows(array $rows): HashChainVerificationResult
    {
        $this->setupQueryMocks($rows);

        return $this->getSubject()->verifyHashChain();
    }

    private function getSubject(): AuditLogService
    {
        self::assertNotNull($this->subject);

        return $this->subject;
    }

    private function setupDatabaseMocks(mixed $previousHashFetchOne = false): void
    {
        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $result = $this->createMock(Result::class);
        // getLatestHash() uses fetchOne(); default `false` means "no prior entry".
        // Tests that exercise chaining override this to return the previous_hash value.
        $result->method('fetchOne')->willReturn($previousHashFetchOne);

        // GET_LOCK on MySQL/MariaDB returns 1 on success. Mock the runtime lock
        // acquisition path so tests that don't explicitly stub it don't fail
        // with AuditWriteException::lockAcquisitionFailed().
        $lockResult = $this->createMock(Result::class);
        $lockResult->method('fetchOne')->willReturn(1);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        // The implementation uses $connection->createQueryBuilder()
        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        // $connection->executeQuery('SELECT GET_LOCK(...)') is called directly
        // (not via QueryBuilder) for the audit advisory lock.
        $this->connection
            ->method('executeQuery')
            ->willReturn($lockResult);

        $this->queryBuilder
            ->method('expr')
            ->willReturn($expressionBuilder);

        $this->queryBuilder
            ->method('select')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('from')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('orderBy')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('setMaxResults')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('executeQuery')
            ->willReturn($result);
    }

    /**
     * @param array<int, array<string, mixed>> $rows
     */
    private function setupQueryMocks(array $rows): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturn($rows);
        $result->method('iterateAssociative')->willReturnCallback(static fn (): Iterator => new ArrayIterator($result->fetchAllAssociative()));

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder
            ->method('select')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('from')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('orderBy')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('setMaxResults')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('setFirstResult')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('executeQuery')
            ->willReturn($result);
    }

    /**
     * @param array<int, array<string, mixed>> $rows
     */
    private function setupQueryMocksWithFilter(ExpressionBuilder&MockObject $expressionBuilder, array $rows): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturn($rows);
        $result->method('iterateAssociative')->willReturnCallback(static fn (): Iterator => new ArrayIterator($result->fetchAllAssociative()));

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder
            ->method('expr')
            ->willReturn($expressionBuilder);

        $this->queryBuilder
            ->method('select')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('from')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('orderBy')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('setMaxResults')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('setFirstResult')
            ->willReturnSelf();

        $this->queryBuilder
            ->method('createNamedParameter')
            ->willReturn('?');

        $this->queryBuilder
            ->method('executeQuery')
            ->willReturn($result);
    }
}
