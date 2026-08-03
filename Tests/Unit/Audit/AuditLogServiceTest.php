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
use InvalidArgumentException;
use Iterator;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditChainAnchor;
use Netresearch\NrVault\Audit\AuditChainAnchorLoad;
use Netresearch\NrVault\Audit\AuditChainAnchorStatus;
use Netresearch\NrVault\Audit\AuditChainAnchorStoreInterface;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\AuditLogFilter;
use Netresearch\NrVault\Audit\AuditLogInputs;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\GenericContext;
use Netresearch\NrVault\Audit\HashChainVerificationResult;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Exception\AuditWriteException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use RuntimeException;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

#[CoversClass(AuditLogService::class)]
#[CoversClass(AuditLogEntry::class)]
#[CoversClass(AuditLogInputs::class)]
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

    /**
     * Typed precisely rather than as a bare MockObject: the constructor takes
     * the interface, and a DNF type lets the analyser see that without an
     * entry in the baseline.
     */
    private AuditChainAnchorStoreInterface&MockObject $anchorStore;

    /**
     * LIMIT / OFFSET recorded per query by `setupPagingQueryMocks()`, and the
     * LIMIT recorded by `verifyWithAnchorLoads()`. Paging and single-row reads
     * are only observable through the arguments the builder received.
     *
     * @var list<int|null>
     */
    private array $recordedLimits = [];

    /** @var list<int|null> */
    private array $recordedOffsets = [];

    /** @var list<int|null> */
    private array $recordedMaxResults = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->connectionPool = $this->createMock(ConnectionPool::class);
        $this->accessControlService = $this->createMock(AccessControlServiceInterface::class);
        $this->masterKeyProvider = $this->createMock(MasterKeyProviderInterface::class);
        $this->extensionConfiguration = $this->createMock(ExtensionConfigurationInterface::class);
        $this->queryBuilder = $this->createMock(QueryBuilder::class);
        $this->connection = $this->createMock(Connection::class);
        // The tip anchor is exercised in its own unit + functional tests; here
        // it stays inert so the existing write/verify assertions are unchanged.
        $this->anchorStore = $this->createMock(AuditChainAnchorStoreInterface::class);
        $this->anchorStore
            ->method('load')
            ->willReturn(new AuditChainAnchorLoad(AuditChainAnchorStatus::Disabled));

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
            $this->anchorStore,
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
    public function logRecordsTechnicalActorAttributionAsReportedByAccessControl(): void
    {
        // Inside a TechnicalActorContext::runAs() scope AccessControlService
        // reports the named technical identity; the audit row must seal it
        // (actor_type 'technical' marks the scope) instead of the ambient
        // CLI/backend attribution.
        $this->setupDatabaseMocks();

        $accessControlService = $this->createMock(AccessControlServiceInterface::class);
        $accessControlService->method('getCurrentActorUid')->willReturn(42);
        $accessControlService->method('getCurrentActorType')->willReturn('technical');
        $accessControlService->method('getCurrentActorUsername')->willReturn('tech_indexer');
        $accessControlService->method('getCurrentUserGroups')->willReturn([5]);

        self::assertNotNull($this->connectionPool);
        self::assertNotNull($this->masterKeyProvider);
        self::assertNotNull($this->extensionConfiguration);
        $subject = new AuditLogService(
            $this->connectionPool,
            $accessControlService,
            $this->masterKeyProvider,
            $this->extensionConfiguration,
            $this->anchorStore,
        );

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['actor_uid'] === 42
                    && $data['actor_type'] === 'technical'
                    && $data['actor_username'] === 'tech_indexer'
                    && $data['actor_role'] === 'groups:5'),
            );

        $subject->log('test_secret', 'read', true);
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

        $subject = new AuditLogService(
            $this->connectionPool,
            $accessControlService,
            $this->masterKeyProvider,
            $this->extensionConfiguration,
            $this->anchorStore,
        );

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

        $cause = new RuntimeException('Insert failed');
        $this->connection
            ->method('insert')
            ->willThrowException($cause);

        $this->connection
            ->expects(self::once())
            ->method('rollBack');

        $this->connection
            ->expects(self::never())
            ->method('commit');

        // Single failure contract: any chain-write failure surfaces as
        // AuditWriteException — the type the SEC-3 compensating rollbacks in
        // VaultService and SecretTcaHook key on — with the driver error
        // chained as previous.
        try {
            $this->getSubject()->log('test_secret', 'create', true);
            self::fail('log() must throw on a failed insert');
        } catch (AuditWriteException $e) {
            self::assertStringContainsString('Insert failed', $e->getMessage());
            self::assertSame($cause, $e->getPrevious());
        }
    }

    #[Test]
    public function logDoesNotDoubleWrapAnAuditWriteException(): void
    {
        // A lock-acquisition failure is already an AuditWriteException; the
        // wrap in log() must rethrow it as-is instead of nesting it.
        $this->setupDatabaseMocks();

        $original = AuditWriteException::lockAcquisitionFailed(0);
        $this->connection
            ->method('insert')
            ->willThrowException($original);

        try {
            $this->getSubject()->log('test_secret', 'create', true);
            self::fail('log() must rethrow the AuditWriteException');
        } catch (AuditWriteException $e) {
            self::assertSame($original, $e);
        }
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
            $this->anchorStore,
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

    /**
     * The v3 payload adds the attribution fields, which come from the same
     * arbitrary-byte sources; hashing must not throw there either.
     */
    #[Test]
    public function calculateHashV3SurvivesInvalidUtf8InTheAttributionFields(): void
    {
        $hash = AuditLogService::calculateHashV3(
            $this->makeV3Row(actorUsername: "valid prefix \xC3\x28 broken sequence"),
            '',
            str_repeat("\xAA", 32),
        );

        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    /**
     * `success` is a flag, not a number: every truthy driver representation
     * has to hash identically, or the same logical row would verify
     * differently depending on which driver read it.
     */
    #[Test]
    public function calculateHashV2TreatsAnyTruthySuccessAsOne(): void
    {
        $hmacKey = str_repeat("\xAA", 32);

        self::assertSame(
            AuditLogService::calculateHashV2($this->makeV2Row(success: 1), '', $hmacKey),
            AuditLogService::calculateHashV2($this->makeV2Row(success: 2), '', $hmacKey),
        );
    }

    /**
     * The master-key-taking derivation is the single home of the HKDF
     * parameters, called by the master-key rotation from outside this class —
     * so it has to stay reachable, and agree with the provider-based variant.
     */
    #[Test]
    public function theMasterKeyTakingHmacDerivationIsPubliclyReachable(): void
    {
        $derived = AuditLogService::deriveHmacKeyFromMasterKey(str_repeat("\x01", 32));

        self::assertSame(32, \strlen($derived));
        self::assertSame(AuditLogService::deriveHmacKey($this->masterKeyProviderMock()), $derived);
    }

    /**
     * Doctrine hands integer columns back as strings on several drivers. The
     * extractors exist to restore the integer type — the hash payload is JSON,
     * where `"7"` and `7` are different values and would break the chain.
     */
    #[Test]
    public function extractHashRowCoercesNumericStringsToIntegers(): void
    {
        $extracted = AuditLogService::extractHashRow([
            'uid' => '7',
            'secret_identifier' => 'sek',
            'action' => 'read',
            'actor_uid' => '3',
            'crdate' => '1704067200',
            'hmac_key_epoch' => '2',
        ]);

        self::assertSame(7, $extracted['uid']);
        self::assertSame(3, $extracted['actorUid']);
        self::assertSame(1704067200, $extracted['crdate']);
        self::assertSame(2, $extracted['epoch']);
    }

    /**
     * A value that is not a number at all falls back to 0 — the neutral value
     * a fresh row would carry, never a sentinel that could collide with a real
     * uid or shift the epoch dispatch.
     */
    #[Test]
    public function extractHashRowFallsBackToZeroForUnusableFields(): void
    {
        $extracted = AuditLogService::extractHashRow([
            'uid' => 'not-a-number',
            'actor_uid' => null,
            'crdate' => 'not-a-number',
            'hmac_key_epoch' => 'not-a-number',
        ]);

        self::assertSame(0, $extracted['uid']);
        self::assertSame(0, $extracted['actorUid']);
        self::assertSame(0, $extracted['crdate']);
        self::assertSame(0, $extracted['epoch']);
    }

    #[Test]
    public function extractV2HashRowCoercesNumericStringsToIntegers(): void
    {
        $extracted = AuditLogService::extractV2HashRow([
            'uid' => '7',
            'actor_uid' => '3',
            'crdate' => '1704067200',
        ]);

        self::assertSame(7, $extracted['uid']);
        self::assertSame(3, $extracted['actor_uid']);
        self::assertSame(1704067200, $extracted['crdate']);
    }

    #[Test]
    public function extractV2HashRowFallsBackToZeroForUnusableFields(): void
    {
        $extracted = AuditLogService::extractV2HashRow([
            'uid' => 'not-a-number',
            'actor_uid' => 'not-a-number',
            'crdate' => 'not-a-number',
            // Neither a bool nor numeric: outside the accepted driver shapes.
            'success' => 'not-a-number',
        ]);

        self::assertSame(0, $extracted['uid']);
        self::assertSame(0, $extracted['actor_uid']);
        self::assertSame(0, $extracted['crdate']);
        self::assertSame(0, $extracted['success']);
    }

    /**
     * `success` is a flag: anything truthy normalises to 1, so the value that
     * enters the hash does not depend on how a driver spelled "true".
     */
    #[Test]
    public function extractV2HashRowNormalisesAnyTruthySuccessToOne(): void
    {
        self::assertSame(1, AuditLogService::extractV2HashRow(['success' => 2])['success']);
        self::assertSame(1, AuditLogService::extractV2HashRow(['success' => true])['success']);
        self::assertSame(0, AuditLogService::extractV2HashRow(['success' => false])['success']);
    }

    /**
     * The epoch is the algorithm selector the v3 payload authenticates, so it
     * has to reach the hash as an integer and default to the keyless 0.
     */
    #[Test]
    public function extractV3HashRowCoercesTheEpochToAnInteger(): void
    {
        self::assertSame(3, AuditLogService::extractV3HashRow(['hmac_key_epoch' => '3'])['hmac_key_epoch']);
        self::assertSame(0, AuditLogService::extractV3HashRow(['hmac_key_epoch' => 'not-a-number'])['hmac_key_epoch']);
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
            $this->anchorStore,
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
        $this->expectExceptionMessageToContain('simulated DB failure');

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
            $this->anchorStore,
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
            $this->anchorStore,
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
            $this->anchorStore,
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
            $this->anchorStore,
        );

        $verification = $subject->verifyHashChain();

        // Kills increments / decrements on gapStart and gapEnd computations.
        self::assertSame([2, 3, 4], $verification->missingUids);
    }

    #[Test]
    public function logStripsUrlQueryStringFromTransportErrorMessage(): void
    {
        // F4 / CWE-532: a SecretPlacement::QueryParam request whose transport
        // throws surfaces the effective URI — including `?api_key=<secret>` —
        // in the ClientExceptionInterface message. VaultHttpClient forwards
        // that message verbatim to log(); the sanitizer MUST strip the query
        // string so the live secret is never sealed into the audit row.
        $this->setupDatabaseMocks();

        $secret = 'SUPERSECRET123';
        $message = 'cURL error 6: Could not resolve host: api.example.com '
            . 'for https://api.example.com/data?api_key=' . $secret;

        $captured = null;
        $this->connection
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static function (array $data) use (&$captured): bool {
                    $captured = $data['error_message'];

                    return true;
                }),
            );

        $this->getSubject()->log('api_creds', 'http_call', false, $message);

        self::assertIsString($captured);
        self::assertStringNotContainsString(
            $secret,
            $captured,
            'The live secret must NOT be persisted in the audit row',
        );
        self::assertStringContainsString(
            '[REDACTED]',
            $captured,
            'The stripped query must be marked [REDACTED]',
        );
        self::assertStringContainsString(
            'https://api.example.com/data',
            $captured,
            'Scheme/host/path forensics are retained',
        );
    }

    #[Test]
    public function verifyHashChainRejectsUniformEpochZeroRelabelOnHmacInstall(): void
    {
        // F3 (audit-chain-integrity): a DB-write attacker relabels EVERY row of an
        // HMAC-migrated chain down to keyless epoch-0 and recomputes a fully valid
        // keyless SHA-256 chain. Per-row hash checks, previous_hash links and the
        // consecutive-epoch check all pass (every row is epoch 0, no DECREASE);
        // only the configured-epoch high-water floor exposes the downgrade. The
        // setUp() subject is configured for HMAC (epoch 1).
        $hash1 = AuditLogService::calculateHash(1, 'a', 'create', 1, 100, '');
        $hash2 = AuditLogService::calculateHash(2, 'b', 'read', 1, 200, $hash1);

        $rows = [
            ['uid' => 1, 'secret_identifier' => 'a', 'action' => 'create', 'actor_uid' => 1, 'crdate' => 100, 'previous_hash' => '', 'entry_hash' => $hash1, 'hmac_key_epoch' => 0],
            ['uid' => 2, 'secret_identifier' => 'b', 'action' => 'read', 'actor_uid' => 1, 'crdate' => 200, 'previous_hash' => $hash1, 'entry_hash' => $hash2, 'hmac_key_epoch' => 0],
        ];

        $verification = $this->runVerifyOverRows($rows);

        self::assertFalse(
            $verification->isValid(),
            'A chain relabelled entirely to keyless epoch 0 on an HMAC-configured install MUST be rejected',
        );
        self::assertArrayHasKey(0, $verification->errors, 'The chain-level epoch-floor error must be recorded');
        self::assertStringContainsString('floor', $verification->errors[0]);
    }

    // =========================================================================
    // F8 — `user_agent` / `request_id` come verbatim from client-controlled
    // request headers and land in fixed-width columns. They must be clipped
    // on the single array that feeds BOTH the INSERT and the entry hash.
    // =========================================================================

    #[Test]
    public function oversizedRequestIdHeaderIsClippedToTheColumnWidth(): void
    {
        // `request_id` is varchar(100); an unauthenticated caller can send any
        // length. Unclipped, strict sql_mode aborts the INSERT (taking the
        // audited operation with it) and non-strict mode truncates behind the
        // hash's back.
        $this->stubServerRequest(requestId: str_repeat('A', 200));

        $captured = $this->captureInsertPayload();

        self::assertIsString($captured['request_id']);
        self::assertSame(str_repeat('A', 100), $captured['request_id']);
    }

    #[Test]
    public function oversizedUserAgentHeaderIsClippedToTheColumnWidth(): void
    {
        $this->stubServerRequest(userAgent: str_repeat('B', 900));

        $captured = $this->captureInsertPayload();

        self::assertIsString($captured['user_agent']);
        self::assertSame(str_repeat('B', 500), $captured['user_agent']);
    }

    #[Test]
    public function headersShorterThanTheColumnWidthAreStoredUnchanged(): void
    {
        $this->stubServerRequest(requestId: 'req-42', userAgent: self::USER_AGENT);

        $captured = $this->captureInsertPayload();

        self::assertSame('req-42', $captured['request_id']);
        self::assertSame(self::USER_AGENT, $captured['user_agent']);
    }

    #[Test]
    public function multiByteHeadersAreClippedOnACharacterBoundary(): void
    {
        // 'ä' is two bytes: a byte-wise cut at the column width would land
        // mid-character and leave an ill-formed sequence that a utf8mb4
        // column rejects outright.
        $this->stubServerRequest(requestId: str_repeat('ä', 200), userAgent: str_repeat('€', 900));

        $captured = $this->captureInsertPayload();

        self::assertIsString($captured['request_id']);
        self::assertIsString($captured['user_agent']);
        self::assertSame(str_repeat('ä', 100), $captured['request_id']);
        self::assertSame(str_repeat('€', 500), $captured['user_agent']);
        self::assertTrue(mb_check_encoding($captured['request_id'], 'UTF-8'));
        self::assertTrue(mb_check_encoding($captured['user_agent'], 'UTF-8'));
    }

    #[Test]
    public function invalidUtf8InHeadersIsScrubbedBeforeStorage(): void
    {
        // Header bytes are arbitrary; an ill-formed sequence is rejected by a
        // utf8mb4 column, so it must be scrubbed before the value is hashed —
        // not left for the database to reject or mangle.
        $this->stubServerRequest(
            requestId: "req \xC3\x28 broken",
            userAgent: "ua \xC3\x28 broken",
        );

        $captured = $this->captureInsertPayload();

        self::assertIsString($captured['request_id']);
        self::assertIsString($captured['user_agent']);
        self::assertTrue(mb_check_encoding($captured['request_id'], 'UTF-8'));
        self::assertTrue(mb_check_encoding($captured['user_agent'], 'UTF-8'));
        self::assertStringStartsWith('req ', $captured['request_id']);
        self::assertStringStartsWith('ua ', $captured['user_agent']);
    }

    /**
     * The heart of the fix: the entry hash must be computed over exactly the
     * bytes that were inserted. Epoch 3 binds `user_agent` and `request_id`
     * into the HMAC, so a clip applied anywhere downstream of the hash (or by
     * the database itself) would make every later verification of this row
     * report a tamper that never happened.
     */
    #[Test]
    public function clippedHeaderValuesAreTheExactBytesTheEntryHashCovers(): void
    {
        $this->stubServerRequest(
            requestId: str_repeat('ä', 200),
            userAgent: str_repeat('€', 900),
        );

        $epoch3Configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $epoch3Configuration->method('getAuditHmacEpoch')->willReturn(3);

        $subject = new AuditLogService(
            $this->connectionPool,
            $this->accessControlService,
            $this->masterKeyProvider,
            $epoch3Configuration,
            $this->anchorStore,
        );

        $this->setupDatabaseMocks();
        $this->connection->method('lastInsertId')->willReturn('42');

        $insertedRow = [];
        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static function (array $data) use (&$insertedRow): bool {
                    $insertedRow = $data;

                    return true;
                }),
            );

        $storedHash = null;
        $this->connection
            ->expects(self::once())
            ->method('update')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static function (array $fields) use (&$storedHash): bool {
                    $storedHash = $fields['entry_hash'] ?? null;

                    return true;
                }),
                self::anything(),
            );

        $subject->log('s', 'create', true);

        self::assertIsArray($insertedRow);
        self::assertIsString($storedHash);

        // Recompute the hash from the row as it was INSERTED (clipped values).
        $expectedHash = AuditLogService::calculateHashV3(
            AuditLogService::extractV3HashRow(['uid' => 42] + $insertedRow),
            '',
            AuditLogService::deriveHmacKey($this->masterKeyProvider),
        );

        self::assertSame(
            $expectedHash,
            $storedHash,
            'entry_hash must cover the clipped values that were actually stored',
        );
    }

    // =========================================================================
    // Guard rails and branches around the chain write.
    // =========================================================================

    /**
     * An unknown action string would be sealed into the tamper-evident chain
     * forever and could never be verified against a known payload again, so it is
     * a hard programming error — not an `AuditWriteException` the VaultService
     * atomicity path compensates for.
     */
    #[Test]
    public function anUnknownActionIsRejectedBeforeAnythingIsWritten(): void
    {
        $this->connectionMock()->expects(self::never())->method('insert');

        try {
            $this->getSubject()->log('api_creds', 'exfiltrate', true);
            self::fail('an unknown action must not be accepted');
        } catch (InvalidArgumentException $e) {
            self::assertSame(1717100000, $e->getCode());
            self::assertStringContainsString('exfiltrate', $e->getMessage());
        }
    }

    #[Test]
    public function everyDeclaredAuditActionIsAcceptedByLog(): void
    {
        $actions = AuditAction::cases();

        $this->setupDatabaseMocks();
        // The guard must reject typos, not the canonical set: every case has to
        // reach the INSERT.
        $this->connectionMock()->expects(self::exactly(\count($actions)))->method('insert');

        foreach ($actions as $action) {
            $this->getSubject()->log('api_creds', $action->value, true);
        }
    }

    /**
     * `export()` materialises what `exportIterable()` streams. Exercised over a
     * non-empty result so the accumulation — not just the empty short-circuit —
     * is covered.
     */
    #[Test]
    public function exportMaterialisesEveryStreamedEntry(): void
    {
        $this->setupQueryMocks([
            ['uid' => 1, 'secret_identifier' => 'a', 'action' => 'create', 'success' => 1, 'actor_uid' => 1, 'crdate' => 100, 'entry_hash' => 'h1', 'previous_hash' => '', 'hmac_key_epoch' => 1],
            ['uid' => 2, 'secret_identifier' => 'b', 'action' => 'read', 'success' => 1, 'actor_uid' => 1, 'crdate' => 200, 'entry_hash' => 'h2', 'previous_hash' => 'h1', 'hmac_key_epoch' => 1],
        ]);

        $entries = $this->getSubject()->export();

        self::assertCount(2, $entries);
        self::assertContainsOnlyInstancesOf(AuditLogEntry::class, $entries);
        self::assertSame([1, 2], array_map(static fn (AuditLogEntry $e): int => $e->uid, $entries));
    }

    #[Test]
    public function exportIterableYieldsTheSameEntriesItStreams(): void
    {
        $this->setupQueryMocks([
            ['uid' => 7, 'secret_identifier' => 'a', 'action' => 'read', 'success' => 1, 'actor_uid' => 1, 'crdate' => 100, 'entry_hash' => 'h7', 'previous_hash' => '', 'hmac_key_epoch' => 1],
        ]);

        $uids = [];
        foreach ($this->getSubject()->exportIterable() as $entry) {
            $uids[] = $entry->uid;
        }

        self::assertSame([7], $uids);
    }

    // =========================================================================
    // verifyChainForReseal() — the gate that stops a re-seal from laundering
    // tampering into a freshly valid chain.
    // =========================================================================

    /**
     * A genuinely-legacy keyless chain carries no HMAC evidence to check; the
     * re-seal is exactly how it FIRST gains protection, so it must be allowed.
     */
    #[Test]
    public function resealVerificationSkipsAChainWithNoHmacRows(): void
    {
        $this->setupResealMocks(rows: [], hmacRowCount: 0);

        self::assertNull($this->getSubject()->verifyChainForReseal());
    }

    #[Test]
    public function resealVerificationPassesAnIntactHmacChain(): void
    {
        $hmacKey = AuditLogService::deriveHmacKey($this->masterKeyProviderMock());
        $hash1 = AuditLogService::calculateHash(1, 'a', 'create', 1, 100, '', $hmacKey);
        $hash2 = AuditLogService::calculateHash(2, 'b', 'read', 1, 200, $hash1, $hmacKey);

        $this->setupResealMocks(
            rows: [
                ['uid' => 1, 'secret_identifier' => 'a', 'action' => 'create', 'actor_uid' => 1, 'crdate' => 100, 'previous_hash' => '', 'entry_hash' => $hash1, 'hmac_key_epoch' => 1],
                ['uid' => 2, 'secret_identifier' => 'b', 'action' => 'read', 'actor_uid' => 1, 'crdate' => 200, 'previous_hash' => $hash1, 'entry_hash' => $hash2, 'hmac_key_epoch' => 1],
            ],
            hmacRowCount: 2,
        );

        self::assertNull(
            $this->getSubject()->verifyChainForReseal(),
            'an intact HMAC chain must not block its own re-seal',
        );
    }

    /**
     * The security-relevant direction: re-sealing recomputes every hash under the
     * current key, which would turn a tampered chain into a valid-looking one. So
     * the tampering has to be REPORTED here, for the caller to refuse on.
     */
    #[Test]
    public function resealVerificationReportsATamperedHmacChainSoTheResealCanBeRefused(): void
    {
        $hmacKey = AuditLogService::deriveHmacKey($this->masterKeyProviderMock());
        $hash1 = AuditLogService::calculateHash(1, 'a', 'create', 1, 100, '', $hmacKey);

        $this->setupResealMocks(
            rows: [
                ['uid' => 1, 'secret_identifier' => 'a', 'action' => 'create', 'actor_uid' => 1, 'crdate' => 100, 'previous_hash' => '', 'entry_hash' => $hash1, 'hmac_key_epoch' => 1],
                // Rewritten identifier: the stored hash no longer matches the payload.
                ['uid' => 2, 'secret_identifier' => 'rewritten', 'action' => 'read', 'actor_uid' => 1, 'crdate' => 200, 'previous_hash' => $hash1, 'entry_hash' => str_repeat('0', 64), 'hmac_key_epoch' => 1],
            ],
            hmacRowCount: 2,
        );

        $result = $this->getSubject()->verifyChainForReseal();

        self::assertInstanceOf(HashChainVerificationResult::class, $result);
        self::assertFalse($result->isValid());
        self::assertArrayHasKey(2, $result->errors);
    }

    /**
     * The re-seal check must verify under the chain's OWN stored epochs, not the
     * configured target: an epoch-1 chain migrating to epoch 2 is legitimate and
     * must not be reported as a downgrade. The subject here is configured for
     * epoch 1 while the chain sits at epoch 0 plus HMAC rows.
     */
    #[Test]
    public function resealVerificationDoesNotApplyTheConfiguredEpochFloor(): void
    {
        $hmacKey = AuditLogService::deriveHmacKey($this->masterKeyProviderMock());
        $hash1 = AuditLogService::calculateHash(1, 'a', 'create', 1, 100, '');
        $hash2 = AuditLogService::calculateHash(2, 'b', 'read', 1, 200, $hash1, $hmacKey);

        $this->setupResealMocks(
            rows: [
                ['uid' => 1, 'secret_identifier' => 'a', 'action' => 'create', 'actor_uid' => 1, 'crdate' => 100, 'previous_hash' => '', 'entry_hash' => $hash1, 'hmac_key_epoch' => 0],
                ['uid' => 2, 'secret_identifier' => 'b', 'action' => 'read', 'actor_uid' => 1, 'crdate' => 200, 'previous_hash' => $hash1, 'entry_hash' => $hash2, 'hmac_key_epoch' => 1],
            ],
            hmacRowCount: 1,
        );

        self::assertNull(
            $this->getSubject()->verifyChainForReseal(),
            'a partly-migrated chain must remain re-sealable',
        );
    }

    // =========================================================================
    // Error-message hygiene and the sink fan-out.
    // =========================================================================

    /**
     * The audit row is long-retained and frequently exported to lower-privilege
     * operators, so `error_message` is bounded: the forensic value is the
     * CATEGORY of failure, not a verbose dump that may carry internal state.
     */
    #[Test]
    public function anOversizedErrorMessageIsTruncatedWithAnEllipsis(): void
    {
        $this->setupDatabaseMocks();

        $captured = [];
        $this->connectionMock()
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static function (array $data) use (&$captured): bool {
                    $captured = $data;

                    return true;
                }),
            );

        $this->getSubject()->log('api_creds', 'read', false, str_repeat('x', 500));

        self::assertIsString($captured['error_message']);
        self::assertSame(200, mb_strlen($captured['error_message']));
        self::assertStringEndsWith('...', $captured['error_message']);
        self::assertSame(str_repeat('x', 197) . '...', $captured['error_message']);
    }

    #[Test]
    public function anErrorMessageAtTheLimitIsStoredWhole(): void
    {
        $this->setupDatabaseMocks();

        $message = str_repeat('y', 200);
        $captured = [];
        $this->connectionMock()
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static function (array $data) use (&$captured): bool {
                    $captured = $data;

                    return true;
                }),
            );

        $this->getSubject()->log('api_creds', 'read', false, $message);

        self::assertSame($message, $captured['error_message']);
    }

    /**
     * The database row is chain-authoritative and already committed by the time
     * the sinks run. A broken fan-out must therefore be reported, never allowed
     * to fail the audited vault operation.
     */
    #[Test]
    public function aBrokenSinkFanOutIsLoggedAndDoesNotFailTheAuditedOperation(): void
    {
        $this->setupDatabaseMocks();
        $this->connectionMock()->method('lastInsertId')->willReturn('42');

        $registry = self::createStub(AuditSinkRegistryInterface::class);
        $registry->method('dispatch')->willThrowException(new RuntimeException('DI graph broken', 1750000020));

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('error')
            ->with(
                self::stringContains('audit sink fan-out failed'),
                self::callback(static fn (array $context): bool => $context['uid'] === 42
                    && $context['error'] === 'DI graph broken'
                    && $context['exception'] === RuntimeException::class),
            );

        $subject = new AuditLogService(
            $this->connectionPoolMock(),
            $this->accessControlMock(),
            $this->masterKeyProviderMock(),
            $this->extensionConfigurationMock(),
            sinkRegistry: $registry,
            logger: $logger,
        );

        $subject->log('api_creds', 'read', true);
    }

    #[Test]
    public function aWorkingSinkFanOutReceivesTheCommittedRowAndItsChainTip(): void
    {
        $this->setupDatabaseMocks();
        $this->connectionMock()->method('lastInsertId')->willReturn('42');

        $registry = $this->createMock(AuditSinkRegistryInterface::class);
        $registry->expects(self::once())
            ->method('dispatch')
            ->with(
                self::callback(static fn (AuditLogEntry $entry): bool => $entry->uid === 42),
                // The chain tip after this write IS this entry's own hash.
                self::matchesRegularExpression(self::SHA256_HEX_PATTERN),
            );

        $subject = new AuditLogService(
            $this->connectionPoolMock(),
            $this->accessControlMock(),
            $this->masterKeyProviderMock(),
            $this->extensionConfigurationMock(),
            sinkRegistry: $registry,
        );

        $subject->log('api_creds', 'read', true);
    }

    // =========================================================================
    // Epoch dispatch on the write path. The stored entry_hash must be the one
    // the configured epoch's algorithm produces, or every later verification of
    // the row reports a tamper that never happened.
    // =========================================================================

    #[Test]
    public function epochZeroWritesAKeylessSha256EntryHash(): void
    {
        [$insertedRow, $storedHash] = $this->captureWriteAtEpoch(0);

        $v1 = AuditLogService::extractHashRow(['uid' => 42] + $insertedRow);

        self::assertSame(
            AuditLogService::calculateHash(
                $v1['uid'],
                $v1['secretId'],
                $v1['action'],
                $v1['actorUid'],
                $v1['crdate'],
                '',
            ),
            $storedHash,
        );
    }

    #[Test]
    public function epochTwoWritesTheExtendedForensicHmacEntryHash(): void
    {
        [$insertedRow, $storedHash] = $this->captureWriteAtEpoch(2);

        self::assertSame(
            AuditLogService::calculateHashV2(
                AuditLogService::extractV2HashRow(['uid' => 42] + $insertedRow),
                '',
                AuditLogService::deriveHmacKey($this->masterKeyProviderMock()),
            ),
            $storedHash,
        );
    }

    /**
     * The epochs must not agree: if epoch 0 and epoch 2 produced the same hash
     * the two tests above would pass without the dispatch working at all.
     */
    #[Test]
    public function theEpochsProduceDifferentEntryHashesForTheSameRow(): void
    {
        [, $epochZeroHash] = $this->captureWriteAtEpoch(0);
        [, $epochTwoHash] = $this->captureWriteAtEpoch(2);

        self::assertNotSame($epochZeroHash, $epochTwoHash);
    }

    /**
     * Double-read stability rule: a hash mismatch is only reported when the raw
     * anchor bytes are IDENTICAL either side of the row read. A re-seal that
     * commits mid-check must never be reported as tampering.
     */
    #[Test]
    public function anchorMismatchThatKeepsChangingIsAnInFlightWarningNotAnError(): void
    {
        $verification = $this->verifyWithAnchorLoads(['raw-1', 'raw-2', 'raw-3', 'raw-4']);

        self::assertTrue($verification->isValid(), 'an in-flight re-seal must never invalidate');
        self::assertSame(AuditChainAnchorStatus::InFlight, $verification->anchorStatus);
        self::assertCount(1, $verification->warnings);
    }

    #[Test]
    public function anchorMismatchThatStaysStableIsAViolation(): void
    {
        $verification = $this->verifyWithAnchorLoads(['raw-1', 'raw-1']);

        self::assertFalse($verification->isValid());
        self::assertSame(AuditChainAnchorStatus::Violated, $verification->anchorStatus);
    }

    /**
     * A retry that stabilises on the second attempt resolves cleanly instead of
     * degrading to a warning.
     */
    #[Test]
    public function anchorMismatchThatStabilisesOnTheRetryIsAViolation(): void
    {
        $verification = $this->verifyWithAnchorLoads(['raw-1', 'raw-2', 'raw-2', 'raw-2']);

        self::assertFalse($verification->isValid());
        self::assertSame(AuditChainAnchorStatus::Violated, $verification->anchorStatus);
    }

    /**
     * `AuditWriteException` is the type `VaultService::compensateAuditFailure()`
     * keys on, so a failing anchor write must arrive as that type — otherwise
     * the vault write is not compensated and the secret persists without a
     * matching audit row.
     */
    #[Test]
    public function anchorWriteFailureSurfacesAsAuditWriteException(): void
    {
        $this->setupDatabaseMocks();

        $anchorStore = $this->createMock(AuditChainAnchorStoreInterface::class);
        $anchorStore->method('advance')->willThrowException(new RuntimeException('registry unavailable'));

        self::assertNotNull($this->connectionPool);
        self::assertNotNull($this->accessControlService);
        $subject = new AuditLogService(
            $this->connectionPool,
            $this->accessControlService,
            $this->masterKeyProvider,
            $this->extensionConfiguration,
            $anchorStore,
        );

        $this->expectException(AuditWriteException::class);
        $this->expectExceptionCode(1753900001);

        $subject->log('secret', 'create', true);
    }

    // =========================================================================
    // Write path — the lock lifecycle, the values that reach the row, and the
    // fan-out that must never fail the audited operation.
    // =========================================================================

    #[Test]
    public function theNamedLockIsReleasedAfterASuccessfulWrite(): void
    {
        $this->setupDatabaseMocks();

        $statements = [];
        $this->connectionMock()
            ->method('executeStatement')
            ->willReturnCallback(static function (string $sql) use (&$statements): int {
                $statements[] = $sql;

                return 0;
            });

        $this->getSubject()->log('s', 'create', true);

        self::assertContains('SELECT RELEASE_LOCK("nr_vault_audit")', $statements);
    }

    /**
     * The release lives in a `finally` for this case: a write that fails must
     * not leave the named lock held for the lifetime of the connection, where
     * it would block every subsequent audit writer.
     */
    #[Test]
    public function theNamedLockIsReleasedWhenTheWriteFails(): void
    {
        $this->setupDatabaseMocks();

        $statements = [];
        $this->connectionMock()
            ->method('executeStatement')
            ->willReturnCallback(static function (string $sql) use (&$statements): int {
                $statements[] = $sql;

                return 0;
            });
        $this->connectionMock()
            ->method('insert')
            ->willThrowException(new RuntimeException('constraint violation'));

        try {
            $this->getSubject()->log('s', 'create', true);
            self::fail('a failed write must surface as an AuditWriteException');
        } catch (AuditWriteException) {
            self::assertContains('SELECT RELEASE_LOCK("nr_vault_audit")', $statements);
        }
    }

    /**
     * The UID reserved by the INSERT addresses the row the UPDATE seals, and
     * the driver hands it out as a string.
     */
    #[Test]
    public function theHashUpdateTargetsTheInsertIdAsAnInteger(): void
    {
        $this->setupDatabaseMocks();
        $this->connectionMock()->method('lastInsertId')->willReturn('42');

        $criteria = [];
        $this->connectionMock()
            ->expects(self::once())
            ->method('update')
            ->with(
                AuditLogService::TABLE_NAME,
                self::anything(),
                self::callback(static function (array $identifier) use (&$criteria): bool {
                    $criteria = $identifier;

                    return true;
                }),
            );

        $this->getSubject()->log('s', 'create', true);

        self::assertSame(['uid' => 42], $criteria);
    }

    /**
     * The anchor pins the row that was just written: its own uid and its own
     * entry hash. Anchoring anything else would either point at a row that
     * does not exist or assert a hash no row carries.
     */
    #[Test]
    public function theTipAnchorIsBuiltFromThePersistedRow(): void
    {
        $this->setupDatabaseMocks();
        $this->connectionMock()->method('lastInsertId')->willReturn('42');

        $storedHash = null;
        $this->connectionMock()
            ->expects(self::once())
            ->method('update')
            ->with(
                AuditLogService::TABLE_NAME,
                self::callback(static function (array $fields) use (&$storedHash): bool {
                    $storedHash = $fields['entry_hash'] ?? null;

                    return true;
                }),
                self::anything(),
            );

        $anchored = null;
        $this->anchorStore
            ->expects(self::once())
            ->method('advance')
            ->willReturnCallback(static function (Connection $connection, AuditChainAnchor $tip) use (&$anchored): void {
                $anchored = $tip;
            });

        $this->getSubject()->log('s', 'create', true);

        self::assertInstanceOf(AuditChainAnchor::class, $anchored);
        self::assertSame(42, $anchored->uid);
        self::assertIsString($storedHash);
        self::assertSame($storedHash, $anchored->entryHash);
    }

    /**
     * Epoch 1 binds the identity fields under the HMAC key — not the v3
     * forensic payload the later epochs use. A row sealed with the wrong
     * algorithm reports a tamper on every subsequent verification.
     */
    #[Test]
    public function epochOneWritesTheIdentityOnlyHmacEntryHash(): void
    {
        [$insertedRow, $storedHash] = $this->captureWriteAtEpoch(1);

        $v1 = AuditLogService::extractHashRow(['uid' => 42] + $insertedRow);

        self::assertSame(
            AuditLogService::calculateHash(
                $v1['uid'],
                $v1['secretId'],
                $v1['action'],
                $v1['actorUid'],
                $v1['crdate'],
                '',
                AuditLogService::deriveHmacKey($this->masterKeyProviderMock()),
            ),
            $storedHash,
        );
    }

    #[Test]
    public function theCallerSuppliedReasonIsSealedIntoTheRowVerbatim(): void
    {
        $captured = $this->captureInsertPayload(reason: 'rotation requested by ops');

        self::assertSame('rotation requested by ops', $captured['reason']);
    }

    /**
     * Column widths are counted in characters, so a value that fits in
     * characters must be stored whole even when its UTF-8 encoding needs more
     * bytes than the column has columns.
     */
    #[Test]
    public function aMultiByteHeaderThatFitsInCharactersIsStoredWhole(): void
    {
        // 300 two-byte characters: 600 bytes, but only 300 of the 500 columns.
        $userAgent = str_repeat('ä', 300);
        $this->stubServerRequest(userAgent: $userAgent);

        $captured = $this->captureInsertPayload();

        self::assertSame($userAgent, $captured['user_agent']);
    }

    /**
     * Clipping keeps the START of the value — the part that identifies the
     * client — not an arbitrary window into it.
     */
    #[Test]
    public function anOversizedHeaderKeepsItsLeadingCharacters(): void
    {
        $this->stubServerRequest(userAgent: 'Z' . str_repeat('b', 600));

        $captured = $this->captureInsertPayload();

        self::assertSame('Z' . str_repeat('b', 499), $captured['user_agent']);
    }

    /**
     * Control characters collapse to spaces, which can leave the message
     * padded at both ends; the stored value is the trimmed one.
     */
    #[Test]
    public function theSanitizedErrorMessageCarriesNoSurroundingWhitespace(): void
    {
        $captured = $this->captureInsertPayload(errorMessage: "\n  decryption failed  \n");

        self::assertSame('decryption failed', $captured['error_message']);
    }

    /**
     * The 200-character bound is counted in characters too: a multi-byte
     * message that fits must not be truncated just because its byte length
     * exceeds the bound.
     */
    #[Test]
    public function aMultiByteErrorMessageIsBoundedInCharactersNotBytes(): void
    {
        // 150 two-byte characters: 300 bytes, 150 of the 200 characters.
        $errorMessage = str_repeat('ä', 150);

        $captured = $this->captureInsertPayload(errorMessage: $errorMessage);

        self::assertSame($errorMessage, $captured['error_message']);
    }

    /**
     * An over-long message keeps its first 197 characters plus the ellipsis —
     * cut on a character boundary, so the stored value stays well-formed
     * UTF-8 and is exactly 200 characters wide.
     */
    #[Test]
    public function anOversizedErrorMessageKeepsItsFirstCharactersUpToTheEllipsis(): void
    {
        $captured = $this->captureInsertPayload(errorMessage: 'Z' . str_repeat('ä', 299));

        self::assertSame('Z' . str_repeat('ä', 196) . '...', $captured['error_message']);
        self::assertIsString($captured['error_message']);
        self::assertSame(200, mb_strlen($captured['error_message']));
    }

    /**
     * With no request in scope the write is a CLI one, and the audit row says
     * so instead of recording an empty actor environment.
     */
    #[Test]
    public function aWriteWithoutAServerRequestIsAttributedToTheCli(): void
    {
        unset($GLOBALS['TYPO3_REQUEST']);

        $captured = $this->captureInsertPayload();

        self::assertSame('CLI', $captured['ip_address']);
        self::assertSame('CLI', $captured['user_agent']);
    }

    #[Test]
    public function aWriteUnderAServerRequestRecordsItsRemoteAddress(): void
    {
        $this->stubServerRequest();

        $captured = $this->captureInsertPayload();

        self::assertSame(self::IP_ADDRESS, $captured['ip_address']);
    }

    /**
     * Without an inbound correlation header the row still gets a request id,
     * generated from 16 random bytes so entries of one request can be tied
     * together after the fact.
     */
    #[Test]
    public function aRequestWithoutACorrelationHeaderGetsAGeneratedRequestId(): void
    {
        $this->stubServerRequest();

        $captured = $this->captureInsertPayload();

        self::assertIsString($captured['request_id']);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $captured['request_id']);
    }

    /**
     * No sinks configured is the default deployment, not a fan-out failure —
     * it must not produce an error-level log line on every audited operation.
     */
    #[Test]
    public function aMissingSinkRegistryIsNotReportedAsAFanOutFailure(): void
    {
        $this->setupDatabaseMocks();

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('error');

        $subject = new AuditLogService(
            $this->connectionPoolMock(),
            $this->accessControlMock(),
            $this->masterKeyProviderMock(),
            $this->extensionConfigurationMock(),
            $this->anchorStore,
            null,
            $logger,
        );

        $this->connectionMock()->expects(self::once())->method('insert');

        $subject->log('s', 'create', true);
    }

    /**
     * The logger is optional, so a broken fan-out on a logger-less service must
     * still be contained: the chain row is committed and the audited operation
     * completes.
     */
    #[Test]
    public function aBrokenSinkFanOutWithoutALoggerStillCompletesTheAuditedOperation(): void
    {
        $this->setupDatabaseMocks();

        $sinkRegistry = $this->createMock(AuditSinkRegistryInterface::class);
        $sinkRegistry->method('dispatch')->willThrowException(new RuntimeException('registry unavailable'));

        $subject = new AuditLogService(
            $this->connectionPoolMock(),
            $this->accessControlMock(),
            $this->masterKeyProviderMock(),
            $this->extensionConfigurationMock(),
            $this->anchorStore,
            $sinkRegistry,
        );

        $captured = [];
        $this->connectionMock()
            ->expects(self::once())
            ->method('insert')
            ->with(
                AuditLogService::TABLE_NAME,
                self::callback(static function (array $data) use (&$captured): bool {
                    $captured = $data;

                    return true;
                }),
            );

        $subject->log('s', 'create', true);

        self::assertSame('create', $captured['action']);
    }

    // =========================================================================
    // Read/verify path — each test below pins one behaviour of the chain walk
    // that would otherwise be free to drift.
    // =========================================================================

    /**
     * `count()` must issue a COUNT over the audit table. Without the builder
     * calls the query degrades to an unbounded SELECT whose first column is
     * returned as the "count".
     */
    #[Test]
    public function countAsksTheDatabaseForACountOverTheAuditTable(): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn(7);

        $this->connectionPoolMock()->method('getConnectionForTable')->willReturn($this->connectionMock());
        $this->connectionMock()->method('createQueryBuilder')->willReturn($this->queryBuilderMock());

        $queryBuilder = $this->queryBuilderMock();
        $queryBuilder->expects(self::once())->method('count')->with('uid')->willReturnSelf();
        $queryBuilder->expects(self::once())->method('from')->with(AuditLogService::TABLE_NAME)->willReturnSelf();
        $queryBuilder->method('executeQuery')->willReturn($result);

        self::assertSame(7, $this->getSubject()->count());
    }

    /**
     * The chain walk depends on ascending-uid order: gap detection, the
     * previous-hash link and the epoch-transition check all compare a row
     * against its immediate predecessor.
     */
    #[Test]
    public function verifyHashChainSelectsEveryColumnOrderedByAscendingUid(): void
    {
        $result = $this->createMock(Result::class);
        $result->method('iterateAssociative')->willReturnCallback(static fn (): Iterator => new ArrayIterator([]));

        $this->connectionPoolMock()->method('getConnectionForTable')->willReturn($this->connectionMock());
        $this->connectionMock()->method('createQueryBuilder')->willReturn($this->queryBuilderMock());

        $queryBuilder = $this->queryBuilderMock();
        $queryBuilder->expects(self::once())->method('select')->with('*')->willReturnSelf();
        $queryBuilder->expects(self::once())->method('from')->with(AuditLogService::TABLE_NAME)->willReturnSelf();
        $queryBuilder->expects(self::once())->method('orderBy')->with('uid', 'ASC')->willReturnSelf();
        $queryBuilder->method('executeQuery')->willReturn($result);

        self::assertTrue($this->getSubject()->verifyHashChain()->valid);
    }

    /**
     * The default window is a literal 1000 rows — the bound that keeps peak
     * memory O(chunkSize) instead of O(table).
     */
    #[Test]
    public function exportIterableDefaultsToAThousandRowWindow(): void
    {
        $this->setupPagingQueryMocks([[]]);

        self::assertSame([], iterator_to_array($this->getSubject()->exportIterable()));
        self::assertSame([1000], $this->recordedLimits);
    }

    /**
     * Every round advances the offset by exactly one window, and the loop
     * keeps going while the window came back full.
     */
    #[Test]
    public function exportIterablePagesForwardByOneWindowPerRound(): void
    {
        $this->setupPagingQueryMocks([
            [['uid' => 1], ['uid' => 2]],
            [['uid' => 3], ['uid' => 4]],
            [['uid' => 5]],
        ]);

        $entries = iterator_to_array($this->getSubject()->exportIterable(chunkSize: 2));

        self::assertCount(5, $entries);
        self::assertSame([0, 2, 4], $this->recordedOffsets);
        self::assertSame([2, 2, 2], $this->recordedLimits);
    }

    /**
     * A non-positive chunk size is clamped to 1, not to 0 — a zero-row window
     * would return an empty chunk forever while the loop condition
     * (`count($chunk) === $chunkSize`) stayed true.
     */
    #[Test]
    public function exportIterableClampsANonPositiveWindowToASingleRow(): void
    {
        $this->setupPagingQueryMocks([[['uid' => 1]], []]);

        $entries = iterator_to_array($this->getSubject()->exportIterable(chunkSize: 0));

        self::assertCount(1, $entries);
        self::assertSame([1, 1], $this->recordedLimits);
    }

    /**
     * The re-seal gate verifies under the chain's OWN stored epochs. An
     * install configured for a higher epoch must not make its own
     * not-yet-migrated chain unresealable — that chain is exactly what the
     * migration exists to lift.
     */
    #[Test]
    public function resealVerificationIgnoresTheConfiguredEpochFloorEntirely(): void
    {
        // Every row sits at epoch 0 while the subject is configured for epoch 1.
        $this->setupResealMocks(rows: $this->epochZeroChain([1, 2]), hmacRowCount: 1);

        self::assertNull($this->getSubject()->verifyChainForReseal());
    }

    /**
     * A range verification starts one uid BELOW the requested start, so rows
     * deleted between `$fromUid` and the first surviving row are still
     * reported instead of falling outside the window unnoticed.
     */
    #[Test]
    public function verifyHashChainDetectsAGapBelowTheFirstRowOfARequestedRange(): void
    {
        $this->setupQueryMocksWithFilter(
            $this->createMock(ExpressionBuilder::class),
            [$this->epochZeroRow(7, '')],
        );

        $verification = $this->getSubject()->verifyHashChain(fromUid: 5);

        self::assertSame([5, 6], $verification->missingUids);
    }

    /**
     * The mirror image: on a full scan there is no prior row to compare the
     * first one against, so a chain whose lowest uid is not 1 must not be
     * reported as starting with a gap.
     */
    #[Test]
    public function verifyHashChainDoesNotInventAGapBeforeTheFirstRowOfAFullScan(): void
    {
        $this->setupQueryMocks($this->epochZeroChain([5, 6]));

        $verification = $this->subjectWithConfiguredEpoch(0)->verifyHashChain();

        self::assertSame([], $verification->missingUids);
        self::assertSame(0, $verification->missingUidCount);
        self::assertTrue($verification->valid);
    }

    /**
     * The enumerated list is capped to bound memory after a mass purge, but
     * the reported COUNT stays exact — that is the number an operator uses to
     * judge the scale of the hole.
     */
    #[Test]
    public function theEnumeratedMissingUidListIsCappedWhileTheCountStaysExact(): void
    {
        // Two 600-uid gaps: the 1000-entry cap admits all of the first and 400
        // of the second, while the count must still report the true 1200.
        $this->setupQueryMocks($this->epochZeroChain([1, 602, 1203]));

        $verification = $this->subjectWithConfiguredEpoch(0)->verifyHashChain();

        self::assertCount(1000, $verification->missingUids);
        self::assertSame(1200, $verification->missingUidCount);
        self::assertSame(2, $verification->missingUids[0]);
        self::assertSame(1002, $verification->missingUids[999]);
    }

    /**
     * Gap sizes accumulate across gaps; the count is the total, not the size
     * of the last one.
     */
    #[Test]
    public function everyMissingUidAcrossSeveralGapsIsCounted(): void
    {
        $this->setupQueryMocks($this->epochZeroChain([1, 4, 8]));

        $verification = $this->subjectWithConfiguredEpoch(0)->verifyHashChain();

        self::assertSame([2, 3, 5, 6, 7], $verification->missingUids);
        self::assertSame(5, $verification->missingUidCount);
    }

    /**
     * A row whose `hmac_key_epoch` drops BELOW its predecessor's is a
     * downgrade — including the negative value a DB-write attacker can set to
     * slip past the epoch dispatch. It must be an error (chain invalid), never
     * the non-fatal warning an epoch INCREASE gets.
     */
    #[Test]
    public function anEpochDropBelowZeroIsReportedAsADowngradeError(): void
    {
        $first = $this->epochZeroRow(1, '');
        $second = [
            'uid' => 2,
            'secret_identifier' => 'a',
            'action' => 'create',
            'success' => 1,
            'actor_uid' => 1,
            'crdate' => 100,
            'error_message' => '',
            'reason' => '',
            'ip_address' => '',
            'user_agent' => '',
            'hash_before' => '',
            'hash_after' => '',
            'context' => '{}',
            'actor_type' => 'backend',
            'actor_username' => 'admin',
            'actor_role' => 'backend',
            'request_id' => '',
            'previous_hash' => $first['entry_hash'],
            'hmac_key_epoch' => -1,
        ];
        // Sign the tampered row correctly, so the ONLY finding left is the
        // epoch downgrade itself rather than a hash mismatch on the same key.
        $second['entry_hash'] = AuditLogService::calculateHashV3(
            AuditLogService::extractV3HashRow($second),
            $first['entry_hash'],
            AuditLogService::deriveHmacKey($this->masterKeyProviderMock()),
        );

        $this->setupQueryMocks([$first, $second]);

        $verification = $this->subjectWithConfiguredEpoch(0)->verifyHashChain();

        self::assertFalse($verification->valid);
        self::assertArrayHasKey(2, $verification->errors);
        self::assertStringContainsString('downgrade', $verification->errors[2]);
    }

    /**
     * A keyless chain carries no HMAC evidence to authenticate, so the re-seal
     * — the operation that FIRST protects those rows — must not be blocked by
     * their content. Only the anchor half of the gate applies.
     */
    #[Test]
    public function resealVerificationOfAKeylessChainSkipsTheRowWalkEntirely(): void
    {
        $this->setupResealMocks(
            rows: [
                // A hash that matches nothing: were the rows walked, this would
                // report tampering and refuse the re-seal.
                ['uid' => 1, 'secret_identifier' => 'a', 'action' => 'create', 'actor_uid' => 1, 'crdate' => 100, 'previous_hash' => '', 'entry_hash' => str_repeat('0', 64), 'hmac_key_epoch' => 0],
            ],
            hmacRowCount: 0,
        );

        self::assertNull($this->getSubject()->verifyChainForReseal());
    }

    /**
     * The anchor-only half of the gate never walked the rows, so it must not
     * claim a missing-uid count it did not measure.
     */
    #[Test]
    public function anAnchorOnlyResealFailureReportsNoMissingUids(): void
    {
        $this->setupResealMocks(rows: [], hmacRowCount: 0);

        // Status Ok with no anchor payload is the "unreadable anchor" case.
        $anchorStore = $this->createMock(AuditChainAnchorStoreInterface::class);
        $anchorStore->method('load')->willReturn(new AuditChainAnchorLoad(AuditChainAnchorStatus::Ok));

        $subject = new AuditLogService(
            $this->connectionPoolMock(),
            $this->accessControlMock(),
            $this->masterKeyProviderMock(),
            $this->extensionConfigurationMock(),
            $anchorStore,
        );

        $result = $subject->verifyChainForReseal();

        self::assertInstanceOf(HashChainVerificationResult::class, $result);
        self::assertSame(AuditChainAnchorStatus::Unreadable, $result->anchorStatus);
        self::assertSame([], $result->missingUids);
        self::assertSame(0, $result->missingUidCount);
    }

    /**
     * "Carries HMAC evidence" means epoch >= 1. Probing for a different
     * threshold would either skip the verification of a protected chain or
     * apply it to a genuinely keyless one.
     */
    #[Test]
    public function theHmacRowProbeAsksForEpochOneOrHigher(): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn(0);

        $this->connectionPoolMock()->method('getConnectionForTable')->willReturn($this->connectionMock());
        $this->connectionMock()->method('createQueryBuilder')->willReturn($this->queryBuilderMock());

        $queryBuilder = $this->queryBuilderMock();
        $queryBuilder->method('expr')->willReturn($this->createMock(ExpressionBuilder::class));
        $queryBuilder->method('count')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder
            ->expects(self::once())
            ->method('createNamedParameter')
            ->with(1, Connection::PARAM_INT)
            ->willReturn('?');
        $queryBuilder->method('executeQuery')->willReturn($result);

        self::assertNull($this->getSubject()->verifyChainForReseal());
    }

    /**
     * The violation message is what an operator acts on, so both halves of it
     * — which uid, and what the mismatch means — have to survive.
     */
    #[Test]
    public function aStableAnchorMismatchNamesTheAnchoredUidAndWhatItMeans(): void
    {
        $verification = $this->verifyWithAnchorLoads(['raw-1', 'raw-1']);

        self::assertSame(
            'Audit chain tip anchor for uid 1 does not match the stored entry hash - the '
            . 'anchored row was replaced (e.g. truncation followed by re-inserted entries)',
            $verification->errors[-3],
        );
    }

    #[Test]
    public function anInFlightAnchorWarningSaysWhatHappenedAndWhatToDo(): void
    {
        $verification = $this->verifyWithAnchorLoads(['raw-1', 'raw-2', 'raw-3', 'raw-4']);

        self::assertSame(
            'Audit chain tip anchor changed while it was '
            . 'being verified (concurrent re-seal); re-run the verification',
            $verification->warnings[-3],
        );
    }

    /**
     * The anchored row is addressed by its primary key, so exactly one row can
     * ever match — a wider limit would read rows the anchor says nothing about.
     */
    #[Test]
    public function theAnchoredRowIsReadWithAnExactSingleRowLimit(): void
    {
        $this->verifyWithAnchorLoads(['raw-1', 'raw-1']);

        self::assertSame([1], $this->recordedMaxResults);
    }

    #[Test]
    public function getLatestHashReadsExactlyOneRow(): void
    {
        $tip = str_repeat('a', 64);

        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn($tip);

        $this->connectionPoolMock()->method('getConnectionForTable')->willReturn($this->connectionMock());
        $this->connectionMock()->method('createQueryBuilder')->willReturn($this->queryBuilderMock());

        $queryBuilder = $this->queryBuilderMock();
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('orderBy')->willReturnSelf();
        $queryBuilder->expects(self::once())->method('setMaxResults')->with(1)->willReturnSelf();
        $queryBuilder->method('executeQuery')->willReturn($result);

        self::assertSame($tip, $this->getSubject()->getLatestHash());
    }

    /**
     * Only a string is a hash. A numeric column value (some drivers coerce, an
     * empty table returns `false`) is "no tip", never a tip of its own.
     */
    #[Test]
    public function getLatestHashReturnsNullForANonStringColumnValue(): void
    {
        $this->setupDatabaseMocks(0);

        self::assertNull($this->getSubject()->getLatestHash());
    }

    /**
     * Both chain-level checks are restricted to a FULL pass: a bounded range
     * may legitimately exclude the higher-epoch rows and the tip, so neither
     * the epoch floor nor the anchor may be applied to it.
     */
    #[Test]
    public function aBoundedRangeVerificationSkipsTheEpochFloorAndTheAnchor(): void
    {
        $this->setupQueryMocksWithFilter(
            $this->createMock(ExpressionBuilder::class),
            $this->epochZeroChain([1, 2]),
        );

        // Configured for epoch 3 while every row sits at epoch 0: on a full
        // scan that is a downgrade, on a sub-range it is out of scope.
        $verification = $this->subjectWithConfiguredEpoch(3)->verifyHashChain(fromUid: 1);

        self::assertTrue($verification->valid);
        self::assertSame(AuditChainAnchorStatus::NotChecked, $verification->anchorStatus);
    }

    /**
     * Run one `log()` at the given epoch and return the inserted row plus the
     * `entry_hash` the second-step UPDATE stored.
     *
     * @return array{array<string, mixed>, string}
     */
    private function captureWriteAtEpoch(int $epoch): array
    {
        $connectionPool = $this->createMock(ConnectionPool::class);
        $connection = $this->createMock(Connection::class);
        $queryBuilder = $this->createMock(QueryBuilder::class);

        $previousHashResult = self::createStub(Result::class);
        // No prior entry: the previous hash is the empty string.
        $previousHashResult->method('fetchOne')->willReturn(false);

        $lockResult = self::createStub(Result::class);
        $lockResult->method('fetchOne')->willReturn(1);

        $connectionPool->method('getConnectionForTable')->willReturn($connection);
        $connection->method('createQueryBuilder')->willReturn($queryBuilder);
        $connection->method('executeQuery')->willReturn($lockResult);
        $connection->method('lastInsertId')->willReturn('42');
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('orderBy')->willReturnSelf();
        $queryBuilder->method('setMaxResults')->willReturnSelf();
        $queryBuilder->method('executeQuery')->willReturn($previousHashResult);

        $insertedRow = [];
        $connection->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static function (array $data) use (&$insertedRow): bool {
                    $insertedRow = $data;

                    return true;
                }),
            );

        $storedHash = null;
        $connection->expects(self::once())
            ->method('update')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static function (array $fields) use (&$storedHash): bool {
                    $storedHash = $fields['entry_hash'] ?? null;

                    return true;
                }),
                self::anything(),
            );

        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getAuditHmacEpoch')->willReturn($epoch);

        $subject = new AuditLogService(
            $connectionPool,
            $this->accessControlMock(),
            $this->masterKeyProviderMock(),
            $configuration,
        );

        $subject->log('api_creds', 'read', true);

        self::assertIsString($storedHash);

        $row = $this->asColumnRow($insertedRow);
        self::assertSame($epoch, $row['hmac_key_epoch']);

        return [$row, $storedHash];
    }

    /**
     * Wire the two queries `verifyChainForReseal()` makes: the HMAC-row count and
     * the full chain scan.
     *
     * @param array<int, array<string, mixed>> $rows
     */
    private function setupResealMocks(array $rows, int $hmacRowCount): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn($hmacRowCount);
        $result->method('fetchAllAssociative')->willReturn($rows);
        $result->method('iterateAssociative')->willReturnCallback(static fn (): Iterator => new ArrayIterator($rows));

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);

        $connection = $this->connectionMock();
        $queryBuilder = $this->queryBuilderMock();

        $this->connectionPoolMock()->method('getConnectionForTable')->willReturn($connection);
        $connection->method('createQueryBuilder')->willReturn($queryBuilder);
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder->method('count')->willReturnSelf();
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('orderBy')->willReturnSelf();
        $queryBuilder->method('setMaxResults')->willReturnSelf();
        $queryBuilder->method('createNamedParameter')->willReturn('?');
        $queryBuilder->method('executeQuery')->willReturn($result);
    }

    /**
     * Install a request whose headers the test controls. A mock is used rather
     * than a real PSR-7 request so that byte sequences a PSR-7 implementation
     * would reject (invalid UTF-8) can be exercised.
     */
    private function stubServerRequest(string $requestId = '', string $userAgent = ''): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request
            ->method('getHeaderLine')
            ->willReturnCallback(static fn (string $name): string => match (strtolower($name)) {
                'x-request-id' => $requestId,
                'user-agent' => $userAgent,
                default => '',
            });
        $request
            ->method('getServerParams')
            ->willReturn(['REMOTE_ADDR' => self::IP_ADDRESS]);

        $GLOBALS['TYPO3_REQUEST'] = $request;
    }

    /**
     * Run one `log()` and return the array handed to `Connection::insert()`.
     *
     * @return array<string, mixed>
     */
    private function captureInsertPayload(?string $errorMessage = null, ?string $reason = null): array
    {
        $this->setupDatabaseMocks();

        $captured = [];
        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static function (array $data) use (&$captured): bool {
                    $captured = $data;

                    return true;
                }),
            );

        $this->getSubject()->log('s', 'create', true, $errorMessage, $reason);

        self::assertIsArray($captured);

        return $captured;
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

    /**
     * The shared mocks are declared as `?MockObject`, which loses the mocked
     * type. These accessors restore it so new tests can call `expects()` /
     * `method()` on a value static analysis knows is non-null and correctly
     * typed.
     */
    private function connectionMock(): Connection&MockObject
    {
        self::assertInstanceOf(Connection::class, $this->connection);

        return $this->connection;
    }

    private function connectionPoolMock(): ConnectionPool&MockObject
    {
        self::assertInstanceOf(ConnectionPool::class, $this->connectionPool);

        return $this->connectionPool;
    }

    private function queryBuilderMock(): QueryBuilder&MockObject
    {
        self::assertInstanceOf(QueryBuilder::class, $this->queryBuilder);

        return $this->queryBuilder;
    }

    private function accessControlMock(): AccessControlServiceInterface&MockObject
    {
        self::assertInstanceOf(AccessControlServiceInterface::class, $this->accessControlService);

        return $this->accessControlService;
    }

    private function masterKeyProviderMock(): MasterKeyProviderInterface&MockObject
    {
        self::assertInstanceOf(MasterKeyProviderInterface::class, $this->masterKeyProvider);

        return $this->masterKeyProvider;
    }

    private function extensionConfigurationMock(): ExtensionConfigurationInterface&MockObject
    {
        self::assertInstanceOf(ExtensionConfigurationInterface::class, $this->extensionConfiguration);

        return $this->extensionConfiguration;
    }

    /**
     * Re-key an array captured from a `Connection::insert()` argument, whose keys
     * static analysis only knows as `array-key`, to the string-keyed row shape the
     * hash extractors require. Audit column names are strings by construction.
     *
     * @param array<mixed> $row
     *
     * @return array<string, mixed>
     */
    private function asColumnRow(array $row): array
    {
        $columns = [];
        foreach ($row as $column => $value) {
            $columns[(string) $column] = $value;
        }

        return $columns;
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
     * Drive `verifyHashChain()` over a single-row chain whose anchor asserts a
     * DIFFERENT hash, handing out the given raw anchor values on successive
     * `load()` calls.
     *
     * @param list<string> $rawSequence raw bytes returned by consecutive loads
     */
    private function verifyWithAnchorLoads(array $rawSequence): HashChainVerificationResult
    {
        $storedHash = AuditLogService::calculateHash(1, 'a', 'create', 1, 100, '');
        $rows = [[
            'uid' => 1,
            'secret_identifier' => 'a',
            'action' => 'create',
            'actor_uid' => 1,
            'crdate' => 100,
            'previous_hash' => '',
            'entry_hash' => $storedHash,
            'hmac_key_epoch' => 0,
        ]];

        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturn($rows);
        $result->method('iterateAssociative')->willReturnCallback(static fn (): Iterator => new ArrayIterator($rows));
        // The by-uid lookup returns the row's REAL hash, which differs from the
        // anchored one below.
        $result->method('fetchOne')->willReturn($storedHash);

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->method('eq')->willReturn('uid = :p');

        self::assertNotNull($this->connectionPool);
        self::assertNotNull($this->connection);
        self::assertNotNull($this->queryBuilder);
        $this->connectionPool->method('getConnectionForTable')->willReturn($this->connection);
        $this->connection->method('createQueryBuilder')->willReturn($this->queryBuilder);
        $this->queryBuilder->method('expr')->willReturn($expressionBuilder);
        $this->queryBuilder->method('createNamedParameter')->willReturn(':p');
        $this->queryBuilder->method('select')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('where')->willReturnSelf();
        $this->queryBuilder->method('orderBy')->willReturnSelf();
        $this->queryBuilder->method('setMaxResults')->willReturnCallback(
            function (?int $limit): QueryBuilder {
                $this->recordedMaxResults[] = $limit;

                return $this->queryBuilderMock();
            },
        );
        $this->queryBuilder->method('executeQuery')->willReturn($result);

        $anchoredHash = str_repeat('c', 64);
        $loads = array_map(
            static fn (string $raw): AuditChainAnchorLoad => new AuditChainAnchorLoad(
                AuditChainAnchorStatus::Ok,
                new AuditChainAnchor(1, $anchoredHash, 1_700_000_000),
                $raw,
            ),
            $rawSequence,
        );

        $anchorStore = $this->createMock(AuditChainAnchorStoreInterface::class);
        $anchorStore->method('load')->willReturn(...$loads);

        $extensionConfig = $this->createMock(ExtensionConfigurationInterface::class);
        $extensionConfig->method('getAuditHmacEpoch')->willReturn(0);

        self::assertNotNull($this->accessControlService);

        return (new AuditLogService(
            $this->connectionPool,
            $this->accessControlService,
            $this->masterKeyProvider,
            $extensionConfig,
            $anchorStore,
        ))->verifyHashChain();
    }

    /**
     * One epoch-0 chain row carrying its correct legacy hash, linked to
     * `$previousHash`.
     *
     * @return array{uid: int, secret_identifier: string, action: string, actor_uid: int, crdate: int, previous_hash: string, entry_hash: string, hmac_key_epoch: int}
     */
    private function epochZeroRow(int $uid, string $previousHash): array
    {
        return [
            'uid' => $uid,
            'secret_identifier' => 'a',
            'action' => 'create',
            'actor_uid' => 1,
            'crdate' => 100,
            'previous_hash' => $previousHash,
            'entry_hash' => AuditLogService::calculateHash($uid, 'a', 'create', 1, 100, $previousHash),
            'hmac_key_epoch' => 0,
        ];
    }

    /**
     * A correctly-linked epoch-0 chain over the given uids, so a test that is
     * about gaps or epochs is not also about hash mismatches.
     *
     * @param list<int> $uids
     *
     * @return list<array<string, mixed>>
     */
    private function epochZeroChain(array $uids): array
    {
        $rows = [];
        $previousHash = '';
        foreach ($uids as $uid) {
            $row = $this->epochZeroRow($uid, $previousHash);
            $previousHash = $row['entry_hash'];
            $rows[] = $row;
        }

        return $rows;
    }

    /**
     * The default subject is configured for epoch 1; tests about the epoch
     * floor need to state the configured epoch themselves.
     */
    private function subjectWithConfiguredEpoch(int $epoch): AuditLogService
    {
        $extensionConfiguration = $this->createMock(ExtensionConfigurationInterface::class);
        $extensionConfiguration->method('getAuditHmacEpoch')->willReturn($epoch);

        return new AuditLogService(
            $this->connectionPoolMock(),
            $this->accessControlMock(),
            $this->masterKeyProviderMock(),
            $extensionConfiguration,
            $this->anchorStore,
        );
    }

    /**
     * Wire `query()` so consecutive calls return the given windows, recording
     * the LIMIT / OFFSET each call asked for in `$recordedLimits` /
     * `$recordedOffsets`.
     *
     * @param list<list<array<string, mixed>>> $windows rows per consecutive query
     */
    private function setupPagingQueryMocks(array $windows): void
    {
        $call = 0;
        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturnCallback(
            static function () use ($windows, &$call): array {
                $rows = $windows[$call] ?? [];
                ++$call;

                return $rows;
            },
        );

        $queryBuilder = $this->queryBuilderMock();
        $this->connectionPoolMock()->method('getConnectionForTable')->willReturn($this->connectionMock());
        $this->connectionMock()->method('createQueryBuilder')->willReturn($queryBuilder);
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('orderBy')->willReturnSelf();
        $queryBuilder->method('setMaxResults')->willReturnCallback(
            function (?int $limit) use ($queryBuilder): QueryBuilder {
                $this->recordedLimits[] = $limit;

                return $queryBuilder;
            },
        );
        $queryBuilder->method('setFirstResult')->willReturnCallback(
            function (?int $offset) use ($queryBuilder): QueryBuilder {
                $this->recordedOffsets[] = $offset;

                return $queryBuilder;
            },
        );
        $queryBuilder->method('executeQuery')->willReturn($result);
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
