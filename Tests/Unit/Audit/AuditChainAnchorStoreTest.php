<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Audit\AuditChainAnchor;
use Netresearch\NrVault\Audit\AuditChainAnchorStatus;
use Netresearch\NrVault\Audit\AuditChainAnchorStore;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Database\Query\Restriction\QueryRestrictionContainerInterface;

/**
 * Unit coverage for the anchor store's decision rules — the parts that decide
 * whether the anchor may move, and what a stored value is allowed to be.
 */
#[CoversClass(AuditChainAnchorStore::class)]
#[AllowMockObjectsWithoutExpectations]
#[CoversClass(AuditChainAnchor::class)]
final class AuditChainAnchorStoreTest extends TestCase
{
    private const MASTER_KEY = 'unit-test-master-key-32-bytes!!!';

    private const HASH_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    private const HASH_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    private Connection&MockObject $connection;

    private ConnectionPool $connectionPool;

    private ExtensionConfigurationInterface $extensionConfiguration;

    protected function setUp(): void
    {
        parent::setUp();

        $this->connection = $this->createMock(Connection::class);
        $this->connectionPool = self::createStub(ConnectionPool::class);
        $this->connectionPool->method('getConnectionForTable')->willReturn($this->connection);
        $this->extensionConfiguration = self::createStub(ExtensionConfigurationInterface::class);
        $this->extensionConfiguration->method('getAuditHmacEpoch')->willReturn(3);
    }

    #[Test]
    public function advanceInsertsTheAnchorWhenNoneExists(): void
    {
        $this->wireReads([false]);

        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'sys_registry',
                self::callback(static fn (array $data): bool => $data['entry_namespace'] === 'tx_nrvault_audit_anchor'
                    && $data['entry_key'] === 'auditChainTip'
                    && \is_string($data['entry_value'])
                    && str_starts_with($data['entry_value'], 'nrvault-audit-tip.v1|7|' . self::HASH_A . '|')),
                ['entry_value' => Connection::PARAM_LOB],
            );

        $this->subject()->advance($this->connection, new AuditChainAnchor(7, self::HASH_A, 1_700_000_000));
    }

    #[Test]
    public function advanceUpdatesTheAnchorWhenTheTipMovedForward(): void
    {
        $this->wireReads([$this->anchorRow($this->encode(4, self::HASH_A))], [self::HASH_A]);

        $this->connection->expects(self::once())->method('update');
        $this->connection->expects(self::never())->method('insert');

        $this->subject()->advance($this->connection, new AuditChainAnchor(9, self::HASH_B, 1_700_000_000));
    }

    /**
     * Forward-only: an out-of-order writer (the lock-free demo seeder) must not
     * be able to drag the anchor backwards. An EQUAL uid is skipped too —
     * rewriting an existing row's hash is `reseal()`'s job, and letting
     * `advance()` do it would let a refilled uid overwrite the very assertion
     * that catches a truncate-then-refill.
     *
     * @param int $storedUid uid already recorded in the anchor
     */
    #[Test]
    #[DataProvider('nonAdvancingUidProvider')]
    public function advanceLeavesTheAnchorAloneWhenTheTipDidNotMoveForward(int $storedUid): void
    {
        $this->wireReads([$this->anchorRow($this->encode($storedUid, self::HASH_A))], [self::HASH_A]);

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        $this->subject()->advance($this->connection, new AuditChainAnchor(5, self::HASH_B, 1_700_000_000));
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function nonAdvancingUidProvider(): iterable
    {
        yield 'stored uid is higher' => [9];
        yield 'stored uid is equal' => [5];
    }

    /**
     * Once the anchor's own assertion is broken it must stand as evidence.
     * Advancing past it would let an attacker truncate the log and have
     * ordinary traffic silently re-arm the anchor on the shortened chain.
     *
     * @param false|string $storedRowHash what the anchored uid reads back as
     */
    #[Test]
    #[DataProvider('violatedAssertionProvider')]
    public function advanceRefusesToMovePastAViolatedAnchor(false|string $storedRowHash): void
    {
        $this->wireReads([$this->anchorRow($this->encode(4, self::HASH_A))], [$storedRowHash]);

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        $this->subject()->advance($this->connection, new AuditChainAnchor(9, self::HASH_B, 1_700_000_000));
    }

    /**
     * @return iterable<string, array{false|string}>
     */
    public static function violatedAssertionProvider(): iterable
    {
        yield 'anchored row deleted' => [false];
        yield 'anchored row rewritten' => [self::HASH_B];
    }

    /**
     * A corrupted anchor must not be repaired by the next append — that repair
     * is exactly what an attacker who truncates AND corrupts would rely on.
     */
    #[Test]
    public function advanceLeavesAnUnparseableAnchorUntouched(): void
    {
        $this->wireReads([$this->anchorRow('O:8:"stdClass":0:{}')]);

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        $this->subject()->advance($this->connection, new AuditChainAnchor(9, self::HASH_B, 1_700_000_000));
    }

    #[Test]
    public function advanceWritesNothingAtEpochZero(): void
    {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getAuditHmacEpoch')->willReturn(0);

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        $subject = new AuditChainAnchorStore($this->connectionPool, $this->masterKeyProvider(), $configuration);
        $subject->advance($this->connection, new AuditChainAnchor(1, self::HASH_A, 1_700_000_000));

        self::assertFalse($subject->isEnabled());
    }

    #[Test]
    public function advanceWritesNothingWhenTheRegistryIsOnAnotherConnection(): void
    {
        $foreignPool = self::createStub(ConnectionPool::class);
        $foreignPool->method('getConnectionForTable')->willReturn(self::createStub(Connection::class));

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        $subject = new AuditChainAnchorStore($foreignPool, $this->masterKeyProvider(), $this->extensionConfiguration);
        $subject->advance($this->connection, new AuditChainAnchor(1, self::HASH_A, 1_700_000_000));

        self::assertFalse($subject->sharesConnection($this->connection));
    }

    #[Test]
    public function loadReturnsTheParsedAnchorForAWellFormedValue(): void
    {
        $this->wireReads([$this->anchorRow($this->encode(12, self::HASH_A))]);

        $load = $this->subject()->load($this->connection);

        self::assertSame(AuditChainAnchorStatus::Ok, $load->status);
        self::assertInstanceOf(AuditChainAnchor::class, $load->anchor);
        self::assertSame(12, $load->anchor->uid);
        self::assertSame(self::HASH_A, $load->anchor->entryHash);
    }

    /**
     * The regex runs before the MAC, so a hostile payload only ever reaches
     * `preg_match()`. Nothing on this path can emit a PHP object.
     */
    #[Test]
    #[DataProvider('rejectedValueProvider')]
    public function loadRejectsAnythingButTheExactFormatAndMac(string $stored): void
    {
        $this->wireReads([$this->anchorRow($stored)]);

        $load = $this->subject()->load($this->connection);

        self::assertSame(AuditChainAnchorStatus::Unreadable, $load->status);
        self::assertNull($load->anchor);
        self::assertSame($stored, $load->raw);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function rejectedValueProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'serialize payload' => ['O:8:"stdClass":0:{}'];
        yield 'wrong prefix' => ['nrvault-audit-tip.v2|1|' . self::HASH_A . '|1|' . self::HASH_B];
        yield 'uppercase hash' => ['nrvault-audit-tip.v1|1|' . strtoupper(self::HASH_A) . '|1|' . self::HASH_B];
        yield 'trailing newline' => ['nrvault-audit-tip.v1|1|' . self::HASH_A . '|1|' . self::HASH_B . "\n"];
        yield 'flipped mac' => ['nrvault-audit-tip.v1|1|' . self::HASH_A . '|1|' . self::HASH_B];
    }

    #[Test]
    public function loadReportsUnanchoredWhenNoRowExists(): void
    {
        $this->wireReads([false]);

        self::assertSame(AuditChainAnchorStatus::Unanchored, $this->subject()->load($this->connection)->status);
    }

    /**
     * `entry_value` is a `mediumblob` (`bytea` on PostgreSQL), so a driver may
     * hand back a stream rather than a string.
     */
    #[Test]
    public function loadNormalisesAResourceTypedEntryValue(): void
    {
        $encoded = $this->encode(3, self::HASH_A);
        $stream = fopen('php://memory', 'r+');
        self::assertIsResource($stream);
        fwrite($stream, $encoded);
        rewind($stream);

        $this->wireReads([$this->anchorRow($stream)]);

        $load = $this->subject()->load($this->connection);

        self::assertSame(AuditChainAnchorStatus::Ok, $load->status);
        self::assertSame($encoded, $load->raw);

        fclose($stream);
    }

    #[Test]
    public function resealWritesNothingWhenTheStoredTipAlreadyMatches(): void
    {
        $this->wireReads([['uid' => 4, 'entry_hash' => self::HASH_A], $this->anchorRow($this->encode(4, self::HASH_A))]);

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        $this->subject()->reseal($this->connection);
    }

    #[Test]
    public function resealRewritesTheAnchorWhenTheTipHashChanged(): void
    {
        $this->wireReads(
            [['uid' => 4, 'entry_hash' => self::HASH_B], $this->anchorRow($this->encode(4, self::HASH_A))],
            [self::HASH_B],
        );

        $this->connection->expects(self::once())->method('update');

        $this->subject()->reseal($this->connection);
    }

    /**
     * A re-seal re-signs the same rows under a new key or epoch. It must not
     * sign a chain that lost rows: the migration gates in front of it are
     * bypassable (`UPDATE … SET hmac_key_epoch = 0` empties the "has HMAC rows"
     * probe), so the store itself has to refuse.
     *
     * The hash cannot be compared here — rewriting it is what a re-seal does —
     * so the assertion is existence of the anchored row plus uid monotonicity.
     *
     * @param false|string $anchoredRowHash what the anchored uid reads back as
     * @param int $tipUid uid of the tip the re-seal would sign
     */
    #[Test]
    #[DataProvider('resealRefusalProvider')]
    public function resealRefusesToSignAChainThatLostTheAnchoredRow(
        false|string $anchoredRowHash,
        int $tipUid,
    ): void {
        $this->wireReads(
            [['uid' => $tipUid, 'entry_hash' => self::HASH_B], $this->anchorRow($this->encode(7, self::HASH_A))],
            [$anchoredRowHash],
        );

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        $this->subject()->reseal($this->connection);
    }

    /**
     * @return iterable<string, array{false|string, int}>
     */
    public static function resealRefusalProvider(): iterable
    {
        yield 'anchored row deleted by a tail truncation' => [false, 3];
        yield 'tip sits below the anchored uid' => [self::HASH_B, 3];
    }

    /**
     * Deleting the anchor on an empty chain would be a downgrade an attacker
     * could induce by wiping the table.
     */
    #[Test]
    public function resealRecordsNothingOnAnEmptyChain(): void
    {
        $this->wireReads([false]);

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');
        $this->connection->expects(self::never())->method('delete');

        $this->subject()->reseal($this->connection);
    }

    /**
     * `UPDATE sys_registry SET entry_value = NULL` leaves the row in place. That
     * must NOT read back as "never anchored": treating it so would let the next
     * ordinary append mint a fresh anchor on whatever the chain now is, and the
     * INSERT it would attempt collides with the `entry_identifier` unique key.
     */
    #[Test]
    public function advanceLeavesAPresentButBlankedAnchorRowAlone(): void
    {
        $this->wireReads([$this->anchorRow(null)]);

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        $this->subject()->advance($this->connection, new AuditChainAnchor(9, self::HASH_B, 1_700_000_000));
    }

    /**
     * With `auditAnchorRequired` on, the operator has asserted the install is
     * anchored, so an absent anchor over an already-populated chain is a removed
     * anchor — never a bootstrap. Signing a new one there would attest the
     * truncated tip as genuine.
     */
    #[Test]
    public function advanceRefusesToArmAnAbsentAnchorOnAPopulatedChainWhenRequired(): void
    {
        $this->wireReads([false], [3]);

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        $this->subjectWithAnchorRequired()
            ->advance($this->connection, new AuditChainAnchor(9, self::HASH_B, 1_700_000_000));
    }

    /**
     * The refusal is UNCONDITIONAL, and this is the case that forces it: no row
     * sits below the tip, so the chain LOOKS fresh — which is precisely the
     * state an attacker produces by emptying the table, because the audit insert
     * that triggers this call has just written the only row there is. An
     * emptiness probe would arm here and hand the attacker a MAC-signed anchor
     * over a wiped chain, reached by deleting MORE rows rather than fewer.
     */
    #[Test]
    public function advanceRefusesToArmAnAbsentAnchorEvenWhenNoRowSitsBelowTheTip(): void
    {
        $this->wireReads([false], [false]);

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        $this->subjectWithAnchorRequired()
            ->advance($this->connection, new AuditChainAnchor(1, self::HASH_A, 1_700_000_000));
    }

    /**
     * `reseal()` can create an anchor from absent state too, so it carries the
     * same rule — otherwise a master-key rotation or an HMAC migration would
     * re-arm what an ordinary append is forbidden to.
     */
    #[Test]
    public function resealRefusesToArmAnAbsentAnchorWhenRequired(): void
    {
        $this->wireReads([['uid' => 7, 'entry_hash' => self::HASH_A], false], [false]);

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        $this->subjectWithAnchorRequired()->reseal($this->connection);
    }

    /**
     * The sanctioned way back: an explicit operator action (`vault:audit
     * --reset-anchor`) arms the current tip regardless of the flag, which is
     * what keeps the escape hatch usable on a hardened installation.
     */
    #[Test]
    public function armRecordsTheCurrentTipEvenWhenTheAnchorIsAbsentAndRequired(): void
    {
        $this->wireReads([['uid' => 7, 'entry_hash' => self::HASH_A], false]);

        $this->connection->expects(self::once())->method('insert');

        self::assertTrue($this->subjectWithAnchorRequired()->arm($this->connection));
    }

    #[Test]
    public function armRecordsNothingOnAnEmptyChain(): void
    {
        $this->wireReads([false]);

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        self::assertFalse($this->subject()->arm($this->connection));
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private function subjectWithAnchorRequired(): AuditChainAnchorStore
    {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getAuditHmacEpoch')->willReturn(3);
        $configuration->method('isAuditAnchorRequired')->willReturn(true);

        return new AuditChainAnchorStore($this->connectionPool, $this->masterKeyProvider(), $configuration);
    }

    private function subject(): AuditChainAnchorStore
    {
        return new AuditChainAnchorStore(
            $this->connectionPool,
            $this->masterKeyProvider(),
            $this->extensionConfiguration,
        );
    }

    private function masterKeyProvider(): MasterKeyProviderInterface
    {
        $provider = self::createStub(MasterKeyProviderInterface::class);
        $provider->method('getMasterKey')->willReturn(self::MASTER_KEY);

        return $provider;
    }

    /**
     * Mirrors the store's own value format so the test asserts the contract
     * rather than reusing the implementation.
     */
    private function encode(int $uid, string $entryHash, int $tstamp = 1_700_000_000): string
    {
        $mac = hash_hmac(
            'sha256',
            json_encode([
                'v' => 1,
                'uid' => $uid,
                'entry_hash' => $entryHash,
                'tstamp' => $tstamp,
            ], JSON_THROW_ON_ERROR),
            hash_hkdf('sha256', self::MASTER_KEY, 32, 'nr-vault-audit-anchor-v1'),
        );

        return \sprintf('nrvault-audit-tip.v1|%d|%s|%d|%s', $uid, $entryHash, $tstamp, $mac);
    }

    /**
     * The `sys_registry` row shape `readRaw()` reads. A row that is PRESENT but
     * carries no usable value is not the same as no row at all — the store has
     * to tell them apart, so the test fixture does too.
     *
     * @return array<string, mixed>
     */
    private function anchorRow(mixed $entryValue): array
    {
        return ['entry_value' => $entryValue];
    }

    /**
     * @param list<array<string, mixed>|false> $fetchAssociativeReturns consecutive row reads,
     *                                                                  in call order: `reseal()`
     *                                                                  and `arm()` read the tip
     *                                                                  first, then the anchor row
     * @param list<mixed> $fetchOneReturns consecutive `fetchOne()` results (audit-table probes)
     */
    private function wireReads(array $fetchAssociativeReturns, array $fetchOneReturns = []): void
    {
        $result = self::createStub(Result::class);
        if ($fetchOneReturns !== []) {
            $result->method('fetchOne')->willReturn(...$fetchOneReturns);
        }
        if ($fetchAssociativeReturns !== []) {
            $result->method('fetchAssociative')->willReturn(...$fetchAssociativeReturns);
        }

        $expressionBuilder = self::createStub(ExpressionBuilder::class);
        $expressionBuilder->method('eq')->willReturn('c = :p');

        $restrictions = self::createStub(QueryRestrictionContainerInterface::class);

        $queryBuilder = self::createStub(QueryBuilder::class);
        $queryBuilder->method('getRestrictions')->willReturn($restrictions);
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder->method('createNamedParameter')->willReturn(':p');
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('orderBy')->willReturnSelf();
        $queryBuilder->method('setMaxResults')->willReturnSelf();
        $queryBuilder->method('executeQuery')->willReturn($result);

        $this->connection->method('createQueryBuilder')->willReturn($queryBuilder);
    }
}
