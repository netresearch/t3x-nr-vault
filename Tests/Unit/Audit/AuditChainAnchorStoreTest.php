<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use Doctrine\DBAL\Result;
use InvalidArgumentException;
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

    /**
     * The restriction container the wired query builder hands out — the seam
     * that proves the anchor lookup drops the default restrictions.
     */
    private QueryRestrictionContainerInterface&MockObject $restrictions;

    private ConnectionPool $connectionPool;

    private ExtensionConfigurationInterface $extensionConfiguration;

    protected function setUp(): void
    {
        parent::setUp();

        $this->connection = $this->createMock(Connection::class);
        $this->restrictions = $this->createMock(QueryRestrictionContainerInterface::class);
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

        // The full argument list is pinned: an UPDATE that carries no value
        // blanks the anchor, one that drops the namespace from its WHERE hits
        // every extension's registry entry under the same key, and one that
        // drops the LOB type corrupts the value on PostgreSQL.
        $this->connection
            ->expects(self::once())
            ->method('update')
            ->with(
                'sys_registry',
                self::callback(static fn (array $data): bool => \is_string($data['entry_value'] ?? null)
                    && str_starts_with($data['entry_value'], 'nrvault-audit-tip.v1|9|' . self::HASH_B . '|')),
                ['entry_namespace' => 'tx_nrvault_audit_anchor', 'entry_key' => 'auditChainTip'],
                ['entry_value' => Connection::PARAM_LOB],
            );
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
        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        $subject = $this->subjectAtEpoch(0);
        $subject->advance($this->connection, new AuditChainAnchor(1, self::HASH_A, 1_700_000_000));

        self::assertFalse($subject->isEnabled());
    }

    /**
     * Epoch 1 is the FIRST anchored epoch, not the second: the anchor exists to
     * pin a KEYED chain, and a chain is keyed from epoch 1 upwards. Anchoring
     * only from epoch 2 would leave every install that stopped at the first
     * HMAC epoch silently unanchored.
     */
    #[Test]
    public function theAnchorIsEnabledFromTheFirstKeyedEpoch(): void
    {
        self::assertFalse($this->subjectAtEpoch(0)->isEnabled());
        self::assertTrue($this->subjectAtEpoch(1)->isEnabled());
    }

    /**
     * Both guards are independent refusals, not a conjunction: a disabled
     * anchor must stay unwritten even though the registry is on the audit
     * connection, which is the ordinary single-connection installation.
     */
    #[Test]
    public function resealWritesNothingAtEpochZero(): void
    {
        $this->wireReads([['uid' => 4, 'entry_hash' => self::HASH_A], false]);

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        $this->subjectAtEpoch(0)->reseal($this->connection);
    }

    #[Test]
    public function armWritesNothingAtEpochZero(): void
    {
        $this->wireReads([['uid' => 4, 'entry_hash' => self::HASH_A], false]);

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        self::assertFalse($this->subjectAtEpoch(0)->arm($this->connection));
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

    /**
     * The "already asserts exactly this tip" short-circuit is what stops a
     * re-seal from rewriting the row on every call. It has to fire on (uid,
     * entry_hash) equality alone — and it has to fire while the anchored row is
     * still present, which is the state every legitimate repeat re-seal is in.
     * Falling through to the truncation guard instead only looks harmless
     * because that guard also refuses; wire the row in and the fall-through
     * writes.
     */
    #[Test]
    public function resealWritesNothingWhenTheStoredTipMatchesAndTheAnchoredRowIsStillThere(): void
    {
        $this->wireReads(
            [['uid' => 4, 'entry_hash' => self::HASH_A], $this->anchorRow($this->encode(4, self::HASH_A))],
            [self::HASH_A],
        );

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        $this->subject()->reseal($this->connection);
    }

    /**
     * `auditAnchorRequired` gates the ABSENT-anchor case only. A re-seal over an
     * anchor that is PRESENT must still happen under the flag — otherwise a
     * master-key rotation on a hardened installation leaves the anchor signed
     * under the old key, and every later verification reports a violation that
     * never happened.
     */
    #[Test]
    public function resealStillRewritesAPresentAnchorWhenImplicitArmingIsRefused(): void
    {
        $this->wireReads(
            [['uid' => 4, 'entry_hash' => self::HASH_B], $this->anchorRow($this->encode(4, self::HASH_A))],
            [self::HASH_B],
        );

        $this->connection->expects(self::once())->method('update');

        $this->subjectWithAnchorRequired()->reseal($this->connection);
    }

    /**
     * The anchor lookup runs with every default restriction removed.
     * `sys_registry` has no `deleted`/`hidden`/workspace columns, so a
     * restriction that survives here turns the read into an SQL error — and an
     * anchor that cannot be read is an anchor that cannot report a truncation.
     */
    #[Test]
    public function theAnchorLookupDropsAllDefaultQueryRestrictions(): void
    {
        $this->wireReads([$this->anchorRow($this->encode(3, self::HASH_A))]);

        $this->restrictions->expects(self::atLeastOnce())->method('removeAll');

        self::assertSame(AuditChainAnchorStatus::Ok, $this->subject()->load($this->connection)->status);
    }

    /**
     * Storing bytes our own reader rejects would leave the installation
     * reporting `Unreadable` forever, so each guard fails loudly on its own.
     * The caller turns this into an `AuditWriteException`, taking the audited
     * operation down with it — fail closed.
     *
     * @param int $uid uid of the tip that must not be anchored
     * @param string $entryHash entry hash of the tip that must not be anchored
     * @param int $tstamp timestamp of the tip that must not be anchored
     */
    #[Test]
    #[DataProvider('unanchorableTipProvider')]
    public function anchoringATipOurOwnReaderWouldRejectFailsLoudly(
        int $uid,
        string $entryHash,
        int $tstamp,
    ): void {
        $this->wireReads([false]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(1753900002);

        $this->subject()->advance($this->connection, new AuditChainAnchor($uid, $entryHash, $tstamp));
    }

    /**
     * @return iterable<string, array{int, string, int}>
     */
    public static function unanchorableTipProvider(): iterable
    {
        yield 'uid below the first row' => [0, self::HASH_A, 1_700_000_000];
        yield 'hash that is not 64 lowercase hex' => [7, strtoupper(self::HASH_A), 1_700_000_000];
        yield 'negative timestamp' => [7, self::HASH_A, -1];
    }

    /**
     * `tstamp` is a point in time, not a duration: the stored format accepts
     * `\d{1,10}`, so 0 is a value the reader takes back. Only NEGATIVE
     * timestamps are refused — rejecting 0 would make the guard stricter than
     * the format it exists to protect.
     */
    #[Test]
    public function aTipWithAZeroTimestampIsAnchored(): void
    {
        $this->wireReads([false]);

        $this->expectInsertedValueStartingWith('nrvault-audit-tip.v1|7|' . self::HASH_A . '|0|');

        $this->subject()->advance($this->connection, new AuditChainAnchor(7, self::HASH_A, 0));
    }

    /**
     * uid 1 is the first row of a fresh chain — the tip a brand-new
     * installation arms on. Refusing it (in the tip read or in the encoder)
     * would leave exactly that installation unanchorable.
     */
    #[Test]
    public function armAnchorsATipAtTheVeryFirstUid(): void
    {
        $this->wireReads([['uid' => 1, 'entry_hash' => self::HASH_A], false]);

        $this->expectInsertedValueStartingWith('nrvault-audit-tip.v1|1|' . self::HASH_A . '|');

        self::assertTrue($this->subject()->arm($this->connection));
    }

    /**
     * Drivers hand `uid` back as a string on more than one supported platform,
     * so the tip read normalises it. Without the cast the anchor DTO refuses the
     * value outright and every anchored write dies with a TypeError.
     */
    #[Test]
    public function theTipUidIsNormalisedFromADriverSuppliedString(): void
    {
        $this->wireReads([['uid' => '7', 'entry_hash' => self::HASH_A], false]);

        $this->expectInsertedValueStartingWith('nrvault-audit-tip.v1|7|' . self::HASH_A . '|');

        self::assertTrue($this->subject()->arm($this->connection));
    }

    /**
     * A tip row the reader cannot make sense of yields NO anchor rather than an
     * invented one: an unusable uid must not fall back to a plausible-looking
     * row number, and a malformed hash must not be signed at all. Both
     * substitutions would MAC-attest a tip that does not exist.
     *
     * @param mixed $uid raw `uid` column value
     * @param mixed $entryHash raw `entry_hash` column value
     */
    #[Test]
    #[DataProvider('unusableTipRowProvider')]
    public function armIgnoresATipRowItCannotRead(mixed $uid, mixed $entryHash): void
    {
        $this->wireReads([['uid' => $uid, 'entry_hash' => $entryHash], false]);

        $this->connection->expects(self::never())->method('update');
        $this->connection->expects(self::never())->method('insert');

        self::assertFalse($this->subject()->arm($this->connection));
    }

    /**
     * @return iterable<string, array{mixed, mixed}>
     */
    public static function unusableTipRowProvider(): iterable
    {
        yield 'uid is not numeric' => [null, self::HASH_A];
        yield 'entry hash is malformed' => [5, 'not-a-sha256-digest'];
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    /**
     * Expect exactly one anchor INSERT whose stored value starts with $prefix.
     */
    private function expectInsertedValueStartingWith(string $prefix): void
    {
        $this->connection->expects(self::never())->method('update');
        $this->connection
            ->expects(self::once())
            ->method('insert')
            ->with(
                'sys_registry',
                self::callback(static fn (array $data): bool => \is_string($data['entry_value'] ?? null)
                    && str_starts_with($data['entry_value'], $prefix)),
                ['entry_value' => Connection::PARAM_LOB],
            );
    }

    private function subjectAtEpoch(int $epoch): AuditChainAnchorStore
    {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getAuditHmacEpoch')->willReturn($epoch);

        return new AuditChainAnchorStore($this->connectionPool, $this->masterKeyProvider(), $configuration);
    }

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

        $queryBuilder = $this->createMock(QueryBuilder::class);
        $queryBuilder->method('getRestrictions')->willReturn($this->restrictions);
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder->method('createNamedParameter')->willReturn(':p');
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('orderBy')->willReturnSelf();
        // Every read this class performs is a single-row lookup — the anchor
        // row, the anchored audit row, the chain tip. The bound is checked here
        // rather than in one test so that no call site can quietly grow a
        // second row (an anchor "read" that returns two rows is a read whose
        // result depends on row order) or lose the limit altogether.
        $queryBuilder->method('setMaxResults')->willReturnCallback(
            static function (?int $maxResults) use ($queryBuilder): QueryBuilder {
                self::assertSame(1, $maxResults, 'every anchor-store read is a single-row lookup');

                return $queryBuilder;
            },
        );
        $queryBuilder->method('executeQuery')->willReturn($result);

        $this->connection->method('createQueryBuilder')->willReturn($queryBuilder);
    }
}
