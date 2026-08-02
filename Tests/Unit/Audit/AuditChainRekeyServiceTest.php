<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Audit\AuditChainAnchorStoreInterface;
use Netresearch\NrVault\Audit\AuditChainRekeyService;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

/**
 * Master-key rotation re-signs the whole audit chain under the new key. Two
 * properties make or break the tamper evidence:
 *
 *  1. **Each row keeps its OWN epoch.** A row written at epoch 2 must be
 *     re-signed with the epoch-2 payload. Re-signing it with a different epoch's
 *     payload would make every later verification report a tamper that never
 *     happened — and rotation is exactly when nobody can tell the difference.
 *  2. **`previous_hash` is re-linked as the walk proceeds**, including across
 *     batch boundaries, or the chain breaks at the seam.
 *
 * {@see \Netresearch\NrVault\Tests\Functional\Audit\AuditChainRekeyServiceTest}
 * proves the result verifies against a real database. These tests pin the
 * per-epoch dispatch and the update decision, which need a row of every epoch in
 * one chain.
 */
#[CoversClass(AuditChainRekeyService::class)]
final class AuditChainRekeyServiceTest extends TestCase
{
    private const NEW_MASTER_KEY_MATERIAL = 'rotation-target-key-material-32b';

    /**
     * Rows per keyset batch, mirroring the service's own `BATCH_SIZE`. A batch
     * of exactly this size is what makes the walk ask for another one.
     */
    private const BATCH_SIZE = 1000;

    /**
     * Values bound as the keyset lower bound, in call order — one per batch.
     * The chain walk is only correct if this sequence is `[0, <last uid of the
     * previous batch>, …]`.
     *
     * @var list<mixed>
     */
    private array $keysetBounds = [];

    /**
     * The load-bearing case: one chain holding a row of every epoch. Each row's
     * expected hash is recomputed here with the algorithm its OWN epoch selects,
     * so a mis-dispatched arm shows up as a mismatch rather than as a silently
     * different-but-plausible hash.
     */
    #[Test]
    public function everyEpochIsReSignedWithItsOwnAlgorithm(): void
    {
        $rows = [
            $this->row(uid: 1, epoch: 0),
            $this->row(uid: 2, epoch: 1),
            $this->row(uid: 3, epoch: 2),
            $this->row(uid: 4, epoch: 3),
        ];

        $updates = [];
        $rewritten = $this->rekey($rows, $updates);

        self::assertSame(4, $rewritten, 'every row carried a stale hash and had to be rewritten');
        self::assertSame([1, 2, 3, 4], array_column($updates, 'uid'));
        self::assertSame(
            $this->expectedHashes($rows),
            array_column($updates, 'entry_hash'),
        );
    }

    /**
     * The four arms must not agree with one another: if two epochs produced the
     * same hash for the same row, a mis-dispatch would be invisible.
     */
    #[Test]
    public function theEpochArmsProduceDistinctHashesForOtherwiseIdenticalRows(): void
    {
        $rows = [
            $this->row(uid: 1, epoch: 0),
            $this->row(uid: 1, epoch: 1),
            $this->row(uid: 1, epoch: 2),
            $this->row(uid: 1, epoch: 3),
        ];

        $hashes = [];
        foreach ($rows as $row) {
            $updates = [];
            $this->rekey([$row], $updates);
            $hash = $updates[0]['entry_hash'];
            self::assertIsString($hash);
            $hashes[] = $hash;
        }

        self::assertSame($hashes, array_unique($hashes));
    }

    /**
     * An epoch above the highest known selector must fall through to the newest
     * algorithm rather than to the oldest — the fail-forward direction, so a
     * future epoch is never re-signed with a weaker payload.
     */
    #[Test]
    public function anEpochAboveTheHighestSelectorUsesTheNewestAlgorithm(): void
    {
        $row = $this->row(uid: 1, epoch: 9);

        $updates = [];
        $this->rekey([$row], $updates);

        self::assertSame(
            AuditLogService::calculateHashV3(
                AuditLogService::extractV3HashRow($row),
                '',
                $this->hmacKey(),
            ),
            $updates[0]['entry_hash'],
        );
    }

    /**
     * `previous_hash` must be re-linked to the RECOMPUTED predecessor, not to
     * whatever the row carried before — otherwise the re-signed chain verifies
     * row-by-row but fails at every link.
     */
    #[Test]
    public function previousHashIsRelinkedToTheRecomputedPredecessor(): void
    {
        $rows = [$this->row(uid: 1, epoch: 3), $this->row(uid: 2, epoch: 3)];

        $updates = [];
        $this->rekey($rows, $updates);

        $expected = $this->expectedHashes($rows);

        self::assertSame('', $updates[0]['previous_hash'], 'the first row anchors the chain at the empty hash');
        self::assertSame($expected[0], $updates[1]['previous_hash']);
    }

    /**
     * A row already carrying the correct hash and link needs no UPDATE. Rewriting
     * it anyway would make a second rotation report work it did not do, and the
     * count is what the rotation command shows the operator.
     */
    #[Test]
    public function alreadyCorrectRowsAreLeftUntouched(): void
    {
        $hmacKey = $this->hmacKey();
        $first = $this->row(uid: 1, epoch: 3);
        $first['entry_hash'] = AuditLogService::calculateHashV3(
            AuditLogService::extractV3HashRow($first),
            '',
            $hmacKey,
        );
        $first['previous_hash'] = '';

        $updates = [];
        $rewritten = $this->rekey([$first], $updates);

        self::assertSame(0, $rewritten);
        self::assertSame([], $updates);
    }

    /**
     * A row whose hash is right but whose link is wrong still has to be rewritten
     * — a broken link is exactly the state a deletion-plus-patch attack leaves.
     */
    #[Test]
    public function aRowWithACorrectHashButAWrongLinkIsStillRewritten(): void
    {
        $hmacKey = $this->hmacKey();
        $first = $this->row(uid: 1, epoch: 3);
        $first['entry_hash'] = AuditLogService::calculateHashV3(
            AuditLogService::extractV3HashRow($first),
            '',
            $hmacKey,
        );
        $first['previous_hash'] = 'stale-link';

        $updates = [];

        self::assertSame(1, $this->rekey([$first], $updates));
        self::assertSame('', $updates[0]['previous_hash']);
    }

    #[Test]
    public function anEmptyChainRewritesNothing(): void
    {
        $updates = [];

        self::assertSame(0, $this->rekey([], $updates));
    }

    /**
     * The rewrite invalidates the entry hash the tip anchor asserts, so
     * re-signing it is part of THIS method's contract rather than a caller
     * obligation: as a docblock every future caller had to honour it, and
     * skipping it makes an entirely healthy chain report a tip-anchor violation
     * on every subsequent verification. It is re-signed under the NEW key — the
     * master-key provider still holds the old one at this point.
     */
    #[Test]
    public function theTipAnchorIsResealedUnderTheNewKey(): void
    {
        $anchorStore = $this->createMock(AuditChainAnchorStoreInterface::class);
        $anchorStore
            ->expects(self::once())
            ->method('reseal')
            ->with(self::isInstanceOf(Connection::class), self::NEW_MASTER_KEY_MATERIAL);

        $updates = [];

        self::assertSame(1, $this->rekey([$this->row(uid: 1, epoch: 3)], $updates, $anchorStore));
    }

    /**
     * The keyset walk starts BELOW the first uid. The bound is exclusive
     * (`uid > :bound`), so it has to be 0 — starting at 1 would skip the very
     * first row of the chain, and the row it skips is the one every later link
     * hangs off.
     */
    #[Test]
    public function theKeysetWalkStartsBelowTheFirstUid(): void
    {
        $updates = [];
        $this->rekey([$this->row(uid: 1, epoch: 3)], $updates);

        self::assertSame([0], $this->keysetBounds);
    }

    /**
     * A chain longer than one batch has to be walked to its end, and each batch
     * has to resume at the highest uid the previous one returned. Stopping after
     * the first full batch would leave the tail of a large log signed under the
     * OLD key, which verifies as a tampered chain.
     *
     * The rows carry `uid` as a STRING, the way the drivers actually hand it
     * back: the bound is bound as `PARAM_INT`, so it has to be normalised
     * before it is handed to the next query.
     */
    #[Test]
    public function theWalkResumesAtTheLastUidOfAFullBatch(): void
    {
        $firstBatch = [];
        for ($uid = 1; $uid <= self::BATCH_SIZE; $uid++) {
            $row = $this->row(uid: $uid, epoch: 0);
            $row['uid'] = (string) $uid;
            $firstBatch[] = $row;
        }

        $updates = [];
        $rewritten = $this->rekeyBatches(
            [$firstBatch, [$this->row(uid: self::BATCH_SIZE + 1, epoch: 0)]],
            $updates,
        );

        self::assertSame(self::BATCH_SIZE + 1, $rewritten, 'the walk stopped at the first full batch');
        self::assertSame([0, self::BATCH_SIZE], $this->keysetBounds);
    }

    /**
     * A batch whose rows carry no usable uid must not move the bound forward.
     * An invented bound skips whatever sits between the real position and the
     * invented one — silently leaving those rows signed under the old key, in
     * the one situation where nobody can tell a stale hash from a tampered one.
     *
     * @param string|null $uid raw `uid` column value; null removes the column entirely
     */
    #[Test]
    #[DataProvider('unusableUidProvider')]
    public function aBatchWithoutUsableUidsDoesNotMoveTheBoundForward(?string $uid): void
    {
        $row = $this->row(uid: 1, epoch: 0);
        if ($uid === null) {
            unset($row['uid']);
        } else {
            $row['uid'] = $uid;
        }

        $updates = [];
        $rewritten = $this->rekeyBatches(
            [array_fill(0, self::BATCH_SIZE, $row), [$this->row(uid: 2, epoch: 0)]],
            $updates,
        );

        self::assertSame(self::BATCH_SIZE + 1, $rewritten);
        self::assertSame([0, 0], $this->keysetBounds);
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function unusableUidProvider(): iterable
    {
        yield 'uid column absent' => [null];
        yield 'uid column not numeric' => ['not-a-uid'];
    }

    /**
     * Run the re-key over `$rows` and collect every UPDATE the service issued.
     *
     * @param list<array<string, mixed>> $rows
     * @param list<array{uid: mixed, entry_hash: mixed, previous_hash: mixed}> $updates
     */
    private function rekey(array $rows, array &$updates, ?AuditChainAnchorStoreInterface $anchorStore = null): int
    {
        return $this->rekeyBatches([$rows], $updates, $anchorStore);
    }

    /**
     * Run the re-key over consecutive keyset batches, collecting every UPDATE
     * and every keyset bound the service asked for.
     *
     * @param non-empty-list<list<array<string, mixed>>> $batches consecutive `fetchAllAssociative()` results
     * @param list<array{uid: mixed, entry_hash: mixed, previous_hash: mixed}> $updates
     */
    private function rekeyBatches(
        array $batches,
        array &$updates,
        ?AuditChainAnchorStoreInterface $anchorStore = null,
    ): int {
        $collected = [];
        $this->keysetBounds = [];

        $result = self::createStub(Result::class);
        $result->method('fetchAllAssociative')->willReturn(...$batches);

        $queryBuilder = self::createStub(QueryBuilder::class);
        $queryBuilder->method('expr')->willReturn(self::createStub(ExpressionBuilder::class));
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('orderBy')->willReturnSelf();
        $queryBuilder->method('setMaxResults')->willReturnSelf();
        $queryBuilder->method('createNamedParameter')->willReturnCallback(
            function (mixed $value): string {
                $this->keysetBounds[] = $value;

                return '?';
            },
        );
        $queryBuilder->method('executeQuery')->willReturn($result);

        $connection = self::createStub(Connection::class);
        $connection->method('createQueryBuilder')->willReturn($queryBuilder);
        $connection->method('update')->willReturnCallback(
            static function (string $table, array $data, array $identifier) use (&$collected): int {
                $collected[] = [
                    'uid' => $identifier['uid'] ?? null,
                    'entry_hash' => $data['entry_hash'] ?? null,
                    'previous_hash' => $data['previous_hash'] ?? null,
                ];

                return 1;
            },
        );

        $rewritten = (new AuditChainRekeyService($anchorStore))
            ->rekeyChain($connection, self::NEW_MASTER_KEY_MATERIAL);

        $updates = $collected;

        return $rewritten;
    }

    /**
     * Recompute the chain's expected hashes independently of the service, using
     * each row's own epoch and re-linking as it goes.
     *
     * @param list<array<string, mixed>> $rows
     *
     * @return list<string>
     */
    private function expectedHashes(array $rows): array
    {
        $hmacKey = $this->hmacKey();
        $previousHash = '';
        $hashes = [];

        foreach ($rows as $row) {
            $entry = AuditLogService::extractHashRow($row);

            $hashes[] = $previousHash = match ($entry['epoch']) {
                0 => AuditLogService::calculateHash(
                    $entry['uid'],
                    $entry['secretId'],
                    $entry['action'],
                    $entry['actorUid'],
                    $entry['crdate'],
                    $previousHash,
                ),
                1 => AuditLogService::calculateHash(
                    $entry['uid'],
                    $entry['secretId'],
                    $entry['action'],
                    $entry['actorUid'],
                    $entry['crdate'],
                    $previousHash,
                    $hmacKey,
                ),
                2 => AuditLogService::calculateHashV2(
                    AuditLogService::extractV2HashRow($row),
                    $previousHash,
                    $hmacKey,
                ),
                default => AuditLogService::calculateHashV3(
                    AuditLogService::extractV3HashRow($row),
                    $previousHash,
                    $hmacKey,
                ),
            };
        }

        return $hashes;
    }

    private function hmacKey(): string
    {
        return AuditLogService::deriveHmacKeyFromMasterKey(self::NEW_MASTER_KEY_MATERIAL);
    }

    /**
     * A full audit row as the chain walk reads it, with a deliberately stale
     * `entry_hash` so the default expectation is "must be rewritten".
     *
     * @return array<string, mixed>
     */
    private function row(int $uid, int $epoch): array
    {
        return [
            'uid' => $uid,
            'secret_identifier' => 'api/stripe',
            'action' => 'read',
            'success' => 1,
            'actor_uid' => 7,
            'crdate' => 1_750_000_000 + $uid,
            'error_message' => '',
            'reason' => '',
            'ip_address' => '203.0.113.7',
            'user_agent' => 'curl/8',
            'hash_before' => '',
            'hash_after' => '',
            'context' => '{}',
            'hmac_key_epoch' => $epoch,
            'actor_type' => 'be_user',
            'actor_username' => 'editor',
            'actor_role' => 'groups:1',
            'request_id' => 'req-' . $uid,
            'previous_hash' => 'stale-previous',
            'entry_hash' => 'stale-entry',
        ];
    }
}
