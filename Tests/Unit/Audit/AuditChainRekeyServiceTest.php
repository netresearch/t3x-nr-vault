<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Audit\AuditChainRekeyService;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
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
     * Run the re-key over `$rows` and collect every UPDATE the service issued.
     *
     * @param list<array<string, mixed>> $rows
     * @param list<array{uid: mixed, entry_hash: mixed, previous_hash: mixed}> $updates
     */
    private function rekey(array $rows, array &$updates): int
    {
        $collected = [];

        $result = self::createStub(Result::class);
        $result->method('fetchAllAssociative')->willReturn($rows);

        $queryBuilder = self::createStub(QueryBuilder::class);
        $queryBuilder->method('expr')->willReturn(self::createStub(ExpressionBuilder::class));
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('orderBy')->willReturnSelf();
        $queryBuilder->method('setMaxResults')->willReturnSelf();
        $queryBuilder->method('createNamedParameter')->willReturn('?');
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

        $rewritten = (new AuditChainRekeyService())->rekeyChain($connection, self::NEW_MASTER_KEY_MATERIAL);

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
