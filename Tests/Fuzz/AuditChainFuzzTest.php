<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Fuzz;

use Netresearch\NrVault\Audit\AuditLogService;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Fuzz tests for the AuditLogService hash-chain pure function.
 *
 * AuditLogService::calculateHash() is a public static method that can be tested
 * without any database or TYPO3 bootstrap. It is the core of the tamper-evident
 * audit log.
 *
 * Properties under test:
 * - Determinism: identical inputs always produce the same hash
 * - Avalanche (single-byte sensitivity): changing any single field changes the hash
 * - Order sensitivity: swapping entry order changes the resulting chain hash
 * - Hash format: always 64 hex characters (SHA-256)
 * - Never throws for arbitrary string inputs
 * - HMAC key provided vs null produces different hashes (epoch 0 vs 1)
 */
#[CoversClass(AuditLogService::class)]
final class AuditChainFuzzTest extends TestCase
{
    // -----------------------------------------------------------------------
    // Data providers
    // -----------------------------------------------------------------------

    /**
     * Entry tuples: [uid, secretIdentifier, action, actorUid, crdate, previousHash].
     *
     * @return array<string, array{int, string, string, int, int, string}>
     */
    public static function entryProvider(): array
    {
        $seed = (int) (getenv('PHPUNIT_SEED') ?: crc32(__FILE__));
        mt_srand($seed);

        $cases = [
            'typical entry' => [1, '01937b6e-4b6c-7abc-8def-000000000001', 'store', 42, 1700000000, ''],
            'first entry empty prev' => [1, 'test-id', 'create', 0, 0, ''],
            'unicode in identifier' => [99, '01937b6e-4b6c-7abc-8def-aabbccddeeff', '読む', 1, 1710000000, str_repeat('0', 64)],
            'empty strings' => [0, '', '', 0, 0, ''],
            'max int uid' => [PHP_INT_MAX, 'long-id', 'delete', PHP_INT_MAX, PHP_INT_MAX, str_repeat('f', 64)],
            'negative actor uid' => [5, 'id', 'rotate', -1, 1720000000, 'abc123'],
            'null bytes in id' => [10, "id\x00with\x00nulls", 'retrieve', 7, 1715000000, ''],
            'very long identifier' => [3, str_repeat('x', 1000), 'access', 2, 1718000000, ''],
            'special chars in action' => [7, 'test', '<script>alert(1)</script>', 0, 1700000001, ''],
        ];

        // 50 random entries
        for ($i = 0; $i < 50; $i++) {
            $uid = mt_rand(1, 100000);
            $idLen = mt_rand(0, 64);
            $secretId = '';
            for ($j = 0; $j < $idLen; $j++) {
                $secretId .= \chr(mt_rand(32, 126));
            }

            $actionLen = mt_rand(1, 20);
            $action = '';
            for ($j = 0; $j < $actionLen; $j++) {
                $action .= \chr(mt_rand(97, 122)); // a-z
            }

            $actorUid = mt_rand(0, 1000);
            $crdate = mt_rand(1000000, 2000000000);
            $prevHash = mt_rand(0, 1) !== 0 ? str_repeat('0', 64) : '';

            $cases["random_{$i}"] = [$uid, $secretId, $action, $actorUid, $crdate, $prevHash];
        }

        return $cases;
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /**
     * Determinism: same inputs always produce the same hash.
     */
    #[Test]
    #[DataProvider('entryProvider')]
    public function calculateHashIsDeterministic(
        int $uid,
        string $secretIdentifier,
        string $action,
        int $actorUid,
        int $crdate,
        string $previousHash,
    ): void {
        $hash1 = AuditLogService::calculateHash($uid, $secretIdentifier, $action, $actorUid, $crdate, $previousHash);
        $hash2 = AuditLogService::calculateHash($uid, $secretIdentifier, $action, $actorUid, $crdate, $previousHash);

        self::assertSame($hash1, $hash2, 'Hash must be deterministic for identical inputs');
    }

    /**
     * Hash format: always exactly 64 hex characters.
     */
    #[Test]
    #[DataProvider('entryProvider')]
    public function calculateHashReturnsSha256HexString(
        int $uid,
        string $secretIdentifier,
        string $action,
        int $actorUid,
        int $crdate,
        string $previousHash,
    ): void {
        $hash = AuditLogService::calculateHash($uid, $secretIdentifier, $action, $actorUid, $crdate, $previousHash);

        self::assertSame(64, \strlen($hash), 'SHA-256 hash must be exactly 64 hex chars');
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash, 'Hash must be lowercase hex');
    }

    /**
     * HMAC key provided vs null produces different hashes (epoch separation).
     */
    #[Test]
    #[DataProvider('entryProvider')]
    public function hmacKeyChangeProducesDifferentHash(
        int $uid,
        string $secretIdentifier,
        string $action,
        int $actorUid,
        int $crdate,
        string $previousHash,
    ): void {
        $hmacKey = random_bytes(32);

        $legacyHash = AuditLogService::calculateHash($uid, $secretIdentifier, $action, $actorUid, $crdate, $previousHash);
        $hmacHash = AuditLogService::calculateHash($uid, $secretIdentifier, $action, $actorUid, $crdate, $previousHash, $hmacKey);

        self::assertNotSame($legacyHash, $hmacHash, 'HMAC hash must differ from SHA-256-only hash');
    }

    /**
     * Avalanche — changing uid changes the hash.
     */
    #[Test]
    public function changingUidChangesHash(): void
    {
        $hash1 = AuditLogService::calculateHash(1, 'id', 'store', 1, 1000, '');
        $hash2 = AuditLogService::calculateHash(2, 'id', 'store', 1, 1000, '');

        self::assertNotSame($hash1, $hash2);
    }

    /**
     * Avalanche — changing secretIdentifier changes the hash.
     */
    #[Test]
    public function changingSecretIdentifierChangesHash(): void
    {
        $hash1 = AuditLogService::calculateHash(1, 'identifier-a', 'store', 1, 1000, '');
        $hash2 = AuditLogService::calculateHash(1, 'identifier-b', 'store', 1, 1000, '');

        self::assertNotSame($hash1, $hash2);
    }

    /**
     * Avalanche — changing action changes the hash.
     */
    #[Test]
    public function changingActionChangesHash(): void
    {
        $hash1 = AuditLogService::calculateHash(1, 'id', 'store', 1, 1000, '');
        $hash2 = AuditLogService::calculateHash(1, 'id', 'retrieve', 1, 1000, '');

        self::assertNotSame($hash1, $hash2);
    }

    /**
     * Avalanche — changing actorUid changes the hash.
     */
    #[Test]
    public function changingActorUidChangesHash(): void
    {
        $hash1 = AuditLogService::calculateHash(1, 'id', 'store', 1, 1000, '');
        $hash2 = AuditLogService::calculateHash(1, 'id', 'store', 2, 1000, '');

        self::assertNotSame($hash1, $hash2);
    }

    /**
     * Avalanche — changing crdate changes the hash.
     */
    #[Test]
    public function changingCrdateChangesHash(): void
    {
        $hash1 = AuditLogService::calculateHash(1, 'id', 'store', 1, 1000, '');
        $hash2 = AuditLogService::calculateHash(1, 'id', 'store', 1, 1001, '');

        self::assertNotSame($hash1, $hash2);
    }

    /**
     * Avalanche — changing previousHash changes the hash.
     */
    #[Test]
    public function changingPreviousHashChangesHash(): void
    {
        $hash1 = AuditLogService::calculateHash(1, 'id', 'store', 1, 1000, str_repeat('a', 64));
        $hash2 = AuditLogService::calculateHash(1, 'id', 'store', 1, 1000, str_repeat('b', 64));

        self::assertNotSame($hash1, $hash2);
    }

    /**
     * Order sensitivity: a chain built in order A→B→C produces a different final
     * hash than one built in order B→A→C.
     */
    #[Test]
    public function chainHashDependsOnEntryOrder(): void
    {
        // Build chain A→B
        $hashA = AuditLogService::calculateHash(1, 'secret-1', 'store', 1, 1000, '');
        $hashAB = AuditLogService::calculateHash(2, 'secret-2', 'retrieve', 1, 1001, $hashA);

        // Build chain B→A (reversed order)
        $hashB = AuditLogService::calculateHash(2, 'secret-2', 'retrieve', 1, 1001, '');
        $hashBA = AuditLogService::calculateHash(1, 'secret-1', 'store', 1, 1000, $hashB);

        self::assertNotSame($hashAB, $hashBA, 'Chain hash must be order-sensitive');
    }

    /**
     * Three-entry chain: two identical sequences produce the same final hash (determinism
     * over sequence).
     */
    #[Test]
    public function identicalChainSequencesProduceSameFinalHash(): void
    {
        $computeChain = static function (): string {
            $h = '';
            $entries = [
                [1, 'id-1', 'store', 10, 1700000000],
                [2, 'id-2', 'retrieve', 11, 1700000001],
                [3, 'id-3', 'delete', 10, 1700000002],
            ];
            foreach ($entries as [$uid, $id, $action, $actor, $crdate]) {
                $h = AuditLogService::calculateHash($uid, $id, $action, $actor, $crdate, $h);
            }

            return $h;
        };

        self::assertSame($computeChain(), $computeChain(), 'Identical chain sequences must produce the same final hash');
    }

    /**
     * Fuzz: calculateHash() never throws for arbitrary string/int inputs.
     */
    #[Test]
    #[DataProvider('entryProvider')]
    public function calculateHashNeverThrows(
        int $uid,
        string $secretIdentifier,
        string $action,
        int $actorUid,
        int $crdate,
        string $previousHash,
    ): void {
        // No expectException — we assert it completes without error
        $hash = AuditLogService::calculateHash($uid, $secretIdentifier, $action, $actorUid, $crdate, $previousHash);
        self::assertNotEmpty($hash);
    }

    /**
     * Avalanche over random single-byte flips in the previous hash.
     *
     * For 10 random single-byte mutations, the resulting hash must always differ
     * from the base hash.
     */
    #[Test]
    public function singleByteMutationInPreviousHashChangesOutputHash(): void
    {
        $basePrevHash = hash('sha256', 'base-entry');
        $baseHash = AuditLogService::calculateHash(1, 'id', 'store', 1, 1000, $basePrevHash);

        $seed = (int) (getenv('PHPUNIT_SEED') ?: crc32(__FILE__) + 42);
        mt_srand($seed);

        for ($i = 0; $i < 10; $i++) {
            $mutated = $basePrevHash;
            $pos = mt_rand(0, \strlen($mutated) - 1);
            // Flip one hex digit (keep it valid hex to ensure position matters, not just format)
            $original = $mutated[$pos];
            $flipped = dechex((hexdec($original) + 1) % 16);
            $mutated[$pos] = $flipped;

            if ($mutated === $basePrevHash) {
                // Edge case: flip wrapped to same char (e.g., 'f'+1='0' still differs)
                continue;
            }

            $mutatedHash = AuditLogService::calculateHash(1, 'id', 'store', 1, 1000, $mutated);
            self::assertNotSame($baseHash, $mutatedHash, "Single-byte mutation at pos {$pos} must change the output hash");
        }
    }
}
