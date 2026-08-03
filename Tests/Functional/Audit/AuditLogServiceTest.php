<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Audit;

use DateTimeImmutable;
use Netresearch\NrVault\Audit\AuditLogFilter;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\HashChainVerificationResult;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Throwable;

/**
 * Functional tests for AuditLogService — log creation, hash-chain computation,
 * query with filters, and verifyHashChain (valid and tampered scenarios).
 */
#[CoversClass(AuditLogService::class)]
#[CoversClass(AuditLogFilter::class)]
#[CoversClass(HashChainVerificationResult::class)]
final class AuditLogServiceTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../../Functional/Service/Fixtures/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 1,
    ];

    #[Test]
    public function logCreatesAuditEntry(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $identifier = 'test_audit_logcreation';

        $auditService->log($identifier, 'create', true, null, 'Unit test');

        $entries = $auditService->query(AuditLogFilter::forSecret($identifier));
        self::assertCount(1, $entries);
        self::assertSame($identifier, $entries[0]->secretIdentifier);
        self::assertSame('create', $entries[0]->action);
        self::assertTrue($entries[0]->success);
    }

    #[Test]
    public function logMultipleEntriesBuildsChain(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        // Store and retrieve to create multiple audit entries
        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'chain-test-value');
        $vaultService->retrieve($identifier);
        $vaultService->delete($identifier, 'cleanup');

        $result = $auditService->verifyHashChain();

        self::assertTrue($result->isValid(), 'Hash chain must be valid after normal operations');
    }

    #[Test]
    public function queryWithActionFilterReturnsMatchingEntries(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'filter_test_value');
        $vaultService->retrieve($identifier);

        // VaultService logs 'create' (not 'store') and 'read' (not 'retrieve')
        $createEntries = $auditService->query(AuditLogFilter::forAction('create'));
        $readEntries = $auditService->query(AuditLogFilter::forAction('read'));

        $createForIdent = array_filter(
            $createEntries,
            static fn ($e): bool => $e->secretIdentifier === $identifier,
        );
        $readForIdent = array_filter(
            $readEntries,
            static fn ($e): bool => $e->secretIdentifier === $identifier,
        );

        self::assertNotEmpty($createForIdent, 'create entries must contain entry for our identifier');
        self::assertNotEmpty($readForIdent, 'read entries must contain entry for our identifier');

        // Cleanup
        $vaultService->delete($identifier, 'cleanup');
    }

    #[Test]
    public function queryWithSuccessFilterReturnsOnlySuccessful(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'success-filter-test');

        $filter = new AuditLogFilter(success: true);
        $entries = $auditService->query($filter);

        foreach ($entries as $entry) {
            self::assertTrue($entry->success, 'All returned entries must have success=true');
        }

        // Cleanup
        $vaultService->delete($identifier, 'cleanup');
    }

    #[Test]
    public function queryWithDateRangeFilterReturnsEntriesInRange(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        $before = new DateTimeImmutable('-1 hour');
        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'date-range-value');
        $after = new DateTimeImmutable('+1 hour');

        $filter = AuditLogFilter::dateRange($before, $after);
        $entries = $auditService->query($filter);

        $forIdent = array_filter(
            $entries,
            static fn ($e): bool => $e->secretIdentifier === $identifier,
        );
        self::assertNotEmpty($forIdent, 'Date range filter must return entries within range');

        // Cleanup
        $vaultService->delete($identifier, 'cleanup');
    }

    #[Test]
    public function queryWithLimitReturnsAtMostLimitEntries(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        // Create several entries
        for ($i = 0; $i < 5; $i++) {
            $id = $this->generateUuidV7();
            $vaultService->store($id, 'limit-test-' . $i);
            $vaultService->delete($id, 'cleanup');
        }

        $entries = $auditService->query(null, 3, 0);

        self::assertLessThanOrEqual(3, \count($entries));
    }

    #[Test]
    public function queryWithOffsetSkipsEntries(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        // Create several entries
        $identifiers = [];
        for ($i = 0; $i < 4; $i++) {
            $id = $this->generateUuidV7();
            $identifiers[] = $id;
            $vaultService->store($id, 'offset-test-' . $i);
        }

        $page1 = $auditService->query(null, 2, 0);
        $page2 = $auditService->query(null, 2, 2);

        // pages should not overlap
        $page1Uids = array_map(static fn ($e) => $e->uid, $page1);
        $page2Uids = array_map(static fn ($e) => $e->uid, $page2);
        $overlap = array_intersect($page1Uids, $page2Uids);
        self::assertEmpty($overlap, 'Paginated queries must not return overlapping entries');

        // Cleanup
        foreach ($identifiers as $id) {
            $vaultService->delete($id, 'cleanup');
        }
    }

    #[Test]
    public function verifyHashChainReturnsTrueForUnmodifiedChain(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'chain-verify-value');
        $vaultService->retrieve($identifier);
        $vaultService->rotate($identifier, 'rotated-chain-value', 'test rotation');
        $vaultService->delete($identifier, 'cleanup');

        $result = $auditService->verifyHashChain();

        self::assertTrue($result->isValid(), 'Hash chain must be valid after normal vault operations');
        self::assertSame([], $result->errors, 'No errors expected for unmodified chain');
        self::assertSame([], $result->missingUids, 'No uid gaps expected for unmodified chain');
    }

    #[Test]
    public function verifyHashChainDetectsTamperedEntry(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'tamper-test-value');

        // Find the entry and tamper with it directly in the DB
        $entries = $auditService->query(AuditLogFilter::forSecret($identifier));
        self::assertNotEmpty($entries, 'Must have at least one audit entry');

        $firstEntry = $entries[0];
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_nrvault_audit_log');
        $connection->update(
            'tx_nrvault_audit_log',
            ['action' => 'tampered_action'],
            ['uid' => $firstEntry->uid],
        );

        $result = $auditService->verifyHashChain();

        self::assertFalse($result->isValid(), 'Hash chain must be invalid after tampering');
        self::assertNotEmpty($result->errors, 'Errors must be reported for tampered entries');

        // Cleanup
        $vaultService->delete($identifier, 'cleanup');
    }

    #[Test]
    public function countReturnsCorrectNumberOfEntries(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        $countBefore = $auditService->count();

        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'count-test-value');
        $vaultService->retrieve($identifier);

        $countAfter = $auditService->count();
        self::assertGreaterThan($countBefore, $countAfter, 'Count must increase after logging entries');

        // Cleanup
        $vaultService->delete($identifier, 'cleanup');
    }

    #[Test]
    public function getLatestHashReturnsNonEmptyStringAfterLogging(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'hash-check-value');

        $latestHash = $auditService->getLatestHash();

        self::assertIsString($latestHash, 'Latest hash must be a string');
        self::assertNotEmpty($latestHash, 'Latest hash must not be empty after logging');

        // Cleanup
        $vaultService->delete($identifier, 'cleanup');
    }

    #[Test]
    public function hashChainDetectsMultiRowTamperPropagation(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        // Seed 10 audit entries
        $identifiers = [];
        for ($i = 0; $i < 10; $i++) {
            $id = $this->generateUuidV7();
            $identifiers[] = $id;
            $vaultService->store($id, 'propagation-test-' . $i);
        }

        // Collect all entry UIDs in insertion order
        $allEntries = $auditService->query(null, 200, 0);
        // query() orders by crdate DESC; reverse to get ascending order
        $allEntries = array_reverse($allEntries);
        self::assertGreaterThanOrEqual(10, \count($allEntries), 'Must have at least 10 entries');

        // Take the last 10 (our seeded entries)
        $seededEntries = \array_slice($allEntries, -10);

        // Entry at index 4 = the 5th seeded entry (0-based)
        $tamperedEntry = $seededEntries[4];

        // Tamper row 5's `entry_hash` directly. Changing `entry_hash` (not
        // just `action`) is what propagates, because row 6's `previous_hash`
        // is bound to row 5's *stored* `entry_hash`. Once row 5's
        // `entry_hash` mismatches its recomputed hash, row 6's
        // `previous_hash` == row 5's old hash no longer equals row 5's
        // current stored hash → row 6 also fails its chain check.
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_nrvault_audit_log');
        $connection->update(
            'tx_nrvault_audit_log',
            ['entry_hash' => str_repeat('0', 64)],
            ['uid' => $tamperedEntry->uid],
        );

        $result = $auditService->verifyHashChain();

        self::assertFalse($result->isValid(), 'Hash chain must be invalid after tampering');

        $errorUids = array_keys($result->errors);
        self::assertContains(
            $tamperedEntry->uid,
            $errorUids,
            'Tampered row 5 uid must appear in errors',
        );

        // At least one subsequent row (entries 6..10) must also be in errors,
        // proving the chain propagation check, not just single-row detection.
        $subsequentUids = array_map(
            static fn ($e) => $e->uid,
            \array_slice($seededEntries, 5),
        );
        $propagatedErrors = array_intersect($errorUids, $subsequentUids);
        self::assertNotEmpty(
            $propagatedErrors,
            'At least one row after the tampered entry must also appear in errors (chain propagation)',
        );

        // Cleanup
        foreach ($identifiers as $id) {
            $vaultService->delete($id, 'cleanup');
        }
    }

    #[Test]
    public function hashChainDetectsDeletedRow(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        // Seed 5 audit entries
        $identifiers = [];
        for ($i = 0; $i < 5; $i++) {
            $id = $this->generateUuidV7();
            $identifiers[] = $id;
            $vaultService->store($id, 'delete-row-test-' . $i);
        }

        // Collect entries in ascending order
        $allEntries = array_reverse($auditService->query(null, 200, 0));
        self::assertGreaterThanOrEqual(5, \count($allEntries));
        $seededEntries = \array_slice($allEntries, -5);

        // Delete the 3rd entry (index 2) directly from the DB,
        // bypassing the audit service to simulate a malicious deletion.
        $deletedEntry = $seededEntries[2];
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_nrvault_audit_log');
        $connection->delete('tx_nrvault_audit_log', ['uid' => $deletedEntry->uid]);

        $result = $auditService->verifyHashChain();

        // BUG FIX verification: verifyHashChain() now compares consecutive UIDs
        // and flags gaps. This closes the attack where an adversary deletes
        // entry N AND patches entry N+1's previous_hash to relink the chain
        // (invisible to the per-row hash check alone).
        self::assertFalse(
            $result->isValid(),
            'Hash chain must be detected as broken after deleting a row',
        );

        self::assertContains(
            $deletedEntry->uid,
            $result->missingUids,
            'The deleted UID must be reported in missingUids so operators can inspect the gap',
        );

        // The gap is reported as an error on the SUCCEEDING row (the first row
        // whose uid is > deleted_uid).
        $successorUids = array_map(
            static fn ($e) => $e->uid,
            \array_slice($seededEntries, 3),
        );
        self::assertNotEmpty(
            array_intersect(array_keys($result->errors), $successorUids),
            'The row immediately after the gap must be reported as an error',
        );

        // Cleanup remaining entries
        foreach ($identifiers as $id) {
            try {
                $vaultService->delete($id, 'cleanup');
            } catch (Throwable) {
                // Entry may already be gone
            }
        }
    }

    #[Test]
    public function hashChainDetectsGapEvenWhenSuccessorPreviousHashPatched(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        // Seed 5 audit entries
        $identifiers = [];
        for ($i = 0; $i < 5; $i++) {
            $id = $this->generateUuidV7();
            $identifiers[] = $id;
            $vaultService->store($id, 'gap-patch-test-' . $i);
        }

        $allEntries = array_reverse($auditService->query(null, 200, 0));
        self::assertGreaterThanOrEqual(5, \count($allEntries));
        $seededEntries = \array_slice($allEntries, -5);

        $victim = $seededEntries[2];        // to be deleted
        $successor = $seededEntries[3];     // will be patched

        $connection = $this->getConnectionPool()->getConnectionForTable('tx_nrvault_audit_log');

        // Read the hash that LINKS to the victim — i.e. the previous_hash
        // recorded on the victim row (equals the entry_hash of victim-1).
        $victimRow = $connection->createQueryBuilder()
            ->select('previous_hash')
            ->from('tx_nrvault_audit_log')
            ->where('uid = :uid')
            ->setParameter('uid', $victim->uid)
            ->executeQuery()
            ->fetchAssociative();
        self::assertNotFalse($victimRow);
        $preVictimHash = \is_string($victimRow['previous_hash'] ?? null)
            ? $victimRow['previous_hash']
            : '';

        // Delete the victim.
        $connection->delete('tx_nrvault_audit_log', ['uid' => $victim->uid]);

        // Patch the successor's previous_hash so the per-row chain check
        // would pass in isolation — simulating a capable attacker.
        $connection->update(
            'tx_nrvault_audit_log',
            ['previous_hash' => $preVictimHash],
            ['uid' => $successor->uid],
        );

        $result = $auditService->verifyHashChain();

        // Without UID-gap detection, this scenario is invisible to
        // verifyHashChain(). The fix makes the gap itself the tell.
        self::assertFalse(
            $result->isValid(),
            'Hash chain must detect the gap even when previous_hash is patched',
        );
        self::assertContains(
            $victim->uid,
            $result->missingUids,
            'Deleted UID must appear in missingUids',
        );

        // Cleanup
        foreach ($identifiers as $id) {
            try {
                $vaultService->delete($id, 'cleanup');
            } catch (Throwable) {
                // Entry may already be gone
            }
        }
    }

    #[Test]
    public function verifyHashChainRejectsFullEpochZeroRelabelOfHmacChain(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'relabel-test-value');
        $vaultService->retrieve($identifier);
        $vaultService->delete($identifier, 'cleanup');

        self::assertTrue($auditService->verifyHashChain()->isValid(), 'Precondition: chain valid before relabel');

        // Attacker relabels EVERY row to keyless epoch-0 and recomputes a valid
        // keyless SHA-256 chain (identity fields only) in UID order.
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_nrvault_audit_log');
        $rows = $connection->createQueryBuilder()
            ->select('uid', 'secret_identifier', 'action', 'actor_uid', 'crdate')
            ->from('tx_nrvault_audit_log')
            ->orderBy('uid', 'ASC')
            ->executeQuery()
            ->fetchAllAssociative();

        $previousHash = '';
        foreach ($rows as $row) {
            $entryHash = AuditLogService::calculateHash(
                (int) $row['uid'],
                (string) $row['secret_identifier'],
                (string) $row['action'],
                (int) $row['actor_uid'],
                (int) $row['crdate'],
                $previousHash,
            );
            $connection->update(
                'tx_nrvault_audit_log',
                ['previous_hash' => $previousHash, 'entry_hash' => $entryHash, 'hmac_key_epoch' => 0],
                ['uid' => (int) $row['uid']],
            );
            $previousHash = $entryHash;
        }

        $result = $auditService->verifyHashChain();

        self::assertFalse(
            $result->isValid(),
            'A uniform relabel to keyless epoch-0 on an HMAC-configured install must be rejected',
        );
        // The distribution names what the verdict only implies: every row is
        // now keyless. This is the report an operator acts on — "invalid" alone
        // does not say the algorithm selector was rewritten wholesale.
        self::assertSame([0 => \count($rows)], $result->epochCounts);
        self::assertSame(0, $result->getMinEpoch());
        self::assertSame(0, $result->getMaxEpoch());
        self::assertFalse($result->hasMixedEpochs());
    }

    /**
     * The chain walk already reads every row's `hmac_key_epoch` to pick the hash
     * algorithm, so counting them is free — and it is the only thing that
     * separates "the chain is valid" from "every stored row is signed at the
     * configured epoch". A chain left at epoch 1 by a stalled migration
     * verifies perfectly while leaving `success` outside the MAC.
     */
    #[Test]
    public function verifyHashChainReportsHowManyRowsCarryEachEpoch(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'epoch-distribution-value');
        $vaultService->retrieve($identifier);
        $vaultService->delete($identifier, 'cleanup');

        // The authoritative answer, read the expensive way the check itself
        // must not: an unindexed GROUP BY over the whole table. Comparing the
        // free counter against it proves the walk agrees with the database,
        // without pinning the epoch the test environment happens to run at.
        $expected = array_map(
            intval(...),
            $this->getConnectionPool()
                ->getConnectionForTable('tx_nrvault_audit_log')
                ->createQueryBuilder()
                ->select('hmac_key_epoch')
                ->addSelectLiteral('COUNT(uid) AS row_count')
                ->from('tx_nrvault_audit_log')
                ->groupBy('hmac_key_epoch')
                ->orderBy('hmac_key_epoch', 'ASC')
                ->executeQuery()
                ->fetchAllKeyValue(),
        );

        $result = $auditService->verifyHashChain();

        self::assertTrue($result->isValid(), 'Precondition: the chain must verify');
        self::assertNotSame([], $expected, 'Precondition: the chain must not be empty');
        self::assertSame($expected, $result->epochCounts);
        self::assertSame(array_sum($expected), array_sum($result->epochCounts));
        self::assertSame(min(array_keys($expected)), $result->getMinEpoch());
        self::assertSame(max(array_keys($expected)), $result->getMaxEpoch());
        self::assertSame(\count($expected) > 1, $result->hasMixedEpochs());
    }

    /**
     * A bounded range reports the epochs of the rows it actually scanned, not of
     * the whole table — `AuditCheck` verifies only the tail, so a distribution
     * that silently widened to the full chain would misreport what was covered.
     */
    #[Test]
    public function verifyHashChainCountsOnlyTheScannedRange(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'bounded-range-value');
        $vaultService->retrieve($identifier);
        $vaultService->retrieve($identifier);
        $vaultService->delete($identifier, 'cleanup');

        $tip = $this->getConnectionPool()
            ->getConnectionForTable('tx_nrvault_audit_log')
            ->createQueryBuilder()
            ->select('uid', 'hmac_key_epoch')
            ->from('tx_nrvault_audit_log')
            ->orderBy('uid', 'DESC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchAssociative();

        self::assertIsArray($tip, 'Precondition: the chain must not be empty');

        $maxUid = (int) $tip['uid'];
        $result = $auditService->verifyHashChain($maxUid, $maxUid);

        // Exactly the one row the range covers — not the whole table.
        self::assertSame([(int) $tip['hmac_key_epoch'] => 1], $result->epochCounts);
    }
}
