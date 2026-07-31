<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

use DateTimeInterface;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use Generator;
use InvalidArgumentException;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Exception\AuditWriteException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Psr\Http\Message\ServerRequestInterface;
use SensitiveParameter;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

/**
 * Audit log service with tamper-evident hash chain.
 */
final readonly class AuditLogService implements AuditLogServiceInterface
{
    use AuditChainLockTrait;

    private const TABLE_NAME = 'tx_nrvault_audit_log';

    /**
     * Column widths (in characters, as `varchar(N)` counts them) of the two
     * audit columns fed straight from attacker-controlled request headers.
     * See `clipToColumnWidth()` and `buildEntryData()`.
     */
    private const MAX_USER_AGENT_LENGTH = 500;

    private const MAX_REQUEST_ID_LENGTH = 100;

    /**
     * Finding keys for the tip-anchor check.
     *
     * Negative so they can never collide with a real audit uid, nor with the
     * chain-level epoch-floor error that already squats on key `0`.
     */
    private const ANCHOR_ERROR_UNREADABLE = -1;

    private const ANCHOR_ERROR_ROW_MISSING = -2;

    private const ANCHOR_ERROR_HASH_MISMATCH = -3;

    private const ANCHOR_ERROR_REQUIRED = -4;

    private const ANCHOR_WARNING_UNANCHORED = -1;

    private const ANCHOR_WARNING_SPLIT_CONNECTION = -2;

    private const ANCHOR_WARNING_IN_FLIGHT = -3;

    public function __construct(
        private ConnectionPool $connectionPool,
        private AccessControlServiceInterface $accessControlService,
        private MasterKeyProviderInterface $masterKeyProvider,
        private ExtensionConfigurationInterface $extensionConfiguration,
        private AuditChainAnchorStoreInterface $anchorStore,
    ) {}

    public function log(
        string $secretIdentifier,
        string $action,
        bool $success,
        ?string $errorMessage = null,
        ?string $reason = null,
        #[SensitiveParameter]
        ?string $hashBefore = null,
        #[SensitiveParameter]
        ?string $hashAfter = null,
        ?AuditContextInterface $context = null,
    ): void {
        // The action is kept a string for BC (callers pass AuditAction::Xxx->value),
        // but it MUST be a known action: a typo would be sealed into the
        // tamper-evident chain forever. Reject unknown actions loudly. This is a
        // programming error, not a write failure, so it is NOT an AuditWriteException
        // (which the VaultService atomicity path compensates) — it must surface.
        if (AuditAction::tryFrom($action) === null) {
            throw new InvalidArgumentException(
                \sprintf('Unknown audit action "%s"; must be one of AuditAction::cases().', $action),
                1717100000,
            );
        }

        $connection = $this->getConnection();
        $isSQLite = $connection->getDatabasePlatform() instanceof SQLitePlatform;
        $this->acquireAuditLock($connection, $isSQLite);

        try {
            $previousHash = $this->fetchPreviousHash($connection);
            $data = $this->buildEntryData(
                new AuditLogInputs(
                    $secretIdentifier,
                    $action,
                    $success,
                    $errorMessage,
                    $reason,
                    $hashBefore,
                    $hashAfter,
                    $context,
                ),
                $previousHash,
            );
            $tip = $this->insertAndUpdateHash($connection, $data, $previousHash);

            // Pin the new tip outside this table, inside the SAME lock and
            // transaction, so anchor and audit row commit or roll back
            // together. Any failure is re-thrown as AuditWriteException
            // because that is the type VaultService's compensating path keys
            // on — a broken anchor write must fail the audited operation
            // closed, not half-commit it.
            try {
                $this->anchorStore->advance($connection, $tip);
            } catch (Throwable $e) {
                throw new AuditWriteException(
                    'Audit chain tip anchor could not be recorded',
                    1753900001,
                    $e,
                );
            }

            $this->commitAuditLock($connection, $isSQLite);
        } catch (Throwable $e) {
            $this->rollbackAuditLock($connection, $isSQLite);

            throw $e;
        } finally {
            $this->releaseAuditLock($connection, $isSQLite);
        }
    }

    public function query(?AuditLogFilter $filter = null, int $limit = 100, int $offset = 0): array
    {
        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $queryBuilder
            ->select('*')
            ->from(self::TABLE_NAME)
            ->orderBy('crdate', 'DESC')
            ->setMaxResults($limit)
            ->setFirstResult($offset);

        if ($filter instanceof AuditLogFilter) {
            $this->applyFilter($queryBuilder, $filter);
        }

        $rows = $queryBuilder->executeQuery()->fetchAllAssociative();

        return array_map(
            AuditLogEntry::fromDatabaseRow(...),
            $rows,
        );
    }

    public function count(?AuditLogFilter $filter = null): int
    {
        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $queryBuilder
            ->count('uid')
            ->from(self::TABLE_NAME);

        if ($filter instanceof AuditLogFilter) {
            $this->applyFilter($queryBuilder, $filter);
        }

        $result = $queryBuilder->executeQuery()->fetchOne();

        return is_numeric($result) ? (int) $result : 0;
    }

    public function export(?AuditLogFilter $filter = null): array
    {
        $entries = [];
        foreach ($this->exportIterable($filter) as $entry) {
            $entries[] = $entry;
        }

        return $entries;
    }

    /**
     * Stream audit entries in bounded-memory chunks instead of materialising
     * the whole table at once. The audit log is the fastest-growing table in
     * the system (every read can add a row), so the previous PHP_INT_MAX
     * single fetch risked OOM on large installs. Each chunk is fetched,
     * yielded, and released before the next is read — peak memory is
     * O(chunkSize), not O(total rows).
     *
     * @return Generator<int, AuditLogEntry>
     */
    public function exportIterable(?AuditLogFilter $filter = null, int $chunkSize = 1000): Generator
    {
        $chunkSize = max(1, $chunkSize);
        $offset = 0;

        do {
            $chunk = $this->query($filter, $chunkSize, $offset);
            foreach ($chunk as $entry) {
                yield $entry;
            }
            $offset += $chunkSize;
        } while (\count($chunk) === $chunkSize);
    }

    public function verifyHashChain(?int $fromUid = null, ?int $toUid = null, ?int $minEpoch = null): HashChainVerificationResult
    {
        // Epoch floor: the lowest per-row epoch the chain may legitimately carry.
        // Defaults to the configured audit HMAC epoch so a DB-write attacker cannot
        // relabel an HMAC-migrated chain down to keyless epoch-0 (which needs no HMAC
        // key to re-sign) and have the recomputed keyless chain still report valid.
        // Callers that must verify a not-yet-migrated chain under its own stored
        // epochs (the HMAC migration) pass 0 to disable the configured floor.
        $epochFloor = $minEpoch ?? $this->getCurrentEpoch();

        $connection = $this->getConnection();
        $queryBuilder = $connection->createQueryBuilder();
        $queryBuilder
            ->select('*')
            ->from(self::TABLE_NAME)
            ->orderBy('uid', 'ASC');

        if ($fromUid !== null) {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->gte('uid', $queryBuilder->createNamedParameter($fromUid, Connection::PARAM_INT)),
            );
        }

        if ($toUid !== null) {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->lte('uid', $queryBuilder->createNamedParameter($toUid, Connection::PARAM_INT)),
            );
        }

        // Stream the rows (single forward pass, read-only): the audit log can
        // be arbitrarily large, and master-key rotation verifies the full chain
        // up front — materialising it wholesale would OOM the rotation command.
        $rows = $queryBuilder->executeQuery()->iterateAssociative();
        $errors = [];
        $warnings = [];
        /** @var list<int> $missingUids */
        $missingUids = [];
        $missingUidCount = 0;
        $previousHash = '';
        $previousEpoch = -1;
        // Highest epoch observed across the chain (the "high-water mark"). Stays
        // -1 for an empty chain so the epoch-floor check below is skipped.
        $maxEpoch = -1;
        // When the caller specified $fromUid, treat $fromUid-1 as the
        // previous UID so a leading gap (first row > $fromUid) is still
        // detected. Otherwise start at -1 meaning "no prior row yet".
        $previousUid = $fromUid !== null ? $fromUid - 1 : -1;
        /** @var int Cap on $missingUids enumeration — beyond this we count only */
        $missingUidCap = 1000;

        // Derive the HMAC key once for all HMAC-epoch entries
        $hmacKey = $this->getHmacKey();

        try {
            foreach ($rows as $row) {
                $entry = self::extractHashRow($row);
                $uid = $entry['uid'];
                $secretId = $entry['secretId'];
                $actionStr = $entry['action'];
                $actorUid = $entry['actorUid'];
                $crdate = $entry['crdate'];
                $epoch = $entry['epoch'];

                // BUG FIX: Detect UID gaps.
                //
                // A malicious actor could delete entry N AND patch entry N+1's
                // previous_hash so that the per-row chain check still succeeds.
                // Such an attack is invisible to the per-row hash check, but it
                // leaves a gap in the UID sequence that we CAN see from here.
                //
                // We flag every gap as an error (chain invalid) AND record the
                // missing UID range so operators can distinguish legitimate
                // deletions (e.g. retention-based purges, which callers may
                // tolerate) from unexpected holes.
                //
                // `$missingUids` is capped at `$missingUidCap` entries to
                // bound memory on systems with huge gaps (e.g. after a mass
                // purge). `$missingUidCount` reports the true total so the
                // verifier can still detect the gap scale.
                if ($previousUid !== -1 && $uid - $previousUid > 1) {
                    $gapStart = $previousUid + 1;
                    $gapEnd = $uid - 1;
                    $gapSize = $gapEnd - $gapStart + 1;
                    $missingUidCount += $gapSize;

                    $remaining = $missingUidCap - \count($missingUids);
                    if ($remaining > 0) {
                        $enumerateEnd = min($gapEnd, $gapStart + $remaining - 1);
                        for ($missing = $gapStart; $missing <= $enumerateEnd; $missing++) {
                            $missingUids[] = $missing;
                        }
                    }
                    $errors[$uid] = \sprintf(
                        'Audit log uid gap detected: missing uids %d..%d (chain could have been tampered by deletion + previous_hash patch)',
                        $gapStart,
                        $gapEnd,
                    );
                }

                $previousUid = $uid;

                // Detect epoch transitions.
                //
                // The per-row hmac_key_epoch selects which algorithm verifies
                // the row, including the keyless epoch-0 SHA-256. A DB-write
                // attacker who downgrades a row (e.g. tail row 2 -> 0) could
                // otherwise re-sign it without the HMAC key and have the chain
                // still report valid. A legitimate chain only ever INCREASES
                // the epoch (a partial migration leaves older rows at a lower
                // epoch ahead of newer rows): a DECREASE between consecutive
                // rows is therefore a tamper signal, recorded as an ERROR so
                // `valid` (errors === []) flips to false. Increases stay a
                // non-fatal warning, preserving backward compatibility for
                // mid-migration chains.
                if ($previousEpoch >= 0 && $epoch < $previousEpoch) {
                    $errors[$uid] = \sprintf(
                        'HMAC key epoch downgrade detected: %d -> %d (possible algorithm-downgrade forgery)',
                        $previousEpoch,
                        $epoch,
                    );
                } elseif ($previousEpoch >= 0 && $epoch !== $previousEpoch) {
                    $warnings[$uid] = \sprintf(
                        'HMAC key epoch boundary: %d -> %d',
                        $previousEpoch,
                        $epoch,
                    );
                }

                $previousEpoch = $epoch;
                if ($epoch > $maxEpoch) {
                    $maxEpoch = $epoch;
                }

                // Epoch-aware hash dispatch:
                //   0 → legacy SHA-256 (identity fields only)
                //   1 → HMAC-SHA256 (identity fields only)
                //   2 → HMAC-SHA256 (extended forensic payload)
                //   3+ → HMAC-SHA256 (forensic payload + epoch selector +
                //        human-readable attribution fields)
                $expectedHash = match (true) {
                    $epoch === 0 => self::calculateHash($uid, $secretId, $actionStr, $actorUid, $crdate, $previousHash),
                    $epoch === 1 => self::calculateHash($uid, $secretId, $actionStr, $actorUid, $crdate, $previousHash, $hmacKey),
                    $epoch === 2 => self::calculateHashV2(self::extractV2HashRow($row), $previousHash, $hmacKey),
                    default => self::calculateHashV3(self::extractV3HashRow($row), $previousHash, $hmacKey),
                };

                // Verify previous_hash matches. Use hash_equals() for the
                // constant-time comparison the project mandates for integrity
                // tags (AGENTS.md Security Requirement #2).
                $rowPrevHash = \is_string($row['previous_hash'] ?? null) ? $row['previous_hash'] : '';
                if (!hash_equals($previousHash, $rowPrevHash)) {
                    $errors[$uid] = 'Previous hash mismatch - chain broken';
                }

                // Verify entry_hash is correct (constant-time).
                $rowEntryHash = \is_string($row['entry_hash'] ?? null) ? $row['entry_hash'] : '';
                if (!hash_equals($expectedHash, $rowEntryHash)) {
                    $errors[$uid] = 'Entry hash mismatch - possible tampering';
                }

                $previousHash = $rowEntryHash;
            }
        } finally {
            sodium_memzero($hmacKey);
        }

        // Chain-level epoch-floor check (finding audit-chain-integrity, F3).
        //
        // The per-row consecutive-epoch check above catches a PARTIAL downgrade
        // (a DECREASE between adjacent rows), but a DB-write attacker can relabel
        // EVERY row uniformly to keyless epoch-0 and recompute a fully self-
        // consistent SHA-256 chain — no decrease, every previous_hash links, every
        // entry_hash matches. The only tell is external: the installation is
        // configured for HMAC, so the chain's highest epoch must reach the floor.
        // A high-water mark below the floor means the algorithm selector was
        // downgraded below the configured protection level. Applied only to a
        // full-chain pass ($fromUid/$toUid null) — a bounded sub-range may
        // legitimately exclude the higher-epoch rows. $maxEpoch === -1 means an
        // empty chain, which has nothing to downgrade.
        if ($fromUid === null && $toUid === null && $maxEpoch !== -1 && $maxEpoch < $epochFloor) {
            $errors[0] = \sprintf(
                'HMAC key epoch downgrade detected: chain high-water epoch %d is below the configured floor %d (possible algorithm-downgrade forgery)',
                $maxEpoch,
                $epochFloor,
            );
        }

        // Tip anchor (finding F2).
        //
        // The walk above only ever inspects rows that are still there, so
        // `DELETE FROM tx_nrvault_audit_log WHERE uid > N` — or a full wipe —
        // leaves a self-consistent chain that every check so far reports as
        // valid. The anchor is an assertion about the tip held OUTSIDE this
        // table and signed with a key that is not in the database, so removing
        // rows can no longer go unnoticed.
        //
        // Restricted to a full-chain pass for the same reason as the epoch
        // floor above: a bounded sub-range may legitimately exclude the tip.
        $anchorStatus = AuditChainAnchorStatus::NotChecked;
        if ($fromUid === null && $toUid === null) {
            $anchorStatus = $this->verifyAnchor($connection, $errors, $warnings);
        }

        return $errors === []
            ? HashChainVerificationResult::valid($warnings, $missingUids, $missingUidCount, $anchorStatus)
            : HashChainVerificationResult::invalid($errors, $warnings, $missingUids, $missingUidCount, $anchorStatus);
    }

    public function verifyChainForReseal(): ?HashChainVerificationResult
    {
        // Genuinely-legacy keyless epoch-0 chains carry no tamper evidence to
        // check — re-sealing them is exactly how they FIRST gain HMAC protection,
        // so there is nothing in the ROWS to launder and nothing to verify there.
        //
        // The ANCHOR still has to be checked. Its validity does not depend on any
        // row's epoch, and `UPDATE tx_nrvault_audit_log SET hmac_key_epoch = 0` is
        // one statement without the master key — so "no HMAC rows" is
        // attacker-selectable. Skipping the whole gate on it lets a truncation be
        // laundered through the very migration this gate protects.
        if (!$this->chainHasHmacRows()) {
            return $this->verifyAnchorForReseal();
        }

        // The chain is (at least partly) HMAC-protected. Verify it under its OWN
        // stored epochs (floor 0 — the chain may legitimately sit below the
        // migration target, e.g. an epoch-1 chain migrating to epoch 2). A
        // DB-write attacker cannot forge a valid HMAC without the key, so any
        // tampering of an HMAC row surfaces here. Re-sealing a tampered chain
        // would rewrite every hash under the current key and launder the
        // tampering into a freshly valid chain — so report it for refusal.
        $result = $this->verifyHashChain(minEpoch: 0);

        return $result->isValid() ? null : $result;
    }

    public function getLatestHash(): ?string
    {
        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $hash = $queryBuilder
            ->select('entry_hash')
            ->from(self::TABLE_NAME)
            ->orderBy('uid', 'DESC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchOne();

        return $hash !== false && \is_string($hash) ? $hash : null;
    }

    /**
     * Calculate an audit log entry hash (legacy / v1 payload).
     *
     * Covers identity-bearing fields only: uid, secret_identifier, action,
     * actor_uid, crdate, previous_hash.
     *
     * When $hmacKey is null, produces a legacy SHA-256 hash (epoch 0).
     * When $hmacKey is provided, produces an HMAC-SHA256 hash (epoch 1).
     *
     * Epoch 2+ entries use `calculateHashV2()` which adds forensic fields
     * (success, error_message, reason, ip_address, user_agent, hash_before,
     * hash_after, context) to the HMAC payload.
     *
     * This method is public so it can be reused by the migration command
     * without duplicating the HKDF derivation logic.
     */
    public static function calculateHash(
        int $uid,
        string $secretIdentifier,
        string $action,
        int $actorUid,
        int $crdate,
        string $previousHash,
        ?string $hmacKey = null,
    ): string {
        $payload = json_encode([
            'uid' => $uid,
            'secret_identifier' => $secretIdentifier,
            'action' => $action,
            'actor_uid' => $actorUid,
            'crdate' => $crdate,
            'previous_hash' => $previousHash,
        ], JSON_THROW_ON_ERROR);

        if ($hmacKey === null) {
            return hash('sha256', $payload);
        }

        return hash_hmac('sha256', $payload, $hmacKey);
    }

    /**
     * Calculate an audit log entry hash with the extended (v2) payload.
     *
     * Includes all forensic fields the verifier cares about: an attacker
     * with database-write privileges can no longer flip `success: false →
     * true` or rewrite `error_message`/`reason`/`ip_address`/`user_agent`
     * without breaking the chain.
     *
     * Payload keys (ordered for deterministic JSON):
     *   uid, secret_identifier, action, success, actor_uid, crdate,
     *   previous_hash, error_message, reason, ip_address, user_agent,
     *   hash_before, hash_after, context
     *
     * @param array{
     *     uid: int,
     *     secret_identifier: string,
     *     action: string,
     *     success: bool|int,
     *     actor_uid: int,
     *     crdate: int,
     *     error_message: string,
     *     reason: string,
     *     ip_address: string,
     *     user_agent: string,
     *     hash_before: string,
     *     hash_after: string,
     *     context: string,
     * } $row
     */
    public static function calculateHashV2(
        array $row,
        string $previousHash,
        #[SensitiveParameter]
        string $hmacKey,
    ): string {
        $payload = json_encode(
            self::forensicPayloadV2($row, $previousHash),
            JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        );

        return hash_hmac('sha256', $payload, $hmacKey);
    }

    /**
     * Calculate an audit log entry hash with the v3 payload.
     *
     * Extends the v2 forensic payload with two integrity-critical additions:
     *
     *  1. `hmac_key_epoch` — the algorithm selector itself. At epoch 0-2 the
     *     epoch was read from the row but never bound into any hash, so a
     *     DB-write attacker could downgrade the (keyless-verifiable) algorithm
     *     by flipping the column and re-signing without the HMAC key. Binding
     *     the epoch makes any such re-sign mismatch the stored entry_hash.
     *  2. The human-readable attribution fields `actor_type`,
     *     `actor_username`, `actor_role` and the `request_id` — surfaced in the
     *     backend audit list and CSV export but excluded from the v2 payload,
     *     so blame could previously be reassigned on any row without breaking
     *     the chain.
     *
     * Payload keys (ordered for deterministic JSON): the v2 keys, then
     * hmac_key_epoch, actor_type, actor_username, actor_role, request_id.
     *
     * @param array{
     *     uid: int,
     *     secret_identifier: string,
     *     action: string,
     *     success: bool|int,
     *     actor_uid: int,
     *     crdate: int,
     *     error_message: string,
     *     reason: string,
     *     ip_address: string,
     *     user_agent: string,
     *     hash_before: string,
     *     hash_after: string,
     *     context: string,
     *     hmac_key_epoch: int,
     *     actor_type: string,
     *     actor_username: string,
     *     actor_role: string,
     *     request_id: string,
     * } $row
     */
    public static function calculateHashV3(
        array $row,
        string $previousHash,
        #[SensitiveParameter]
        string $hmacKey,
    ): string {
        $payload = json_encode(
            self::forensicPayloadV2($row, $previousHash) + [
                // v3 additions — authenticate the algorithm selector and the
                // human-facing attribution surface.
                'hmac_key_epoch' => (int) $row['hmac_key_epoch'],
                'actor_type' => (string) $row['actor_type'],
                'actor_username' => (string) $row['actor_username'],
                'actor_role' => (string) $row['actor_role'],
                'request_id' => (string) $row['request_id'],
            ],
            JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        );

        return hash_hmac('sha256', $payload, $hmacKey);
    }

    /**
     * Type-safe extraction of the audit-row fields that feed into the v1
     * hash calculation (`calculateHash()`). Defends against `mixed` shapes
     * returned by Doctrine `fetchAssociative()` on different drivers.
     *
     * @param array<string, mixed> $row
     *
     * @return array{uid: int, secretId: string, action: string, actorUid: int, crdate: int, epoch: int}
     */
    public static function extractHashRow(array $row): array
    {
        return [
            'uid' => is_numeric($row['uid'] ?? null) ? (int) $row['uid'] : 0,
            'secretId' => \is_string($row['secret_identifier'] ?? null) ? $row['secret_identifier'] : '',
            'action' => \is_string($row['action'] ?? null) ? $row['action'] : '',
            'actorUid' => is_numeric($row['actor_uid'] ?? null) ? (int) $row['actor_uid'] : 0,
            'crdate' => is_numeric($row['crdate'] ?? null) ? (int) $row['crdate'] : 0,
            'epoch' => is_numeric($row['hmac_key_epoch'] ?? null) ? (int) $row['hmac_key_epoch'] : 0,
        ];
    }

    /**
     * Type-safe extraction of the audit-row fields for the v2 hash payload
     * (`calculateHashV2()`). Adds the forensic fields that v1 does not bind
     * into the chain: success, error_message, reason, ip_address, user_agent,
     * hash_before, hash_after, context.
     *
     * @param array<string, mixed> $row
     *
     * @return array{
     *     uid: int,
     *     secret_identifier: string,
     *     action: string,
     *     success: int,
     *     actor_uid: int,
     *     crdate: int,
     *     error_message: string,
     *     reason: string,
     *     ip_address: string,
     *     user_agent: string,
     *     hash_before: string,
     *     hash_after: string,
     *     context: string,
     * }
     */
    public static function extractV2HashRow(array $row): array
    {
        $rawSuccess = $row['success'] ?? null;

        return [
            'uid' => is_numeric($row['uid'] ?? null) ? (int) $row['uid'] : 0,
            'secret_identifier' => \is_string($row['secret_identifier'] ?? null) ? $row['secret_identifier'] : '',
            'action' => \is_string($row['action'] ?? null) ? $row['action'] : '',
            // Doctrine returns `success` as int on MySQL/SQLite, bool on
            // PostgreSQL, and string on some drivers with emulated prepares.
            // `is_numeric()` rejects native booleans — keep them in the chain
            // by accepting bool|int|numeric-string and coercing through bool.
            'success' => (\is_bool($rawSuccess) || is_numeric($rawSuccess)) ? (int) (bool) $rawSuccess : 0,
            'actor_uid' => is_numeric($row['actor_uid'] ?? null) ? (int) $row['actor_uid'] : 0,
            'crdate' => is_numeric($row['crdate'] ?? null) ? (int) $row['crdate'] : 0,
            'error_message' => \is_string($row['error_message'] ?? null) ? $row['error_message'] : '',
            'reason' => \is_string($row['reason'] ?? null) ? $row['reason'] : '',
            'ip_address' => \is_string($row['ip_address'] ?? null) ? $row['ip_address'] : '',
            'user_agent' => \is_string($row['user_agent'] ?? null) ? $row['user_agent'] : '',
            'hash_before' => \is_string($row['hash_before'] ?? null) ? $row['hash_before'] : '',
            'hash_after' => \is_string($row['hash_after'] ?? null) ? $row['hash_after'] : '',
            'context' => \is_string($row['context'] ?? null) ? $row['context'] : '',
        ];
    }

    /**
     * Type-safe extraction of the audit-row fields for the v3 hash payload
     * (`calculateHashV3()`). Adds, on top of the v2 fields, the algorithm
     * selector `hmac_key_epoch` and the four human-readable attribution
     * fields (actor_type, actor_username, actor_role, request_id) that v2
     * does not bind into the chain.
     *
     * @param array<string, mixed> $row
     *
     * @return array{
     *     uid: int,
     *     secret_identifier: string,
     *     action: string,
     *     success: int,
     *     actor_uid: int,
     *     crdate: int,
     *     error_message: string,
     *     reason: string,
     *     ip_address: string,
     *     user_agent: string,
     *     hash_before: string,
     *     hash_after: string,
     *     context: string,
     *     hmac_key_epoch: int,
     *     actor_type: string,
     *     actor_username: string,
     *     actor_role: string,
     *     request_id: string,
     * }
     */
    public static function extractV3HashRow(array $row): array
    {
        return self::extractV2HashRow($row) + [
            'hmac_key_epoch' => is_numeric($row['hmac_key_epoch'] ?? null) ? (int) $row['hmac_key_epoch'] : 0,
            'actor_type' => \is_string($row['actor_type'] ?? null) ? $row['actor_type'] : '',
            'actor_username' => \is_string($row['actor_username'] ?? null) ? $row['actor_username'] : '',
            'actor_role' => \is_string($row['actor_role'] ?? null) ? $row['actor_role'] : '',
            'request_id' => \is_string($row['request_id'] ?? null) ? $row['request_id'] : '',
        ];
    }

    /**
     * Derive the HMAC key from the master key via HKDF.
     *
     * Uses a distinct info string to ensure the HMAC key is separate from the encryption key.
     *
     * NOTE: The current implementation always derives the same key from a given master key,
     * regardless of the epoch value. The epoch is a version marker, not a key diversifier.
     * After master key rotation, a new epoch should be started so the verifier knows which
     * key to use for verification.
     */
    public static function deriveHmacKey(MasterKeyProviderInterface $masterKeyProvider): string
    {
        $masterKey = $masterKeyProvider->getMasterKey();

        try {
            return self::deriveHmacKeyFromMasterKey($masterKey);
        } finally {
            sodium_memzero($masterKey);
        }
    }

    /**
     * Derive the audit-chain HMAC key from an explicit master key.
     *
     * Single home of the HKDF parameters (info string + length) so callers
     * that hold a master key directly — e.g. the master-key rotation, which
     * must derive the NEW chain key before the provider is reconfigured —
     * cannot drift from the runtime derivation above.
     */
    public static function deriveHmacKeyFromMasterKey(#[SensitiveParameter] string $masterKey): string
    {
        return hash_hkdf('sha256', $masterKey, 32, 'nr-vault-audit-hmac-v1');
    }

    /**
     * The anchor half of the re-seal gate, for chains whose rows carry no HMAC
     * evidence of their own. Returns null when the anchor raises no error —
     * `Unanchored` (or `Disabled`) is a warning, so a pre-anchor install still
     * migrates.
     */
    private function verifyAnchorForReseal(): ?HashChainVerificationResult
    {
        $errors = [];
        $warnings = [];
        $status = $this->verifyAnchor($this->getConnection(), $errors, $warnings);

        return $errors === []
            ? null
            : HashChainVerificationResult::invalid($errors, $warnings, [], 0, $status);
    }

    /**
     * Whether any row is already HMAC-protected (epoch >= 1). Distinguishes a
     * genuinely-legacy keyless chain (nothing to authenticate) from one that
     * carries HMAC tamper evidence worth verifying before a re-seal.
     */
    private function chainHasHmacRows(): bool
    {
        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $count = $queryBuilder
            ->count('uid')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->gte(
                    'hmac_key_epoch',
                    $queryBuilder->createNamedParameter(1, Connection::PARAM_INT),
                ),
            )
            ->executeQuery()
            ->fetchOne();

        return is_numeric($count) && (int) $count > 0;
    }

    /**
     * Build the ordered v2 forensic payload shared by calculateHashV2() and
     * calculateHashV3(), so the v3 payload does not duplicate the v2 key set.
     * The key order is load-bearing for hash stability — do not reorder.
     *
     * @param array{
     *     uid: int,
     *     secret_identifier: string,
     *     action: string,
     *     success: bool|int,
     *     actor_uid: int,
     *     crdate: int,
     *     error_message: string,
     *     reason: string,
     *     ip_address: string,
     *     user_agent: string,
     *     hash_before: string,
     *     hash_after: string,
     *     context: string,
     *     ...
     * } $row
     *
     * @return array<string, int|string>
     */
    private static function forensicPayloadV2(array $row, string $previousHash): array
    {
        return [
            'uid' => (int) $row['uid'],
            'secret_identifier' => (string) $row['secret_identifier'],
            'action' => (string) $row['action'],
            'success' => (int) (bool) $row['success'],
            'actor_uid' => (int) $row['actor_uid'],
            'crdate' => (int) $row['crdate'],
            'previous_hash' => $previousHash,
            'error_message' => (string) $row['error_message'],
            'reason' => (string) $row['reason'],
            'ip_address' => (string) $row['ip_address'],
            'user_agent' => (string) $row['user_agent'],
            'hash_before' => (string) $row['hash_before'],
            'hash_after' => (string) $row['hash_after'],
            'context' => (string) $row['context'],
        ];
    }

    /**
     * Check the chain tip against the anchor. Read-only on every path.
     *
     * Why no interleaving can raise a false alarm:
     *
     *  - *Appends.* The question asked is "does row A still exist and still
     *    carry hash H" — about ONE already-committed row, never a comparison
     *    against something the walk observed. An append only adds a row with a
     *    higher uid; `insertAndUpdateHash()` touches only its own uid. No
     *    interleaving, before/during/after the walk, can change the answer.
     *  - *Re-seals.* The only writers that rewrite an existing row's hash
     *    (master-key rotation, the HMAC wizard, the migrate command) rewrite
     *    the row AND re-record the anchor in one transaction. So the reads are
     *    ordered anchor V1 -> row -> anchor V2: if V1 and V2 differ byte-wise a
     *    re-seal landed mid-read and we retry once, then report `InFlight` as a
     *    warning; if they are identical, no re-seal committed in that window, so
     *    a hash mismatch is genuine.
     *
     * This needs no transaction, no lock and no isolation level, so it behaves
     * identically on SQLite, MariaDB/MySQL and PostgreSQL — unlike a
     * "consistent snapshot" read transaction, which PostgreSQL's default READ
     * COMMITTED does not provide.
     *
     * @param array<int, string> $errors
     * @param array<int, string> $warnings
     */
    private function verifyAnchor(Connection $connection, array &$errors, array &$warnings): AuditChainAnchorStatus
    {
        for ($attempt = 1; $attempt <= 2; $attempt++) {
            $load = $this->anchorStore->load($connection);

            if ($load->status === AuditChainAnchorStatus::Disabled) {
                return AuditChainAnchorStatus::Disabled;
            }

            if ($load->status === AuditChainAnchorStatus::Unanchored) {
                return $this->reportUnanchored($connection, $errors, $warnings);
            }

            if (!$load->anchor instanceof AuditChainAnchor) {
                $errors[self::ANCHOR_ERROR_UNREADABLE] = 'Audit chain tip anchor is unreadable '
                    . '(malformed value or invalid MAC) - the anchor was tampered with, or the '
                    . 'master key changed without re-sealing the chain';

                return AuditChainAnchorStatus::Unreadable;
            }

            $anchor = $load->anchor;
            $storedHash = $this->fetchEntryHashForUid($connection, $anchor->uid);

            if ($storedHash === null) {
                // No legitimate path deletes audit rows, so this needs no
                // stability check: the anchored row is simply gone.
                $errors[self::ANCHOR_ERROR_ROW_MISSING] = \sprintf(
                    'Audit chain tip anchor points at uid %d, which no longer exists - the log was '
                    . 'truncated or wiped',
                    $anchor->uid,
                );

                return AuditChainAnchorStatus::Violated;
            }

            if (hash_equals($anchor->entryHash, $storedHash)) {
                return AuditChainAnchorStatus::Ok;
            }

            // Mismatch: decide whether a re-seal committed under us.
            if ($this->anchorStore->load($connection)->raw === $load->raw) {
                $errors[self::ANCHOR_ERROR_HASH_MISMATCH] = \sprintf(
                    'Audit chain tip anchor for uid %d does not match the stored entry hash - the '
                    . 'anchored row was replaced (e.g. truncation followed by re-inserted entries)',
                    $anchor->uid,
                );

                return AuditChainAnchorStatus::Violated;
            }
        }

        $warnings[self::ANCHOR_WARNING_IN_FLIGHT] = 'Audit chain tip anchor changed while it was '
            . 'being verified (concurrent re-seal); re-run the verification';

        return AuditChainAnchorStatus::InFlight;
    }

    /**
     * No anchor is readable. Distinguish "sys_registry lives on a different
     * database connection" (a deployment fact we cannot anchor across, always a
     * warning) from "no anchor row" (a pre-anchor install, a wiped registry, or
     * an attacker who deleted the anchor before truncating).
     *
     * "Never existed" and "was deleted" are indistinguishable from database
     * state alone, so the default is a warning — otherwise every install that
     * has not yet appended an audit entry would false-alarm. Operators who have
     * confirmed the anchor is armed can promote it with `auditAnchorRequired`,
     * which lives in a settings FILE and is therefore out of a DB-write
     * attacker's reach.
     *
     * @param array<int, string> $errors
     * @param array<int, string> $warnings
     */
    private function reportUnanchored(Connection $connection, array &$errors, array &$warnings): AuditChainAnchorStatus
    {
        if (!$this->anchorStore->sharesConnection($connection)) {
            $warnings[self::ANCHOR_WARNING_SPLIT_CONNECTION] = 'Audit chain tip anchor is not '
                . 'available: sys_registry and tx_nrvault_audit_log are mapped to different database '
                . 'connections, so the anchor cannot commit atomically with an audit write';

            return AuditChainAnchorStatus::Unanchored;
        }

        $message = 'No audit chain tip anchor recorded - tail truncation and full wipes of the '
            . 'audit log are NOT detectable until the next audit write arms the anchor';

        if ($this->extensionConfiguration->isAuditAnchorRequired()) {
            $errors[self::ANCHOR_ERROR_REQUIRED] = $message . ' (auditAnchorRequired is enabled)';
        } else {
            $warnings[self::ANCHOR_WARNING_UNANCHORED] = $message;
        }

        return AuditChainAnchorStatus::Unanchored;
    }

    /**
     * Read one row's `entry_hash` by uid, or null when the row is gone.
     */
    private function fetchEntryHashForUid(Connection $connection, int $uid): ?string
    {
        $queryBuilder = $connection->createQueryBuilder();
        $hash = $queryBuilder
            ->select('entry_hash')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->eq(
                    'uid',
                    $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT),
                ),
            )
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchOne();

        return \is_string($hash) ? $hash : null;
    }

    /**
     * Read the entry_hash of the most recently inserted row.
     *
     * The advisory lock (acquired by `acquireAuditLock`) ensures no concurrent
     * writer can insert between this SELECT and the caller's INSERT.
     */
    private function fetchPreviousHash(Connection $connection): string
    {
        $result = $connection->createQueryBuilder()
            ->select('entry_hash')
            ->from(self::TABLE_NAME)
            ->orderBy('uid', 'DESC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchOne();

        return \is_string($result) ? $result : '';
    }

    /**
     * Assemble the audit-row data array.
     *
     * Reads from the environment (`time()`, `$_SERVER`, `getCurrentEpoch()`,
     * `getClientIp()`, `getUserAgent()`, `getRequestId()`) but does not
     * mutate any state — does not write the DB, does not touch the audit
     * chain, does not allocate locks. Safe to call ahead of `insertAndUpdateHash`.
     *
     * @return array<string, mixed>
     */
    private function buildEntryData(
        AuditLogInputs $inputs,
        string $previousHash,
    ): array {
        return [
            'pid' => 0,
            'secret_identifier' => $inputs->secretIdentifier,
            'action' => $inputs->action,
            'success' => $inputs->success ? 1 : 0,
            'error_message' => $this->sanitizeErrorMessage($inputs->errorMessage),
            'reason' => $inputs->reason ?? '',
            'actor_uid' => $this->accessControlService->getCurrentActorUid(),
            'actor_type' => $this->accessControlService->getCurrentActorType(),
            'actor_username' => $this->accessControlService->getCurrentActorUsername(),
            'actor_role' => $this->getCurrentUserRole(),
            'ip_address' => $this->getClientIp(),
            // Both come straight from a request header the client controls, and
            // both land in a fixed-width column. Clip HERE, on the single array
            // that feeds both the INSERT and the entry hash, so the bytes that
            // are stored are exactly the bytes that are hashed (F8 / CWE-20).
            'user_agent' => $this->clipToColumnWidth($this->getUserAgent(), self::MAX_USER_AGENT_LENGTH),
            'request_id' => $this->clipToColumnWidth($this->getRequestId(), self::MAX_REQUEST_ID_LENGTH),
            'previous_hash' => $previousHash,
            'hash_before' => $inputs->hashBefore ?? '',
            'hash_after' => $inputs->hashAfter ?? '',
            'crdate' => time(),
            'hmac_key_epoch' => $this->getCurrentEpoch(),
            'context' => $inputs->context instanceof AuditContextInterface ? json_encode($inputs->context->toArray()) : '{}',
        ];
    }

    /**
     * Fit a request-header-derived value into its fixed-width audit column.
     *
     * `user_agent` (`varchar(500)`) and `request_id` (`varchar(100)`) are the
     * only audit columns written verbatim from a header an unauthenticated
     * client controls, so they are the only ones that can be overflowed at
     * will. Left unbounded, an oversized header either aborts the INSERT under
     * strict `sql_mode` (taking the audited operation down with it) or is
     * silently truncated by the database — and a database-side truncation
     * desynchronises the row from the `entry_hash`, which is computed over the
     * untruncated in-memory value, raising a permanent false tamper alarm.
     * Clipping here, upstream of both writes, keeps stored and hashed bytes
     * identical.
     *
     * Two normalisations, in order:
     *   1. Scrub invalid UTF-8. Header bytes are arbitrary; a `utf8mb4` column
     *      rejects an ill-formed sequence outright, so this must happen before
     *      the value is hashed, not just before it is stored.
     *   2. Cut to `$maxLength` *characters* on a character boundary. That is
     *      what `varchar(N)` counts, and cutting on a boundary avoids leaving
     *      a mangled half-character (which would itself be invalid UTF-8).
     */
    private function clipToColumnWidth(string $value, int $maxLength): string
    {
        if ($value === '') {
            return '';
        }

        if (!mb_check_encoding($value, 'UTF-8')) {
            $scrubbed = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
            $value = \is_string($scrubbed) ? $scrubbed : '';
        }

        if (mb_strlen($value, 'UTF-8') <= $maxLength) {
            return $value;
        }

        return mb_substr($value, 0, $maxLength, 'UTF-8');
    }

    /**
     * Normalise a caller-supplied error message before it is sealed into the
     * tamper-evident, long-retained audit row (SEC-AUDIT-5).
     *
     * Raw `$e->getMessage()` from libsodium/Doctrine can carry filesystem
     * paths, key-length detail, or fragments of internal state, and the audit
     * log is frequently exported and read by lower-privilege operators. We
     * keep the audit row's `error_message` to a bounded, single-line,
     * control-character-free string; verbose diagnostics belong in the
     * privileged system log, not here. The discipline lives at this boundary
     * so no individual caller can reintroduce the leak.
     */
    private function sanitizeErrorMessage(?string $errorMessage): string
    {
        if ($errorMessage === null || $errorMessage === '') {
            return '';
        }

        // Collapse any control characters / newlines to single spaces so a
        // multi-line stack fragment cannot bloat or break the forensic row.
        $clean = (string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', $errorMessage);

        // Strip URL query strings before the message is sealed into the
        // tamper-evident row (F4 / CWE-532). A transport error from an
        // outbound HTTP call surfaces the effective request URI in the
        // driver's exception message; for SecretPlacement::QueryParam that
        // URI carries the injected secret as `?<param>=<secret>`. The secret's
        // parameter name is caller-configurable, so we drop the ENTIRE query
        // component of every embedded http(s) URL and keep only scheme/host/
        // path. Bounded, delimiter-anchored classes (no `.*?`, no nested
        // quantifiers) — linear time, no catastrophic backtracking.
        $clean = (string) preg_replace(
            '~(https?://[^\s?#"\'<>]+)\?[^\s"\'<>]*~i',
            '${1}?[REDACTED]',
            $clean,
        );

        $clean = trim($clean);

        // Bound the length: forensic value is in the category of failure, not
        // a verbose dump. 200 chars is plenty for a human-readable summary.
        if (mb_strlen($clean) > 200) {
            return mb_substr($clean, 0, 197) . '...';
        }

        return $clean;
    }

    /**
     * Two-step write: INSERT reserves a UID, then UPDATE writes the entry hash
     * derived from that UID. The reserve-then-hash pattern lets the hash bind
     * its own row (otherwise the hash would need a placeholder UID).
     *
     * Returns the row it just wrote as the chain's new tip, so the caller can
     * anchor it without a second read.
     *
     * @param array<string, mixed> $data
     */
    private function insertAndUpdateHash(
        Connection $connection,
        array $data,
        string $previousHash,
    ): AuditChainAnchor {
        $connection->insert(self::TABLE_NAME, $data);
        $uid = (int) $connection->lastInsertId();
        $data['uid'] = $uid;

        $entryHash = $this->calculateEntryHashFromRow($data, $previousHash);

        $connection->update(
            self::TABLE_NAME,
            ['entry_hash' => $entryHash],
            ['uid' => $uid],
        );

        $crdate = is_numeric($data['crdate'] ?? null) ? (int) $data['crdate'] : time();

        return new AuditChainAnchor($uid, $entryHash, $crdate);
    }

    /**
     * Calculate the entry hash for a freshly-inserted (or to-be-rehashed)
     * row, dispatching by `hmac_key_epoch`:
     *
     *   - epoch 0 → legacy SHA-256 over identity fields only (no HMAC key)
     *   - epoch 1 → HMAC-SHA256 over identity fields
     *   - epoch 2 → HMAC-SHA256 over identity + forensic fields (success,
     *               error_message, reason, ip_address, user_agent,
     *               hash_before, hash_after, context)
     *   - epoch 3 → HMAC-SHA256 over the epoch-2 payload plus the algorithm
     *               selector (hmac_key_epoch) and the attribution fields
     *               (actor_type, actor_username, actor_role, request_id)
     *
     * @param array<string, mixed> $row Must contain `hmac_key_epoch`; epoch
     *                                  2 also requires the forensic fields
     *                                  (see `extractV2HashRow()`), epoch 3 the
     *                                  attribution fields (see `extractV3HashRow()`).
     */
    private function calculateEntryHashFromRow(array $row, string $previousHash): string
    {
        $epoch = \is_int($row['hmac_key_epoch'] ?? null) ? $row['hmac_key_epoch'] : 0;
        $v1 = self::extractHashRow($row);

        if ($epoch === 0) {
            return self::calculateHash(
                $v1['uid'],
                $v1['secretId'],
                $v1['action'],
                $v1['actorUid'],
                $v1['crdate'],
                $previousHash,
            );
        }

        $hmacKey = $this->getHmacKey();

        try {
            if ($epoch === 1) {
                return self::calculateHash(
                    $v1['uid'],
                    $v1['secretId'],
                    $v1['action'],
                    $v1['actorUid'],
                    $v1['crdate'],
                    $previousHash,
                    $hmacKey,
                );
            }

            if ($epoch === 2) {
                // Extended payload that covers forensic fields too.
                return self::calculateHashV2(self::extractV2HashRow($row), $previousHash, $hmacKey);
            }

            // Epoch 3+: also binds the epoch selector and attribution fields.
            return self::calculateHashV3(self::extractV3HashRow($row), $previousHash, $hmacKey);
        } finally {
            sodium_memzero($hmacKey);
        }
    }

    private function getHmacKey(): string
    {
        return self::deriveHmacKey($this->masterKeyProvider);
    }

    /**
     * Get the current HMAC key epoch from extension configuration.
     */
    private function getCurrentEpoch(): int
    {
        return $this->extensionConfiguration->getAuditHmacEpoch();
    }

    /**
     * Apply filter to query builder.
     */
    private function applyFilter(QueryBuilder $queryBuilder, AuditLogFilter $filter): void
    {
        if ($filter->secretIdentifier !== null) {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->eq(
                    'secret_identifier',
                    $queryBuilder->createNamedParameter($filter->secretIdentifier),
                ),
            );
        }

        if ($filter->action !== null) {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->eq(
                    'action',
                    $queryBuilder->createNamedParameter($filter->action),
                ),
            );
        }

        if ($filter->actorUid !== null) {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->eq(
                    'actor_uid',
                    $queryBuilder->createNamedParameter($filter->actorUid, Connection::PARAM_INT),
                ),
            );
        }

        if ($filter->success !== null) {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->eq(
                    'success',
                    $queryBuilder->createNamedParameter($filter->success ? 1 : 0, Connection::PARAM_INT),
                ),
            );
        }

        if ($filter->since instanceof DateTimeInterface) {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->gte(
                    'crdate',
                    $queryBuilder->createNamedParameter($filter->since->getTimestamp(), Connection::PARAM_INT),
                ),
            );
        }

        if ($filter->until instanceof DateTimeInterface) {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->lte(
                    'crdate',
                    $queryBuilder->createNamedParameter($filter->until->getTimestamp(), Connection::PARAM_INT),
                ),
            );
        }
    }

    private function getCurrentUserRole(): string
    {
        $groups = $this->accessControlService->getCurrentUserGroups();
        if ($groups === []) {
            return $this->accessControlService->getCurrentActorType();
        }

        return 'groups:' . implode(',', $groups);
    }

    private function getClientIp(): string
    {
        $request = $this->getServerRequest();
        if (!$request instanceof ServerRequestInterface) {
            return PHP_SAPI === 'cli' ? 'CLI' : '';
        }

        $serverParams = $request->getServerParams();
        $remoteAddr = $serverParams['REMOTE_ADDR'] ?? '';

        return \is_string($remoteAddr) ? $remoteAddr : '';
    }

    private function getUserAgent(): string
    {
        $request = $this->getServerRequest();
        if (!$request instanceof ServerRequestInterface) {
            return PHP_SAPI === 'cli' ? 'CLI' : '';
        }

        // Bounding happens in buildEntryData() via clipToColumnWidth(), on the
        // same array that is hashed — a byte-wise substr() here could cut a
        // multi-byte character in half.
        return $request->getHeaderLine('User-Agent');
    }

    private function getRequestId(): string
    {
        $request = $this->getServerRequest();
        if (!$request instanceof ServerRequestInterface) {
            return '';
        }

        // Try to get request ID from header
        $requestId = $request->getHeaderLine('X-Request-Id');
        if ($requestId !== '') {
            return $requestId;
        }

        // Generate one
        return bin2hex(random_bytes(16));
    }

    private function getServerRequest(): ?ServerRequestInterface
    {
        $request = $GLOBALS['TYPO3_REQUEST'] ?? null;
        if ($request instanceof ServerRequestInterface) {
            return $request;
        }

        return null;
    }

    private function getConnection(): Connection
    {
        return $this->connectionPool->getConnectionForTable(self::TABLE_NAME);
    }
}
