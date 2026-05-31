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

    public function __construct(
        private ConnectionPool $connectionPool,
        private AccessControlServiceInterface $accessControlService,
        private MasterKeyProviderInterface $masterKeyProvider,
        private ExtensionConfigurationInterface $extensionConfiguration,
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
            $this->insertAndUpdateHash($connection, $data, $previousHash);
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

    public function verifyHashChain(?int $fromUid = null, ?int $toUid = null): HashChainVerificationResult
    {
        $queryBuilder = $this->getConnection()->createQueryBuilder();
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

        $rows = $queryBuilder->executeQuery()->fetchAllAssociative();
        $errors = [];
        $warnings = [];
        /** @var list<int> $missingUids */
        $missingUids = [];
        $missingUidCount = 0;
        $previousHash = '';
        $previousEpoch = -1;
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

                // Detect epoch boundary and report warning
                if ($previousEpoch >= 0 && $epoch !== $previousEpoch) {
                    $warnings[$uid] = \sprintf(
                        'HMAC key epoch boundary: %d -> %d',
                        $previousEpoch,
                        $epoch,
                    );
                }

                $previousEpoch = $epoch;

                // Epoch-aware hash dispatch:
                //   0 → legacy SHA-256 (identity fields only)
                //   1 → HMAC-SHA256 (identity fields only)
                //   2+ → HMAC-SHA256 (extended forensic payload)
                $expectedHash = match (true) {
                    $epoch === 0 => self::calculateHash($uid, $secretId, $actionStr, $actorUid, $crdate, $previousHash),
                    $epoch === 1 => self::calculateHash($uid, $secretId, $actionStr, $actorUid, $crdate, $previousHash, $hmacKey),
                    default => self::calculateHashV2(self::extractV2HashRow($row), $previousHash, $hmacKey),
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

        return $errors === []
            ? HashChainVerificationResult::valid($warnings, $missingUids, $missingUidCount)
            : HashChainVerificationResult::invalid($errors, $warnings, $missingUids, $missingUidCount);
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
        $payload = json_encode([
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
        ], JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

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
            return hash_hkdf('sha256', $masterKey, 32, 'nr-vault-audit-hmac-v1');
        } finally {
            sodium_memzero($masterKey);
        }
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
            'user_agent' => $this->getUserAgent(),
            'request_id' => $this->getRequestId(),
            'previous_hash' => $previousHash,
            'hash_before' => $inputs->hashBefore ?? '',
            'hash_after' => $inputs->hashAfter ?? '',
            'crdate' => time(),
            'hmac_key_epoch' => $this->getCurrentEpoch(),
            'context' => $inputs->context instanceof AuditContextInterface ? json_encode($inputs->context->toArray()) : '{}',
        ];
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
     * @param array<string, mixed> $data
     */
    private function insertAndUpdateHash(
        Connection $connection,
        array $data,
        string $previousHash,
    ): void {
        $connection->insert(self::TABLE_NAME, $data);
        $uid = (int) $connection->lastInsertId();
        $data['uid'] = $uid;

        $entryHash = $this->calculateEntryHashFromRow($data, $previousHash);

        $connection->update(
            self::TABLE_NAME,
            ['entry_hash' => $entryHash],
            ['uid' => $uid],
        );
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
     *
     * @param array<string, mixed> $row Must contain `hmac_key_epoch`; epoch
     *                                  2 also requires the forensic fields
     *                                  (see `extractV2HashRow()`).
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

            // Epoch 2+: extended payload that covers forensic fields too.
            return self::calculateHashV2(self::extractV2HashRow($row), $previousHash, $hmacKey);
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

        $userAgent = $request->getHeaderLine('User-Agent');
        if (\strlen($userAgent) > 500) {
            return substr($userAgent, 0, 500);
        }

        return $userAgent;
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
