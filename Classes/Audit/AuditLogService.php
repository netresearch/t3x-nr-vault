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
        $connection = $this->getConnection();

        // Acquire an advisory lock to serialize hash chain writes across concurrent processes.
        // MySQL/MariaDB: named lock via GET_LOCK; SQLite: BEGIN EXCLUSIVE serializes writers.
        $isSQLite = $connection->getDatabasePlatform() instanceof SQLitePlatform;

        if ($isSQLite) {
            // SQLite BEGIN EXCLUSIVE acquires a write lock immediately, serializing all writers
            $connection->executeStatement('BEGIN EXCLUSIVE');
        } else {
            // MySQL/MariaDB: acquire a named advisory lock (5 second timeout)
            $connection->executeStatement('SELECT GET_LOCK("nr_vault_audit", 5)');
            $connection->beginTransaction();
        }

        try {
            // Get previous hash – the advisory lock (or EXCLUSIVE transaction) ensures no
            // concurrent writer can insert between this SELECT and our INSERT below.
            $queryBuilder = $connection->createQueryBuilder();
            $result = $queryBuilder
                ->select('entry_hash')
                ->from(self::TABLE_NAME)
                ->orderBy('uid', 'DESC')
                ->setMaxResults(1)
                ->executeQuery()
                ->fetchOne();
            $previousHash = \is_string($result) ? $result : '';

            // Build entry data
            $currentEpoch = $this->getCurrentEpoch();
            $data = [
                'pid' => 0,
                'secret_identifier' => $secretIdentifier,
                'action' => $action,
                'success' => $success ? 1 : 0,
                'error_message' => $errorMessage ?? '',
                'reason' => $reason ?? '',
                'actor_uid' => $this->accessControlService->getCurrentActorUid(),
                'actor_type' => $this->accessControlService->getCurrentActorType(),
                'actor_username' => $this->accessControlService->getCurrentActorUsername(),
                'actor_role' => $this->getCurrentUserRole(),
                'ip_address' => $this->getClientIp(),
                'user_agent' => $this->getUserAgent(),
                'request_id' => $this->getRequestId(),
                'previous_hash' => $previousHash,
                'hash_before' => $hashBefore ?? '',
                'hash_after' => $hashAfter ?? '',
                'crdate' => time(),
                'hmac_key_epoch' => $currentEpoch,
                'context' => $context instanceof AuditContextInterface ? json_encode($context->toArray()) : '{}',
            ];

            // Reserve UID first via INSERT, then calculate hash and UPDATE
            $connection->insert(self::TABLE_NAME, $data);
            $uid = (int) $connection->lastInsertId();

            // Calculate entry hash with the known UID
            $entryHash = $this->calculateEntryHash($uid, $secretIdentifier, $action, $data['actor_uid'], $data['crdate'], $previousHash, $currentEpoch);

            // Set the hash
            $connection->update(
                self::TABLE_NAME,
                ['entry_hash' => $entryHash],
                ['uid' => $uid],
            );

            if ($isSQLite) {
                $connection->executeStatement('COMMIT');
            } else {
                $connection->commit();
            }
        } catch (Throwable $e) {
            if ($isSQLite) {
                $connection->executeStatement('ROLLBACK');
            } else {
                $connection->rollBack();
            }

            throw $e;
        } finally {
            if (!$isSQLite) {
                $connection->executeStatement('SELECT RELEASE_LOCK("nr_vault_audit")');
            }
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
        return $this->query($filter, PHP_INT_MAX, 0);
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
                $rowUid = $row['uid'] ?? 0;
                $uid = is_numeric($rowUid) ? (int) $rowUid : 0;
                $rowSecretId = $row['secret_identifier'] ?? '';
                $secretId = \is_string($rowSecretId) ? $rowSecretId : '';
                $rowAction = $row['action'] ?? '';
                $actionStr = \is_string($rowAction) ? $rowAction : '';
                $rowActorUid = $row['actor_uid'] ?? 0;
                $actorUid = is_numeric($rowActorUid) ? (int) $rowActorUid : 0;
                $rowCrdate = $row['crdate'] ?? 0;
                $crdate = is_numeric($rowCrdate) ? (int) $rowCrdate : 0;
                $rowEpoch = $row['hmac_key_epoch'] ?? 0;
                $epoch = is_numeric($rowEpoch) ? (int) $rowEpoch : 0;

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

                $expectedHash = self::calculateHash(
                    $uid,
                    $secretId,
                    $actionStr,
                    $actorUid,
                    $crdate,
                    $previousHash,
                    $epoch === 0 ? null : $hmacKey,
                );

                // Verify previous_hash matches
                $rowPrevHash = $row['previous_hash'] ?? '';
                if ($rowPrevHash !== $previousHash) {
                    $errors[$uid] = 'Previous hash mismatch - chain broken';
                }

                // Verify entry_hash is correct
                $rowEntryHash = $row['entry_hash'] ?? '';
                if ($rowEntryHash !== $expectedHash) {
                    $errors[$uid] = 'Entry hash mismatch - possible tampering';
                }

                $previousHash = \is_string($rowEntryHash) ? $rowEntryHash : '';
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
     * Calculate an audit log entry hash.
     *
     * When $hmacKey is null, produces a legacy SHA-256 hash (epoch 0).
     * When $hmacKey is provided, produces an HMAC-SHA256 hash (epoch 1+).
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
     * Calculate hash for an audit log entry.
     *
     * Epoch 0 uses legacy SHA-256 (no HMAC key) for backward compatibility.
     * Epoch 1+ uses HMAC-SHA256 with a key derived from the master key.
     */
    private function calculateEntryHash(
        int $uid,
        string $secretIdentifier,
        string $action,
        int $actorUid,
        int $crdate,
        string $previousHash,
        int $epoch = 0,
    ): string {
        if ($epoch === 0) {
            return self::calculateHash($uid, $secretIdentifier, $action, $actorUid, $crdate, $previousHash);
        }

        $hmacKey = $this->getHmacKey();

        try {
            return self::calculateHash($uid, $secretIdentifier, $action, $actorUid, $crdate, $previousHash, $hmacKey);
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
