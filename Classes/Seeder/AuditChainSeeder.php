<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Seeder;

use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use RuntimeException;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Appends a valid, backdated segment to the tamper-evident audit hash chain by
 * reusing AuditLogService's public static hashing API. Dev-only (demo data).
 */
final readonly class AuditChainSeeder
{
    private const TABLE = 'tx_nrvault_audit_log';

    private const SUPPORTED_EPOCHS = [0, 1, 2];

    public function __construct(
        private ConnectionPool $connectionPool,
        private MasterKeyProviderInterface $masterKeyProvider,
        private ExtensionConfigurationInterface $extensionConfiguration,
    ) {}

    /**
     * @param list<array{secret_identifier: string, action: string, success: bool, actor_uid: int, actor_type: string, actor_username: string, crdate: int, context: array<string, scalar|null>}> $events
     *                                                                                                                                                                                                    MUST be ordered ascending by crdate.
     */
    public function seed(array $events): void
    {
        $epoch = $this->extensionConfiguration->getAuditHmacEpoch();
        if (!\in_array($epoch, self::SUPPORTED_EPOCHS, true)) {
            throw new RuntimeException(
                \sprintf('Demo seeder supports audit epoch 0/1/2; configured epoch is %d.', $epoch),
                1_748_736_000,
            );
        }

        $connection = $this->connectionPool->getConnectionForTable(self::TABLE);
        $previousHash = $this->fetchLatestHash($connection);
        $hmacKey = $epoch >= 1 ? AuditLogService::deriveHmacKey($this->masterKeyProvider) : null;

        try {
            foreach ($events as $event) {
                $row = $this->buildRow($event, $previousHash, $epoch);
                $connection->insert(self::TABLE, $row);
                $uid = (int) $connection->lastInsertId();
                $row['uid'] = $uid;

                $entryHash = $this->hashFor($row, $previousHash, $epoch, $hmacKey);
                $connection->update(self::TABLE, ['entry_hash' => $entryHash], ['uid' => $uid]);
                $previousHash = $entryHash;
            }
        } finally {
            if ($hmacKey !== null) {
                sodium_memzero($hmacKey);
            }
        }
    }

    private function fetchLatestHash(Connection $connection): string
    {
        $hash = $connection->createQueryBuilder()
            ->select('entry_hash')
            ->from(self::TABLE)
            ->orderBy('uid', 'DESC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchOne();

        return \is_string($hash) ? $hash : '';
    }

    /**
     * @param array{secret_identifier: string, action: string, success: bool, actor_uid: int, actor_type: string, actor_username: string, crdate: int, context: array<string, scalar|null>} $event
     *
     * @return array<string, mixed>
     */
    private function buildRow(array $event, string $previousHash, int $epoch): array
    {
        return [
            'pid' => 0,
            'secret_identifier' => $event['secret_identifier'],
            'action' => $event['action'],
            'success' => $event['success'] ? 1 : 0,
            'error_message' => '',
            'reason' => '',
            'actor_uid' => $event['actor_uid'],
            'actor_type' => $event['actor_type'],
            'actor_username' => $event['actor_username'],
            'actor_role' => '',
            'ip_address' => 'CLI',
            'user_agent' => 'demo-seed',
            'request_id' => '',
            'previous_hash' => $previousHash,
            'hash_before' => '',
            'hash_after' => '',
            'crdate' => $event['crdate'],
            'hmac_key_epoch' => $epoch,
            'context' => json_encode($event['context'], JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            'entry_hash' => '',
        ];
    }

    /**
     * @param array<string, mixed> $row
     */
    private function hashFor(array $row, string $previousHash, int $epoch, ?string $hmacKey): string
    {
        $v1 = AuditLogService::extractHashRow($row);

        if ($epoch === 0) {
            return AuditLogService::calculateHash($v1['uid'], $v1['secretId'], $v1['action'], $v1['actorUid'], $v1['crdate'], $previousHash);
        }

        \assert($hmacKey !== null);

        if ($epoch === 1) {
            return AuditLogService::calculateHash($v1['uid'], $v1['secretId'], $v1['action'], $v1['actorUid'], $v1['crdate'], $previousHash, $hmacKey);
        }

        return AuditLogService::calculateHashV2(AuditLogService::extractV2HashRow($row), $previousHash, $hmacKey);
    }
}
