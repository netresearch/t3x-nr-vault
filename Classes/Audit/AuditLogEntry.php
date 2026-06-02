<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

use JsonSerializable;

/**
 * Represents an audit log entry.
 */
final readonly class AuditLogEntry implements JsonSerializable
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public int $uid,
        public string $secretIdentifier,
        public string $action,
        public bool $success,
        public ?string $errorMessage,
        public ?string $reason,
        public int $actorUid,
        public string $actorType,
        public string $actorUsername,
        public string $actorRole,
        public string $ipAddress,
        public string $userAgent,
        public string $requestId,
        public string $previousHash,
        public string $entryHash,
        public string $hashBefore,
        public string $hashAfter,
        public int $crdate,
        public array $context,
    ) {}

    /**
     * Create from database row.
     *
     * @param array<string, mixed> $row
     */
    public static function fromDatabaseRow(array $row): self
    {
        return new self(
            uid: self::intOrZero($row['uid'] ?? null),
            secretIdentifier: self::stringOrEmpty($row['secret_identifier'] ?? null),
            action: self::stringOrEmpty($row['action'] ?? null),
            success: (bool) ($row['success'] ?? false),
            errorMessage: self::nonEmptyStringOrNull($row['error_message'] ?? null),
            reason: self::nonEmptyStringOrNull($row['reason'] ?? null),
            actorUid: self::intOrZero($row['actor_uid'] ?? null),
            actorType: self::stringOrEmpty($row['actor_type'] ?? null),
            actorUsername: self::stringOrEmpty($row['actor_username'] ?? null),
            actorRole: self::stringOrEmpty($row['actor_role'] ?? null),
            ipAddress: self::stringOrEmpty($row['ip_address'] ?? null),
            userAgent: self::stringOrEmpty($row['user_agent'] ?? null),
            requestId: self::stringOrEmpty($row['request_id'] ?? null),
            previousHash: self::stringOrEmpty($row['previous_hash'] ?? null),
            entryHash: self::stringOrEmpty($row['entry_hash'] ?? null),
            hashBefore: self::stringOrEmpty($row['hash_before'] ?? null),
            hashAfter: self::stringOrEmpty($row['hash_after'] ?? null),
            crdate: self::intOrZero($row['crdate'] ?? null),
            context: self::decodeContext($row['context'] ?? null),
        );
    }

    /**
     * @return array<string, scalar|array<string, mixed>|null>
     */
    public function jsonSerialize(): array
    {
        return [
            'uid' => $this->uid,
            'secretIdentifier' => $this->secretIdentifier,
            'action' => $this->action,
            'success' => $this->success,
            'errorMessage' => $this->errorMessage,
            'reason' => $this->reason,
            'actorUid' => $this->actorUid,
            'actorType' => $this->actorType,
            'actorUsername' => $this->actorUsername,
            'actorRole' => $this->actorRole,
            'ipAddress' => $this->ipAddress,
            'userAgent' => $this->userAgent,
            'requestId' => $this->requestId,
            'previousHash' => $this->previousHash,
            'entryHash' => $this->entryHash,
            'hashBefore' => $this->hashBefore,
            'hashAfter' => $this->hashAfter,
            'timestamp' => date('c', $this->crdate),
            'context' => $this->context,
        ];
    }

    /**
     * Decode the JSON-encoded context column into an array.
     *
     * @return array<string, mixed>
     */
    private static function decodeContext(mixed $contextValue): array
    {
        if (empty($contextValue)) {
            return [];
        }

        $decoded = json_decode(\is_string($contextValue) ? $contextValue : '', true);
        if (\is_array($decoded)) {
            /** @var array<string, mixed> $decoded */
            return $decoded;
        }

        return [];
    }

    private static function stringOrEmpty(mixed $value): string
    {
        return \is_string($value) ? $value : '';
    }

    private static function nonEmptyStringOrNull(mixed $value): ?string
    {
        return \is_string($value) && $value !== '' ? $value : null;
    }

    private static function intOrZero(mixed $value): int
    {
        return is_numeric($value) ? (int) $value : 0;
    }
}
