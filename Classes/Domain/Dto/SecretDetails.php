<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain\Dto;

use Netresearch\NrVault\Domain\Model\Secret;

/**
 * Data Transfer Object for detailed secret metadata.
 *
 * Contains all secret metadata including access control settings.
 * Used by VaultServiceInterface::getMetadata().
 */
readonly class SecretDetails
{
    /**
     * @param int $uid Database UID
     * @param string $identifier Unique secret identifier
     * @param string $description Human-readable description
     * @param int $ownerUid Owner backend user UID
     * @param list<int> $groups Allowed backend user group UIDs
     * @param string $context Permission context scope
     * @param bool $frontendAccessible Whether secret can be accessed in frontend
     * @param int $version Secret version number
     * @param int $createdAt Unix timestamp of creation
     * @param int $updatedAt Unix timestamp of last update
     * @param int|null $expiresAt Unix timestamp when secret expires
     * @param int|null $lastRotatedAt Unix timestamp of last rotation
     * @param int $readCount Number of times secret was read
     * @param int|null $lastReadAt Unix timestamp of last read
     * @param array<string, mixed> $metadata Custom metadata
     * @param int $scopePid Page ID for multi-site scoping
     * @param bool $enabled Whether the secret is available to consumers — a
     *                      disabled one exists and can be administered, but
     *                      resolves to nothing on every read path
     */
    public function __construct(
        public int $uid,
        public string $identifier,
        public string $description,
        public int $ownerUid,
        public array $groups,
        public string $context,
        public bool $frontendAccessible,
        public int $version,
        public int $createdAt,
        public int $updatedAt,
        public ?int $expiresAt,
        public ?int $lastRotatedAt,
        public int $readCount,
        public ?int $lastReadAt,
        public array $metadata,
        public int $scopePid,
        public bool $enabled = true,
    ) {}

    /**
     * Create from Secret domain model.
     */
    public static function fromSecret(Secret $secret): self
    {
        /** @var list<int> $groups */
        $groups = $secret->getAllowedGroups();

        return new self(
            uid: $secret->getUid() ?? 0,
            identifier: $secret->getIdentifier(),
            description: $secret->getDescription(),
            ownerUid: $secret->getOwnerUid(),
            groups: $groups,
            context: $secret->getContext(),
            frontendAccessible: $secret->isFrontendAccessible(),
            version: $secret->getVersion(),
            createdAt: $secret->getCrdate(),
            updatedAt: $secret->getTstamp(),
            expiresAt: $secret->getExpiresAt() ?: null,
            lastRotatedAt: $secret->getLastRotatedAt() ?: null,
            readCount: $secret->getReadCount(),
            lastReadAt: $secret->getLastReadAt() ?: null,
            metadata: $secret->getMetadata(),
            scopePid: $secret->getScopePid(),
            enabled: !$secret->isHidden(),
        );
    }

    /**
     * Check if secret has expired.
     */
    public function isExpired(): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }

        return $this->expiresAt < time();
    }

    /**
     * Check if secret expires within given days.
     */
    public function expiresSoon(int $days): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }

        $threshold = time() + ($days * 86400);

        return $this->expiresAt <= $threshold && !$this->isExpired();
    }

    /**
     * Convert to array for JSON serialization.
     *
     * @return array{
     *     uid: int,
     *     identifier: string,
     *     description: string,
     *     owner: int,
     *     owner_uid: int,
     *     groups: list<int>,
     *     context: string,
     *     frontend_accessible: bool,
     *     version: int,
     *     createdAt: int,
     *     updatedAt: int,
     *     expiresAt: int|null,
     *     expires_at: int|null,
     *     lastRotatedAt: int|null,
     *     read_count: int,
     *     last_read_at: int|null,
     *     metadata: array<string, mixed>,
     *     scopePid: int,
     *     enabled: bool,
     * }
     */
    public function toArray(): array
    {
        return [
            'uid' => $this->uid,
            'identifier' => $this->identifier,
            'description' => $this->description,
            'owner' => $this->ownerUid,
            'owner_uid' => $this->ownerUid,
            'groups' => $this->groups,
            'context' => $this->context,
            'frontend_accessible' => $this->frontendAccessible,
            'version' => $this->version,
            'createdAt' => $this->createdAt,
            'updatedAt' => $this->updatedAt,
            'expiresAt' => $this->expiresAt,
            'expires_at' => $this->expiresAt,
            'lastRotatedAt' => $this->lastRotatedAt,
            'read_count' => $this->readCount,
            'last_read_at' => $this->lastReadAt,
            'metadata' => $this->metadata,
            'scopePid' => $this->scopePid,
            'enabled' => $this->enabled,
        ];
    }
}
