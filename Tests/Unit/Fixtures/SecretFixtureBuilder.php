<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Fixtures;

use Netresearch\NrVault\Domain\Dto\SecretDetails;
use Netresearch\NrVault\Domain\Dto\SecretMetadata;
use Netresearch\NrVault\Domain\Model\Secret;

/**
 * Fluent builder for real (non-mock) Secret / SecretDetails / SecretMetadata
 * DTOs used in unit tests.
 *
 * Replaces ~6 hand-rolled `createSecretDetails()` / `createSecretMetadata()`
 * helpers that duplicated the same constructor-call boilerplate across:
 *  - `Tests/Unit/Controller/AjaxControllerTest.php`
 *  - `Tests/Unit/Command/VaultRotateCommandTest.php`
 *  - `Tests/Unit/Command/VaultDeleteCommandTest.php`
 *  - `Tests/Unit/Command/VaultCleanupOrphansCommandTest.php`
 *  - `Tests/Unit/Task/OrphanCleanupTaskTest.php`
 *
 * Example:
 *
 * ```php
 * $details = SecretFixtureBuilder::create('my-secret')
 *     ->withOwner(42)
 *     ->withGroups([1, 2])
 *     ->buildDetails();
 *
 * $metadata = SecretFixtureBuilder::create('cron-secret')
 *     ->withCreatedAt(time() - 3600)
 *     ->withMetadata(['source' => 'cron'])
 *     ->buildMetadata();
 *
 * $secret = SecretFixtureBuilder::create('domain-entity')
 *     ->asDisabled()
 *     ->buildSecret();
 * ```
 *
 * This is a **mutable** fluent builder: each `with*` method mutates the current
 * instance and returns `$this`, matching the semantics of the hand-rolled
 * factory helpers it replaces. Call `create()` per fixture to get a fresh
 * instance; do not share a builder between tests.
 */
final class SecretFixtureBuilder
{
    private const DEFAULT_TIMESTAMP = 1_704_067_200; // 2024-01-01 00:00:00 UTC

    private int $uid = 1;

    private string $description = 'Test secret';

    private int $ownerUid = 1;

    /** @var list<int> */
    private array $groups = [];

    private string $context = 'default';

    private bool $frontendAccessible = false;

    private int $version = 1;

    private int $createdAt = self::DEFAULT_TIMESTAMP;

    private int $updatedAt = self::DEFAULT_TIMESTAMP;

    private ?int $expiresAt = null;

    private ?int $lastRotatedAt = null;

    private int $readCount = 0;

    private ?int $lastReadAt = null;

    /** @var array<string, mixed> */
    private array $metadata = [];

    private int $scopePid = 0;

    private bool $disabled = false;

    private function __construct(private string $identifier) {}

    public static function create(string $identifier = 'test-secret'): self
    {
        return new self($identifier);
    }

    public function withIdentifier(string $identifier): self
    {
        $this->identifier = $identifier;

        return $this;
    }

    public function withUid(int $uid): self
    {
        $this->uid = $uid;

        return $this;
    }

    public function withDescription(string $description): self
    {
        $this->description = $description;

        return $this;
    }

    public function withOwner(int $ownerUid): self
    {
        $this->ownerUid = $ownerUid;

        return $this;
    }

    /**
     * @param list<int> $groups
     */
    public function withGroups(array $groups): self
    {
        $this->groups = $groups;

        return $this;
    }

    public function withContext(string $context): self
    {
        $this->context = $context;

        return $this;
    }

    public function withFrontendAccessible(bool $frontendAccessible = true): self
    {
        $this->frontendAccessible = $frontendAccessible;

        return $this;
    }

    public function withVersion(int $version): self
    {
        $this->version = $version;

        return $this;
    }

    public function withCreatedAt(int $createdAt): self
    {
        $this->createdAt = $createdAt;

        return $this;
    }

    public function withUpdatedAt(int $updatedAt): self
    {
        $this->updatedAt = $updatedAt;

        return $this;
    }

    public function withExpiresAt(?int $expiresAt): self
    {
        $this->expiresAt = $expiresAt;

        return $this;
    }

    public function withLastRotatedAt(?int $lastRotatedAt): self
    {
        $this->lastRotatedAt = $lastRotatedAt;

        return $this;
    }

    public function withReadCount(int $readCount): self
    {
        $this->readCount = $readCount;

        return $this;
    }

    public function withLastReadAt(?int $lastReadAt): self
    {
        $this->lastReadAt = $lastReadAt;

        return $this;
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function withMetadata(array $metadata): self
    {
        $this->metadata = $metadata;

        return $this;
    }

    public function withScopePid(int $scopePid): self
    {
        $this->scopePid = $scopePid;

        return $this;
    }

    public function asDisabled(): self
    {
        $this->disabled = true;

        return $this;
    }

    /**
     * Build a `SecretDetails` DTO (what most controllers/commands expect).
     *
     * `build()` is provided as an alias so the most common form
     * (`$builder->build()`) stays concise — use the typed variants when the
     * intent is otherwise ambiguous.
     */
    public function build(): SecretDetails
    {
        return $this->buildDetails();
    }

    public function buildDetails(): SecretDetails
    {
        return new SecretDetails(
            uid: $this->uid,
            identifier: $this->identifier,
            description: $this->description,
            ownerUid: $this->ownerUid,
            groups: $this->groups,
            context: $this->context,
            frontendAccessible: $this->frontendAccessible,
            version: $this->version,
            createdAt: $this->createdAt,
            updatedAt: $this->updatedAt,
            expiresAt: $this->expiresAt,
            lastRotatedAt: $this->lastRotatedAt,
            readCount: $this->readCount,
            lastReadAt: $this->lastReadAt,
            metadata: $this->metadata,
            scopePid: $this->scopePid,
        );
    }

    public function buildMetadata(): SecretMetadata
    {
        return new SecretMetadata(
            identifier: $this->identifier,
            ownerUid: $this->ownerUid,
            createdAt: $this->createdAt,
            updatedAt: $this->updatedAt,
            readCount: $this->readCount,
            lastReadAt: $this->lastReadAt,
            description: $this->description,
            version: $this->version,
            metadata: $this->metadata,
        );
    }

    /**
     * Build a real `Secret` domain entity (no mocking).
     *
     * Uses placeholder ciphertext so the builder stays usable in tests that
     * only need the entity shell — production code that decrypts the result
     * will throw, which is desirable: a test that reaches that branch should
     * wire real crypto instead.
     */
    public function buildSecret(): Secret
    {
        return new Secret(
            identifier: $this->identifier,
            uid: $this->uid,
            scopePid: $this->scopePid,
            description: $this->description,
            encryptedValue: 'test-ciphertext',
            valueChecksum: 'test-checksum',
            ownerUid: $this->ownerUid,
            allowedGroups: $this->groups,
            context: $this->context,
            frontendAccessible: $this->frontendAccessible,
            version: $this->version,
            expiresAt: $this->expiresAt ?? 0,
            lastRotatedAt: $this->lastRotatedAt ?? 0,
            metadata: $this->metadata,
            tstamp: $this->updatedAt,
            crdate: $this->createdAt,
            hidden: $this->disabled,
            readCount: $this->readCount,
            lastReadAt: $this->lastReadAt ?? 0,
        );
    }
}
