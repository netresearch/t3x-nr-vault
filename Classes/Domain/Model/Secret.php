<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain\Model;

use Netresearch\NrVault\Crypto\EncryptedData;
use Netresearch\NrVault\Exception\ValidationException;

/**
 * Secret entity representing an encrypted secret.
 *
 * Immutable: all properties are readonly. Lifecycle transitions
 * (assigning a UID after INSERT, rotating the encrypted value,
 * re-encrypting the DEK with a new master key, merging metadata)
 * return a new instance via named `with*()` methods rather than
 * mutating the existing one.
 */
final readonly class Secret
{
    /**
     * @param int[] $allowedGroups
     * @param array<string, mixed> $metadata
     *
     * @throws ValidationException If cryptographic fields are inconsistent
     */
    public function __construct(
        public string $identifier,
        public ?int $uid = null,
        public int $scopePid = 0,
        public string $description = '',
        public ?string $encryptedValue = null,
        public string $encryptedDek = '',
        public string $dekNonce = '',
        public string $valueNonce = '',
        public int $encryptionVersion = 1,
        public string $valueChecksum = '',
        public int $ownerUid = 0,
        public array $allowedGroups = [],
        public string $context = '',
        public bool $frontendAccessible = false,
        public int $version = 1,
        public int $expiresAt = 0,
        public int $lastRotatedAt = 0,
        public array $metadata = [],
        public string $adapter = 'local',
        public string $externalReference = '',
        public int $tstamp = 0,
        public int $crdate = 0,
        public int $cruserId = 0,
        public bool $deleted = false,
        public bool $hidden = false,
        public int $readCount = 0,
        public int $lastReadAt = 0,
    ) {
        // Envelope-encryption fields must be consistently set or unset —
        // a partial set indicates a programming error that would produce
        // an undecryptable secret.
        $setCount = (int) ($this->encryptedDek !== '')
            + (int) ($this->dekNonce !== '')
            + (int) ($this->valueNonce !== '');
        if ($setCount !== 0 && $setCount !== 3) {
            throw ValidationException::invalidOption(
                'cryptographic fields',
                'encryptedDek, dekNonce, and valueNonce must all be set or all be empty',
            );
        }
    }

    // ------------------------------------------------------------------
    // Lifecycle transitions — each returns a new Secret instance.
    // ------------------------------------------------------------------

    /**
     * Attach the UID assigned by the DB after an INSERT. Called from
     * `SecretRepository::save()`; production callers don't invoke this
     * directly.
     */
    public function withUid(?int $uid): self
    {
        return $this->cloneWith(['uid' => $uid]);
    }

    /**
     * Apply a value rotation: bundles the seven crypto/version/timestamp
     * fields that change together during `VaultService::rotate()`. Returns
     * a new Secret with `version + 1`, `lastRotatedAt = $rotatedAt`, and
     * the new envelope-encryption envelope.
     */
    public function withValueRotation(EncryptedData $encrypted, int $rotatedAt): self
    {
        return $this->cloneWith([
            'encryptedValue' => $encrypted->encryptedValue,
            'encryptedDek' => $encrypted->encryptedDek,
            'dekNonce' => $encrypted->dekNonce,
            'valueNonce' => $encrypted->valueNonce,
            'valueChecksum' => $encrypted->valueChecksum,
            'version' => $this->version + 1,
            'lastRotatedAt' => $rotatedAt,
        ]);
    }

    /**
     * Master-key rotation: replace the DEK envelope (encryptedDek +
     * dekNonce) while leaving the value envelope (encryptedValue +
     * valueNonce + valueChecksum) untouched. Called from
     * `VaultRotateMasterKeyCommand::rotateOne()`.
     */
    public function withReEncryptedDek(string $encryptedDek, string $dekNonce): self
    {
        return $this->cloneWith([
            'encryptedDek' => $encryptedDek,
            'dekNonce' => $dekNonce,
        ]);
    }

    /**
     * Replace the metadata array. Called from
     * `LocalEncryptionAdapter::storeMetadata()` when an adapter needs to
     * persist its own bookkeeping (e.g. external-reference details).
     *
     * @param array<string, mixed> $metadata
     */
    public function withMetadata(array $metadata): self
    {
        return $this->cloneWith(['metadata' => $metadata]);
    }

    // ------------------------------------------------------------------
    // Derived state.
    // ------------------------------------------------------------------

    public function isExpired(): bool
    {
        return $this->expiresAt > 0 && $this->expiresAt < time();
    }

    // ------------------------------------------------------------------
    // Backwards-compatible getter shims.
    //
    // The fields are now public readonly, so callers can read them
    // directly (\$secret->uid, \$secret->identifier, …). The getters
    // below are kept so the wider codebase (and any extension code
    // consuming this entity) keeps compiling. Prefer property access
    // in new code.
    // ------------------------------------------------------------------

    public function getUid(): ?int
    {
        return $this->uid;
    }

    public function getScopePid(): int
    {
        return $this->scopePid;
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function getEncryptedValue(): ?string
    {
        return $this->encryptedValue;
    }

    public function getEncryptedDek(): string
    {
        return $this->encryptedDek;
    }

    public function getDekNonce(): string
    {
        return $this->dekNonce;
    }

    public function getValueNonce(): string
    {
        return $this->valueNonce;
    }

    public function getEncryptionVersion(): int
    {
        return $this->encryptionVersion;
    }

    public function getValueChecksum(): string
    {
        return $this->valueChecksum;
    }

    public function getOwnerUid(): int
    {
        return $this->ownerUid;
    }

    /**
     * @return int[]
     */
    public function getAllowedGroups(): array
    {
        return $this->allowedGroups;
    }

    public function getContext(): string
    {
        return $this->context;
    }

    public function isFrontendAccessible(): bool
    {
        return $this->frontendAccessible;
    }

    public function getVersion(): int
    {
        return $this->version;
    }

    public function getExpiresAt(): int
    {
        return $this->expiresAt;
    }

    public function getLastRotatedAt(): int
    {
        return $this->lastRotatedAt;
    }

    /**
     * @return array<string, mixed>
     */
    public function getMetadata(): array
    {
        return $this->metadata;
    }

    public function getAdapter(): string
    {
        return $this->adapter;
    }

    public function getExternalReference(): string
    {
        return $this->externalReference;
    }

    public function getTstamp(): int
    {
        return $this->tstamp;
    }

    public function getCrdate(): int
    {
        return $this->crdate;
    }

    public function getCruserId(): int
    {
        return $this->cruserId;
    }

    public function isDeleted(): bool
    {
        return $this->deleted;
    }

    public function isHidden(): bool
    {
        return $this->hidden;
    }

    public function getReadCount(): int
    {
        return $this->readCount;
    }

    public function getLastReadAt(): int
    {
        return $this->lastReadAt;
    }

    // ------------------------------------------------------------------
    // Persistence boundary.
    // ------------------------------------------------------------------

    /**
     * Hydrate from a `tx_nrvault_secret` row. The allowed-groups list is
     * stored in a separate MM table, so the caller must look it up and
     * pass it here — there is no second-step `setAllowedGroups()` after
     * construction.
     *
     * @param array<string, mixed> $row
     * @param int[] $allowedGroups
     */
    public static function fromDatabaseRow(array $row, array $allowedGroups = []): self
    {
        $metadata = [];
        if (!empty($row['metadata'])) {
            $decoded = json_decode((string) $row['metadata'], true);
            $metadata = \is_array($decoded) ? $decoded : [];
        }

        // If the caller didn't pre-load the MM table, fall back to the
        // comma-separated denormalised column some legacy rows still carry.
        if ($allowedGroups === [] && !empty($row['allowed_groups'])) {
            $groups = (string) $row['allowed_groups'];
            $allowedGroups = array_values(array_filter(
                array_map(\intval(...), explode(',', $groups)),
            ));
        }

        $encryptedValue = $row['encrypted_value'] ?? null;

        return new self(
            identifier: (string) ($row['identifier'] ?? ''),
            uid: isset($row['uid']) ? (int) $row['uid'] : null,
            scopePid: (int) ($row['scope_pid'] ?? 0),
            description: (string) ($row['description'] ?? ''),
            encryptedValue: \is_string($encryptedValue) ? $encryptedValue : null,
            encryptedDek: (string) ($row['encrypted_dek'] ?? ''),
            dekNonce: (string) ($row['dek_nonce'] ?? ''),
            valueNonce: (string) ($row['value_nonce'] ?? ''),
            encryptionVersion: (int) ($row['encryption_version'] ?? 1),
            valueChecksum: (string) ($row['value_checksum'] ?? ''),
            ownerUid: (int) ($row['owner_uid'] ?? 0),
            allowedGroups: array_map(\intval(...), $allowedGroups),
            context: (string) ($row['context'] ?? ''),
            frontendAccessible: (bool) ($row['frontend_accessible'] ?? false),
            version: (int) ($row['version'] ?? 1),
            expiresAt: (int) ($row['expires_at'] ?? 0),
            lastRotatedAt: (int) ($row['last_rotated_at'] ?? 0),
            metadata: $metadata,
            adapter: (string) ($row['adapter'] ?? 'local'),
            externalReference: (string) ($row['external_reference'] ?? ''),
            tstamp: (int) ($row['tstamp'] ?? 0),
            crdate: (int) ($row['crdate'] ?? 0),
            cruserId: (int) ($row['cruser_id'] ?? 0),
            deleted: (bool) ($row['deleted'] ?? false),
            hidden: (bool) ($row['hidden'] ?? false),
            readCount: (int) ($row['read_count'] ?? 0),
            lastReadAt: (int) ($row['last_read_at'] ?? 0),
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toDatabaseRow(): array
    {
        return [
            'scope_pid' => $this->scopePid,
            'identifier' => $this->identifier,
            'description' => $this->description,
            'encrypted_value' => $this->encryptedValue,
            'encrypted_dek' => $this->encryptedDek,
            'dek_nonce' => $this->dekNonce,
            'value_nonce' => $this->valueNonce,
            'encryption_version' => $this->encryptionVersion,
            'value_checksum' => $this->valueChecksum,
            'owner_uid' => $this->ownerUid,
            'allowed_groups' => implode(',', $this->allowedGroups),
            'context' => $this->context,
            'frontend_accessible' => $this->frontendAccessible ? 1 : 0,
            'version' => $this->version,
            'expires_at' => $this->expiresAt,
            'last_rotated_at' => $this->lastRotatedAt,
            'metadata' => json_encode($this->metadata),
            'adapter' => $this->adapter,
            'external_reference' => $this->externalReference,
            'tstamp' => time(),
            'cruser_id' => $this->cruserId,
            'deleted' => $this->deleted ? 1 : 0,
            'hidden' => $this->hidden ? 1 : 0,
            'read_count' => $this->readCount,
            'last_read_at' => $this->lastReadAt,
        ];
    }

    /**
     * Shared cloning primitive for the named withers. Builds a fresh
     * instance from the current state, overriding the supplied subset
     * of fields. The named-arg spread expansion relies on the constructor
     * parameter names matching the property names — constructor promotion
     * guarantees this by construction.
     *
     * @param array<string, mixed> $changes
     */
    private function cloneWith(array $changes): self
    {
        /** @var array<string, mixed> $current */
        $current = get_object_vars($this);

        /** @phpstan-ignore-next-line argument.unpackNonIterableStringKeys */
        return new self(...array_merge($current, $changes));
    }
}
