<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain\Model;

use Netresearch\NrVault\Crypto\EncryptedData;
use Netresearch\NrVault\Crypto\EncryptionAlgorithm;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
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
    private const CRYPTO_FIELDS_LABEL = 'cryptographic fields';

    /**
     * @param int[] $allowedGroups Backend group UIDs with READ access (read-only tier)
     * @param int[] $writeGroups Backend group UIDs with WRITE access (read + write tier)
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
        public int $encryptionVersion = EncryptionServiceInterface::ENCRYPTION_VERSION_LEGACY,
        public string $encryptionAlgorithm = '',
        public string $valueChecksum = '',
        public int $ownerUid = 0,
        public array $allowedGroups = [],
        public array $writeGroups = [],
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
        // Envelope-encryption fields must be consistently set or unset — a
        // partial set indicates a programming error that would produce an
        // undecryptable secret. The check covers the FULL envelope: omitting
        // encryptedValue/valueChecksum let an undecryptable secret (DEK +
        // nonces present, ciphertext absent) be constructed.
        $setCount = (int) ($this->encryptedValue !== null && $this->encryptedValue !== '')
            + (int) ($this->encryptedDek !== '')
            + (int) ($this->dekNonce !== '')
            + (int) ($this->valueNonce !== '')
            + (int) ($this->valueChecksum !== '');
        if ($setCount !== 0 && $setCount !== 5) {
            throw ValidationException::invalidOption(
                self::CRYPTO_FIELDS_LABEL,
                'encryptedValue, encryptedDek, dekNonce, valueNonce, and valueChecksum must all be set or all be empty',
            );
        }

        // The version/algorithm marker is part of the same invariant:
        //  - version 2+ means "algorithm recorded explicitly", so it requires
        //    a full envelope AND a KNOWN algorithm marker — anything else
        //    would be undecryptable (decrypt refuses to guess for v2 rows);
        //  - version 1 (legacy) rows predate the marker and must not carry
        //    one, or decrypt-time behaviour would silently diverge from what
        //    the marker claims.
        if ($this->encryptionVersion >= EncryptionServiceInterface::ENCRYPTION_VERSION_CURRENT) {
            if ($setCount !== 5) {
                throw ValidationException::invalidOption(
                    self::CRYPTO_FIELDS_LABEL,
                    'encryption version 2+ requires the full encryption envelope to be set',
                );
            }

            if (!EncryptionAlgorithm::tryFrom($this->encryptionAlgorithm) instanceof EncryptionAlgorithm) {
                throw ValidationException::invalidOption(
                    self::CRYPTO_FIELDS_LABEL,
                    'encryption version 2+ requires a known encryptionAlgorithm marker',
                );
            }
        } elseif ($this->encryptionAlgorithm !== '') {
            throw ValidationException::invalidOption(
                self::CRYPTO_FIELDS_LABEL,
                'legacy encryption version 1 must not carry an encryptionAlgorithm marker',
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
     * Apply a value rotation: bundles the crypto/version/timestamp fields
     * that change together during `VaultService::rotate()`. Returns a new
     * Secret with `version + 1`, `lastRotatedAt = $rotatedAt`, the new
     * encryption envelope, and the envelope's version/algorithm marker
     * (a rotation re-encrypts the value, so a legacy v1 secret is upgraded
     * to the marker the new envelope was produced with).
     */
    public function withValueRotation(EncryptedData $encrypted, int $rotatedAt): self
    {
        return $this->cloneWith([
            'encryptedValue' => $encrypted->encryptedValue,
            'encryptedDek' => $encrypted->encryptedDek,
            'dekNonce' => $encrypted->dekNonce,
            'valueNonce' => $encrypted->valueNonce,
            'valueChecksum' => $encrypted->valueChecksum,
            'encryptionVersion' => $encrypted->encryptionVersion,
            'encryptionAlgorithm' => $encrypted->encryptionAlgorithm->value,
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

    /**
     * Replace the read-tier allowed-groups list. Returns a new Secret;
     * the MM relations are persisted by `SecretRepository::save()`.
     *
     * @param int[] $allowedGroups
     */
    public function cloneWithGroups(array $allowedGroups): self
    {
        return $this->cloneWith(['allowedGroups' => array_map(\intval(...), $allowedGroups)]);
    }

    /**
     * Replace the write-tier groups list. Returns a new Secret; the MM
     * relations are persisted by `SecretRepository::save()`.
     *
     * @param int[] $writeGroups
     */
    public function cloneWithWriteGroups(array $writeGroups): self
    {
        return $this->cloneWith(['writeGroups' => array_map(\intval(...), $writeGroups)]);
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

    public function getEncryptionAlgorithm(): string
    {
        return $this->encryptionAlgorithm;
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

    /**
     * @return int[]
     */
    public function getWriteGroups(): array
    {
        return $this->writeGroups;
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
     * Hydrate from a `tx_nrvault_secret` row. The allowed-groups and
     * write-groups lists are each stored in a separate MM table, so the
     * caller must look them up and pass them here — there is no
     * second-step `setAllowedGroups()` after construction.
     *
     * The row's own `allowed_groups`/`write_groups` columns are deliberately
     * NOT consulted: for MM-backed TCA group fields they hold the relation
     * COUNT, not the related UIDs (DataHandler writes
     * `RelationHandler::countItems()` there, and `toDatabaseRow()` mirrors
     * that). Reading them as a UID list would turn "3 groups are allowed"
     * into "group 3 is allowed" — a silent ACL forgery. The MM tables are
     * the single source of truth for both tiers.
     *
     * @param array<string, mixed> $row
     * @param int[] $allowedGroups Read-tier group UIDs (from MM table)
     * @param int[] $writeGroups Write-tier group UIDs (from MM table)
     */
    public static function fromDatabaseRow(array $row, array $allowedGroups = [], array $writeGroups = []): self
    {
        $metadata = [];
        if (!empty($row['metadata'])) {
            $decoded = json_decode((string) $row['metadata'], true);
            $metadata = \is_array($decoded) ? $decoded : [];
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
            encryptionVersion: (int) ($row['encryption_version'] ?? EncryptionServiceInterface::ENCRYPTION_VERSION_LEGACY),
            encryptionAlgorithm: (string) ($row['encryption_algorithm'] ?? ''),
            valueChecksum: (string) ($row['value_checksum'] ?? ''),
            ownerUid: (int) ($row['owner_uid'] ?? 0),
            allowedGroups: array_map(\intval(...), $allowedGroups),
            writeGroups: array_map(\intval(...), $writeGroups),
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
     * Serialise to a `tx_nrvault_secret` row for INSERT/UPDATE.
     *
     * Note: `uid` and `crdate` are intentionally omitted (the DB layer
     * assigns/owns them — `uid` is auto-increment, `crdate` is set by
     * `SecretRepository::save()` on INSERT only), and `tstamp` is set to
     * the current time on every write rather than echoing `$this->tstamp`.
     * These three columns are therefore DB-managed; a `fromDatabaseRow()`
     * → `toDatabaseRow()` round-trip is not an identity for them.
     *
     * The `allowed_groups`/`write_groups` columns are MM-backed TCA group
     * fields, so their column value is the relation COUNT — the convention
     * DataHandler writes on the FormEngine path
     * (`RelationHandler::countItems()`). Writing the same count here keeps
     * one meaning for the column no matter which writer produced the row;
     * the group UIDs themselves live solely in the MM tables, written by
     * `SecretRepository::save()` from the very lists counted here.
     *
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
            'encryption_algorithm' => $this->encryptionAlgorithm,
            'value_checksum' => $this->valueChecksum,
            'owner_uid' => $this->ownerUid,
            'allowed_groups' => \count($this->allowedGroups),
            'write_groups' => \count($this->writeGroups),
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
