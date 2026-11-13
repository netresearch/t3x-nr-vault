<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Adapter;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Exception\HashiCorpException;
use Netresearch\NrVault\Storage\ExternalStoreJournal;
use Netresearch\NrVault\Storage\HashiCorp\AtomicKvStoreInterface;
use Netresearch\NrVault\Storage\HashiCorp\HashiCorpEndpoint;
use Netresearch\NrVault\Storage\HashiCorp\KvStoreInterface;
use Netresearch\NrVault\Storage\HashiCorp\LegacyKvStoreNotice;
use Netresearch\NrVault\Storage\InstallationMarker;
use Psr\Log\LoggerInterface;
use SensitiveParameter;
use Throwable;

use function array_key_exists;
use function in_array;
use function is_int;
use function is_string;

/**
 * Stores the encryption envelope of a secret in HashiCorp Vault (KV v2).
 *
 * The registry row in the TYPO3 database stays: it carries the owner, the group
 * tiers, the metadata, the counters and a pointer to the Vault object, so
 * listing, access control, expiry and the audit trail work exactly as for a
 * local secret. What moves is the envelope — encrypted value, wrapped data key,
 * nonces and checksum. The value is still encrypted by nr-vault before it
 * leaves the process; Vault holds ciphertext it cannot read, and a stolen
 * database holds no envelope at all.
 *
 * Each row routes by its own `adapter` column. A secret stored locally before
 * the setting changed stays local and keeps working; only a secret that does
 * not exist yet (or exists without a value, the FormEngine creation path) goes
 * to Vault.
 *
 * Write order is Vault first, then the row. A crash between the two leaves an
 * unreferenced Vault object, which the next store of the same identifier
 * overwrites. Delete order is the reverse of what would be convenient: Vault
 * first, then the row, so a delete that fails half-way can be repeated.
 */
final readonly class HashiCorpAdapter implements CreateCompensatingAdapterInterface, VaultAdapterInterface
{
    public const IDENTIFIER = 'hashicorp';

    private const FORMAT = 1;

    private const CLAIM_ATTEMPTS = 3;

    public function __construct(
        private LocalEncryptionAdapter $registry,
        private KvStoreInterface $kv,
        private ExtensionConfigurationInterface $configuration,
        private InstallationMarker $installation,
        private ExternalStoreJournal $journal,
        private LoggerInterface $logger,
    ) {}

    public function getIdentifier(): string
    {
        return self::IDENTIFIER;
    }

    public function isAvailable(): bool
    {
        try {
            HashiCorpEndpoint::fromConfig($this->configuration->getHashiCorpConfig());
        } catch (HashiCorpException) {
            return false;
        }

        return true;
    }

    public function store(Secret $secret, bool $persistGroupRelations = true): Secret
    {
        $identifier = $secret->getIdentifier();
        $existing   = $this->registry->retrieveIncludingDisabled($identifier);

        $this->assertNotBoundElsewhere($existing);
        $this->assertNotBoundElsewhere($secret);

        // A write without a value has nothing to put into Vault. Restoring a
        // valueless row that is, or just was, bound to Vault also removes the
        // value written since, so the restore is complete; the previous object
        // is put back if the row write fails.
        if (($secret->getEncryptedValue() ?? '') === '') {
            $boundToVault = $secret->getAdapter() === self::IDENTIFIER
                || ($existing instanceof Secret && $existing->getAdapter() === self::IDENTIFIER);
            $previous = null;
            if ($boundToVault) {
                $this->assertOwnsLocation($existing instanceof Secret && $existing->getAdapter() === self::IDENTIFIER ? $existing : $secret);
                // This is also the compensation of a failed audit write on the
                // FormEngine completion path. A store recorded in this request is
                // taken back exactly: a key it created is destroyed, one it took
                // over is put back.
                $entry = $this->journal->take(self::IDENTIFIER, $identifier);
                if ($entry !== null) {
                    $this->undoVaultWrite($identifier, $entry['previous'], is_int($entry['version']) ? $entry['version'] : null, true);
                } else {
                    $previous = $this->readOwned($identifier);
                    $this->kv->destroy($identifier);
                }
            }

            try {
                return $this->registry->store($secret, $persistGroupRelations);
            } catch (Throwable $e) {
                if ($previous !== null) {
                    $this->restore($identifier, $previous);
                }

                throw $e;
            }
        }

        if (!$this->belongsInVault($existing)) {
            return $this->registry->store($secret, $persistGroupRelations);
        }

        // A row bound to Vault owns its key. For any other row the path may
        // hold somebody else's data: it is claimed only when empty, or when it
        // is an earlier write of nr-vault for this very identifier (an
        // unreferenced one left by a crash). Only a key this call created is
        // destroyed again on failure; an adopted one is put back.
        $payload = $this->toPayload($secret);
        if ($existing instanceof Secret && $existing->getAdapter() === self::IDENTIFIER) {
            $this->assertOwnsLocation($existing);
            $previous = $this->readOwned($identifier);
            $version  = $this->put($identifier, $payload);
        } else {
            [$previous, $version] = $this->claimPath($identifier, $payload);
        }

        $row = $secret->withExternalStorage(self::IDENTIFIER, $this->kv->reference($identifier));
        $this->journal->remember(self::IDENTIFIER, $identifier, $previous, $version);

        try {
            return $this->registry->store($row, $persistGroupRelations)->withEnvelope(...$this->envelopeOf($secret));
        } catch (Throwable $e) {
            $this->journal->forget(self::IDENTIFIER, $identifier);
            $this->undoVaultWrite($identifier, $previous, $version);

            throw $e;
        }
    }

    public function compensateCreate(string $identifier): void
    {
        $entry = $this->journal->take(self::IDENTIFIER, $identifier);
        if ($entry === null) {
            $this->logger->warning(
                'nr-vault: no store of this secret was recorded in this request, so the create was compensated by deleting it.',
                ['secret' => $identifier],
            );
            $this->delete($identifier);

            return;
        }

        $this->undoVaultWrite($identifier, $entry['previous'], is_int($entry['version']) ? $entry['version'] : null, true);
        $this->registry->delete($identifier);
    }

    public function releaseStore(string $identifier): void
    {
        $this->journal->forget(self::IDENTIFIER, $identifier);
    }

    public function retrieve(string $identifier): ?Secret
    {
        $row = $this->registry->retrieve($identifier);
        $this->assertNotBoundElsewhere($row);

        return $this->withBackingEnvelope($row, true);
    }

    public function retrieveIncludingDisabled(string $identifier): ?Secret
    {
        return $this->withBackingEnvelope($this->registry->retrieveIncludingDisabled($identifier), false);
    }

    public function setHidden(int $uid, bool $hidden): void
    {
        $this->registry->setHidden($uid, $hidden);
    }

    public function delete(string $identifier): void
    {
        $row = $this->registry->retrieveIncludingDisabled($identifier);
        $this->assertNotBoundElsewhere($row);

        $previous = null;
        if ($row instanceof Secret && $row->getAdapter() === self::IDENTIFIER) {
            $this->assertOwnsLocation($row);
            $previous = $this->readOwned($identifier);
            $this->kv->destroy($identifier);
        }

        try {
            $this->registry->delete($identifier);
        } catch (Throwable $e) {
            // The row stays, so the value it points at must stay too.
            if ($previous !== null) {
                $this->restore($identifier, $previous);
            }

            throw $e;
        }
    }

    public function exists(string $identifier): bool
    {
        return $this->registry->exists($identifier);
    }

    public function list(?SecretFilters $filters = null): array
    {
        return $this->registry->list($filters);
    }

    public function listSecrets(?SecretFilters $filters = null): array
    {
        return $this->registry->listSecrets($filters);
    }

    public function getMetadata(string $identifier): ?array
    {
        return $this->registry->getMetadata($identifier);
    }

    public function updateMetadata(string $identifier, array $metadata): void
    {
        $this->registry->updateMetadata($identifier, $metadata);
    }

    public function incrementReadCount(int $uid): void
    {
        $this->registry->incrementReadCount($uid);
    }

    /**
     * Take back a Vault write after the row could not be written. A first
     * insert removes the key it created, unless a row for the identifier
     * exists by now: a concurrent create that won the unique key owns it. An
     * update puts the previous envelope back.
     *
     * With a store that reports versions, both are check-and-set against the
     * version this call wrote: Vault applies the rollback only if nobody wrote
     * since, so a concurrent writer is never overwritten or deleted and no
     * payload is compared. A store without versions gets the plain behaviour.
     *
     * @param array<string, mixed>|null $previous
     */
    private function undoVaultWrite(string $identifier, #[SensitiveParameter] ?array $previous, ?int $version, bool $rowIsBeingRemoved = false): void
    {
        try {
            if ($version !== null && $this->kv instanceof AtomicKvStoreInterface) {
                if ($previous !== null) {
                    $applied = $this->kv->restoreIfCurrent($identifier, $previous, $version);
                } elseif ($rowIsBeingRemoved || !$this->registry->exists($identifier)) {
                    $applied = $this->kv->destroyIfCurrent($identifier, $version);
                } else {
                    return;
                }

                if (!$applied) {
                    $this->logger->warning(
                        'nr-vault: the rollback of a HashiCorp Vault write was skipped because the key is not at the version this call wrote (somebody wrote since, or the read was stale). The key was left as it is.',
                        ['secret' => $identifier],
                    );
                }

                return;
            }

            if ($previous !== null) {
                $this->kv->write($identifier, $previous);
            } elseif ($rowIsBeingRemoved || !$this->registry->exists($identifier)) {
                $this->kv->destroy($identifier);
            }
        } catch (Throwable $e) {
            // The original failure is the one to report.
            $this->warnRollbackFailed($identifier, $e);
        }
    }

    private function warnRollbackFailed(string $identifier, Throwable $e): void
    {
        $this->logger->warning(
            'nr-vault: restoring a HashiCorp Vault write failed; check the key. ' . $e::class . ': ' . $e->getMessage(),
            ['secret' => $identifier],
        );
    }

    /**
     * The row's stored location must be the one the current configuration
     * resolves to. After hashicorp.path changed, or on a database copy run with
     * another path, the same identifier names an unrelated key, which a write
     * would overwrite and a delete would destroy.
     *
     * @throws HashiCorpException
     */
    private function assertOwnsLocation(Secret $row): void
    {
        if ($row->getExternalReference() !== $this->kv->reference($row->getIdentifier())) {
            throw HashiCorpException::pathMismatch($row->getIdentifier());
        }
    }

    /**
     * Read the key of a row that is bound to it. What is there must be an
     * nr-vault write for this identifier; anything else is somebody else's. A
     * write that carries another installation's marker is refused. One without
     * a marker was written by 1.6.x: a row bound to Vault holds no envelope to
     * compare it with, so it is accepted on identifier, format and the row's
     * recorded location, and the next write stamps the marker.
     *
     * @return array<string, mixed>|null
     *
     * @throws HashiCorpException
     */
    private function readOwned(string $identifier): ?array
    {
        $payload = $this->kv->read($identifier);
        if ($payload !== null && (($payload['identifier'] ?? null) !== $identifier || ($payload['format'] ?? null) !== self::FORMAT || (array_key_exists('installation', $payload) && $payload['installation'] !== $this->installation->value()))) {
            throw HashiCorpException::pathTaken($identifier);
        }

        return $payload;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function restore(string $identifier, #[SensitiveParameter] array $payload): void
    {
        try {
            $this->kv->write($identifier, $payload);
        } catch (Throwable $e) {
            // The original failure is the one to report.
            $this->warnRollbackFailed($identifier, $e);
        }
    }

    /**
     * Write a new version; the version is known only for a store that reports it.
     *
     * @param array<string, mixed> $payload
     */
    private function put(string $identifier, #[SensitiveParameter] array $payload): ?int
    {
        if ($this->kv instanceof AtomicKvStoreInterface) {
            return $this->kv->writeVersioned($identifier, $payload);
        }

        $this->kv->write($identifier, $payload);

        return null;
    }

    /**
     * @param array<string, mixed> $payload
     *
     * @return array{0: array<string, mixed>|null, 1: int|null} The adopted earlier write (null when
     *                                                          the key was created now) and the KV
     *                                                          version written (null for a store
     *                                                          that does not report it)
     *
     * @throws HashiCorpException When the path belongs to something else
     */
    private function claimPath(string $identifier, #[SensitiveParameter] array $payload): array
    {
        if (!$this->kv instanceof AtomicKvStoreInterface) {
            LegacyKvStoreNotice::report();

            return $this->adopt($identifier, $payload, $this->kv->read($identifier));
        }

        // A key that vanishes between the refused create and the read is not
        // written over: the create is tried again, so whoever creates it in
        // that window meets the existence check and the ownership check too.
        for ($attempt = 1; $attempt <= self::CLAIM_ATTEMPTS; ++$attempt) {
            try {
                return [null, $this->kv->create($identifier, $payload)];
            } catch (HashiCorpException $e) {
                if ($e->getCode() !== 1794400013) {
                    throw $e;
                }
            }

            $existing = $this->kv->read($identifier);
            if ($existing !== null) {
                return $this->adopt($identifier, $payload, $existing);
            }
        }

        throw HashiCorpException::claimUnstable($identifier);
    }

    /**
     * The key exists, or not any more. It is taken over only when it is an
     * earlier nr-vault write for this identifier.
     *
     * @param array<string, mixed>      $payload
     * @param array<string, mixed>|null $existing
     *
     * @return array{0: array<string, mixed>|null, 1: int|null}
     */
    private function adopt(string $identifier, #[SensitiveParameter] array $payload, #[SensitiveParameter] ?array $existing): array
    {
        if ($existing !== null && (($existing['identifier'] ?? null) !== $identifier || ($existing['format'] ?? null) !== self::FORMAT || ($existing['installation'] ?? null) !== $this->installation->value())) {
            throw HashiCorpException::pathTaken($identifier);
        }

        return [$existing, $this->put($identifier, $payload)];
    }

    /**
     * A row that another external adapter owns stays with it. Rebinding it here
     * would write a second copy of the envelope and orphan the first; deleting
     * it would orphan that copy and leave a secret nothing refers to.
     *
     * @throws ConfigurationException
     */
    private function assertNotBoundElsewhere(?Secret $secret): void
    {
        if (!$secret instanceof Secret) {
            return;
        }

        $boundTo = $secret->getAdapter();
        if (!in_array($boundTo, ['local', self::IDENTIFIER], true)) {
            throw ConfigurationException::secretBoundToAnotherAdapter($secret->getIdentifier(), $boundTo, self::IDENTIFIER);
        }
    }

    /**
     * A new secret, or a row that exists but holds no value yet, goes to Vault;
     * a row already bound to Vault stays there; a row that was stored locally
     * stays local.
     */
    private function belongsInVault(?Secret $existing): bool
    {
        if (!$existing instanceof Secret) {
            return true;
        }

        if ($existing->getAdapter() === self::IDENTIFIER) {
            return true;
        }

        return ($existing->getEncryptedValue() ?? '') === '';
    }

    /**
     * @param bool $requireValue A missing Vault object is an error on the path
     *                           that returns plaintext. On the administrative
     *                           lookup it is not: the row comes back without an
     *                           envelope, so the operator can still delete it
     *                           and a rotation can write a new value to Vault.
     */
    private function withBackingEnvelope(?Secret $row, bool $requireValue): ?Secret
    {
        if (!$row instanceof Secret || $row->getAdapter() !== self::IDENTIFIER) {
            return $row;
        }

        $identifier = $row->getIdentifier();
        if ($row->getExternalReference() !== $this->kv->reference($identifier)) {
            if ($requireValue) {
                throw HashiCorpException::pathMismatch($identifier);
            }

            return $row;
        }

        try {
            $payload = $this->kv->read($identifier);
            if ($payload === null) {
                if ($requireValue) {
                    throw HashiCorpException::backingObjectMissing($identifier);
                }

                return $row;
            }

            if (($payload['identifier'] ?? null) !== $identifier || ($payload['format'] ?? null) !== self::FORMAT) {
                throw HashiCorpException::backingObjectMismatch($identifier);
            }

            return $this->rowWithEnvelope($row, $payload);
        } catch (HashiCorpException $e) {
            // The administrative lookup must not fail on a broken or foreign
            // object: the row comes back bare, and delete() or a rotation decides
            // what may touch that key (they refuse a foreign identifier).
            if ($requireValue || !in_array($e->getCode(), [1794400008, 1794400010], true)) {
                throw $e;
            }

            return $row;
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function rowWithEnvelope(Secret $row, #[SensitiveParameter] array $payload): Secret
    {
        $identifier = $row->getIdentifier();

        $version = $payload['encryption_version'] ?? null;
        $fields  = [];
        foreach (['encrypted_value', 'encrypted_dek', 'dek_nonce', 'value_nonce'] as $key) {
            $decoded = is_string($payload[$key] ?? null) ? base64_decode($payload[$key], true) : false;
            if ($decoded === false) {
                throw HashiCorpException::backingObjectMismatch($identifier);
            }

            $fields[$key] = $decoded;
        }

        $checksum  = $payload['value_checksum'] ?? null;
        $algorithm = $payload['encryption_algorithm'] ?? null;
        if (!is_string($checksum) || !is_string($algorithm) || !is_int($version)) {
            throw HashiCorpException::backingObjectMismatch($identifier);
        }

        return $row->withEnvelope(
            $fields['encrypted_value'],
            $fields['encrypted_dek'],
            $fields['dek_nonce'],
            $fields['value_nonce'],
            $checksum,
            $version,
            $algorithm,
        );
    }

    /**
     * Binary fields are base64 so the JSON body is lossless.
     *
     * @return array<string, mixed>
     */
    private function toPayload(Secret $secret): array
    {
        return [
            'format'               => self::FORMAT,
            'installation'         => $this->installation->value(),
            'identifier'           => $secret->getIdentifier(),
            'encrypted_value'      => base64_encode($secret->getEncryptedValue() ?? ''),
            'encrypted_dek'        => base64_encode($secret->getEncryptedDek()),
            'dek_nonce'            => base64_encode($secret->getDekNonce()),
            'value_nonce'          => base64_encode($secret->getValueNonce()),
            'value_checksum'       => $secret->getValueChecksum(),
            'encryption_version'   => $secret->getEncryptionVersion(),
            'encryption_algorithm' => $secret->getEncryptionAlgorithm(),
        ];
    }

    /**
     * @return array{string, string, string, string, string, int, string}
     */
    private function envelopeOf(Secret $secret): array
    {
        return [
            $secret->getEncryptedValue() ?? '',
            $secret->getEncryptedDek(),
            $secret->getDekNonce(),
            $secret->getValueNonce(),
            $secret->getValueChecksum(),
            $secret->getEncryptionVersion(),
            $secret->getEncryptionAlgorithm(),
        ];
    }
}
