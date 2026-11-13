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
use Netresearch\NrVault\Exception\HashiCorpException;
use Netresearch\NrVault\Storage\HashiCorp\HashiCorpEndpoint;
use Netresearch\NrVault\Storage\HashiCorp\KvStoreInterface;
use Throwable;

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
final readonly class HashiCorpAdapter implements VaultAdapterInterface
{
    public const IDENTIFIER = 'hashicorp';

    private const FORMAT = 1;

    public function __construct(
        private LocalEncryptionAdapter $registry,
        private KvStoreInterface $kv,
        private ExtensionConfigurationInterface $configuration,
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
        $existing = $this->registry->retrieveIncludingDisabled($secret->getIdentifier());

        $identifier = $secret->getIdentifier();

        // A write without a value (restoring a row that had none) has nothing
        // to put into Vault and must not mark the row as Vault-backed.
        if (($secret->getEncryptedValue() ?? '') === '' || !$this->belongsInVault($existing)) {
            return $this->registry->store($secret, $persistGroupRelations);
        }

        $this->kv->write($identifier, $this->toPayload($secret));

        $row = $secret->withExternalStorage(self::IDENTIFIER, $this->kv->reference($identifier));

        try {
            return $this->registry->store($row, $persistGroupRelations)->withEnvelope(...$this->envelopeOf($secret));
        } catch (Throwable $e) {
            // A failed first insert must not leave a value in Vault that no
            // row refers to. An update keeps its object: the previous version
            // is the row's last good state.
            if (!$existing instanceof Secret) {
                try {
                    $this->kv->destroy($identifier);
                } catch (Throwable) {
                    // The original failure is the one to report.
                }
            }

            throw $e;
        }
    }

    public function retrieve(string $identifier): ?Secret
    {
        return $this->withBackingEnvelope($this->registry->retrieve($identifier), true);
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
        if ($row instanceof Secret && $row->getAdapter() === self::IDENTIFIER) {
            $this->kv->destroy($identifier);
        }

        $this->registry->delete($identifier);
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
        $payload    = $this->kv->read($identifier);
        if ($payload === null) {
            if ($requireValue) {
                throw HashiCorpException::backingObjectMissing($identifier);
            }

            return $row;
        }

        if (($payload['identifier'] ?? null) !== $identifier || ($payload['format'] ?? null) !== self::FORMAT) {
            throw HashiCorpException::backingObjectMismatch($identifier);
        }

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
