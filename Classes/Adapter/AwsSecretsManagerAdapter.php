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
use Netresearch\NrVault\Exception\AwsSecretsManagerException;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Storage\Aws\AwsSecretsEndpoint;
use Netresearch\NrVault\Storage\Aws\AwsSecretStoreInterface;
use Throwable;

use function in_array;
use function is_int;
use function is_string;

/**
 * Stores the encryption envelope of a secret in AWS Secrets Manager.
 *
 * Same design as {@see HashiCorpAdapter} (ADR-053), applied to a second store
 * (ADR-054). The registry row in the TYPO3 database stays: it carries the owner,
 * the group tiers, the metadata, the counters and a pointer to the AWS secret,
 * so listing, access control, expiry and the audit trail work exactly as for a
 * local secret. What moves is the envelope: encrypted value, wrapped data key,
 * nonces and checksum. The value is still encrypted by nr-vault before it leaves
 * the process; AWS holds ciphertext it cannot read, and a stolen database holds
 * no envelope at all.
 *
 * Each row routes by its own `adapter` column. A secret stored locally before
 * the setting changed stays local and keeps working; only a secret that does not
 * exist yet (or exists without a value, the FormEngine creation path) goes to
 * AWS. A row bound to a different external adapter is refused rather than
 * rebound: moving it would leave the other store's object behind.
 *
 * Write order is AWS first, then the row. A crash between the two leaves an
 * unreferenced AWS secret, which the next store of the same identifier
 * overwrites. A delete removes the AWS secret first and the row second, so a
 * delete that fails half-way can be repeated.
 */
final readonly class AwsSecretsManagerAdapter implements VaultAdapterInterface
{
    public const IDENTIFIER = 'aws';

    private const FORMAT = 1;

    private const CLAIM_ATTEMPTS = 3;

    public function __construct(
        private LocalEncryptionAdapter $registry,
        private AwsSecretStoreInterface $store,
        private ExtensionConfigurationInterface $configuration,
    ) {}

    public function getIdentifier(): string
    {
        return self::IDENTIFIER;
    }

    public function isAvailable(): bool
    {
        if (!$this->store->isSdkInstalled()) {
            return false;
        }

        try {
            AwsSecretsEndpoint::fromConfig($this->configuration->getAwsConfig());
        } catch (AwsSecretsManagerException) {
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

        // A write without a value has nothing to put into AWS. Restoring a
        // valueless row that is, or just was, bound to AWS also removes the
        // value written since, so the restore is complete; the previous object
        // is put back if the row write fails.
        if (($secret->getEncryptedValue() ?? '') === '') {
            $boundToAws = $secret->getAdapter() === self::IDENTIFIER
                || ($existing instanceof Secret && $existing->getAdapter() === self::IDENTIFIER);
            $previous = $boundToAws ? $this->store->read($identifier) : null;
            if ($boundToAws) {
                $this->store->destroy($identifier);
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

        if (!$this->belongsInAws($existing)) {
            return $this->registry->store($secret, $persistGroupRelations);
        }

        $payload = $this->toPayload($secret);
        $bound   = $existing instanceof Secret && $existing->getAdapter() === self::IDENTIFIER;

        // A row bound to AWS owns its secret. For any other row the name may
        // belong to somebody else: the secret is created, never overwritten,
        // unless it is an earlier write of nr-vault for this very identifier
        // (an unreferenced one left by a crash). Every write reports the
        // version id it created; taking a write back is applied only while the
        // secret is still at that version, so a concurrent writer is neither
        // overwritten nor deleted and no payload is compared.
        $previous = $bound ? $this->store->read($identifier) : null;
        if ($previous !== null) {
            $version = $this->store->write($identifier, $payload);
        } else {
            [$previous, $version] = $this->createOrAdopt($identifier, $payload);
        }

        $row = $secret->withExternalStorage(self::IDENTIFIER, $this->store->reference($identifier));

        try {
            return $this->registry->store($row, $persistGroupRelations)->withEnvelope(...$this->envelopeOf($secret));
        } catch (Throwable $e) {
            $this->undoAwsWrite($identifier, $previous, $version);

            throw $e;
        }
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
            $previous = $this->store->read($identifier);
            $this->store->destroy($identifier);
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
     * Take back an AWS write after the row could not be written. A first insert
     * removes the secret it created, unless a row for the identifier exists by
     * now: a concurrent create that won the unique key owns it. An update puts
     * the previous envelope back as a new version. Both apply only while the
     * secret is still at the version this call wrote.
     *
     * @param array<string, mixed>|null $previous
     */
    private function undoAwsWrite(string $identifier, ?array $previous, string $version): void
    {
        try {
            if ($previous !== null) {
                $this->store->restoreIfCurrent($identifier, $previous, $version);
            } elseif (!$this->registry->exists($identifier)) {
                $this->store->destroyIfCurrent($identifier, $version);
            }
        } catch (Throwable) {
            // The original failure is the one to report.
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function restore(string $identifier, array $payload): void
    {
        try {
            $this->store->write($identifier, $payload);
        } catch (Throwable) {
            // The original failure is the one to report.
        }
    }

    /**
     * @param array<string, mixed> $payload
     *
     * @return array{0: array<string, mixed>|null, 1: string} The adopted earlier write (null when the
     *                                                        secret was created now) and the version id
     *                                                        written
     *
     * @throws AwsSecretsManagerException When the name belongs to something else
     */
    private function createOrAdopt(string $identifier, array $payload): array
    {
        // A secret that vanishes between the refused create and the read is
        // not written over: the create is tried again, so whoever creates it in
        // that window meets the existence check and the ownership check too.
        for ($attempt = 1; $attempt <= self::CLAIM_ATTEMPTS; ++$attempt) {
            try {
                return [null, $this->store->create($identifier, $payload)];
            } catch (AwsSecretsManagerException $e) {
                if ($e->getCode() !== 1794500012) {
                    throw $e;
                }
            }

            try {
                $existing = $this->store->read($identifier);
            } catch (AwsSecretsManagerException $e) {
                // Present, but not a JSON object: not ours either.
                throw $e->getCode() === 1794500008 ? AwsSecretsManagerException::nameTaken($identifier) : $e;
            }

            if ($existing === null) {
                continue;
            }

            if (($existing['identifier'] ?? null) !== $identifier || ($existing['format'] ?? null) !== self::FORMAT) {
                throw AwsSecretsManagerException::nameTaken($identifier);
            }

            return [$existing, $this->store->write($identifier, $payload)];
        }

        throw AwsSecretsManagerException::claimUnstable($identifier);
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
     * A new secret, or a row that exists but holds no value yet, goes to AWS; a
     * row already bound to AWS stays there; a row that was stored locally stays
     * local.
     */
    private function belongsInAws(?Secret $existing): bool
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
     * @param bool $requireValue A missing AWS secret is an error on the path
     *                           that returns plaintext. On the administrative
     *                           lookup it is not: the row comes back without an
     *                           envelope, so the operator can still delete it
     *                           and a rotation can write a new value to AWS.
     */
    private function withBackingEnvelope(?Secret $row, bool $requireValue): ?Secret
    {
        if (!$row instanceof Secret || $row->getAdapter() !== self::IDENTIFIER) {
            return $row;
        }

        $identifier = $row->getIdentifier();
        $payload    = $this->store->read($identifier);
        if ($payload === null) {
            if ($requireValue) {
                throw AwsSecretsManagerException::backingObjectMissing($identifier);
            }

            return $row;
        }

        if (($payload['identifier'] ?? null) !== $identifier || ($payload['format'] ?? null) !== self::FORMAT) {
            throw AwsSecretsManagerException::backingObjectMismatch($identifier);
        }

        $version = $payload['encryption_version'] ?? null;
        $fields  = [];
        foreach (['encrypted_value', 'encrypted_dek', 'dek_nonce', 'value_nonce'] as $key) {
            $decoded = is_string($payload[$key] ?? null) ? base64_decode($payload[$key], true) : false;
            if ($decoded === false) {
                throw AwsSecretsManagerException::backingObjectMismatch($identifier);
            }

            $fields[$key] = $decoded;
        }

        $checksum  = $payload['value_checksum'] ?? null;
        $algorithm = $payload['encryption_algorithm'] ?? null;
        if (!is_string($checksum) || !is_string($algorithm) || !is_int($version)) {
            throw AwsSecretsManagerException::backingObjectMismatch($identifier);
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
     * Binary fields are base64 so the JSON document is lossless.
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
