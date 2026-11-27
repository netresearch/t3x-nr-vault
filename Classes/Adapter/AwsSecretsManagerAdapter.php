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
use Netresearch\NrVault\Storage\Aws\AwsVersionedSecretStoreInterface;
use Netresearch\NrVault\Storage\ExternalEnvelopeCodec;
use Netresearch\NrVault\Storage\ExternalStoreJournal;
use Netresearch\NrVault\Storage\InstallationMarker;
use Psr\Log\LoggerInterface;
use SensitiveParameter;
use Throwable;

use function array_key_exists;
use function in_array;
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
final readonly class AwsSecretsManagerAdapter implements CreateCompensatingAdapterInterface, VaultAdapterInterface
{
    public const IDENTIFIER = 'aws';

    private const FORMAT = ExternalEnvelopeCodec::FORMAT;

    private const CLAIM_ATTEMPTS = 3;

    public function __construct(
        private LocalEncryptionAdapter $registry,
        private AwsSecretStoreInterface $store,
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
            $previous = null;
            if ($boundToAws) {
                $this->assertOwnsLocation($existing instanceof Secret && $existing->getAdapter() === self::IDENTIFIER ? $existing : $secret);
                // This is also the compensation of a failed audit write on the
                // FormEngine completion path. A store recorded in this request is
                // taken back exactly: a secret it created is destroyed, one it
                // took over is put back.
                $entry = $this->journal->take(self::IDENTIFIER, $identifier);
                if ($entry !== null) {
                    $this->undoJournalled($identifier, $entry);
                } else {
                    $previous = $this->readOwned($identifier, false)['data'] ?? null;
                    $this->store->destroy($identifier);
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

        if (!$this->belongsInAws($existing)) {
            return $this->registry->store($secret, $persistGroupRelations);
        }

        $payload = ExternalEnvelopeCodec::encode($secret, $this->installation->value());
        $bound   = $existing instanceof Secret && $existing->getAdapter() === self::IDENTIFIER;

        // A row bound to AWS owns its secret. For any other row the name may
        // belong to somebody else: the secret is created, never overwritten,
        // unless it is an earlier write of nr-vault for this very identifier
        // (an unreferenced one left by a crash). Every write reports the
        // version id it created; taking a write back is applied only while the
        // secret is still at that version, and no payload is compared. The
        // checks and their remaining windows are described in ADR-054.
        // The previous document and its version id come from one read, so the
        // rollback can move AWSCURRENT back to exactly that version (#567).
        $previous = null;
        if ($bound) {
            $this->assertOwnsLocation($existing);
            $previous = $this->readOwned($identifier, true);
        }

        if ($previous !== null) {
            $version = $this->store->write($identifier, $payload);
        } else {
            [$previous, $version] = $this->createOrAdopt($identifier, $payload);
        }

        $previousData    = $previous['data'] ?? null;
        $previousVersion = $previous['versionId'] ?? null;

        $row = $secret->withExternalStorage(self::IDENTIFIER, $this->store->reference($identifier));
        $this->journal->remember(self::IDENTIFIER, $identifier, $previousData, $version, $previousVersion);

        try {
            return $this->registry->store($row, $persistGroupRelations)->withEnvelope(...ExternalEnvelopeCodec::envelopeOf($secret));
        } catch (Throwable $e) {
            $this->journal->forget(self::IDENTIFIER, $identifier);
            $this->undoAwsWrite($identifier, $previousData, $version, $previousVersion);

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

        $rolledBack = $this->undoJournalled($identifier, $entry);
        if (!$rolledBack) {
            // The secret is at a version somebody else wrote since, or the
            // conditional move failed without applying and the value this call
            // wrote is still there. Its row stays, so whatever AWS holds keeps
            // its pointer. A rollback that throws is not caught here: it
            // reaches VaultService, which reports the inconsistency.
            $this->logger->warning(
                'nr-vault: the row was kept because the AWS write that is being compensated was not taken back (the secret changed since, or the conditional move failed without applying).',
                ['secret' => $identifier],
            );

            return;
        }

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

            try {
                $previous = $this->readOwned($identifier, false)['data'] ?? null;
            } catch (AwsSecretsManagerException $e) {
                // The row owns this secret by its recorded location; a value that
                // is not even a JSON object must not make the row undeletable.
                if ($e->getCode() !== 1794500008) {
                    throw $e;
                }
            }

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
     * Take back the AWS write recorded in the journal, while the row is being
     * removed. This runs as the compensation of a failed audit write, so a
     * rollback that fails is thrown: VaultService then reports the mutation
     * that persisted without an audit record (#567).
     *
     * @param array{previous: array<string, mixed>|null, version: int|string|null, previousVersion: int|string|null} $entry
     *
     * @throws Throwable When the rollback fails
     */
    private function undoJournalled(string $identifier, #[SensitiveParameter] array $entry): bool
    {
        return $this->undoAwsWrite(
            $identifier,
            $entry['previous'],
            is_string($entry['version']) ? $entry['version'] : null,
            is_string($entry['previousVersion']) ? $entry['previousVersion'] : null,
            true,
            true,
        );
    }

    /**
     * Take back an AWS write after the row could not be written. A first insert
     * removes the secret it created, unless a row for the identifier exists by
     * now: a concurrent create that won the unique key owns it. An update moves
     * AWSCURRENT back to the version it replaced (or, without that version's
     * id, puts the previous envelope back as a new version). Both apply only
     * while the secret is still at the version this call wrote.
     *
     * @param array<string, mixed>|null $previous
     * @param bool                      $rethrow  Throw a failed rollback instead of reporting it as a warning
     *
     * @return bool True when the write was taken back or there was nothing to take back; false when the
     *              rollback was skipped or failed, so a caller that removes the row keeps it
     */
    private function undoAwsWrite(string $identifier, #[SensitiveParameter] ?array $previous, ?string $version, ?string $previousVersion = null, bool $rowIsBeingRemoved = false, bool $rethrow = false): bool
    {
        try {
            $applied = true;
            if ($version !== null && $previous !== null) {
                $applied = $previousVersion !== null && $this->store instanceof AwsVersionedSecretStoreInterface
                    ? $this->store->restoreToVersionIfCurrent($identifier, $previous, $version, $previousVersion)
                    : $this->store->restoreIfCurrent($identifier, $previous, $version);
            } elseif ($version !== null && ($rowIsBeingRemoved || !$this->registry->exists($identifier))) {
                $applied = $this->store->destroyIfCurrent($identifier, $version);
            }

            if (!$applied) {
                $this->logger->warning(
                    'nr-vault: the rollback of an AWS Secrets Manager write was skipped: the secret is not at the version this call wrote (somebody wrote since, or the read was stale), or the conditional move failed without applying. The secret was left as it is.',
                    ['secret' => $identifier],
                );
            }

            return $applied;
        } catch (Throwable $e) {
            if ($rethrow) {
                throw $e;
            }

            // The original failure is the one to report; a failed rollback is
            // not an applied one.
            $this->warnRollbackFailed($identifier, $e);

            return false;
        }
    }

    private function warnRollbackFailed(string $identifier, Throwable $e): void
    {
        $this->logger->warning(
            'nr-vault: restoring an AWS Secrets Manager write failed; check the secret. ' . $e::class . ': ' . $e->getMessage(),
            ['secret' => $identifier],
        );
    }

    /**
     * Put a value back that this call destroyed a moment ago. It is a create,
     * not a write: AWS deletes asynchronously, and the store's create waits out
     * that deletion (#539). A name that exists again is not written into: it
     * belongs to another writer, or AWS answered the deletion window with
     * ResourceExistsException instead of the assumed InvalidRequestException.
     *
     * @param array<string, mixed> $payload
     */
    private function restore(string $identifier, #[SensitiveParameter] array $payload): void
    {
        try {
            $this->store->create($identifier, $payload);
        } catch (AwsSecretsManagerException $e) {
            // The original failure is the one to report.
            if ($e->getCode() === 1794500012) {
                $this->logger->warning(
                    'nr-vault: the AWS Secrets Manager value destroyed by this call was not put back, because a secret of that name exists (another writer, or AWS has not finished the deletion). Check the secret and its row.',
                    ['secret' => $identifier],
                );

                return;
            }

            $this->warnRollbackFailed($identifier, $e);
        } catch (Throwable $e) {
            $this->warnRollbackFailed($identifier, $e);
        }
    }

    /**
     * @param array<string, mixed> $payload
     *
     * @return array{0: array{data: array<string, mixed>, versionId: string|null}|null, 1: string} The adopted earlier
     *                                                                                             write with its version
     *                                                                                             id (null when the secret
     *                                                                                             was created now) and the
     *                                                                                             version id written
     *
     * @throws AwsSecretsManagerException When the name belongs to something else
     */
    private function createOrAdopt(string $identifier, #[SensitiveParameter] array $payload): array
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
                $existing = $this->readCurrent($identifier);
            } catch (AwsSecretsManagerException $e) {
                // Present, but not a JSON object: not ours either.
                throw $e->getCode() === 1794500008 ? AwsSecretsManagerException::nameTaken($identifier) : $e;
            }

            if ($existing === null) {
                continue;
            }

            $document = $existing['data'];
            if (($document['identifier'] ?? null) !== $identifier || ($document['format'] ?? null) !== self::FORMAT || ($document['installation'] ?? null) !== $this->installation->value()) {
                throw AwsSecretsManagerException::nameTaken($identifier);
            }

            return [$existing, $this->store->write($identifier, $payload)];
        }

        throw AwsSecretsManagerException::claimUnstable($identifier);
    }

    /**
     * The row's stored location must be the one the current configuration
     * resolves to. After the region or the prefix changed, or on a database copy
     * run with other settings, the same identifier names an unrelated secret,
     * which a write would overwrite and a delete would destroy.
     *
     * @throws AwsSecretsManagerException
     */
    private function assertOwnsLocation(Secret $row): void
    {
        if ($row->getExternalReference() !== $this->store->reference($row->getIdentifier())) {
            throw AwsSecretsManagerException::pathMismatch($row->getIdentifier());
        }
    }

    /**
     * Read the secret of a row that is bound to it. What is there must be an
     * nr-vault write for this identifier; anything else is somebody else's. A
     * write that carries another installation's marker is refused. One without a
     * marker was written by an earlier version: a row bound to AWS holds no
     * envelope to compare it with, so it is accepted on identifier, format and
     * the row's recorded location, and the next write stamps the marker.
     *
     * @return array{data: array<string, mixed>, versionId: string|null}|null The document and the version it was read from
     *
     * @throws AwsSecretsManagerException
     */
    private function readOwned(string $identifier, bool $withVersion): ?array
    {
        if ($withVersion) {
            $read = $this->readCurrent($identifier);
        } else {
            $data = $this->store->read($identifier);
            $read = $data === null ? null : ['data' => $data, 'versionId' => null];
        }

        $payload = $read['data'] ?? null;
        if ($payload !== null && (($payload['identifier'] ?? null) !== $identifier || ($payload['format'] ?? null) !== self::FORMAT || (array_key_exists('installation', $payload) && $payload['installation'] !== $this->installation->value()))) {
            throw AwsSecretsManagerException::nameTaken($identifier);
        }

        return $read;
    }

    /**
     * The document and, from the same response, its version id when the store
     * can move back to a version (null otherwise).
     *
     * @return array{data: array<string, mixed>, versionId: string|null}|null
     *
     * @throws AwsSecretsManagerException
     */
    private function readCurrent(string $identifier): ?array
    {
        if ($this->store instanceof AwsVersionedSecretStoreInterface) {
            return $this->store->readWithVersion($identifier);
        }

        $data = $this->store->read($identifier);

        return $data === null ? null : ['data' => $data, 'versionId' => null];
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
        if ($row->getExternalReference() !== $this->store->reference($identifier)) {
            if ($requireValue) {
                throw AwsSecretsManagerException::pathMismatch($identifier);
            }

            return $row;
        }

        try {
            $payload = $this->store->read($identifier);
            if ($payload === null) {
                if ($requireValue) {
                    throw AwsSecretsManagerException::backingObjectMissing($identifier);
                }

                return $row;
            }

            return ExternalEnvelopeCodec::decode($row, $payload, AwsSecretsManagerException::backingObjectMismatch(...));
        } catch (AwsSecretsManagerException $e) {
            // The administrative lookup must not fail on an unreadable or foreign
            // object: the row comes back bare, and delete() or a rotation decides
            // what may touch that secret (they refuse a foreign identifier).
            if ($requireValue || !in_array($e->getCode(), [1794500008, 1794500010], true)) {
                throw $e;
            }

            return $row;
        }
    }
}
