<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service;

use DateTimeInterface;
use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\EncryptedData;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Domain\Dto\SecretDetails;
use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Domain\Dto\SecretMetadata;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Event\SecretAccessedEvent;
use Netresearch\NrVault\Event\SecretCreatedEvent;
use Netresearch\NrVault\Event\SecretDeletedEvent;
use Netresearch\NrVault\Event\SecretRotatedEvent;
use Netresearch\NrVault\Event\SecretUpdatedEvent;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\AuditWriteException;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Exception\SecretExpiredException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Http\VaultHttpClientFactoryInterface;
use Netresearch\NrVault\Http\VaultHttpClientInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Utility\IdentifierValidator;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use SensitiveParameter;
use Throwable;
use TYPO3\CMS\Core\SingletonInterface;

/**
 * Main vault service implementation.
 */
final class VaultService implements VaultServiceInterface, SingletonInterface
{
    /** @var array<string, string> Request-scoped cache */
    private array $cache = [];

    public function __construct(
        private readonly VaultAdapterInterface $adapter,
        private readonly EncryptionServiceInterface $encryptionService,
        private readonly AccessControlServiceInterface $accessControlService,
        private readonly AuditLogServiceInterface $auditLogService,
        private readonly ExtensionConfigurationInterface $configuration,
        private readonly VaultHttpClientFactoryInterface $httpClientFactory,
        private readonly ?EventDispatcherInterface $eventDispatcher = null,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    public function __destruct()
    {
        $this->clearCache();
    }

    /**
     * @param array<string, mixed> $options
     */
    public function store(string $identifier, #[SensitiveParameter] string $secret, array $options = []): void
    {
        try {
            IdentifierValidator::validate($identifier);
            if ($secret === '') {
                throw ValidationException::emptySecret();
            }

            $existing = $this->adapter->retrieve($identifier);

            $this->assertWritePermission($identifier, $existing);

            $encrypted = $this->encryptionService->encrypt($secret, $identifier);
            $secretEntity = $this->buildSecretEntity($identifier, $encrypted, $options, $existing);

            // Capture the stored instance so the SecretCreatedEvent below
            // sees the freshly-assigned UID — the readonly entity passed in
            // has uid=null on create, the adapter returns the uid-bearing
            // instance from the repository's INSERT.
            $secretEntity = $this->adapter->store($secretEntity);

            // SEC-3 atomicity: the mutation and its tamper-evident audit
            // entry MUST be all-or-nothing. A single shared DB transaction is
            // NOT usable here — AuditLogService manages its own transaction
            // lifecycle (SQLite `BEGIN EXCLUSIVE`/`COMMIT`, MySQL advisory
            // GET_LOCK), so nesting log() inside an outer transaction would
            // either error or prematurely commit the mutation. We therefore
            // compensate: if the audit write throws, revert the adapter change
            // so a secret never persists without an audit record.
            try {
                $this->auditLogService->log(
                    $identifier,
                    $existing instanceof Secret ? AuditAction::Update->value : AuditAction::Create->value,
                    true,
                    null,
                    null,
                    $existing?->getValueChecksum(),
                    $encrypted->valueChecksum,
                );
            } catch (AuditWriteException $auditException) {
                $this->compensateAuditFailure(
                    $identifier,
                    function () use ($existing, $identifier): void {
                        if ($existing instanceof Secret) {
                            // Update: restore the prior encrypted envelope/version.
                            $this->adapter->store($existing);
                        } else {
                            // Create: remove the just-inserted record.
                            $this->adapter->delete($identifier);
                        }
                    },
                    $auditException,
                );
            }

            $this->dispatchStoreEvent($identifier, $secretEntity, !$existing instanceof Secret);

            unset($this->cache[$identifier]);
        } finally {
            // Securely wipe the plaintext even if an exception occurred
            sodium_memzero($secret);
        }
    }

    public function retrieve(string $identifier): ?string
    {
        // Check request-scoped cache
        if ($this->configuration->isCacheEnabled() && isset($this->cache[$identifier])) {
            return $this->cache[$identifier];
        }

        $secret = $this->adapter->retrieve($identifier);
        if (!$secret instanceof Secret) {
            return null;
        }

        // Check access
        if (!$this->accessControlService->canRead($secret)) {
            $this->auditLogService->log($identifier, AuditAction::AccessDenied->value, false, 'Read access denied');

            throw AccessDeniedException::forIdentifier($identifier, 'insufficient permissions');
        }

        // Check expiration
        if ($secret->isExpired()) {
            $this->auditLogService->log($identifier, AuditAction::Read->value, false, 'Secret has expired');

            throw SecretExpiredException::forIdentifier($identifier, $secret->getExpiresAt());
        }

        // Decrypt
        try {
            $plaintext = $this->encryptionService->decrypt(
                $secret->getEncryptedValue() ?? '',
                $secret->getEncryptedDek(),
                $secret->getDekNonce(),
                $secret->getValueNonce(),
                $identifier,
            );
        } catch (EncryptionException $e) {
            $this->auditLogService->log($identifier, AuditAction::Read->value, false, 'Decryption failed: ' . $e->getMessage());

            throw $e;
        }

        // Update read statistics atomically (avoids full entity save + MM table churn)
        $uid = $secret->getUid();
        if ($uid !== null) {
            $this->adapter->incrementReadCount($uid);
        }

        // Log success (can be disabled for high-throughput scenarios)
        if ($this->configuration->isAuditReadsEnabled()) {
            $this->auditLogService->log($identifier, AuditAction::Read->value, true);
        }

        // Dispatch PSR-14 event
        $this->eventDispatcher?->dispatch(new SecretAccessedEvent(
            $identifier,
            $this->accessControlService->getCurrentActorUid(),
            $secret->getContext(),
        ));

        // Cache for this request
        if ($this->configuration->isCacheEnabled()) {
            $this->cache[$identifier] = $plaintext;
        }

        return $plaintext;
    }

    public function exists(string $identifier): bool
    {
        return $this->adapter->exists($identifier);
    }

    public function delete(string $identifier, string $reason = ''): void
    {
        $secret = $this->adapter->retrieve($identifier);
        if (!$secret instanceof Secret) {
            throw SecretNotFoundException::forIdentifier($identifier);
        }

        // Check access
        if (!$this->accessControlService->canDelete($secret)) {
            $this->auditLogService->log($identifier, AuditAction::AccessDenied->value, false, 'Delete access denied');

            throw AccessDeniedException::forIdentifier($identifier, 'delete permission denied');
        }

        $hashBefore = $secret->getValueChecksum();

        // Delete
        $this->adapter->delete($identifier);

        // SEC-3 atomicity (compensating rollback — see store() for rationale):
        // if the audit write fails, re-insert the just-deleted record so a
        // delete never persists without a tamper-evident audit entry.
        try {
            $this->auditLogService->log(
                $identifier,
                AuditAction::Delete->value,
                true,
                null,
                $reason,
                $hashBefore,
            );
        } catch (AuditWriteException $auditException) {
            $this->compensateAuditFailure(
                $identifier,
                function () use ($secret): void {
                    $this->adapter->store($secret);
                },
                $auditException,
            );
        }

        // Dispatch PSR-14 event
        $this->eventDispatcher?->dispatch(new SecretDeletedEvent(
            $identifier,
            $this->accessControlService->getCurrentActorUid(),
            $reason,
        ));

        // Clear cache
        unset($this->cache[$identifier]);
    }

    public function rotate(string $identifier, #[SensitiveParameter] string $newSecret, string $reason = ''): void
    {
        $secret = $this->adapter->retrieve($identifier);
        if (!$secret instanceof Secret) {
            throw SecretNotFoundException::forIdentifier($identifier);
        }

        // Check access
        if (!$this->accessControlService->canWrite($secret)) {
            $this->auditLogService->log($identifier, AuditAction::AccessDenied->value, false, 'Rotate access denied');

            throw AccessDeniedException::forIdentifier($identifier, 'rotate permission denied');
        }

        if ($newSecret === '') {
            throw ValidationException::emptySecret();
        }

        try {
            $hashBefore = $secret->getValueChecksum();

            // Keep the pre-rotation instance for compensating rollback.
            $previousSecret = $secret;

            // Encrypt the new secret
            $encrypted = $this->encryptionService->encrypt($newSecret, $identifier);

            // Rotate value envelope, bump version, stamp rotation time
            $secret = $secret->withValueRotation($encrypted, time());

            // Store; capture the returned instance for the rotated event
            // (UPDATE returns the same instance unchanged, but use the
            // result to stay consistent with the create path).
            $secret = $this->adapter->store($secret);

            // SEC-3 atomicity (compensating rollback — see store() for
            // rationale): if the audit write fails, restore the previous
            // envelope/version so a rotation never persists without a
            // tamper-evident audit entry.
            try {
                $this->auditLogService->log(
                    $identifier,
                    AuditAction::Rotate->value,
                    true,
                    null,
                    $reason,
                    $hashBefore,
                    $encrypted->valueChecksum,
                );
            } catch (AuditWriteException $auditException) {
                $this->compensateAuditFailure(
                    $identifier,
                    function () use ($previousSecret): void {
                        $this->adapter->store($previousSecret);
                    },
                    $auditException,
                );
            }

            // Dispatch PSR-14 event
            $this->eventDispatcher?->dispatch(new SecretRotatedEvent(
                $identifier,
                $secret->getVersion(),
                $this->accessControlService->getCurrentActorUid(),
                $reason,
            ));

            // Clear cache
            unset($this->cache[$identifier]);
        } finally {
            // Securely wipe the plaintext even if an exception occurred
            sodium_memzero($newSecret);
        }
    }

    public function list(?string $pattern = null): array
    {
        $filters = $pattern !== null ? new SecretFilters(prefix: $pattern) : null;

        $allSecrets = $this->adapter->listSecrets($filters);

        // Build metadata array for accessible secrets
        $secrets = [];
        foreach ($allSecrets as $secret) {
            // Check access
            if (!$this->accessControlService->canRead($secret)) {
                continue;
            }

            $secrets[] = new SecretMetadata(
                identifier: $secret->getIdentifier(),
                ownerUid: $secret->getOwnerUid(),
                createdAt: $secret->getCrdate(),
                updatedAt: $secret->getTstamp(),
                readCount: $secret->getReadCount(),
                lastReadAt: $secret->getLastReadAt(),
                description: $secret->getDescription(),
                version: $secret->getVersion(),
                metadata: $secret->getMetadata(),
            );
        }

        return $secrets;
    }

    public function getMetadata(string $identifier): SecretDetails
    {
        $secret = $this->adapter->retrieve($identifier);
        if (!$secret instanceof Secret) {
            throw SecretNotFoundException::forIdentifier($identifier);
        }

        // Check access
        if (!$this->accessControlService->canRead($secret)) {
            $this->auditLogService->log($identifier, AuditAction::AccessDenied->value, false, 'Metadata access denied');

            throw AccessDeniedException::forIdentifier($identifier, 'insufficient permissions');
        }

        return SecretDetails::fromSecret($secret);
    }

    public function http(): VaultHttpClientInterface
    {
        return $this->httpClientFactory->create($this);
    }

    /**
     * Clear the request-scoped cache.
     */
    public function clearCache(): void
    {
        // Securely wipe cached values via reference to avoid copy-on-write
        foreach ($this->cache as &$value) {
            sodium_memzero($value);
        }
        unset($value);
        $this->cache = [];
    }

    /**
     * Compensate a failed audit write by reverting the just-applied mutation,
     * then re-throw the original `AuditWriteException` so the caller sees the
     * real cause.
     *
     * The revert is itself guarded: if it throws (e.g. the same DB fault that
     * broke the audit write also breaks the revert), the mutation has persisted
     * WITHOUT a tamper-evident audit record — a violation of the SEC-3
     * all-or-nothing invariant. We log that inconsistency at CRITICAL (with the
     * identifier, never the secret value) so it can be reconciled, chain the
     * revert failure onto the original exception as `previous`, and still
     * surface the original `AuditWriteException` as the thrown type.
     *
     * @param callable():void $revert Reapplies the pre-mutation adapter state.
     */
    private function compensateAuditFailure(
        string $identifier,
        callable $revert,
        AuditWriteException $auditException,
    ): never {
        try {
            $revert();
        } catch (Throwable $revertFailure) {
            $this->logger?->critical(
                'Vault inconsistency: mutation persisted without an audit record; '
                . 'the compensating rollback also failed. Manual reconciliation required.',
                [
                    'identifier' => $identifier,
                    'auditError' => $auditException->getMessage(),
                    'rollbackError' => $revertFailure->getMessage(),
                ],
            );

            unset($this->cache[$identifier]);

            throw new AuditWriteException(
                $auditException->getMessage(),
                $auditException->getCode(),
                $revertFailure,
            );
        }

        unset($this->cache[$identifier]);

        throw $auditException;
    }

    /**
     * Verify the current actor can create-or-update this secret. Logs the
     * denial and throws `AccessDeniedException` on rejection.
     *
     * `$existing === null` is treated as a create attempt; a non-null
     * `$existing` is treated as an update attempt.
     */
    private function assertWritePermission(string $identifier, ?Secret $existing): void
    {
        if (!$existing instanceof Secret) {
            if (!$this->accessControlService->canCreate()) {
                $this->auditLogService->log($identifier, AuditAction::AccessDenied->value, false, 'Create access denied');

                throw AccessDeniedException::forIdentifier($identifier, 'create permission denied');
            }

            return;
        }
        if (!$this->accessControlService->canWrite($existing)) {
            $this->auditLogService->log($identifier, AuditAction::AccessDenied->value, false, 'Update access denied');

            throw AccessDeniedException::forIdentifier($identifier, 'update permission denied');
        }
    }

    /**
     * Assemble the `Secret` aggregate from the encryption output + options.
     *
     * `$existing === null` → create path (new entity, new crdate/cruserId).
     * `$existing !== null` → update path (preserve uid/crdate/version).
     *
     * @param array<string, mixed> $options
     */
    private function buildSecretEntity(
        string $identifier,
        EncryptedData $encrypted,
        array $options,
        ?Secret $existing,
    ): Secret {
        $optional = $this->collectOptionalFields($options);

        return new Secret(
            identifier: $identifier,
            uid: $existing?->getUid(),
            scopePid: $optional['scopePid'],
            description: $optional['description'],
            encryptedValue: $encrypted->encryptedValue,
            encryptedDek: $encrypted->encryptedDek,
            dekNonce: $encrypted->dekNonce,
            valueNonce: $encrypted->valueNonce,
            valueChecksum: $encrypted->valueChecksum,
            ownerUid: $this->resolveOwnerUid($options, $existing),
            allowedGroups: $optional['allowedGroups'],
            context: $optional['context'],
            frontendAccessible: $this->resolveFrontendAccessible($optional['frontendAccessible'], $existing),
            version: $existing instanceof Secret ? $existing->getVersion() : 1,
            expiresAt: $optional['expiresAt'],
            metadata: $optional['metadata'],
            adapter: 'local',
            crdate: $existing instanceof Secret ? $existing->getCrdate() : time(),
            cruserId: $existing instanceof Secret ? $existing->getCruserId() : $this->accessControlService->getCurrentActorUid(),
        );
    }

    /**
     * Owner-UID is privileged: a non-admin BE user that tries to set or
     * change `owner` is silently coerced back to the default (existing
     * owner on update, current actor on create).
     *
     * @param array<string, mixed> $options
     */
    private function resolveOwnerUid(array $options, ?Secret $existing): int
    {
        $defaultOwner = $existing instanceof Secret
            ? $existing->getOwnerUid()
            : $this->accessControlService->getCurrentActorUid();
        $requestedOwner = $defaultOwner;
        if (isset($options['owner'])) {
            $ownerRaw = $options['owner'];
            $requestedOwner = is_numeric($ownerRaw) ? (int) $ownerRaw : 0;
        }
        if ($requestedOwner !== $defaultOwner
            && $this->accessControlService->getCurrentActorType() === 'backend'
            && !$this->accessControlService->isCurrentActorAdmin()
        ) {
            return $defaultOwner;
        }

        return $requestedOwner;
    }

    /**
     * `frontend_accessible` is privileged: it flips a secret from
     * "encrypted, ACL-gated" to "readable by any frontend/api code path".
     * Mirroring the `owner_uid` coercion, a non-admin BACKEND caller that
     * tries to mark a secret frontend-accessible is silently coerced back
     * to the secret's prior value (false on create, the existing flag on
     * update). CLI/api/scheduler actor types are trusted callers and are
     * not coerced (a non-BE programmatic caller already controls the call,
     * consistent with `resolveOwnerUid`).
     */
    private function resolveFrontendAccessible(bool $requested, ?Secret $existing): bool
    {
        $default = $existing instanceof Secret && $existing->isFrontendAccessible();
        if ($requested === $default) {
            return $default;
        }
        if ($this->accessControlService->getCurrentActorType() === 'backend'
            && !$this->accessControlService->isCurrentActorAdmin()
        ) {
            return $default;
        }

        return $requested;
    }

    /**
     * Collect the value-type-flexible options from the `store($options)`
     * array into a typed bundle. Each option is defensively coerced to
     * its expected type; options not supplied get the Secret-default
     * value (matching the previous mutator-based behaviour where unset
     * options left the constructed entity at its default).
     *
     * @param array<string, mixed> $options
     *
     * @return array{
     *     scopePid: int,
     *     description: string,
     *     allowedGroups: list<int>,
     *     context: string,
     *     frontendAccessible: bool,
     *     expiresAt: int,
     *     metadata: array<string, mixed>,
     * }
     */
    private function collectOptionalFields(array $options): array
    {
        $metadata = [];
        if (isset($options['metadata'])) {
            /** @var array<string, mixed> $metadata */
            $metadata = (array) $options['metadata'];
        }

        return [
            'scopePid' => isset($options['scopePid'])
                ? (is_numeric($options['scopePid']) ? (int) $options['scopePid'] : 0)
                : 0,
            'description' => isset($options['description']) ? $this->coerceToString($options['description']) : '',
            'allowedGroups' => isset($options['groups']) ? $this->coerceGroupList($options['groups']) : [],
            'context' => isset($options['context']) ? $this->coerceToString($options['context']) : '',
            'frontendAccessible' => isset($options['frontendAccessible']) && (bool) $options['frontendAccessible'],
            'expiresAt' => isset($options['expiresAt']) ? $this->coerceTimestamp($options['expiresAt']) : 0,
            'metadata' => $metadata,
        ];
    }

    /**
     * @return list<int>
     */
    private function coerceGroupList(mixed $raw): array
    {
        if (!\is_array($raw)) {
            return [];
        }
        /** @var list<int> $groups */
        $groups = [];
        foreach ($raw as $groupId) {
            if (\is_int($groupId)) {
                $groups[] = $groupId;
            } elseif (is_numeric($groupId)) {
                $groups[] = (int) $groupId;
            } else {
                $groups[] = 0;
            }
        }

        return $groups;
    }

    private function coerceToString(mixed $raw): string
    {
        return \is_string($raw) || is_numeric($raw) ? (string) $raw : '';
    }

    private function coerceTimestamp(mixed $raw): int
    {
        if ($raw instanceof DateTimeInterface) {
            return $raw->getTimestamp();
        }

        return is_numeric($raw) ? (int) $raw : 0;
    }

    private function dispatchStoreEvent(string $identifier, Secret $secretEntity, bool $isNew): void
    {
        if (!$this->eventDispatcher instanceof EventDispatcherInterface) {
            return;
        }
        if ($isNew) {
            $this->eventDispatcher->dispatch(new SecretCreatedEvent(
                $identifier,
                $secretEntity,
                $this->accessControlService->getCurrentActorUid(),
            ));

            return;
        }
        $this->eventDispatcher->dispatch(new SecretUpdatedEvent(
            $identifier,
            $secretEntity->getVersion(),
            $this->accessControlService->getCurrentActorUid(),
        ));
    }
}
