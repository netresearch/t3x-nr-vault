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
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
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
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Exception\SecretExpiredException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Http\VaultHttpClientFactoryInterface;
use Netresearch\NrVault\Http\VaultHttpClientInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Utility\IdentifierValidator;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
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
            // Validate identifier
            IdentifierValidator::validate($identifier);

            if ($secret === '') {
                throw ValidationException::emptySecret();
            }

            // Determine new vs. update before access-control checks so we use the right gate
            $existing = $this->adapter->retrieve($identifier);
            $isNew = !$existing instanceof Secret;

            // Access control: create vs. write are distinct permissions.
            if ($isNew) {
                if (!$this->accessControlService->canCreate()) {
                    $this->auditLogService->log($identifier, 'access_denied', false, 'Create access denied');

                    throw AccessDeniedException::forIdentifier($identifier, 'create permission denied');
                }
            } elseif (!$this->accessControlService->canWrite($existing)) {
                $this->auditLogService->log($identifier, 'access_denied', false, 'Update access denied');

                throw AccessDeniedException::forIdentifier($identifier, 'update permission denied');
            }

            // Encrypt the secret
            $encrypted = $this->encryptionService->encrypt($secret, $identifier);

            // Build secret entity
            $secretEntity = new Secret();
            $secretEntity->setIdentifier($identifier);
            $secretEntity->setEncryptedValue($encrypted->encryptedValue);
            $secretEntity->setEncryptedDek($encrypted->encryptedDek);
            $secretEntity->setDekNonce($encrypted->dekNonce);
            $secretEntity->setValueNonce($encrypted->valueNonce);
            $secretEntity->setValueChecksum($encrypted->valueChecksum);
            $secretEntity->setAdapter('local');

            // Apply options. owner_uid is privileged: only admins may change it; otherwise
            // we fall back to the existing owner (update) or the current actor (create).
            if ($isNew) {
                $defaultOwner = $this->accessControlService->getCurrentActorUid();
            } else {
                $defaultOwner = $existing->getOwnerUid();
            }
            $requestedOwner = $defaultOwner;
            if (isset($options['owner'])) {
                $ownerRaw = $options['owner'];
                $requestedOwner = is_numeric($ownerRaw) ? (int) $ownerRaw : 0;
            }
            if ($requestedOwner !== $defaultOwner && $this->accessControlService->getCurrentActorType() === 'backend'
                && !$this->isCurrentActorAdmin()
            ) {
                // Non-admin BE user tried to set/change owner_uid → silently coerce to default.
                $requestedOwner = $defaultOwner;
            }
            $secretEntity->setOwnerUid($requestedOwner);

            if (isset($options['groups'])) {
                /** @var list<int> $groups */
                $groups = [];
                if (\is_array($options['groups'])) {
                    foreach ($options['groups'] as $groupId) {
                        $groups[] = \is_int($groupId) ? $groupId : (is_numeric($groupId) ? (int) $groupId : 0);
                    }
                }
                $secretEntity->setAllowedGroups($groups);
            }

            if (isset($options['context'])) {
                $contextRaw = $options['context'];
                $secretEntity->setContext(\is_string($contextRaw) || is_numeric($contextRaw) ? (string) $contextRaw : '');
            }

            if (isset($options['description'])) {
                $descRaw = $options['description'];
                $secretEntity->setDescription(\is_string($descRaw) || is_numeric($descRaw) ? (string) $descRaw : '');
            }

            if (isset($options['metadata'])) {
                /** @var array<string, mixed> $metadata */
                $metadata = (array) $options['metadata'];
                $secretEntity->setMetadata($metadata);
            }

            if (isset($options['scopePid'])) {
                $scopePidRaw = $options['scopePid'];
                $secretEntity->setScopePid(is_numeric($scopePidRaw) ? (int) $scopePidRaw : 0);
            }

            if (isset($options['expiresAt'])) {
                $expiresAt = $options['expiresAt'];
                if ($expiresAt instanceof DateTimeInterface) {
                    $expiresAt = $expiresAt->getTimestamp();
                }
                $secretEntity->setExpiresAt(is_numeric($expiresAt) ? (int) $expiresAt : 0);
            }

            if (isset($options['frontendAccessible'])) {
                $secretEntity->setFrontendAccessible((bool) $options['frontendAccessible']);
            }

            if (!$isNew) {
                $secretEntity->setUid($existing->getUid());
                $secretEntity->setCrdate($existing->getCrdate());
                $secretEntity->setVersion($existing->getVersion());
            } else {
                $secretEntity->setCrdate(time());
                $secretEntity->setCruserId($this->accessControlService->getCurrentActorUid());
            }

            // Store the secret
            $this->adapter->store($secretEntity);

            // Log the action
            $this->auditLogService->log(
                $identifier,
                $isNew ? 'create' : 'update',
                true,
                null,
                null,
                $isNew ? null : $existing->getValueChecksum(),
                $encrypted->valueChecksum,
            );

            // Dispatch PSR-14 event
            if ($isNew) {
                $this->eventDispatcher?->dispatch(new SecretCreatedEvent(
                    $identifier,
                    $secretEntity,
                    $this->accessControlService->getCurrentActorUid(),
                ));
            } else {
                $this->eventDispatcher?->dispatch(new SecretUpdatedEvent(
                    $identifier,
                    $secretEntity->getVersion(),
                    $this->accessControlService->getCurrentActorUid(),
                ));
            }

            // Clear cache
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
            $this->auditLogService->log($identifier, 'access_denied', false, 'Read access denied');

            throw AccessDeniedException::forIdentifier($identifier, 'insufficient permissions');
        }

        // Check expiration
        if ($secret->isExpired()) {
            $this->auditLogService->log($identifier, 'read', false, 'Secret has expired');

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
            $this->auditLogService->log($identifier, 'read', false, 'Decryption failed: ' . $e->getMessage());

            throw $e;
        }

        // Update read statistics atomically (avoids full entity save + MM table churn)
        $uid = $secret->getUid();
        if ($uid !== null) {
            $this->adapter->incrementReadCount($uid);
        }

        // Log success (can be disabled for high-throughput scenarios)
        if ($this->configuration->isAuditReadsEnabled()) {
            $this->auditLogService->log($identifier, 'read', true);
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
            $this->auditLogService->log($identifier, 'access_denied', false, 'Delete access denied');

            throw AccessDeniedException::forIdentifier($identifier, 'delete permission denied');
        }

        $hashBefore = $secret->getValueChecksum();

        // Delete
        $this->adapter->delete($identifier);

        // Log
        $this->auditLogService->log(
            $identifier,
            'delete',
            true,
            null,
            $reason,
            $hashBefore,
        );

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
            $this->auditLogService->log($identifier, 'access_denied', false, 'Rotate access denied');

            throw AccessDeniedException::forIdentifier($identifier, 'rotate permission denied');
        }

        if ($newSecret === '') {
            throw ValidationException::emptySecret();
        }

        try {
            $hashBefore = $secret->getValueChecksum();

            // Encrypt the new secret
            $encrypted = $this->encryptionService->encrypt($newSecret, $identifier);

            // Update secret
            $secret->setEncryptedValue($encrypted->encryptedValue);
            $secret->setEncryptedDek($encrypted->encryptedDek);
            $secret->setDekNonce($encrypted->dekNonce);
            $secret->setValueNonce($encrypted->valueNonce);
            $secret->setValueChecksum($encrypted->valueChecksum);
            $secret->incrementVersion();
            $secret->setLastRotatedAt(time());

            // Store
            $this->adapter->store($secret);

            // Log
            $this->auditLogService->log(
                $identifier,
                'rotate',
                true,
                null,
                $reason,
                $hashBefore,
                $encrypted->valueChecksum,
            );

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
            $this->auditLogService->log($identifier, 'access_denied', false, 'Metadata access denied');

            throw AccessDeniedException::forIdentifier($identifier, 'insufficient permissions');
        }

        return SecretDetails::fromSecret($secret);
    }

    public function http(): VaultHttpClientInterface
    {
        return $this->httpClientFactory->create($this);
    }

    /**
     * Is the current request driven by an admin BE user?
     *
     * Non-BE actors (CLI / scheduler / API) bypass the BE-user admin check and
     * are treated as admin equivalents — callers must already be context-bound
     * by separate authentication.
     */
    private function isCurrentActorAdmin(): bool
    {
        if ($this->accessControlService->getCurrentActorType() !== 'backend') {
            return true;
        }
        $beUser = $GLOBALS['BE_USER'] ?? null;

        return \is_object($beUser) && method_exists($beUser, 'isAdmin') && $beUser->isAdmin() === true;
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
}
