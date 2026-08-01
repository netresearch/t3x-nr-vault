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
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Utility\IdentifierValidator;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use SensitiveParameter;
use Throwable;
use TYPO3\CMS\Core\SingletonInterface;

/**
 * Main vault service implementation.
 */
final readonly class VaultService implements VaultServiceInterface, SingletonInterface
{
    public function __construct(
        private VaultAdapterInterface $adapter,
        private EncryptionServiceInterface $encryptionService,
        private AccessControlServiceInterface $accessControlService,
        private AuditLogServiceInterface $auditLogService,
        private ExtensionConfigurationInterface $configuration,
        private VaultHttpClientFactoryInterface $httpClientFactory,
        private ?EventDispatcherInterface $eventDispatcher = null,
        private ?LoggerInterface $logger = null,
    ) {}

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

            // A record that exists but carries no encrypted value is a
            // creation in progress, not a rotation target: the FormEngine
            // path inserts the tx_nrvault_secret row first (DataHandler) and
            // hands the value to store() afterwards. Classify by the VALUE,
            // so that path faces secret.create — like the module controller —
            // and is audited as the creation it is.
            $isCreation = !$existing instanceof Secret
                || ($existing->getEncryptedValue() ?? '') === '';

            // Separation of duties: the per-secret ACL above answers "may this
            // actor touch THIS secret", the operation permission answers "may
            // this actor perform this KIND of operation at all". Both gates
            // must pass at this business boundary — controller checks are UX,
            // not the security boundary (a DataHandler request or programmatic
            // caller never passes through them).
            if ($isCreation) {
                $this->assertOperationGranted(VaultPermission::SecretCreate, $identifier, 'Create');
            } else {
                $this->assertOperationGranted(VaultPermission::SecretRotate, $identifier, 'Update');
            }
            if ($existing instanceof Secret && !$isCreation) {
                $this->assertPolicyChangeGranted($identifier, $options, $existing);
            }

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
                    $isCreation ? AuditAction::Create->value : AuditAction::Update->value,
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

            $this->dispatchStoreEvent($identifier, $secretEntity, $isCreation);
        } finally {
            // Securely wipe the plaintext even if an exception occurred
            sodium_memzero($secret);
        }
    }

    public function retrieve(string $identifier): ?string
    {
        return $this->doRetrieve($identifier, enforceSecretUse: true);
    }

    public function retrieveForFrontend(string $identifier): ?string
    {
        $secret = $this->adapter->retrieve($identifier);
        if (!$secret instanceof Secret) {
            return null;
        }

        // Frontend visibility is a property of the SECRET, never of whoever
        // happens to render the page. `retrieve()` alone would decide against
        // the ambient actor — AccessControlService takes its backend-user
        // branch as soon as $GLOBALS['BE_USER'] is set, which is the case for
        // a backend user browsing the frontend — and would hand out a secret
        // that was deliberately withheld from the frontend, into output that
        // is shared (page cache) with anonymous visitors.
        if (!$secret->isFrontendAccessible()) {
            $this->auditLogService->log(
                $identifier,
                AuditAction::AccessDenied->value,
                false,
                'Frontend read access denied: secret is not frontend accessible',
            );

            throw AccessDeniedException::forIdentifier($identifier, 'not frontend accessible');
        }

        // The remaining checks (read permission, expiry), the audit trail and
        // the decryption stay with the single read path — minus the
        // interactive `secret.use` gate, see doRetrieve().
        return $this->doRetrieve($identifier, enforceSecretUse: false);
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

        // Separation of duties: per-secret ACL AND operation permission.
        $this->assertOperationGranted(VaultPermission::SecretDelete, $identifier, 'Delete');

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

        // Separation of duties: per-secret ACL AND operation permission.
        $this->assertOperationGranted(VaultPermission::SecretRotate, $identifier, 'Rotate');

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
     * The single read path shared by `retrieve()` and `retrieveForFrontend()`.
     *
     * `$enforceSecretUse` toggles ONLY the interactive-backend-user operation
     * gate: the frontend path must not be subjected to it, because a frontend
     * request's visibility is a property of the secret (`frontend_accessible`),
     * never of whichever backend user happens to hold a session while
     * rendering a page whose output is shared via the page cache. Every other
     * check (per-secret ACL, expiry, audit trail, decryption) is identical for
     * both entry points.
     */
    private function doRetrieve(string $identifier, bool $enforceSecretUse): ?string
    {
        $secret = $this->adapter->retrieve($identifier);
        if (!$secret instanceof Secret) {
            return null;
        }

        // Check access
        if (!$this->accessControlService->canRead($secret)) {
            $this->auditLogService->log($identifier, AuditAction::AccessDenied->value, false, 'Read access denied');

            throw AccessDeniedException::forIdentifier($identifier, 'insufficient permissions');
        }

        if ($enforceSecretUse) {
            $this->assertInteractiveUseGranted($identifier);
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
                $secret->getEncryptionVersion(),
                $secret->getEncryptionAlgorithm(),
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

        return $plaintext;
    }

    /**
     * Assert the `secret.use` operation permission for an interactively
     * authenticated NON-ADMIN backend user.
     *
     * Applies on top of the per-secret `canRead()` tiers and only to actor type
     * `backend`: CLI, technical actors, the frontend and admins keep exactly
     * the behaviour they had. Non-admin backend users therefore need
     * `secret.use` for every plaintext read — the FormEngine vault widget,
     * FlexForm/TCA placeholder resolution and the reveal endpoint alike.
     *
     * The admin exemption is deliberately expressed through
     * `isCurrentActorAdmin()` (mirroring `resolveOwnerUid()` /
     * `resolveFrontendAccessible()`) rather than by relying on `isGranted()`
     * returning true for admins, so this stays readable as "admins are not
     * gated here".
     */
    private function assertInteractiveUseGranted(string $identifier): void
    {
        if ($this->accessControlService->getCurrentActorType() !== 'backend') {
            return;
        }

        if ($this->accessControlService->isCurrentActorAdmin()) {
            return;
        }

        if ($this->accessControlService->isGranted(VaultPermission::SecretUse)) {
            return;
        }

        $this->auditLogService->log(
            $identifier,
            AuditAction::AccessDenied->value,
            false,
            'Read access denied: missing ' . VaultPermission::SecretUse->value . ' permission',
        );

        throw AccessDeniedException::forIdentifier(
            $identifier,
            'missing ' . VaultPermission::SecretUse->value . ' permission',
        );
    }

    /**
     * Assert an operation-level vault permission for the current actor, on
     * top of the per-secret ACL tier the caller already verified.
     *
     * `isGranted()` resolves the actor-appropriate grant source: custom
     * permission options for interactive backend users (admins pass via the
     * central bypass seam), group-provisioned grants for technical actors,
     * the CLI trust switch for unauthenticated CLI, and a hard deny for
     * frontend requests — which never mutate the vault.
     */
    private function assertOperationGranted(
        VaultPermission $permission,
        string $identifier,
        string $operation,
    ): void {
        if ($this->accessControlService->isGranted($permission)) {
            return;
        }

        $this->auditLogService->log(
            $identifier,
            AuditAction::AccessDenied->value,
            false,
            $operation . ' denied: missing ' . $permission->value . ' permission',
        );

        throw AccessDeniedException::forIdentifier(
            $identifier,
            'missing ' . $permission->value . ' permission',
        );
    }

    /**
     * A `store()` over an existing secret that changes its access policy
     * (owner, group tiers, frontend availability) additionally requires
     * `secret.manage_policy` — widening who can read or write a secret is
     * vault administration, not day-to-day secret handling.
     *
     * The comparison uses the EFFECTIVE values (after the owner /
     * frontend-accessible coercions below): a submitted change that the
     * coercion silently reverts for a non-admin backend user is not a policy
     * change and must not start requiring an additional permission.
     *
     * @param array<string, mixed> $options
     */
    private function assertPolicyChangeGranted(string $identifier, array $options, Secret $existing): void
    {
        $optional = $this->collectOptionalFields($options, $existing);

        $ownerChanges = $this->resolveOwnerUid($options, $existing) !== $existing->getOwnerUid();
        $frontendChanges = $this->resolveFrontendAccessible($optional['frontendAccessible'], $existing)
            !== $existing->isFrontendAccessible();

        $groupsChange = false;
        if (isset($options['groups'])) {
            $submittedGroups = $optional['allowedGroups'];
            $existingGroups = $existing->getAllowedGroups();
            sort($submittedGroups);
            sort($existingGroups);
            $groupsChange = $submittedGroups !== $existingGroups;
        }

        if (!$ownerChanges && !$frontendChanges && !$groupsChange) {
            return;
        }

        $this->assertOperationGranted(VaultPermission::SecretManagePolicy, $identifier, 'Policy change');
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

            throw new AuditWriteException(
                $auditException->getMessage(),
                $auditException->getCode(),
                $revertFailure,
            );
        }

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
     * `$existing !== null` → update path (preserve uid/crdate/version — and
     * every metadata field the caller did NOT explicitly submit). The
     * preserve semantics matter twice over: the FormEngine path persists the
     * metadata columns via DataHandler BEFORE handing the value to store(),
     * so replace-with-defaults would wipe what the editor just entered; and
     * a programmatic `store('id', $value)` on an existing secret must not
     * silently reset description, ACL group tiers, write_groups, expiry or
     * frontend availability — those are policy fields whose CHANGE is gated
     * by secret.manage_policy, so an accidental reset is a policy change
     * without its permission.
     *
     * @param array<string, mixed> $options
     */
    private function buildSecretEntity(
        string $identifier,
        EncryptedData $encrypted,
        array $options,
        ?Secret $existing,
    ): Secret {
        $optional = $this->collectOptionalFields($options, $existing);

        return new Secret(
            identifier: $identifier,
            uid: $existing?->getUid(),
            scopePid: $optional['scopePid'],
            description: $optional['description'],
            encryptedValue: $encrypted->encryptedValue,
            encryptedDek: $encrypted->encryptedDek,
            dekNonce: $encrypted->dekNonce,
            valueNonce: $encrypted->valueNonce,
            encryptionVersion: $encrypted->encryptionVersion,
            encryptionAlgorithm: $encrypted->encryptionAlgorithm->value,
            valueChecksum: $encrypted->valueChecksum,
            ownerUid: $this->resolveOwnerUid($options, $existing),
            allowedGroups: $optional['allowedGroups'],
            writeGroups: $existing instanceof Secret ? $existing->getWriteGroups() : [],
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
     * array into a typed bundle. Each option is defensively coerced to its
     * expected type. An option NOT supplied keeps the existing secret's
     * value on update (preserve semantics — see buildSecretEntity()) and
     * gets the Secret-default value on create.
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
    private function collectOptionalFields(array $options, ?Secret $existing): array
    {
        $metadata = $existing?->getMetadata() ?? [];
        if (isset($options['metadata'])) {
            /** @var array<string, mixed> $metadata */
            $metadata = (array) $options['metadata'];
        }

        return [
            'scopePid' => (isset($options['scopePid']) && is_numeric($options['scopePid']))
                ? (int) $options['scopePid']
                : ($existing?->getScopePid() ?? 0),
            'description' => isset($options['description'])
                ? $this->coerceToString($options['description'])
                : ($existing?->getDescription() ?? ''),
            'allowedGroups' => isset($options['groups'])
                ? $this->coerceGroupList($options['groups'])
                : array_values($existing?->getAllowedGroups() ?? []),
            'context' => isset($options['context'])
                ? $this->coerceToString($options['context'])
                : ($existing?->getContext() ?? ''),
            'frontendAccessible' => isset($options['frontendAccessible'])
                ? (bool) $options['frontendAccessible']
                : ($existing instanceof Secret && $existing->isFrontendAccessible()),
            'expiresAt' => isset($options['expiresAt'])
                ? $this->coerceTimestamp($options['expiresAt'])
                : ($existing?->getExpiresAt() ?? 0),
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
