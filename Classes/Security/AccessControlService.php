<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Domain\Model\Secret;
use Throwable;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Access control service implementation.
 */
final class AccessControlService implements AccessControlServiceInterface
{
    /**
     * Per-request cache of group UIDs that actually exist in the be_groups table.
     * Reset only for the lifetime of the service instance.
     *
     * @var list<int>|null
     */
    private ?array $existingGroupIdsCache = null;

    public function __construct(
        private readonly ExtensionConfigurationInterface $configuration,
        private readonly ?ConnectionPool $connectionPool = null,
    ) {}

    public function canRead(Secret $secret): bool
    {
        return $this->hasAccess($secret);
    }

    public function canWrite(Secret $secret): bool
    {
        return $this->hasAccess($secret);
    }

    public function canDelete(Secret $secret): bool
    {
        return $this->hasAccess($secret);
    }

    public function canCreate(): bool
    {
        $backendUser = $this->getBackendUser();

        // Backend user takes precedence
        if ($backendUser instanceof BackendUserAuthentication) {
            // Defence-in-depth: disabled users must not create secrets,
            // even if a stale session is still active.
            return !($this->isBackendUserDisabled($backendUser));
            // Any authenticated backend user can create
        }

        // CLI check (only when no backend user)
        if ($this->isRealCliContext()) {
            return $this->configuration->isCliAccessAllowed();
        }

        // No backend user and not CLI
        return false;
    }

    public function isCurrentActorAdmin(): bool
    {
        $backendUser = $this->getBackendUser();
        if (!$backendUser instanceof BackendUserAuthentication) {
            return false;
        }
        if ($this->isBackendUserDisabled($backendUser)) {
            return false;
        }

        return $backendUser->isAdmin();
    }

    public function getCurrentActorUid(): int
    {
        $backendUser = $this->getBackendUser();
        if (!$backendUser instanceof BackendUserAuthentication) {
            return 0;
        }

        /** @phpstan-ignore property.internal */
        $userRecord = $backendUser->user;
        /** @var array<string, mixed> $userRecordTyped */
        $userRecordTyped = \is_array($userRecord) ? $userRecord : [];

        return \is_int($userRecordTyped['uid'] ?? null) ? $userRecordTyped['uid'] : 0;
    }

    public function getCurrentActorType(): string
    {
        $backendUser = $this->getBackendUser();
        if ($backendUser instanceof BackendUserAuthentication) {
            return 'backend';
        }

        if ($this->isRealCliContext()) {
            return 'cli';
        }

        /** @phpstan-ignore constant.notFound */
        if (\defined('TYPO3_cliMode') && \TYPO3_CLIMODE) {
            return 'cli';
        }

        return 'api';
    }

    public function getCurrentActorUsername(): string
    {
        $backendUser = $this->getBackendUser();
        if ($backendUser instanceof BackendUserAuthentication) {
            /** @phpstan-ignore property.internal */
            $userRecord = $backendUser->user;
            /** @var array<string, mixed> $userRecordTyped */
            $userRecordTyped = \is_array($userRecord) ? $userRecord : [];

            return \is_string($userRecordTyped['username'] ?? null) ? $userRecordTyped['username'] : 'Unknown';
        }

        // No backend user - check context
        if ($this->isRealCliContext()) {
            return 'CLI';
        }

        return 'Anonymous';
    }

    public function getCurrentUserGroups(): array
    {
        $backendUser = $this->getBackendUser();
        if (!$backendUser instanceof BackendUserAuthentication) {
            return [];
        }

        /** @phpstan-ignore nullCoalesce.property */
        $groups = $backendUser->userGroupsUID ?? [];

        /** @var list<int> $result */
        $result = [];
        foreach ($groups as $groupId) {
            $result[] = \is_int($groupId) ? $groupId : (is_numeric($groupId) ? (int) $groupId : 0);
        }

        return $result;
    }

    /**
     * Filter a list of group UIDs to only those that actually exist in be_groups.
     *
     * Stale group UIDs (deleted groups still referenced in a user session)
     * must not grant access. This is a defence-in-depth measure on top of
     * TYPO3's own session handling.
     *
     * The result is cached per request (per service instance) to avoid
     * repeated lookups on hot paths.
     *
     * @param int[] $groupIds
     *
     * @return list<int>
     */
    public function filterExistingGroupIds(array $groupIds): array
    {
        if ($groupIds === []) {
            return [];
        }

        $existing = $this->loadExistingGroupIds();
        if ($existing === null) {
            // No DB available (e.g. unit tests, CLI bootstrap): fail CLOSED
            // rather than open. The caller can still fall back to the
            // owner/admin checks which do not require this lookup.
            return [];
        }

        return array_values(array_intersect($groupIds, $existing));
    }

    /**
     * Detect if we're in an actual CLI context (not PHPUnit tests).
     */
    private function isRealCliContext(): bool
    {
        // PHPUnit sets this constant
        if (\defined('PHPUNIT_COMPOSER_INSTALL') || \defined('__PHPUNIT_PHAR__')) {
            return false;
        }

        return PHP_SAPI === 'cli';
    }

    /**
     * Check access to a secret.
     */
    private function hasAccess(Secret $secret): bool
    {
        $backendUser = $this->getBackendUser();

        // Backend user takes precedence
        if ($backendUser instanceof BackendUserAuthentication) {
            return $this->hasBackendUserAccess($backendUser, $secret);
        }

        // CLI access control (only when no backend user)
        if ($this->isRealCliContext()) {
            if (!$this->configuration->isCliAccessAllowed()) {
                return false;
            }

            // Check CLI access groups if configured
            $cliAccessGroups = $this->configuration->getCliAccessGroups();
            if ($cliAccessGroups !== []) {
                $secretGroups = $secret->getAllowedGroups();

                return array_intersect($secretGroups, $cliAccessGroups) !== [];
            }

            // CLI allowed and no group restrictions
            return true;
        }

        // Frontend access for secrets explicitly marked as frontend_accessible
        // This allows TypoScript and other frontend contexts to resolve vault placeholders
        // No backend user and not CLI
        return $secret->isFrontendAccessible();
    }

    /**
     * Check if backend user has access to a secret.
     */
    private function hasBackendUserAccess(BackendUserAuthentication $backendUser, Secret $secret): bool
    {
        // BUG FIX: Defence-in-depth — disabled users must be rejected even if
        // their BE_USER session somehow reaches this layer. TYPO3 core normally
        // blocks disabled users earlier, but the vault MUST NOT rely on that
        // alone.
        if ($this->isBackendUserDisabled($backendUser)) {
            return false;
        }

        // Admin access
        if ($backendUser->isAdmin()) {
            return true;
        }

        // System maintainer access
        if ($backendUser->isSystemMaintainer()) {
            return true;
        }

        // Owner access
        /** @phpstan-ignore property.internal */
        $userRecord = $backendUser->user;
        /** @var array<string, mixed> $userRecordTyped */
        $userRecordTyped = \is_array($userRecord) ? $userRecord : [];
        $currentUserUid = \is_int($userRecordTyped['uid'] ?? null) ? $userRecordTyped['uid'] : 0;
        if ($secret->getOwnerUid() === $currentUserUid) {
            return true;
        }

        // Group access
        $secretGroups = $secret->getAllowedGroups();
        if ($secretGroups !== []) {
            // BUG FIX: Filter out stale / deleted group UIDs before the
            // intersection check. A deleted group whose UID is still in the
            // user session must NOT grant access to a secret that lists it.
            $userGroups = $this->filterExistingGroupIds($this->getCurrentUserGroups());

            if (array_intersect($secretGroups, $userGroups) !== []) {
                return true;
            }
        }

        return false;
    }

    /**
     * Read the `disable` flag from a backend user record.
     *
     * TYPO3 stores `be_users.disable` as a 0/1 integer (DataHandler casts
     * string "1" from form submissions to int 1). Any non-zero value
     * therefore indicates a disabled user. A missing key is treated as
     * "not disabled" to preserve existing behaviour for tests that do not
     * set the flag.
     */
    private function isBackendUserDisabled(BackendUserAuthentication $backendUser): bool
    {
        /** @phpstan-ignore property.internal */
        $userRecord = $backendUser->user;
        /** @var array<string, mixed> $userRecordTyped */
        $userRecordTyped = \is_array($userRecord) ? $userRecord : [];

        $disable = $userRecordTyped['disable'] ?? 0;
        if (\is_int($disable)) {
            return $disable !== 0;
        }

        if (is_numeric($disable)) {
            return (int) $disable !== 0;
        }

        return false;
    }

    /**
     * Load the set of existing be_groups UIDs from the database.
     *
     * Returns null when the connection pool is not available (unit tests,
     * CLI bootstrap without DB). Cached per service instance.
     *
     * @return list<int>|null
     */
    private function loadExistingGroupIds(): ?array
    {
        if ($this->existingGroupIdsCache !== null) {
            return $this->existingGroupIdsCache;
        }

        if (!$this->connectionPool instanceof ConnectionPool) {
            return null;
        }

        try {
            $queryBuilder = $this->connectionPool
                ->getQueryBuilderForTable('be_groups');
            $queryBuilder->getRestrictions()->removeAll();

            $rows = $queryBuilder
                ->select('uid')
                ->from('be_groups')
                ->where(
                    $queryBuilder->expr()->eq(
                        'deleted',
                        $queryBuilder->createNamedParameter(0, Connection::PARAM_INT),
                    ),
                )
                ->executeQuery()
                ->fetchAllAssociative();
        } catch (Throwable) {
            // DB query failed (schema missing, permissions, etc.) — fail
            // closed: treat all group IDs as stale.
            return $this->existingGroupIdsCache = [];
        }

        /** @var list<int> $uids */
        $uids = [];
        foreach ($rows as $row) {
            $uid = $row['uid'] ?? null;
            if (\is_int($uid)) {
                $uids[] = $uid;
            } elseif (is_numeric($uid)) {
                $uids[] = (int) $uid;
            }
        }

        return $this->existingGroupIdsCache = $uids;
    }

    private function getBackendUser(): ?BackendUserAuthentication
    {
        $beUser = $GLOBALS['BE_USER'] ?? null;

        return $beUser instanceof BackendUserAuthentication ? $beUser : null;
    }
}
