<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Traits;

use Netresearch\NrVault\Security\VaultPermission;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;

/**
 * Shared helper for building `BackendUserAuthentication` mocks in unit tests.
 *
 * Extracted from copies in:
 *  - `Tests/Unit/Service/VaultFieldPermissionServiceTest.php`
 *  - `Tests/Unit/Security/AccessControlServiceTest.php`
 *  - `Tests/Unit/Form/Element/VaultSecretElementTest.php`
 *
 * @phpstan-require-extends TestCase
 */
trait BackendUserMockTrait
{
    /**
     * Create a fully-populated `BackendUserAuthentication` mock.
     *
     * The returned mock answers `isAdmin()` and `isSystemMaintainer()`, exposes
     * a `$user` record (uid + synthetic username), a `$userGroupsUID` list and
     * a boolean `disabled` flag via the `user['disable']` column (mirroring the
     * TYPO3 `be_users.disable` field).
     *
     * Vault operation permissions are wired the way TYPO3 stores them: as the
     * comma-separated `groupData['custom_options']` list that
     * `AccessControlService` evaluates. Do NOT stub `check()` instead — core's
     * `check()` returns true unconditionally for admins, so a test that stubs it
     * cannot tell a real group grant from the admin override and would pass
     * while the override is disabled.
     *
     * @param list<int> $groupIds backend user group UIDs (populates `userGroupsUID`)
     * @param bool $isSystemMaintainer answer for `isSystemMaintainer()` — core
     *                                 treats the role as strictly stronger than
     *                                 `admin`, and the vault's permission gates
     *                                 must honour it independently
     * @param list<VaultPermission> $grantedPermissions vault operation
     *                                                  permissions granted via
     *                                                  the user's groups
     */
    protected function createMockBackendUser(
        int $uid = 1,
        bool $isAdmin = false,
        array $groupIds = [],
        bool $disabled = false,
        bool $isSystemMaintainer = false,
        array $grantedPermissions = [],
    ): BackendUserAuthentication&MockObject {
        /** @var BackendUserAuthentication&MockObject $backendUser */
        $backendUser = $this->createMock(BackendUserAuthentication::class);
        $backendUser->method('isAdmin')->willReturn($isAdmin);
        $backendUser->method('isSystemMaintainer')->willReturn($isSystemMaintainer);

        $backendUser->user = [
            'uid' => $uid,
            'username' => 'test-user-' . $uid,
            'disable' => $disabled ? 1 : 0,
        ];
        $backendUser->userGroupsUID = $groupIds;
        /** @phpstan-ignore property.internal */
        $backendUser->groupData['custom_options'] = implode(',', array_map(
            static fn (VaultPermission $permission): string => 'tx_nrvault:' . $permission->value,
            $grantedPermissions,
        ));

        return $backendUser;
    }
}
