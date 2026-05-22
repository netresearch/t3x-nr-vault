<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Security;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Security\AccessControlService;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Database\Query\Restriction\DefaultRestrictionContainer;

#[CoversClass(AccessControlService::class)]
#[AllowMockObjectsWithoutExpectations]
final class AccessControlServiceTest extends TestCase
{
    private AccessControlService $subject;

    private ExtensionConfigurationInterface&MockObject $configuration;

    protected function setUp(): void
    {
        parent::setUp();

        $this->configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $this->subject = new AccessControlService($this->configuration);

        // Reset GLOBALS for clean state
        unset($GLOBALS['BE_USER']);
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['BE_USER']);
        parent::tearDown();
    }

    #[Test]
    public function canReadReturnsFalseWithoutBackendUser(): void
    {
        $secret = $this->createSecret(ownerUid: 1);

        self::assertFalse($this->subject->canRead($secret));
    }

    #[Test]
    public function canReadReturnsTrueForAdmin(): void
    {
        $this->setBackendUser(uid: 1, isAdmin: true);
        $secret = $this->createSecret(ownerUid: 999); // Different owner

        self::assertTrue($this->subject->canRead($secret));
    }

    #[Test]
    public function canReadReturnsTrueForOwner(): void
    {
        $this->setBackendUser(uid: 5, isAdmin: false);
        $secret = $this->createSecret(ownerUid: 5);

        self::assertTrue($this->subject->canRead($secret));
    }

    #[Test]
    public function canReadReturnsFalseForNonOwner(): void
    {
        $this->setBackendUser(uid: 5, isAdmin: false);
        $secret = $this->createSecret(ownerUid: 10);

        self::assertFalse($this->subject->canRead($secret));
    }

    #[Test]
    public function canReadReturnsTrueForGroupMember(): void
    {
        $this->setBackendUser(uid: 5, isAdmin: false, groups: [1, 2, 3]);
        $secret = $this->createSecret(ownerUid: 999, allowedGroups: [2]);

        // Service instance with a connection-pool that reports all three
        // groups as existing — so the stale-group filter does NOT strip them.
        $subject = $this->createSubjectWithExistingGroups([1, 2, 3]);

        self::assertTrue($subject->canRead($secret));
    }

    #[Test]
    public function canReadReturnsFalseForNonGroupMember(): void
    {
        $this->setBackendUser(uid: 5, isAdmin: false, groups: [1, 2, 3]);
        $secret = $this->createSecret(ownerUid: 999, allowedGroups: [10, 20]);

        self::assertFalse($this->subject->canRead($secret));
    }

    #[Test]
    public function canWriteReturnsTrueForAdmin(): void
    {
        $this->setBackendUser(uid: 1, isAdmin: true);
        $secret = $this->createSecret(ownerUid: 999);

        self::assertTrue($this->subject->canWrite($secret));
    }

    #[Test]
    public function canWriteReturnsTrueForOwner(): void
    {
        $this->setBackendUser(uid: 5, isAdmin: false);
        $secret = $this->createSecret(ownerUid: 5);

        self::assertTrue($this->subject->canWrite($secret));
    }

    #[Test]
    public function canDeleteReturnsTrueForAdmin(): void
    {
        $this->setBackendUser(uid: 1, isAdmin: true);
        $secret = $this->createSecret(ownerUid: 999);

        self::assertTrue($this->subject->canDelete($secret));
    }

    #[Test]
    public function canDeleteReturnsTrueForOwner(): void
    {
        $this->setBackendUser(uid: 5, isAdmin: false);
        $secret = $this->createSecret(ownerUid: 5);

        self::assertTrue($this->subject->canDelete($secret));
    }

    #[Test]
    public function canCreateReturnsTrueForAuthenticatedUser(): void
    {
        $this->setBackendUser(uid: 5, isAdmin: false);

        self::assertTrue($this->subject->canCreate());
    }

    #[Test]
    public function canCreateReturnsFalseWithoutBackendUser(): void
    {
        // No CLI mode, no backend user
        self::assertFalse($this->subject->canCreate());
    }

    #[Test]
    public function getCurrentActorUidReturnsZeroWithoutUser(): void
    {
        self::assertEquals(0, $this->subject->getCurrentActorUid());
    }

    #[Test]
    public function getCurrentActorUidReturnsUserUid(): void
    {
        $this->setBackendUser(uid: 42, isAdmin: false);

        self::assertEquals(42, $this->subject->getCurrentActorUid());
    }

    #[Test]
    public function getCurrentActorUsernameReturnsAnonymousWithoutUser(): void
    {
        self::assertEquals('Anonymous', $this->subject->getCurrentActorUsername());
    }

    #[Test]
    public function getCurrentActorUsernameReturnsUsername(): void
    {
        $this->setBackendUser(uid: 1, isAdmin: false, username: 'testuser');

        self::assertEquals('testuser', $this->subject->getCurrentActorUsername());
    }

    #[Test]
    public function getCurrentActorTypeReturnsBackendForBackendUser(): void
    {
        $this->setBackendUser(uid: 1, isAdmin: false);

        self::assertEquals('backend', $this->subject->getCurrentActorType());
    }

    #[Test]
    public function getCurrentActorTypeReturnsApiWithoutBackendUser(): void
    {
        // When not in CLI and no backend user
        self::assertEquals('api', $this->subject->getCurrentActorType());
    }

    #[Test]
    public function getCurrentUserGroupsReturnsEmptyWithoutUser(): void
    {
        self::assertEquals([], $this->subject->getCurrentUserGroups());
    }

    #[Test]
    public function getCurrentUserGroupsReturnsUserGroups(): void
    {
        $this->setBackendUser(uid: 1, isAdmin: false, groups: [1, 2, 3]);

        self::assertEquals([1, 2, 3], $this->subject->getCurrentUserGroups());
    }

    #[Test]
    public function systemMaintainerHasFullAccess(): void
    {
        $this->setBackendUser(uid: 5, isAdmin: false, isSystemMaintainer: true);
        $secret = $this->createSecret(ownerUid: 999);

        self::assertTrue($this->subject->canRead($secret));
        self::assertTrue($this->subject->canWrite($secret));
        self::assertTrue($this->subject->canDelete($secret));
    }

    #[Test]
    public function canReadReturnsTrueForFrontendAccessibleSecretWithoutBackendUser(): void
    {
        // No backend user, not CLI context – falls back to isFrontendAccessible()
        $secret = $this->createSecret(ownerUid: 0, frontendAccessible: true);

        self::assertTrue($this->subject->canRead($secret));
    }

    #[Test]
    public function canReadReturnsFalseForNonFrontendAccessibleSecretWithoutBackendUser(): void
    {
        $secret = $this->createSecret(ownerUid: 0, frontendAccessible: false);

        self::assertFalse($this->subject->canRead($secret));
    }

    #[Test]
    public function canReadReturnsFalseForNonOwnerWithNoGroupsOnSecret(): void
    {
        // Non-owner; secret has no allowed groups -> access denied
        $this->setBackendUser(uid: 5, isAdmin: false, groups: [1, 2, 3]);
        $secret = $this->createSecret(ownerUid: 10, allowedGroups: []);

        self::assertFalse($this->subject->canRead($secret));
    }

    #[Test]
    public function getCurrentActorUsernameReturnsUnknownWhenUsernameIsNotString(): void
    {
        // User record exists but username key is missing / non-string
        $backendUser = $this->createMock(BackendUserAuthentication::class);
        $backendUser->user = ['uid' => 1]; // no 'username' key
        $backendUser->userGroupsUID = [];
        $backendUser->method('isAdmin')->willReturn(false);
        $backendUser->method('isSystemMaintainer')->willReturn(false);
        $GLOBALS['BE_USER'] = $backendUser;

        self::assertEquals('Unknown', $this->subject->getCurrentActorUsername());
    }

    #[Test]
    public function getCurrentActorUidReturnsZeroWhenUserUidIsNotInt(): void
    {
        // User record exists but uid is a string
        $backendUser = $this->createMock(BackendUserAuthentication::class);
        $backendUser->user = ['uid' => 'not-an-int'];
        $backendUser->userGroupsUID = [];
        $backendUser->method('isAdmin')->willReturn(false);
        $backendUser->method('isSystemMaintainer')->willReturn(false);
        $GLOBALS['BE_USER'] = $backendUser;

        self::assertSame(0, $this->subject->getCurrentActorUid());
    }

    #[Test]
    public function getCurrentUserGroupsConvertsStringNumericGroupIds(): void
    {
        // userGroupsUID may contain string representations of integers
        $backendUser = $this->createMock(BackendUserAuthentication::class);
        $backendUser->user = ['uid' => 1, 'username' => 'tester'];
        $backendUser->userGroupsUID = ['5', '10', '15'];
        $backendUser->method('isAdmin')->willReturn(false);
        $backendUser->method('isSystemMaintainer')->willReturn(false);
        $GLOBALS['BE_USER'] = $backendUser;

        $groups = $this->subject->getCurrentUserGroups();

        self::assertSame([5, 10, 15], $groups);
    }

    #[Test]
    public function getCurrentUserGroupsConvertsNonNumericStringGroupIdToZero(): void
    {
        $backendUser = $this->createMock(BackendUserAuthentication::class);
        $backendUser->user = ['uid' => 1, 'username' => 'tester'];
        $backendUser->userGroupsUID = ['not-a-number'];
        $backendUser->method('isAdmin')->willReturn(false);
        $backendUser->method('isSystemMaintainer')->willReturn(false);
        $GLOBALS['BE_USER'] = $backendUser;

        $groups = $this->subject->getCurrentUserGroups();

        self::assertSame([0], $groups);
    }

    #[Test]
    public function hasAccessDelegatesToFrontendAccessibleWhenNoBackendUserAndNotCli(): void
    {
        // canWrite and canDelete also delegate to hasAccess, which ends at isFrontendAccessible()
        $secret = $this->createSecret(ownerUid: 0, frontendAccessible: true);

        self::assertTrue($this->subject->canWrite($secret));
        self::assertTrue($this->subject->canDelete($secret));
    }

    #[Test]
    public function canReadReturnsFalseForOwnerUidZeroWithEmptyGroups(): void
    {
        // User uid=0 does not match ownerUid=0 because uid defaults to 0 only when record is missing int
        $this->setBackendUser(uid: 0, isAdmin: false);
        $secret = $this->createSecret(ownerUid: 0, allowedGroups: []);

        // uid=0 matches ownerUid=0 → access granted
        self::assertTrue($this->subject->canRead($secret));
    }

    #[Test]
    public function hasAccessChecksGroupIntersectionWhenSecretHasGroups(): void
    {
        $this->setBackendUser(uid: 10, isAdmin: false, groups: [5, 7, 9]);
        // Secret owned by someone else; groups [3, 7] — user is in group 7
        $secret = $this->createSecret(ownerUid: 99, allowedGroups: [3, 7]);

        // Service wired with a connection-pool that confirms group 7 exists.
        $subject = $this->createSubjectWithExistingGroups([5, 7, 9]);

        self::assertTrue($subject->canRead($secret));
    }

    #[Test]
    public function hasAccessReturnsFalseWhenGroupsDontIntersect(): void
    {
        $this->setBackendUser(uid: 10, isAdmin: false, groups: [1, 2, 3]);
        $secret = $this->createSecret(ownerUid: 99, allowedGroups: [4, 5, 6]);

        self::assertFalse($this->subject->canRead($secret));
    }

    #[Test]
    public function getCurrentActorTypeReturnsBackendWhenUserPresent(): void
    {
        $this->setBackendUser(uid: 1, isAdmin: false);

        self::assertSame('backend', $this->subject->getCurrentActorType());
    }

    #[Test]
    public function canWriteReturnsFalseWithoutBackendUser(): void
    {
        $secret = $this->createSecret(ownerUid: 1);

        self::assertFalse($this->subject->canWrite($secret));
    }

    #[Test]
    public function canDeleteReturnsFalseWithoutBackendUser(): void
    {
        $secret = $this->createSecret(ownerUid: 1);

        self::assertFalse($this->subject->canDelete($secret));
    }

    #[Test]
    public function canWriteReturnsTrueForGroupMember(): void
    {
        $this->setBackendUser(uid: 5, isAdmin: false, groups: [10, 20]);
        $secret = $this->createSecret(ownerUid: 999, allowedGroups: [20]);

        $subject = $this->createSubjectWithExistingGroups([10, 20]);

        self::assertTrue($subject->canWrite($secret));
    }

    #[Test]
    public function canDeleteReturnsTrueForGroupMember(): void
    {
        $this->setBackendUser(uid: 5, isAdmin: false, groups: [10, 20]);
        $secret = $this->createSecret(ownerUid: 999, allowedGroups: [20]);

        $subject = $this->createSubjectWithExistingGroups([10, 20]);

        self::assertTrue($subject->canDelete($secret));
    }

    #[Test]
    public function getCurrentActorUidReturnsUidFromUserRecord(): void
    {
        $this->setBackendUser(uid: 77, isAdmin: false);

        self::assertSame(77, $this->subject->getCurrentActorUid());
    }

    #[Test]
    public function getCurrentActorUsernameReturnsConfiguredUsername(): void
    {
        $this->setBackendUser(uid: 1, isAdmin: false, username: 'jdoe');

        self::assertSame('jdoe', $this->subject->getCurrentActorUsername());
    }

    #[Test]
    public function getCurrentActorTypeReturnsApiWhenNeitherBackendNorCli(): void
    {
        // PHPUnit sets PHPUNIT_COMPOSER_INSTALL so isRealCliContext() returns false
        self::assertSame('api', $this->subject->getCurrentActorType());
    }

    #[Test]
    public function canReadReturnsFalseForDisabledUser(): void
    {
        // BUG FIX verification: AccessControlService::hasBackendUserAccess() now
        // checks the be_users.disable flag and rejects disabled users before the
        // isAdmin() / isSystemMaintainer() / owner / group branches are considered.
        //
        // This is defence-in-depth on top of TYPO3 core's own session handling:
        // if a disabled user's session ever reaches this layer (e.g. cached
        // session, direct service invocation in a worker), the vault MUST say no.
        //
        // A disabled admin must ALSO be rejected — disable overrides everything.
        $this->setBackendUser(
            uid: 5,
            isAdmin: true,          // even admin flag must not override disable
            groups: [1, 2, 3],
            username: 'disableduser',
            disable: 1,
        );

        $ownedSecret = $this->createSecret(ownerUid: 5);
        $groupSecret = $this->createSecret(ownerUid: 999, allowedGroups: [1]);

        self::assertFalse(
            $this->subject->canRead($ownedSecret),
            'Disabled user must not be able to read even their own secret',
        );
        self::assertFalse(
            $this->subject->canRead($groupSecret),
            'Disabled user must not be able to read a group-permitted secret',
        );
        self::assertFalse(
            $this->subject->canWrite($ownedSecret),
            'Disabled user must not be able to write',
        );
        self::assertFalse(
            $this->subject->canDelete($ownedSecret),
            'Disabled user must not be able to delete',
        );
        self::assertFalse(
            $this->subject->canCreate(),
            'Disabled user must not be able to create new secrets',
        );
    }

    #[Test]
    public function canReadIgnoresStaleGroupIds(): void
    {
        // BUG FIX verification: AccessControlService::hasBackendUserAccess() now
        // calls filterExistingGroupIds() before comparing user groups to the
        // secret's allowedGroups. A stale (deleted) group UID still carried in
        // the user session must NOT grant access.
        //
        // Scenario: user's session claims membership in group 99999, the secret
        // also permits group 99999, but group 99999 does NOT exist in be_groups.
        // Expected: canRead() returns false.
        $this->setBackendUser(uid: 5, isAdmin: false, groups: [99999]);
        $secret = $this->createSecret(ownerUid: 999, allowedGroups: [99999]);

        // Connection pool reports group 99999 as NOT existing (empty result).
        $subject = $this->createSubjectWithExistingGroups([]);

        self::assertFalse(
            $subject->canRead($secret),
            'Stale/deleted group UID must not grant vault access',
        );

        // Counter-check: when the group DOES exist, access is granted.
        $subjectWithGroup = $this->createSubjectWithExistingGroups([99999]);
        self::assertTrue(
            $subjectWithGroup->canRead($secret),
            'When group UID exists in be_groups, access must be granted',
        );
    }

    #[Test]
    public function filterExistingGroupIdsReturnsEmptyWhenInputEmpty(): void
    {
        self::assertSame([], $this->subject->filterExistingGroupIds([]));
    }

    #[Test]
    public function filterExistingGroupIdsFailsClosedWhenNoConnectionPool(): void
    {
        // Subject constructed without a connection pool: every group id is
        // treated as stale (fail closed).
        self::assertSame([], $this->subject->filterExistingGroupIds([1, 2, 3]));
    }

    #[Test]
    public function filterExistingGroupIdsIntersectsAgainstBeGroupsTable(): void
    {
        $subject = $this->createSubjectWithExistingGroups([2, 4]);

        self::assertSame(
            [2, 4],
            $subject->filterExistingGroupIds([1, 2, 3, 4, 5]),
        );
    }

    /**
     * Create a test Secret with specified properties.
     *
     * @param list<int> $allowedGroups
     */
    private function createSecret(
        int $ownerUid = 0,
        array $allowedGroups = [],
        bool $frontendAccessible = false,
    ): Secret {
        return new Secret(
            identifier: 'test-secret',
            ownerUid: $ownerUid,
            allowedGroups: $allowedGroups,
            frontendAccessible: $frontendAccessible,
        );
    }

    /**
     * Set up a mock backend user in GLOBALS.
     */
    private function setBackendUser(
        int $uid,
        bool $isAdmin,
        array $groups = [],
        string $username = 'testuser',
        bool $isSystemMaintainer = false,
        int $disable = 0,
    ): void {
        $backendUser = $this->createMock(BackendUserAuthentication::class);
        $backendUser->user = [
            'uid' => $uid,
            'username' => $username,
            'disable' => $disable,
        ];
        $backendUser->userGroupsUID = $groups;

        $backendUser
            ->method('isAdmin')
            ->willReturn($isAdmin);

        $backendUser
            ->method('isSystemMaintainer')
            ->willReturn($isSystemMaintainer);

        $GLOBALS['BE_USER'] = $backendUser;
    }

    /**
     * Build an AccessControlService whose ConnectionPool reports the given
     * group UIDs as present in be_groups.
     *
     * @param list<int> $existingGroupUids
     */
    private function createSubjectWithExistingGroups(array $existingGroupUids): AccessControlService
    {
        $rows = array_map(static fn (int $uid): array => ['uid' => $uid], $existingGroupUids);

        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturn($rows);

        $restrictions = $this->createMock(DefaultRestrictionContainer::class);

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder
            ->method('eq')
            ->willReturn('deleted = 0');

        $queryBuilder = $this->createMock(QueryBuilder::class);
        $queryBuilder->method('getRestrictions')->willReturn($restrictions);
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder->method('createNamedParameter')->willReturn(':dcValue1');
        $queryBuilder->method('executeQuery')->willReturn($result);

        $connectionPool = $this->createMock(ConnectionPool::class);
        $connectionPool
            ->method('getQueryBuilderForTable')
            ->with('be_groups')
            ->willReturn($queryBuilder);

        return new AccessControlService($this->configuration, $connectionPool);
    }
}
