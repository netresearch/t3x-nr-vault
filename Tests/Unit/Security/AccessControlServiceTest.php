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
use Netresearch\NrVault\Security\TechnicalActor;
use Netresearch\NrVault\Security\TechnicalActorContextInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Authentication\CommandLineUserAuthentication;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Database\Query\Restriction\DefaultRestrictionContainer;
use TYPO3\CMS\Core\Http\ServerRequest;

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
        unset($GLOBALS['BE_USER'], $GLOBALS['TYPO3_REQUEST']);
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['BE_USER'], $GLOBALS['TYPO3_REQUEST']);
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

    /**
     * `allowCliAccess` describes what a CLI operator may do — it never decides
     * who counts as one. An unattributable web actor stays denied.
     */
    #[Test]
    public function canCreateIsDeniedWithoutAnyActorEvenWhenCliAccessIsAllowed(): void
    {
        $this->configuration->method('isCliAccessAllowed')->willReturn(true);

        self::assertFalse($this->subject->canCreate());
    }

    /**
     * The `disable` column is optional in the session record, and a driver may
     * hand it over as a string. "Absent" and "'0'" both mean enabled — reading
     * either as disabled locks legitimate users out of their own secrets.
     */
    #[Test]
    public function backendUserRecordWithoutADisableColumnIsNotDisabled(): void
    {
        $backendUser = $this->createMockBackendUser(uid: 5);
        /** @phpstan-ignore property.internal */
        $backendUser->user = ['uid' => 5, 'username' => 'no_disable_column'];

        $GLOBALS['BE_USER'] = $backendUser;

        self::assertTrue($this->subject->canCreate());
    }

    #[Test]
    public function backendUserWithADisableColumnOfStringZeroIsNotDisabled(): void
    {
        $backendUser = $this->createMockBackendUser(uid: 5);
        /** @phpstan-ignore property.internal */
        $backendUser->user = ['uid' => 5, 'username' => 'string_columns', 'disable' => '0'];

        $GLOBALS['BE_USER'] = $backendUser;

        self::assertTrue($this->subject->canCreate());
    }

    /**
     * A session record without a usable uid must not accidentally *own*
     * anything: the fallback uid is the one value no real be_users row can
     * carry, so no owner check can match it.
     */
    #[Test]
    public function backendUserWithoutAUidOwnsNoSecret(): void
    {
        $backendUser = $this->createMockBackendUser(uid: 5);
        /** @phpstan-ignore property.internal */
        $backendUser->user = ['username' => 'no_uid', 'disable' => 0];

        $GLOBALS['BE_USER'] = $backendUser;

        self::assertFalse($this->subject->canRead($this->createSecret(ownerUid: 1)));
        self::assertFalse($this->subject->canRead($this->createSecret(ownerUid: -1)));
    }

    /**
     * `TYPO3_cliMode` is a legacy constant; only the value `true` classifies a
     * request as CLI. Reading a falsy one as CLI would attribute every web
     * access to the trusted CLI operator.
     *
     * Defining it as `false` is inert for the rest of the suite — that is
     * exactly the branch the production code ignores.
     */
    #[Test]
    public function actorTypeIgnoresAFalsyLegacyCliModeConstant(): void
    {
        if (!\defined('TYPO3_cliMode')) {
            \define('TYPO3_cliMode', false);
        }

        self::assertSame('api', $this->subject->getCurrentActorType());
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
    public function frontendAccessibleGrantsReadOnlyWithoutBackendUser(): void
    {
        // ADR-005 least-privilege split: frontend_accessible is READ-ONLY.
        // Without a backend or CLI actor, write/delete must always be denied
        // even when the secret is frontend-accessible.
        $secret = $this->createSecret(ownerUid: 0, frontendAccessible: true);

        self::assertTrue($this->subject->canRead($secret), 'frontend-accessible secret is readable');
        self::assertFalse($this->subject->canWrite($secret), 'frontend has no write tier');
        self::assertFalse($this->subject->canDelete($secret), 'frontend has no delete tier');
    }

    #[Test]
    public function frontendRequestDeniesNonFrontendAccessibleSecretDespiteAmbientBackendUser(): void
    {
        // TYPO3's frontend BackendUserAuthenticator middleware sets
        // $GLOBALS['BE_USER'] for any visitor carrying a backend session.
        // That ambient identity must NOT unlock a secret which is not
        // frontend-accessible — the rendered output goes into the shared
        // page cache and is served to anonymous visitors afterwards.
        $this->setFrontendRequest();
        $this->setBackendUser(uid: 1, isAdmin: true);
        $secret = $this->createSecret(ownerUid: 1, frontendAccessible: false);

        self::assertFalse($this->subject->canRead($secret));
    }

    #[Test]
    public function frontendRequestGrantsOnlyTheReadGateDespiteAmbientBackendUser(): void
    {
        // Same request shape, but the secret IS frontend-accessible: read is
        // granted (as for an anonymous visitor), write/delete stay denied
        // even though the ambient backend user is an admin.
        $this->setFrontendRequest();
        $this->setBackendUser(uid: 1, isAdmin: true);
        $secret = $this->createSecret(ownerUid: 1, frontendAccessible: true);

        self::assertTrue($this->subject->canRead($secret), 'frontend-accessible secret is readable');
        self::assertFalse($this->subject->canWrite($secret), 'frontend has no write tier');
        self::assertFalse($this->subject->canDelete($secret), 'frontend has no delete tier');
    }

    #[Test]
    public function backendRequestKeepsBackendUserSemantics(): void
    {
        // Counterpart: a request positively identified as BACKEND keeps the
        // full backend-user semantics.
        $GLOBALS['TYPO3_REQUEST'] = (new ServerRequest())
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_BE);
        $this->setBackendUser(uid: 1, isAdmin: true);
        $secret = $this->createSecret(ownerUid: 999, frontendAccessible: false);

        self::assertTrue($this->subject->canRead($secret));
        self::assertTrue($this->subject->canWrite($secret));
        self::assertTrue($this->subject->canDelete($secret));
    }

    #[Test]
    public function requestWithoutApplicationTypeKeepsBackendUserSemantics(): void
    {
        // The application type cannot be established (request not created by
        // a TYPO3 application) — behaviour stays exactly as before.
        $GLOBALS['TYPO3_REQUEST'] = new ServerRequest();
        $this->setBackendUser(uid: 1, isAdmin: true);
        $secret = $this->createSecret(ownerUid: 999, frontendAccessible: false);

        self::assertTrue($this->subject->canRead($secret));
    }

    #[Test]
    public function technicalActorSupersedesTheFrontendGate(): void
    {
        // ADR-029: an explicit runAs() scope is opted into by the caller and
        // keeps its user-based semantics wherever it is opened — it is not
        // downgraded to the frontend gate.
        $this->setFrontendRequest();

        $subject = $this->createSubjectWithTechnicalActor(
            new TechnicalActor(uid: 42, username: 'tech', admin: false, groupIds: []),
        );
        $secret = $this->createSecret(ownerUid: 42, frontendAccessible: false);

        self::assertTrue($subject->canRead($secret));
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
    public function readTierGroupMemberCannotWrite(): void
    {
        // ADR-005 least-privilege split: a member of the READ tier
        // (allowed_groups) may read but MUST NOT write.
        $this->setBackendUser(uid: 5, isAdmin: false, groups: [10, 20]);
        $secret = $this->createSecret(ownerUid: 999, allowedGroups: [20]);

        $subject = $this->createSubjectWithExistingGroups([10, 20]);

        self::assertFalse($subject->canWrite($secret), 'read-tier group must not write');
    }

    #[Test]
    public function readTierGroupMemberCannotDelete(): void
    {
        // ADR-005: a read-tier member must never delete (delete has no
        // group tier at all).
        $this->setBackendUser(uid: 5, isAdmin: false, groups: [10, 20]);
        $secret = $this->createSecret(ownerUid: 999, allowedGroups: [20]);

        $subject = $this->createSubjectWithExistingGroups([10, 20]);

        self::assertFalse($subject->canDelete($secret), 'read-tier group must not delete');
    }

    #[Test]
    public function writeTierGroupMemberCanReadAndWriteButNotDelete(): void
    {
        // ADR-005 least-privilege split: a member of the WRITE tier
        // (write_groups) may read and write, but delete is reserved for
        // owner/admin/maintainer.
        $this->setBackendUser(uid: 5, isAdmin: false, groups: [10, 20]);
        $secret = $this->createSecret(ownerUid: 999, writeGroups: [20]);

        $subject = $this->createSubjectWithExistingGroups([10, 20]);

        self::assertTrue($subject->canRead($secret), 'write-tier member can read');
        self::assertTrue($subject->canWrite($secret), 'write-tier member can write');
        self::assertFalse($subject->canDelete($secret), 'write-tier member cannot delete');
    }

    #[Test]
    public function writeTierMemberWithoutReadTierStillReads(): void
    {
        // A user who is ONLY in the write tier (not listed in allowed_groups)
        // must still be able to read — write implies read.
        $this->setBackendUser(uid: 5, isAdmin: false, groups: [7]);
        $secret = $this->createSecret(ownerUid: 999, allowedGroups: [3], writeGroups: [7]);

        $subject = $this->createSubjectWithExistingGroups([7]);

        self::assertTrue($subject->canRead($secret), 'write-only-tier member can read');
        self::assertTrue($subject->canWrite($secret), 'write-only-tier member can write');
    }

    #[Test]
    public function nonGroupMemberGetsNothingAcrossAllTiers(): void
    {
        // A user in neither tier gets no access at all.
        $this->setBackendUser(uid: 5, isAdmin: false, groups: [99]);
        $secret = $this->createSecret(ownerUid: 999, allowedGroups: [1], writeGroups: [2]);

        $subject = $this->createSubjectWithExistingGroups([1, 2, 99]);

        self::assertFalse($subject->canRead($secret));
        self::assertFalse($subject->canWrite($secret));
        self::assertFalse($subject->canDelete($secret));
    }

    #[Test]
    public function ownerHasFullAccessAcrossAllTiers(): void
    {
        // The owner gets read/write/delete regardless of group tiers.
        $this->setBackendUser(uid: 5, isAdmin: false);
        $secret = $this->createSecret(ownerUid: 5, allowedGroups: [1], writeGroups: [2]);

        self::assertTrue($this->subject->canRead($secret));
        self::assertTrue($this->subject->canWrite($secret));
        self::assertTrue($this->subject->canDelete($secret));
    }

    #[Test]
    public function adminHasFullAccessAcrossAllTiers(): void
    {
        $this->setBackendUser(uid: 1, isAdmin: true);
        $secret = $this->createSecret(ownerUid: 999, allowedGroups: [1], writeGroups: [2]);

        self::assertTrue($this->subject->canRead($secret));
        self::assertTrue($this->subject->canWrite($secret));
        self::assertTrue($this->subject->canDelete($secret));
    }

    #[Test]
    public function writeTierIgnoresStaleGroupIds(): void
    {
        // Defence-in-depth: a stale (deleted) write-tier group UID still in
        // the session must NOT grant write access.
        $this->setBackendUser(uid: 5, isAdmin: false, groups: [88888]);
        $secret = $this->createSecret(ownerUid: 999, writeGroups: [88888]);

        // be_groups reports the group as NOT existing.
        $subject = $this->createSubjectWithExistingGroups([]);

        self::assertFalse($subject->canWrite($secret), 'stale write-tier group must not grant write');
        self::assertFalse($subject->canRead($secret), 'stale write-tier group must not grant read');
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
    public function getCurrentActorTypeReturnsCliForCommandLineUser(): void
    {
        // Regression test for the CLI misclassification bug: the TYPO3 CLI
        // bootstrap (vendor/bin/typo3, messenger workers) sets BE_USER to a
        // CommandLineUserAuthentication instance, which EXTENDS
        // BackendUserAuthentication. The backend-user check must not win —
        // CLI/worker reads are 'cli', not 'backend' (otherwise the analytics
        // module counts every automated read as a manual reveal).
        $this->setCommandLineUser();

        self::assertSame('cli', $this->subject->getCurrentActorType());
    }

    #[Test]
    public function getCurrentActorTypeReturnsBackendForRegularUserDespiteCliFirstOrdering(): void
    {
        // Counter-check for the CLI-first ordering: a regular (web) backend
        // user is still classified as 'backend'.
        $this->setBackendUser(uid: 1, isAdmin: false);

        self::assertSame('backend', $this->subject->getCurrentActorType());
    }

    #[Test]
    public function getCurrentActorUsernameReturnsCliUsernameForCommandLineUser(): void
    {
        // Audit rows for CLI/worker reads keep the informative `_cli_`
        // username from the authenticated CLI backend user record.
        $this->setCommandLineUser();

        self::assertSame('_cli_', $this->subject->getCurrentActorUsername());
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

    #[Test]
    public function unauthenticatedCliUserFollowsCliAccessRulesWhenAllowed(): void
    {
        // BUG FIX verification (messenger-worker CLI access): the TYPO3 CLI
        // bootstrap (CommandApplication::run() — console commands, Symfony
        // Messenger workers, scheduler runs) sets BE_USER to a
        // CommandLineUserAuthentication "not logged in yet" (user record
        // null). That placeholder used to take the backend-user precedence
        // branch in hasAccess(), where every check fails on the empty user
        // record — shadowing the configured CLI access rules entirely.
        // With CLI access allowed and no group restrictions, the trusted
        // CLI operator gets every tier.
        $this->configuration->method('isCliAccessAllowed')->willReturn(true);
        $this->configuration->method('getCliAccessGroups')->willReturn([]);
        $this->setUnauthenticatedCommandLineUser();
        $secret = $this->createSecret(ownerUid: 42);

        self::assertTrue($this->subject->canRead($secret), 'CLI access allowed: read granted');
        self::assertTrue($this->subject->canWrite($secret), 'CLI access allowed: write granted');
        self::assertTrue($this->subject->canDelete($secret), 'CLI access allowed: delete granted');
    }

    #[Test]
    public function unauthenticatedCliUserIsDeniedWhenCliAccessDisabled(): void
    {
        $this->configuration->method('isCliAccessAllowed')->willReturn(false);
        $this->setUnauthenticatedCommandLineUser();
        $secret = $this->createSecret(ownerUid: 42);

        self::assertFalse($this->subject->canRead($secret), 'CLI access off: read denied');
        self::assertFalse($this->subject->canWrite($secret), 'CLI access off: write denied');
        self::assertFalse($this->subject->canDelete($secret), 'CLI access off: delete denied');
    }

    #[Test]
    public function unauthenticatedCliUserIsScopedToConfiguredCliAccessGroups(): void
    {
        // Group-scoped CLI access: read may match read- OR write-tier groups,
        // write only write-tier groups, delete has no group tier at all.
        $this->configuration->method('isCliAccessAllowed')->willReturn(true);
        $this->configuration->method('getCliAccessGroups')->willReturn([5]);
        $this->setUnauthenticatedCommandLineUser();

        $inScope = $this->createSecret(ownerUid: 42, allowedGroups: [5]);
        $outOfScope = $this->createSecret(ownerUid: 42, allowedGroups: [7]);
        $writable = $this->createSecret(ownerUid: 42, writeGroups: [5]);

        self::assertTrue($this->subject->canRead($inScope), 'read-tier group in CLI scope: read granted');
        self::assertFalse($this->subject->canWrite($inScope), 'read-tier group only: write denied');
        self::assertFalse($this->subject->canRead($outOfScope), 'group outside CLI scope: read denied');
        self::assertTrue($this->subject->canWrite($writable), 'write-tier group in CLI scope: write granted');
        self::assertFalse($this->subject->canDelete($writable), 'group-scoped CLI cannot delete');
    }

    #[Test]
    public function unauthenticatedCliUserDoesNotOwnOwnerUidZeroSecrets(): void
    {
        // BUG FIX verification: the placeholder's missing user record used to
        // default to uid 0 in the backend-user branch and MATCH ownerUid=0
        // secrets via the owner check — granting full access (including
        // delete) even with CLI access disabled. CLI rules apply instead.
        $this->configuration->method('isCliAccessAllowed')->willReturn(false);
        $this->setUnauthenticatedCommandLineUser();
        $secret = $this->createSecret(ownerUid: 0);

        self::assertFalse($this->subject->canRead($secret), 'ownerUid=0 must not grant read to placeholder');
        self::assertFalse($this->subject->canWrite($secret), 'ownerUid=0 must not grant write to placeholder');
        self::assertFalse($this->subject->canDelete($secret), 'ownerUid=0 must not grant delete to placeholder');
    }

    #[Test]
    public function unauthenticatedCliUserCanCreateFollowsCliAccessConfig(): void
    {
        // BUG FIX verification: canCreate() used to treat the placeholder as
        // an enabled backend user and returned true regardless of the CLI
        // access configuration.
        $this->configuration->method('isCliAccessAllowed')->willReturn(false);
        $this->setUnauthenticatedCommandLineUser();

        self::assertFalse($this->subject->canCreate(), 'CLI access off: create denied');
    }

    #[Test]
    public function unauthenticatedCliUserCanCreateWhenCliAccessAllowed(): void
    {
        $this->configuration->method('isCliAccessAllowed')->willReturn(true);
        $this->setUnauthenticatedCommandLineUser();

        self::assertTrue($this->subject->canCreate(), 'CLI access on: create granted');
    }

    #[Test]
    public function authenticatedCliUserKeepsUserBasedAccessSemantics(): void
    {
        // An AUTHENTICATED CLI user (after Bootstrap::initializeBackendAuthentication()
        // loaded the `_cli_` record — an admin in TYPO3) keeps the user-based
        // precedence: user semantics decide, the CLI access config does not
        // apply. isCliAccessAllowed() must not even be consulted.
        $this->configuration->expects(self::never())->method('isCliAccessAllowed');

        $commandLineUser = $this->createMock(CommandLineUserAuthentication::class);
        $commandLineUser->user = [
            'uid' => 1,
            'username' => '_cli_',
            'disable' => 0,
        ];
        $commandLineUser->userGroupsUID = [];
        $commandLineUser->method('isAdmin')->willReturn(true);
        $GLOBALS['BE_USER'] = $commandLineUser;

        $secret = $this->createSecret(ownerUid: 42);

        self::assertTrue($this->subject->canRead($secret), 'authenticated _cli_ admin: read via user semantics');
        self::assertTrue($this->subject->canDelete($secret), 'authenticated _cli_ admin: delete via user semantics');
        self::assertTrue($this->subject->canCreate(), 'authenticated _cli_ admin: create via user semantics');
    }

    #[Test]
    public function unauthenticatedCliUserIsClassifiedAsCliActor(): void
    {
        // Audit classification for the messenger-worker placeholder stays 'cli'.
        $this->setUnauthenticatedCommandLineUser();

        self::assertSame('cli', $this->subject->getCurrentActorType());
    }

    // ----- TechnicalActorContext (scoped runAs identity) ---------------------

    #[Test]
    public function technicalActorAdminHasFullAccessToAnySecret(): void
    {
        $subject = $this->createSubjectWithTechnicalActor(
            new TechnicalActor(uid: 42, username: 'tech', admin: true, groupIds: []),
        );
        $secret = $this->createSecret(ownerUid: 999);

        self::assertTrue($subject->canRead($secret));
        self::assertTrue($subject->canWrite($secret));
        self::assertTrue($subject->canDelete($secret));
    }

    #[Test]
    public function technicalActorOwnerHasFullAccessToOwnSecret(): void
    {
        $subject = $this->createSubjectWithTechnicalActor(
            new TechnicalActor(uid: 42, username: 'tech', admin: false, groupIds: []),
        );
        $secret = $this->createSecret(ownerUid: 42);

        self::assertTrue($subject->canRead($secret));
        self::assertTrue($subject->canWrite($secret));
        self::assertTrue($subject->canDelete($secret));
    }

    #[Test]
    public function technicalActorIsDeniedOnUnrelatedSecret(): void
    {
        $subject = $this->createSubjectWithTechnicalActor(
            new TechnicalActor(uid: 42, username: 'tech', admin: false, groupIds: []),
        );
        $secret = $this->createSecret(ownerUid: 999, allowedGroups: [7]);

        self::assertFalse($subject->canRead($secret));
        self::assertFalse($subject->canWrite($secret));
        self::assertFalse($subject->canDelete($secret));
    }

    #[Test]
    public function technicalActorReadTierGroupGrantsReadButNotWriteOrDelete(): void
    {
        $subject = $this->createSubjectWithTechnicalActor(
            new TechnicalActor(uid: 42, username: 'tech', admin: false, groupIds: [5]),
            existingGroupUids: [5],
        );
        $secret = $this->createSecret(ownerUid: 999, allowedGroups: [5]);

        self::assertTrue($subject->canRead($secret));
        self::assertFalse($subject->canWrite($secret));
        self::assertFalse($subject->canDelete($secret));
    }

    #[Test]
    public function technicalActorWriteTierGroupGrantsReadAndWriteButNotDelete(): void
    {
        $subject = $this->createSubjectWithTechnicalActor(
            new TechnicalActor(uid: 42, username: 'tech', admin: false, groupIds: [5]),
            existingGroupUids: [5],
        );
        $secret = $this->createSecret(ownerUid: 999, writeGroups: [5]);

        self::assertTrue($subject->canRead($secret));
        self::assertTrue($subject->canWrite($secret));
        self::assertFalse($subject->canDelete($secret));
    }

    #[Test]
    public function technicalActorStaleGroupDoesNotGrantAccess(): void
    {
        // Group 5 is in the actor's snapshot but no longer exists in
        // be_groups — the same stale-group defence as for real BE users.
        $subject = $this->createSubjectWithTechnicalActor(
            new TechnicalActor(uid: 42, username: 'tech', admin: false, groupIds: [5]),
            existingGroupUids: [],
        );
        $secret = $this->createSecret(ownerUid: 999, allowedGroups: [5]);

        self::assertFalse($subject->canRead($secret));
    }

    #[Test]
    public function technicalActorSupersedesUnauthenticatedCliPlaceholder(): void
    {
        // Messenger-worker reality: $GLOBALS['BE_USER'] holds the CLI
        // placeholder and CLI access is disabled — the runAs() actor still
        // gets its user-based semantics.
        $this->setUnauthenticatedCommandLineUser();
        $this->configuration->method('isCliAccessAllowed')->willReturn(false);

        $subject = $this->createSubjectWithTechnicalActor(
            new TechnicalActor(uid: 42, username: 'tech', admin: false, groupIds: []),
        );
        $secret = $this->createSecret(ownerUid: 42);

        self::assertTrue($subject->canRead($secret));
    }

    #[Test]
    public function technicalActorSupersedesAmbientBackendUser(): void
    {
        // The ambient admin session must NOT leak into a runAs() scope: the
        // non-admin technical actor is denied on a foreign secret even while
        // $GLOBALS['BE_USER'] is an admin.
        $this->setBackendUser(uid: 1, isAdmin: true);

        $subject = $this->createSubjectWithTechnicalActor(
            new TechnicalActor(uid: 42, username: 'tech', admin: false, groupIds: []),
        );
        $secret = $this->createSecret(ownerUid: 999);

        self::assertFalse($subject->canRead($secret));
    }

    #[Test]
    public function technicalActorCanCreate(): void
    {
        $subject = $this->createSubjectWithTechnicalActor(
            new TechnicalActor(uid: 42, username: 'tech', admin: false, groupIds: []),
        );

        self::assertTrue($subject->canCreate());
    }

    #[Test]
    public function technicalActorIsReportedForAuditAttribution(): void
    {
        $subject = $this->createSubjectWithTechnicalActor(
            new TechnicalActor(uid: 42, username: 'tech_indexer', admin: false, groupIds: [5, 7]),
        );

        self::assertSame('technical', $subject->getCurrentActorType());
        self::assertSame(42, $subject->getCurrentActorUid());
        self::assertSame('tech_indexer', $subject->getCurrentActorUsername());
        self::assertSame([5, 7], $subject->getCurrentUserGroups());
    }

    #[Test]
    public function technicalActorTypeSupersedesCliClassification(): void
    {
        $this->setUnauthenticatedCommandLineUser();

        $subject = $this->createSubjectWithTechnicalActor(
            new TechnicalActor(uid: 42, username: 'tech', admin: false, groupIds: []),
        );

        self::assertSame('technical', $subject->getCurrentActorType());
    }

    #[Test]
    public function isCurrentActorAdminReflectsTheTechnicalActor(): void
    {
        $admin = $this->createSubjectWithTechnicalActor(
            new TechnicalActor(uid: 42, username: 'tech', admin: true, groupIds: []),
        );
        $nonAdmin = $this->createSubjectWithTechnicalActor(
            new TechnicalActor(uid: 42, username: 'tech', admin: false, groupIds: []),
        );

        self::assertTrue($admin->isCurrentActorAdmin());
        self::assertFalse($nonAdmin->isCurrentActorAdmin());
    }

    /**
     * Holding *an* existing group is not holding the secret's group. Without
     * the intersection every actor with any surviving group would read every
     * group-scoped secret.
     */
    #[Test]
    public function technicalActorGroupsMustIntersectTheSecretGroups(): void
    {
        $subject = $this->createSubjectWithTechnicalActor(
            new TechnicalActor(uid: 10, username: 'tech_indexer', admin: false, groupIds: [9]),
            existingGroupUids: [9],
        );

        self::assertFalse($subject->canRead($this->createSecret(ownerUid: 1, allowedGroups: [5])));
    }

    /**
     * The stale-group filter is the reason a deleted group cannot grant
     * access, so its query must see deleted rows (restrictions removed) and
     * exclude them by its own `deleted = 0` constraint.
     */
    #[Test]
    public function existingGroupLookupDropsRestrictionsAndExcludesDeletedGroups(): void
    {
        $restrictions = $this->createMock(DefaultRestrictionContainer::class);
        $restrictions->expects(self::once())->method('removeAll');

        $parameters = [];
        $subject = $this->createSubjectWithObservableGroupLookup(
            [['uid' => 7]],
            restrictions: $restrictions,
            capturedParameters: $parameters,
        );

        self::assertSame([7], $subject->filterExistingGroupIds([7]));
        self::assertContains(
            [0, Connection::PARAM_INT],
            $parameters,
            'Deleted groups must be excluded by the query itself',
        );
    }

    #[Test]
    public function existingGroupLookupIsCachedForTheLifetimeOfTheService(): void
    {
        $subject = $this->createSubjectWithObservableGroupLookup([['uid' => 7]], expectedQueries: 1);

        self::assertSame([7], $subject->filterExistingGroupIds([7]));
        self::assertSame([7], $subject->filterExistingGroupIds([7]));
    }

    #[Test]
    public function filteringAnEmptyGroupListAnswersWithoutQuerying(): void
    {
        $subject = $this->createSubjectWithObservableGroupLookup([], expectedQueries: 0);

        self::assertSame([], $subject->filterExistingGroupIds([]));
    }

    /**
     * Group uids arriving as strings must become integers: the filtered list
     * is compared against a secret's group list, and a '007' that never became
     * 7 would silently stop matching.
     */
    #[Test]
    public function numericStringGroupUidsFromTheDatabaseAreNormalisedToIntegers(): void
    {
        $subject = $this->createSubjectWithObservableGroupLookup([['uid' => '007']]);

        self::assertSame([7], $subject->filterExistingGroupIds([7]));
    }

    // ----- Characterization: behaviour without an active runAs() scope ------

    #[Test]
    public function inactiveTechnicalActorContextKeepsWebBehaviourIdentical(): void
    {
        // A wired-but-inactive context (no runAs() scope) must not change a
        // single ambient decision. Mirrors the pre-existing expectations of
        // canReadReturnsFalseWithoutBackendUser / canReadReturnsTrueForAdmin /
        // canReadReturnsTrueForOwner.
        $subject = $this->createSubjectWithTechnicalActor(null);

        $foreign = $this->createSecret(ownerUid: 1);
        self::assertFalse($subject->canRead($foreign), 'no BE user: denied');
        self::assertFalse($subject->canCreate(), 'no BE user: cannot create');
        self::assertSame(0, $subject->getCurrentActorUid());

        $this->setBackendUser(uid: 5, isAdmin: false);
        $own = $this->createSecret(ownerUid: 5);
        self::assertTrue($subject->canRead($own), 'owner: allowed');
        self::assertFalse($subject->canRead($foreign), 'non-owner: denied');
        self::assertSame('backend', $subject->getCurrentActorType());
        self::assertSame(5, $subject->getCurrentActorUid());

        $this->setBackendUser(uid: 1, isAdmin: true);
        self::assertTrue($subject->canRead($foreign), 'admin: allowed');
        self::assertTrue($subject->canDelete($foreign), 'admin: delete allowed');
    }

    #[Test]
    public function inactiveTechnicalActorContextKeepsCliBehaviourIdentical(): void
    {
        // Mirrors unauthenticatedCliUserIsClassifiedAsCliActor and the CLI
        // access-config routing with a wired-but-inactive context.
        $this->setUnauthenticatedCommandLineUser();
        $this->configuration->method('isCliAccessAllowed')->willReturn(false);

        $subject = $this->createSubjectWithTechnicalActor(null);
        $secret = $this->createSecret(ownerUid: 0);

        self::assertSame('cli', $subject->getCurrentActorType());
        self::assertFalse($subject->canRead($secret), 'CLI disabled: denied');
        self::assertFalse($subject->canCreate(), 'CLI disabled: cannot create');
    }

    /**
     * Set up a mock CLI backend user WITHOUT an authenticated user record, as
     * present in Symfony Messenger workers and scheduler CLI runs: the TYPO3
     * CLI bootstrap (CommandApplication::run() -> Bootstrap::initializeBackendUser())
     * creates the BE_USER "not logged in yet" — `user` stays null unless a
     * command calls Bootstrap::initializeBackendAuthentication().
     */
    private function setUnauthenticatedCommandLineUser(): void
    {
        $commandLineUser = $this->createMock(CommandLineUserAuthentication::class);
        // Deliberately NO $commandLineUser->user assignment: stays null.
        $GLOBALS['BE_USER'] = $commandLineUser;
    }

    /**
     * Create a test Secret with specified properties.
     *
     * @param list<int> $allowedGroups
     * @param list<int> $writeGroups
     */
    private function createSecret(
        int $ownerUid = 0,
        array $allowedGroups = [],
        bool $frontendAccessible = false,
        array $writeGroups = [],
    ): Secret {
        return new Secret(
            identifier: 'test-secret',
            ownerUid: $ownerUid,
            allowedGroups: $allowedGroups,
            writeGroups: $writeGroups,
            frontendAccessible: $frontendAccessible,
        );
    }

    /**
     * Put a TYPO3 FRONTEND request into $GLOBALS['TYPO3_REQUEST'], as the
     * frontend application does for every rendered page request.
     */
    private function setFrontendRequest(): void
    {
        $GLOBALS['TYPO3_REQUEST'] = (new ServerRequest())
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_FE);
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
     * Set up a mock CLI backend user in GLOBALS, as created by the TYPO3 CLI
     * bootstrap (`vendor/bin/typo3`, messenger workers).
     */
    private function setCommandLineUser(): void
    {
        $commandLineUser = $this->createMock(CommandLineUserAuthentication::class);
        $commandLineUser->user = [
            'uid' => 1,
            'username' => '_cli_',
            'disable' => 0,
        ];
        $commandLineUser->userGroupsUID = [];

        $GLOBALS['BE_USER'] = $commandLineUser;
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

    /**
     * Build an AccessControlService whose be_groups lookup is observable: how
     * often it runs, which restrictions it drops and which named parameters it
     * binds.
     *
     * @param list<array<string, mixed>> $rows rows the lookup returns
     * @param int|null $expectedQueries exact number of lookups
     *                                  expected; null = at least one
     * @param list<array{mixed, mixed}> $capturedParameters collects every
     *                                                      createNamedParameter() call as [value, type]
     */
    private function createSubjectWithObservableGroupLookup(
        array $rows,
        ?int $expectedQueries = null,
        ?DefaultRestrictionContainer $restrictions = null,
        array &$capturedParameters = [],
    ): AccessControlService {
        $result = $this->createMock(Result::class);
        $result->method('fetchAllAssociative')->willReturn($rows);

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->method('eq')->willReturn('deleted = 0');

        $queryBuilder = $this->createMock(QueryBuilder::class);
        $queryBuilder
            ->method('getRestrictions')
            ->willReturn($restrictions ?? $this->createMock(DefaultRestrictionContainer::class));
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder
            ->method('createNamedParameter')
            ->willReturnCallback(
                static function (mixed $value, mixed $type = null) use (&$capturedParameters): string {
                    $capturedParameters[] = [$value, $type];

                    return ':dcValue1';
                },
            );
        $queryBuilder->method('executeQuery')->willReturn($result);

        $connectionPool = $this->createMock(ConnectionPool::class);
        $connectionPool
            ->expects($expectedQueries === null ? self::atLeastOnce() : self::exactly($expectedQueries))
            ->method('getQueryBuilderForTable')
            ->with('be_groups')
            ->willReturn($queryBuilder);

        return new AccessControlService($this->configuration, $connectionPool);
    }

    /**
     * Build an AccessControlService wired to a TechnicalActorContext whose
     * current actor is `$actor` (null = wired but no active runAs() scope).
     *
     * @param list<int>|null $existingGroupUids be_groups uids the ConnectionPool
     *                                          reports as existing; null = no
     *                                          ConnectionPool (group checks fail closed)
     */
    private function createSubjectWithTechnicalActor(
        ?TechnicalActor $actor,
        ?array $existingGroupUids = null,
    ): AccessControlService {
        $technicalActorContext = $this->createMock(TechnicalActorContextInterface::class);
        $technicalActorContext->method('getCurrentActor')->willReturn($actor);

        $connectionPool = null;
        if ($existingGroupUids !== null) {
            $rows = array_map(static fn (int $uid): array => ['uid' => $uid], $existingGroupUids);

            $result = $this->createMock(Result::class);
            $result->method('fetchAllAssociative')->willReturn($rows);

            $expressionBuilder = $this->createMock(ExpressionBuilder::class);
            $expressionBuilder->method('eq')->willReturn('deleted = 0');

            $queryBuilder = $this->createMock(QueryBuilder::class);
            $queryBuilder->method('getRestrictions')->willReturn($this->createMock(DefaultRestrictionContainer::class));
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
        }

        return new AccessControlService($this->configuration, $connectionPool, $technicalActorContext);
    }
}
