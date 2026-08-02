<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Security;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Security\AccessControlService;
use Netresearch\NrVault\Security\BreakGlassStateInterface;
use Netresearch\NrVault\Security\TechnicalActor;
use Netresearch\NrVault\Security\TechnicalActorContextInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * The disableable admin override.
 *
 * These are the invariants the feature exists for, and they are asserted across
 * BOTH gates on purpose: an override that is removed from the operation
 * permissions but left intact on the per-secret tiers (or vice versa) is
 * disabled in name only, and the deployment would believe it is protected while
 * an admin still reads every colleague's secret.
 *
 * @see AccessControlServiceIsGrantedTest for the permission matrix with the override in place
 */
#[CoversClass(AccessControlService::class)]
#[AllowMockObjectsWithoutExpectations]
final class AccessControlServiceAdminOverrideTest extends TestCase
{
    private const ADMIN_UID = 5;

    private const FOREIGN_OWNER_UID = 999;

    protected function setUp(): void
    {
        parent::setUp();
        unset($GLOBALS['BE_USER'], $GLOBALS['TYPO3_REQUEST']);
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['BE_USER'], $GLOBALS['TYPO3_REQUEST']);
        parent::tearDown();
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function hardenedAndDisabledRevokesEveryOperationPermissionFromAnAdmin(VaultPermission $permission): void
    {
        $this->setAdminBackendUser();
        $subject = $this->createSubject(SecurityProfile::Hardened, overrideDisabled: true);

        self::assertFalse($subject->isGranted($permission));
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function hardenedAndDisabledRevokesEveryOperationPermissionFromASystemMaintainer(
        VaultPermission $permission,
    ): void {
        // The maintainer role is checked separately from `admin` throughout the
        // service, so it needs its own assertion — a bypass that survives only
        // for maintainers is still a bypass.
        $this->setAdminBackendUser(isAdmin: false, isSystemMaintainer: true);
        $subject = $this->createSubject(SecurityProfile::Hardened, overrideDisabled: true);

        self::assertFalse($subject->isGranted($permission));
    }

    #[Test]
    public function hardenedAndDisabledRevokesPerSecretAccessToAForeignSecret(): void
    {
        $this->setAdminBackendUser();
        $subject = $this->createSubject(SecurityProfile::Hardened, overrideDisabled: true);
        $foreign = $this->createSecret(self::FOREIGN_OWNER_UID);

        self::assertFalse($subject->canRead($foreign), 'admin must not read a foreign secret');
        self::assertFalse($subject->canWrite($foreign));
        self::assertFalse($subject->canDelete($foreign));
    }

    #[Test]
    public function hardenedAndDisabledLeavesTheOwnerTierIntact(): void
    {
        // The override is what is removed — not every path an admin has. An
        // admin who owns a secret keeps it, exactly like any other user, which
        // is what makes the disabled state survivable at all.
        $this->setAdminBackendUser();
        $subject = $this->createSubject(SecurityProfile::Hardened, overrideDisabled: true);
        $own = $this->createSecret(self::ADMIN_UID);

        self::assertTrue($subject->canRead($own));
        self::assertTrue($subject->canWrite($own));
        self::assertTrue($subject->canDelete($own));
    }

    #[Test]
    public function hardenedAndDisabledRevokesTheAdminBypassReportedToCallers(): void
    {
        // `isCurrentActorAdmin()` is consumed as an authorization bypass by
        // SecretTcaHook (privileged columns) and VaultService (the `secret.use`
        // exemption, owner_uid / frontend_accessible coercion). If it kept
        // answering "yes" the override would still be live on those paths.
        $this->setAdminBackendUser();
        $subject = $this->createSubject(SecurityProfile::Hardened, overrideDisabled: true);

        self::assertFalse($subject->isCurrentActorAdmin());
    }

    #[Test]
    public function hardenedAndDisabledStillHonoursAnExplicitGroupGrant(): void
    {
        // Losing the override does not exile the admin from the vault: they can
        // be granted the same custom permission options as anyone else.
        $this->setAdminBackendUser(grantedOptions: [VaultPermission::SecretUse]);
        $subject = $this->createSubject(SecurityProfile::Hardened, overrideDisabled: true);

        self::assertTrue($subject->isGranted(VaultPermission::SecretUse));
        self::assertFalse($subject->isGranted(VaultPermission::SecretDelete));
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function standardProfileIgnoresTheFlagEntirely(VaultPermission $permission): void
    {
        // Lockout guard: the flag alone, without the rest of the hardened
        // policy, is far more likely to be a misunderstanding than a decision,
        // and its failure mode locks every administrator out of the vault.
        $this->setAdminBackendUser();
        $subject = $this->createSubject(SecurityProfile::Standard, overrideDisabled: true);

        self::assertTrue($subject->isGranted($permission));
    }

    #[Test]
    public function standardProfileIgnoresTheFlagForPerSecretAccessToo(): void
    {
        $this->setAdminBackendUser();
        $subject = $this->createSubject(SecurityProfile::Standard, overrideDisabled: true);

        self::assertTrue($subject->canRead($this->createSecret(self::FOREIGN_OWNER_UID)));
        self::assertTrue($subject->isCurrentActorAdmin());
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function hardenedProfileWithoutTheFlagKeepsTheOverride(VaultPermission $permission): void
    {
        $this->setAdminBackendUser();
        $subject = $this->createSubject(SecurityProfile::Hardened, overrideDisabled: false);

        self::assertTrue($subject->isGranted($permission));
    }

    #[Test]
    public function hardenedProfileWithoutTheFlagKeepsPerSecretAccess(): void
    {
        $this->setAdminBackendUser();
        $subject = $this->createSubject(SecurityProfile::Hardened, overrideDisabled: false);

        self::assertTrue($subject->canRead($this->createSecret(self::FOREIGN_OWNER_UID)));
        self::assertTrue($subject->isCurrentActorAdmin());
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function anOpenBreakGlassWindowRestoresEveryOperationPermission(VaultPermission $permission): void
    {
        $this->setAdminBackendUser();
        $subject = $this->createSubject(
            SecurityProfile::Hardened,
            overrideDisabled: true,
            breakGlassActive: true,
        );

        self::assertTrue($subject->isGranted($permission));
    }

    #[Test]
    public function anOpenBreakGlassWindowRestoresPerSecretAccessAndTheReportedBypass(): void
    {
        $this->setAdminBackendUser();
        $subject = $this->createSubject(
            SecurityProfile::Hardened,
            overrideDisabled: true,
            breakGlassActive: true,
        );
        $foreign = $this->createSecret(self::FOREIGN_OWNER_UID);

        self::assertTrue($subject->canRead($foreign));
        self::assertTrue($subject->canWrite($foreign));
        self::assertTrue($subject->canDelete($foreign));
        self::assertTrue($subject->isCurrentActorAdmin());
    }

    #[Test]
    public function aClosedBreakGlassWindowLeavesTheOverrideDisabled(): void
    {
        // The state seam reports expiry itself (read-time comparison), so
        // "expired" reaches access control as plain `isActive() === false`.
        $this->setAdminBackendUser();
        $subject = $this->createSubject(
            SecurityProfile::Hardened,
            overrideDisabled: true,
            breakGlassActive: false,
        );

        self::assertFalse($subject->isGranted(VaultPermission::SecretReveal));
        self::assertFalse($subject->canRead($this->createSecret(self::FOREIGN_OWNER_UID)));
    }

    #[Test]
    public function aMissingBreakGlassSeamFailsClosed(): void
    {
        // Nothing wired (the service constructed without the optional seam):
        // the absence of a break-glass store must read as "no window open",
        // never as "cannot tell, so allow".
        $this->setAdminBackendUser();
        $subject = new AccessControlService(
            $this->createConfiguration(SecurityProfile::Hardened, overrideDisabled: true),
        );

        self::assertFalse($subject->isGranted(VaultPermission::SecretReveal));
        self::assertFalse($subject->canRead($this->createSecret(self::FOREIGN_OWNER_UID)));
    }

    #[Test]
    public function anAdminTechnicalActorLosesItsBypassToo(): void
    {
        // A `runAs()` snapshot carrying the admin flag is the same override
        // wearing a different hat — headless code must not keep what the
        // interactive admin lost.
        $subject = $this->createSubject(
            SecurityProfile::Hardened,
            overrideDisabled: true,
            technicalActorAdmin: true,
        );

        self::assertFalse($subject->canRead($this->createSecret(self::FOREIGN_OWNER_UID)));
        self::assertFalse($subject->isGranted(VaultPermission::SecretDelete));
        self::assertTrue(
            $subject->isGranted(VaultPermission::SecretUse),
            'secret.use stays granted to every technical actor — its per-secret tier still gates it',
        );
    }

    #[Test]
    public function anOpenWindowRestoresTheTechnicalActorBypass(): void
    {
        $subject = $this->createSubject(
            SecurityProfile::Hardened,
            overrideDisabled: true,
            breakGlassActive: true,
            technicalActorAdmin: true,
        );

        self::assertTrue($subject->canRead($this->createSecret(self::FOREIGN_OWNER_UID)));
        self::assertTrue($subject->isGranted(VaultPermission::SecretDelete));
    }

    #[Test]
    public function aNonAdminIsUnaffectedByTheFlag(): void
    {
        // Regression guard on the first gate of the seam: the flag must not
        // change anything for users who never had a bypass.
        $this->setAdminBackendUser(isAdmin: false, grantedOptions: [VaultPermission::SecretUse]);
        $subject = $this->createSubject(SecurityProfile::Hardened, overrideDisabled: true);

        self::assertTrue($subject->isGranted(VaultPermission::SecretUse));
        self::assertFalse($subject->isGranted(VaultPermission::SecretRotate));
        self::assertTrue($subject->canRead($this->createSecret(self::ADMIN_UID)), 'owner tier unchanged');
    }

    /**
     * @return iterable<string, array{VaultPermission}>
     */
    public static function allPermissionsProvider(): iterable
    {
        foreach (VaultPermission::cases() as $permission) {
            yield $permission->value => [$permission];
        }
    }

    private function createSubject(
        SecurityProfile $profile,
        bool $overrideDisabled,
        bool $breakGlassActive = false,
        ?bool $technicalActorAdmin = null,
    ): AccessControlService {
        $breakGlass = $this->createMock(BreakGlassStateInterface::class);
        $breakGlass->method('isActive')->willReturn($breakGlassActive);

        $technicalActorContext = null;
        if ($technicalActorAdmin !== null) {
            $technicalActorContext = $this->createMock(TechnicalActorContextInterface::class);
            $technicalActorContext
                ->method('getCurrentActor')
                ->willReturn(new TechnicalActor(
                    uid: 10,
                    username: 'tech_indexer',
                    admin: $technicalActorAdmin,
                    groupIds: [],
                ));
        }

        return new AccessControlService(
            $this->createConfiguration($profile, $overrideDisabled),
            null,
            $technicalActorContext,
            $breakGlass,
        );
    }

    private function createConfiguration(
        SecurityProfile $profile,
        bool $overrideDisabled,
    ): ExtensionConfigurationInterface&MockObject {
        $configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $configuration->method('getSecurityProfile')->willReturn($profile);
        $configuration->method('isAdminOverrideDisabled')->willReturn($overrideDisabled);

        return $configuration;
    }

    /**
     * @param list<VaultPermission> $grantedOptions
     */
    private function setAdminBackendUser(
        bool $isAdmin = true,
        bool $isSystemMaintainer = false,
        array $grantedOptions = [],
    ): void {
        $GLOBALS['BE_USER'] = $this->createMockBackendUser(
            uid: self::ADMIN_UID,
            isAdmin: $isAdmin,
            isSystemMaintainer: $isSystemMaintainer,
            grantedPermissions: $grantedOptions,
        );
    }

    private function createSecret(int $ownerUid): Secret
    {
        return new Secret(
            identifier: 'test-secret',
            ownerUid: $ownerUid,
        );
    }
}
