<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Security;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Security\AccessControlService;
use Netresearch\NrVault\Security\TechnicalActor;
use Netresearch\NrVault\Security\TechnicalActorContextInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use TYPO3\CMS\Core\Authentication\CommandLineUserAuthentication;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\Http\ServerRequest;

/**
 * Operation-permission matrix for {@see AccessControlService::isGranted()}.
 *
 * Kept separate from the per-secret tier tests in
 * {@see AccessControlServiceTest} because this is the orthogonal gate: which
 * KINDS of operation an actor may perform, independent of any single secret.
 */
#[CoversClass(AccessControlService::class)]
#[AllowMockObjectsWithoutExpectations]
final class AccessControlServiceIsGrantedTest extends TestCase
{
    private AccessControlService $subject;

    private ExtensionConfigurationInterface&MockObject $configuration;

    protected function setUp(): void
    {
        parent::setUp();

        $this->configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $this->subject = new AccessControlService($this->configuration);

        unset($GLOBALS['BE_USER'], $GLOBALS['TYPO3_REQUEST']);
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['BE_USER'], $GLOBALS['TYPO3_REQUEST']);
        parent::tearDown();
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function adminIsGrantedEveryPermission(VaultPermission $permission): void
    {
        $this->setBackendUser(isAdmin: true);

        self::assertTrue($this->subject->isGranted($permission));
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function systemMaintainerIsGrantedEveryPermission(VaultPermission $permission): void
    {
        $this->setBackendUser(isAdmin: false, isSystemMaintainer: true);

        self::assertTrue($this->subject->isGranted($permission));
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function nonAdminWithoutAnyCustomOptionIsGrantedNothing(VaultPermission $permission): void
    {
        $this->setBackendUser(isAdmin: false, grantedOptions: []);

        self::assertFalse($this->subject->isGranted($permission));
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function nonAdminWithMatchingCustomOptionIsGranted(VaultPermission $permission): void
    {
        $this->setBackendUser(isAdmin: false, grantedOptions: [$permission]);

        self::assertTrue($this->subject->isGranted($permission));
    }

    #[Test]
    public function nonAdminGrantIsScopedToTheGrantedPermission(): void
    {
        $this->setBackendUser(isAdmin: false, grantedOptions: [VaultPermission::SecretUse]);

        self::assertTrue($this->subject->isGranted(VaultPermission::SecretUse));
        self::assertFalse(
            $this->subject->isGranted(VaultPermission::SecretReveal),
            'secret.use must not imply secret.reveal',
        );
        self::assertFalse($this->subject->isGranted(VaultPermission::SecretDelete));
        self::assertFalse($this->subject->isGranted(VaultPermission::MasterKeyRotate));
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function noBackendUserIsGrantedNothing(VaultPermission $permission): void
    {
        self::assertFalse($this->subject->isGranted($permission));
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function disabledBackendUserIsGrantedNothing(VaultPermission $permission): void
    {
        // Disabled AND admin AND holding the option: every possible grant path
        // must still lose to the disable flag.
        $this->setBackendUser(
            isAdmin: true,
            grantedOptions: VaultPermission::cases(),
            disable: 1,
        );

        self::assertFalse($this->subject->isGranted($permission));
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function adminTechnicalActorIsGrantedEveryPermission(VaultPermission $permission): void
    {
        $subject = $this->createSubjectWithTechnicalActor(admin: true);

        self::assertTrue($subject->isGranted($permission));
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function nonAdminTechnicalActorIsGrantedOnlySecretUse(VaultPermission $permission): void
    {
        $subject = $this->createSubjectWithTechnicalActor(admin: false);

        self::assertSame(
            $permission === VaultPermission::SecretUse,
            $subject->isGranted($permission),
            'A non-admin technical actor may only consume secrets programmatically.',
        );
    }

    #[Test]
    public function nonAdminTechnicalActorSupersedesAnAmbientAdminBackendUser(): void
    {
        // An ambient admin session must not widen a runAs() scope: the scope
        // asked to be evaluated as the named (non-admin) technical actor.
        $this->setBackendUser(isAdmin: true);
        $subject = $this->createSubjectWithTechnicalActor(admin: false);

        self::assertFalse($subject->isGranted(VaultPermission::SecretReveal));
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function frontendRequestIsGrantedNothingEvenWithAnAdminSession(VaultPermission $permission): void
    {
        $this->setBackendUser(isAdmin: true);
        $this->setFrontendRequest();

        self::assertFalse($this->subject->isGranted($permission));
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function unauthenticatedCliOperatorIsDeniedWhenCliAccessIsOff(VaultPermission $permission): void
    {
        $this->configuration->method('isCliAccessAllowed')->willReturn(false);
        $this->setUnauthenticatedCommandLineUser();

        self::assertFalse($this->subject->isGranted($permission));
    }

    #[Test]
    #[DataProvider('allPermissionsProvider')]
    public function unauthenticatedCliOperatorIsGrantedWhenCliAccessIsOn(VaultPermission $permission): void
    {
        $this->configuration->method('isCliAccessAllowed')->willReturn(true);
        $this->setUnauthenticatedCommandLineUser();

        self::assertTrue($this->subject->isGranted($permission));
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

    /**
     * Install a backend user whose groups grant exactly the given permissions.
     *
     * Mirrors TYPO3 core storage: the grants live in the merged
     * `groupData['custom_options']` list, so a grant is present or it is not —
     * there is no per-user override.
     *
     * @param list<VaultPermission> $grantedOptions
     */
    private function setBackendUser(
        bool $isAdmin,
        array $grantedOptions = [],
        bool $isSystemMaintainer = false,
        int $disable = 0,
    ): void {
        $GLOBALS['BE_USER'] = $this->createMockBackendUser(
            uid: 5,
            isAdmin: $isAdmin,
            disabled: $disable !== 0,
            isSystemMaintainer: $isSystemMaintainer,
            grantedPermissions: $grantedOptions,
        );
    }

    /**
     * Install the unauthenticated CommandLineUserAuthentication placeholder the
     * TYPO3 CLI bootstrap puts into $GLOBALS['BE_USER'] (no user record).
     */
    private function setUnauthenticatedCommandLineUser(): void
    {
        $cliUser = $this->createMock(CommandLineUserAuthentication::class);
        /** @phpstan-ignore property.internal */
        $cliUser->user = ['uid' => 0];

        $GLOBALS['BE_USER'] = $cliUser;
    }

    private function setFrontendRequest(): void
    {
        /** @phpstan-ignore classConstant.internal */
        $frontendType = SystemEnvironmentBuilder::REQUESTTYPE_FE;

        /** @phpstan-ignore new.internalClass, method.internalClass */
        $request = new ServerRequest('https://example.com/');

        /** @phpstan-ignore method.internalClass */
        $GLOBALS['TYPO3_REQUEST'] = $request->withAttribute('applicationType', $frontendType);
    }

    private function createSubjectWithTechnicalActor(bool $admin): AccessControlService
    {
        $context = $this->createMock(TechnicalActorContextInterface::class);
        $context
            ->method('getCurrentActor')
            ->willReturn(new TechnicalActor(
                uid: 10,
                username: 'tech_indexer',
                admin: $admin,
                groupIds: [5],
            ));

        return new AccessControlService($this->configuration, null, $context);
    }
}
