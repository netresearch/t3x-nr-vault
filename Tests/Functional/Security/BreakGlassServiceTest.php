<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Security;

use Closure;
use DateTimeImmutable;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Event\BreakGlassActivatedEvent;
use Netresearch\NrVault\Event\BreakGlassDeactivatedEvent;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\BreakGlassService;
use Netresearch\NrVault\Security\BreakGlassSession;
use Netresearch\NrVault\Security\BreakGlassState;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\EventDispatcher\EventDispatcherInterface;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;

/**
 * Break-glass end to end: real `sys_registry` state, real HMAC-chained audit
 * rows, and the access-control integration that is the whole point.
 *
 * Runs in the hardened profile with `disableAdminOverride` set — the only
 * configuration where break-glass changes any outcome — so the tests assert the
 * real recovery path rather than a simulation of it.
 *
 * @see \Netresearch\NrVault\Tests\Unit\Security\BreakGlassServiceTest for the policy matrix
 */
#[CoversClass(BreakGlassService::class)]
final class BreakGlassServiceTest extends AbstractVaultFunctionalTestCase
{
    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    private const ADMIN_UID = 1;

    private const EDITOR_UID = 2;

    private const FOREIGN_OWNER_UID = 999;

    protected ?string $backendUserFixture = __DIR__ . '/../Fixtures/Users/be_users.csv';

    /** Log in explicitly per test — the actor is what is under test. */
    protected ?int $backendUserUid = null;

    /**
     * The hardened profile refuses the `typo3` master-key provider, so the file
     * provider the base class already wires up must be selected explicitly.
     *
     * @var array<string, mixed>
     */
    protected array $extensionConfiguration = [
        'securityProfile' => 'hardened',
        'masterKeyProvider' => 'file',
        'disableAdminOverride' => 1,
    ];

    /** @var list<object> */
    private array $dispatchedEvents = [];

    #[Test]
    public function activationWritesExactlyOneAuditRowCarryingTheReason(): void
    {
        $this->setUpBackendUser(self::ADMIN_UID);

        $this->createSubject()->activate('INC-4711 rotate leaked deploy key', 20);

        self::assertSame(
            1,
            $this->countAudit(AuditAction::BreakGlassActivated->value),
            'exactly one activation row',
        );

        $row = $this->latestAuditRow();
        self::assertSame(BreakGlassService::AUDIT_PSEUDO_IDENTIFIER, $row['secret_identifier']);
        self::assertSame('INC-4711 rotate leaked deploy key', $row['reason']);
        self::assertSame(1, (int) $row['success']);
        self::assertSame('admin', $row['actor_username']);
    }

    #[Test]
    public function theActivationRowIsSealedIntoTheHashChain(): void
    {
        // The evidence is only worth anything if it cannot be edited away, so
        // the new action value must verify under the configured HMAC epoch like
        // any other row.
        $this->setUpBackendUser(self::ADMIN_UID);

        $this->createSubject()->activate('INC-4711');

        $result = $this->get(AuditLogServiceInterface::class)->verifyHashChain();

        self::assertTrue($result->isValid(), 'the audit chain must verify after a break-glass row');
    }

    #[Test]
    public function deactivationWritesExactlyOneAuditRow(): void
    {
        $this->setUpBackendUser(self::ADMIN_UID);
        $subject = $this->createSubject();

        $subject->activate('INC-4711');
        $subject->deactivate('INC-4711 closed');

        self::assertSame(1, $this->countAudit(AuditAction::BreakGlassDeactivated->value));

        $row = $this->latestAuditRow();
        self::assertSame('INC-4711 closed', $row['reason']);
    }

    #[Test]
    public function deactivatingAClosedWindowWritesNoAuditRow(): void
    {
        $this->setUpBackendUser(self::ADMIN_UID);

        $this->createSubject()->deactivate('nothing to do');

        self::assertSame(0, $this->countAudit(AuditAction::BreakGlassDeactivated->value));
    }

    #[Test]
    public function bothTransitionsDispatchTheirEvent(): void
    {
        $this->setUpBackendUser(self::ADMIN_UID);
        $subject = $this->createSubject();

        $session = $subject->activate('INC-4711', 20);
        $subject->deactivate('INC-4711 closed');

        self::assertCount(2, $this->dispatchedEvents);

        $activated = $this->dispatchedEvents[0];
        self::assertInstanceOf(BreakGlassActivatedEvent::class, $activated);
        self::assertSame('INC-4711', $activated->getReason());
        self::assertSame('admin', $activated->getActorUsername());
        self::assertSame(self::ADMIN_UID, $activated->getActorUid());
        self::assertSame($session->expiresAt->getTimestamp(), $activated->getExpiresAt()->getTimestamp());

        self::assertInstanceOf(BreakGlassDeactivatedEvent::class, $this->dispatchedEvents[1]);
    }

    #[Test]
    public function theSessionIsPersistedForALaterRequest(): void
    {
        // The operator activates on the CLI and then works in the backend, so
        // the window has to outlive the request that opened it. Asserted against
        // the `sys_registry` ROW rather than through the Registry service, whose
        // in-process entry cache would answer from memory and prove nothing
        // about what was actually written.
        $this->setUpBackendUser(self::ADMIN_UID);
        $this->createSubject()->activate('INC-4711', 20);

        $stored = $this->readRegistryRow();

        self::assertIsString($stored);
        self::assertStringContainsString('INC-4711', $stored);
    }

    #[Test]
    public function aNonAdminHoldingEveryOperationPermissionStillCannotActivate(): void
    {
        $this->setUpBackendUser(self::EDITOR_UID);
        $this->grantEveryCustomOption();

        // Sanity: the grants really are in place, so the refusal below is about
        // the admin role and not about a missing permission.
        self::assertTrue(
            $this->get(AccessControlServiceInterface::class)->isGranted(VaultPermission::VaultConfigure),
            'the editor must actually hold the operation permissions for this test to mean anything',
        );

        $this->expectException(AccessDeniedException::class);

        $this->createSubject()->activate('I would like more power');
    }

    #[Test]
    public function aNonAdminCannotCloseAWindowEither(): void
    {
        $this->setUpBackendUser(self::ADMIN_UID);
        $this->createSubject()->activate('INC-4711');

        $this->setUpBackendUser(self::EDITOR_UID);
        $this->grantEveryCustomOption();

        $this->expectException(AccessDeniedException::class);

        $this->createSubject()->deactivate('let me hide this');
    }

    #[Test]
    public function anOpenWindowRestoresTheAdminBypassEndToEnd(): void
    {
        $this->setUpBackendUser(self::ADMIN_UID);
        $accessControl = $this->get(AccessControlServiceInterface::class);
        $foreign = new Secret(identifier: 'someone-elses-secret', ownerUid: self::FOREIGN_OWNER_UID);

        // Baseline: hardened + disabled really did remove the bypass.
        self::assertFalse($accessControl->isGranted(VaultPermission::SecretReveal));
        self::assertFalse($accessControl->canRead($foreign));

        $this->createSubject()->activate('INC-4711', 20);

        self::assertTrue($accessControl->isGranted(VaultPermission::SecretReveal));
        self::assertTrue($accessControl->canRead($foreign));
        self::assertTrue($accessControl->canDelete($foreign));
    }

    #[Test]
    public function closingTheWindowRemovesTheBypassAgain(): void
    {
        $this->setUpBackendUser(self::ADMIN_UID);
        $accessControl = $this->get(AccessControlServiceInterface::class);
        $subject = $this->createSubject();

        $subject->activate('INC-4711', 20);
        self::assertTrue($accessControl->isGranted(VaultPermission::SecretReveal));

        $subject->deactivate('INC-4711 closed');

        self::assertFalse($accessControl->isGranted(VaultPermission::SecretReveal));
    }

    #[Test]
    public function anExpiredWindowGrantsNothing(): void
    {
        // Time is frozen by writing an already-lapsed expiry straight into the
        // registry: that is exactly the state a forgotten window leaves behind,
        // and read-time expiry has to handle it with no cleanup job involved.
        $this->setUpBackendUser(self::ADMIN_UID);
        $this->writeExpiredSessionToRegistry();

        $accessControl = $this->get(AccessControlServiceInterface::class);

        self::assertFalse($accessControl->isGranted(VaultPermission::SecretReveal));
        self::assertFalse($accessControl->isCurrentActorAdmin());
        self::assertFalse(
            $accessControl->canRead(new Secret(identifier: 'foreign', ownerUid: self::FOREIGN_OWNER_UID)),
        );
    }

    /**
     * A service instance whose event dispatcher records what was dispatched.
     * Every other collaborator is the real container service.
     */
    private function createSubject(): BreakGlassService
    {
        $record = function (object $event): void {
            $this->dispatchedEvents[] = $event;
        };

        $recordingDispatcher = new class ($record) implements EventDispatcherInterface {
            /**
             * @param Closure(object): void $record
             */
            public function __construct(private readonly Closure $record) {}

            public function dispatch(object $event): object
            {
                ($this->record)($event);

                return $event;
            }
        };

        return new BreakGlassService(
            $this->get(BreakGlassState::class),
            $this->get(AccessControlServiceInterface::class),
            $this->get(AuditLogServiceInterface::class),
            $recordingDispatcher,
        );
    }

    /**
     * Grant every vault operation permission to the logged-in user by writing
     * the merged group data core's `check('custom_options', …)` reads.
     */
    private function grantEveryCustomOption(): void
    {
        $backendUser = $GLOBALS['BE_USER'] ?? null;
        self::assertInstanceOf(BackendUserAuthentication::class, $backendUser);

        $options = array_map(
            static fn (VaultPermission $permission): string => 'tx_nrvault:' . $permission->value,
            VaultPermission::cases(),
        );
        /** @phpstan-ignore property.internal */
        $backendUser->groupData['custom_options'] = implode(',', $options);
    }

    private function writeExpiredSessionToRegistry(): void
    {
        $this->get(BreakGlassState::class)->store(new BreakGlassSession(
            activatedByUid: self::ADMIN_UID,
            activatedByUsername: 'admin',
            reason: 'INC-4711 forgotten',
            activatedAt: (new DateTimeImmutable())->setTimestamp(time() - 3600),
            expiresAt: (new DateTimeImmutable())->setTimestamp(time() - 60),
        ));
    }

    /**
     * The raw serialized `sys_registry` value for the break-glass entry.
     */
    private function readRegistryRow(): mixed
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable('sys_registry');
        $queryBuilder->getRestrictions()->removeAll();

        return $queryBuilder
            ->select('entry_value')
            ->from('sys_registry')
            ->where(
                $queryBuilder->expr()->eq(
                    'entry_namespace',
                    $queryBuilder->createNamedParameter(BreakGlassState::REGISTRY_NAMESPACE),
                ),
                $queryBuilder->expr()->eq(
                    'entry_key',
                    $queryBuilder->createNamedParameter(BreakGlassState::REGISTRY_KEY),
                ),
            )
            ->executeQuery()
            ->fetchOne();
    }

    private function countAudit(string $action): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::AUDIT_TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $count = $queryBuilder
            ->count('uid')
            ->from(self::AUDIT_TABLE)
            ->where(
                $queryBuilder->expr()->eq('action', $queryBuilder->createNamedParameter($action)),
            )
            ->executeQuery()
            ->fetchOne();

        return is_numeric($count) ? (int) $count : 0;
    }

    /**
     * @return array<string, mixed>
     */
    private function latestAuditRow(): array
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::AUDIT_TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $row = $queryBuilder
            ->select('*')
            ->from(self::AUDIT_TABLE)
            ->orderBy('uid', 'DESC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchAssociative();

        self::assertIsArray($row, 'expected at least one audit row');

        return $row;
    }
}
