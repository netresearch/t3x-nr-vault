<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Security;

use Closure;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\BreakGlassService;
use Netresearch\NrVault\Security\BreakGlassServiceInterface;
use Netresearch\NrVault\Security\BreakGlassSession;
use Netresearch\NrVault\Security\BreakGlassState;
use Netresearch\NrVault\Security\TechnicalActorContextInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\EventDispatcher\EventDispatcherInterface;
use TYPO3\CMS\Core\Authentication\CommandLineUserAuthentication;
use TYPO3\CMS\Core\Utility\GeneralUtility;

#[CoversClass(BreakGlassService::class)]
final class BreakGlassTechnicalContextTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../Fixtures/Users/be_users.csv';

    protected ?int $backendUserUid = 1;

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'securityProfile'      => 'hardened',
        'masterKeyProvider'    => 'file',
        'disableAdminOverride' => 1,
    ];

    /** @var list<object> */
    private array $dispatchedEvents = [];

    #[Test]
    #[DataProvider('technicalOperations')]
    public function technicalScopesCannotChangeWindowStateOrProduceEvidence(
        int $technicalAdmin,
        bool $alreadyActive,
        string $operation,
    ): void {
        $this->importCSVDataSet(__DIR__ . '/Fixtures/technical_actors.csv');
        $this
            ->getConnectionPool()
            ->getConnectionForTable('be_users')
            ->update('be_users', ['admin' => $technicalAdmin], ['uid' => 10]);
        $context = $this->get(TechnicalActorContextInterface::class);
        $access  = $this->get(AccessControlServiceInterface::class);
        $service = $this->createRecordingSubject();
        $ambient = $GLOBALS['BE_USER'];
        if ($alreadyActive) {
            $service->activate('real administrator window');
        }

        $before        = $this->readEffects();
        $sessionBefore = $service->getActiveSession()?->toArray();
        $actorEvidence = null;

        $caught = $this->captureRefusal(
            static function () use ($context, $access, $service, $operation, &$actorEvidence): void {
                $context->runAs(
                    10,
                    static function () use ($context, $access, $service, $operation, &$actorEvidence): void {
                        $actorEvidence = [
                            $access->getCurrentActorType(),
                            $access->getCurrentActorUid(),
                            $context->getCurrentActor()?->admin,
                        ];
                        if ($operation === 'activation') {
                            $service->activate(
                                'technical scope must not mint bypass',
                            );
                        } else {
                            $service->deactivate(
                                'technical scope must not close window',
                            );
                        }
                    },
                );
            },
        );

        self::assertSame(
            ['technical', 10, $technicalAdmin === 1],
            $actorEvidence,
        );
        self::assertSame(
            [
                'error'  => AccessDeniedException::class,
                'code'   => 1753900001,
                'active' => $alreadyActive,
            ],
            [
                'error'  => $caught instanceof AccessDeniedException ? $caught::class : null,
                'code'   => $caught?->getCode(),
                'active' => $service->isActive(),
            ],
        );
        self::assertSame(
            $sessionBefore,
            $service->getActiveSession()?->toArray(),
        );
        self::assertSame(
            $before,
            $this->readEffects(),
            'Refusal must preserve raw registry bytes, audit rows and dispatched events',
        );
        self::assertSame($ambient, $GLOBALS['BE_USER']);
        self::assertNull($context->getCurrentActor());
        self::assertSame('backend', $access->getCurrentActorType());
        self::assertSame(1, $access->getCurrentActorUid());

        // The actual ambient administrator remains able to operate after the
        // technical scope has unwound, independently of the initial state.
        if ($alreadyActive) {
            $service->deactivate('administrator closes original window');
        }

        $session = $service->activate('administrator operates after scope');
        self::assertSame(1, $session->activatedByUid);
        self::assertTrue($service->isActive());
        $service->deactivate('administrator closes after scope');
        self::assertFalse($service->isActive());
        self::assertTrue(
            $this
                ->get(AuditLogServiceInterface::class)
                ->verifyHashChain()
                ->isValid(),
        );
        self::assertCount($alreadyActive ? 4 : 2, $this->dispatchedEvents);
    }

    /**
     * @return iterable<string, array{int, bool, string}>
     */
    public static function technicalOperations(): iterable
    {
        foreach ([0, 1] as $admin) {
            foreach ([false, true] as $active) {
                foreach (['activation', 'deactivation'] as $operation) {
                    yield 'admin-' . $admin . '-active-' . (int) $active . '-' . $operation => [$admin, $active, $operation];
                }
            }
        }
    }

    #[Test]
    public function ordinaryAmbientAdministratorStillOperatesTheContainerService(): void
    {
        $service = $this->get(BreakGlassServiceInterface::class);
        $session = $service->activate('healthy real administrator');
        self::assertSame(1, $session->activatedByUid);
        self::assertTrue($service->isActive());
        $service->deactivate('healthy real administrator done');
        self::assertFalse($service->isActive());
        self::assertTrue(
            $this
                ->get(AuditLogServiceInterface::class)
                ->verifyHashChain()
                ->isValid(),
        );
    }

    #[Test]
    public function technicalScopeWithoutAnAmbientAdministratorRemainsRefused(): void
    {
        $this->importCSVDataSet(__DIR__ . '/Fixtures/technical_actors.csv');
        unset($GLOBALS['BE_USER']);
        $context = $this->get(TechnicalActorContextInterface::class);
        $service = $this->createRecordingSubject();
        $before  = $this->readEffects();
        $caught  = $this->captureRefusal(
            static function () use ($context, $service): void {
                $context->runAs(
                    10,
                    static fn (): BreakGlassSession => $service->activate('headless technical scope'),
                );
            },
        );
        self::assertInstanceOf(AccessDeniedException::class, $caught);
        self::assertSame(1753900001, $caught->getCode());
        self::assertFalse($service->isActive());
        self::assertSame($before, $this->readEffects());
        self::assertNull($context->getCurrentActor());
    }

    #[Test]
    public function realCliCanOperateAfterItsTechnicalScopeIsRefused(): void
    {
        $this->importCSVDataSet(__DIR__ . '/Fixtures/technical_actors.csv');
        $cliUser            = GeneralUtility::makeInstance(CommandLineUserAuthentication::class);
        $GLOBALS['BE_USER'] = $cliUser;
        $context            = $this->get(TechnicalActorContextInterface::class);
        $access             = $this->get(AccessControlServiceInterface::class);
        $service            = $this->createRecordingSubject();
        self::assertSame('cli', $access->getCurrentActorType());
        $service->activate('real CLI opens window');
        $before = $this->readEffects();
        $caught = $this->captureRefusal(
            static function () use ($context, $service): void {
                $context->runAs(
                    10,
                    static fn () => $service->deactivate('technical scope within real CLI'),
                );
            },
        );
        self::assertInstanceOf(AccessDeniedException::class, $caught);
        self::assertSame(1753900001, $caught->getCode());
        self::assertSame($before, $this->readEffects());
        self::assertSame($cliUser, $GLOBALS['BE_USER']);
        self::assertNull($context->getCurrentActor());
        self::assertSame('cli', $access->getCurrentActorType());
        $service->deactivate('real CLI closes window after scope');
        self::assertFalse($service->isActive());
        self::assertCount(2, $this->dispatchedEvents);
        self::assertTrue(
            $this
                ->get(AuditLogServiceInterface::class)
                ->verifyHashChain()
                ->isValid(),
        );
    }

    private function createRecordingSubject(): BreakGlassService
    {
        $record = function (object $event): void {
            $this->dispatchedEvents[] = $event;
        };
        $dispatcher = new class ($record) implements EventDispatcherInterface {
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
            $dispatcher,
        );
    }

    /**
     * @return array{registry: mixed, audit: list<array<string, mixed>>, events: list<object>}
     */
    private function readEffects(): array
    {
        $registry = $this->getConnectionPool()->getQueryBuilderForTable('sys_registry');
        $registry->getRestrictions()->removeAll();
        $raw = $registry
            ->select('entry_value')
            ->from('sys_registry')
            ->where(
                $registry->expr()->eq(
                    'entry_namespace',
                    $registry->createNamedParameter(
                        BreakGlassState::REGISTRY_NAMESPACE,
                    ),
                ),
                $registry->expr()->eq(
                    'entry_key',
                    $registry->createNamedParameter(
                        BreakGlassState::REGISTRY_KEY,
                    ),
                ),
            )
            ->executeQuery()
            ->fetchOne();
        $audit = $this
            ->getConnectionPool()
            ->getQueryBuilderForTable('tx_nrvault_audit_log');
        $audit->getRestrictions()->removeAll();
        $rows = $audit
            ->select('*')
            ->from('tx_nrvault_audit_log')
            ->orderBy('uid')
            ->executeQuery()
            ->fetchAllAssociative();

        return [
            'registry' => $raw,
            'audit'    => $rows,
            'events'   => $this->dispatchedEvents,
        ];
    }

    /**
     * @param callable(): void $operation
     */
    private function captureRefusal(callable $operation): ?AccessDeniedException
    {
        try {
            $operation();
        } catch (AccessDeniedException $exception) {
            return $exception;
        }

        return null;
    }
}
