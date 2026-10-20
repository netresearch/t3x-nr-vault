<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Security;

use Netresearch\NrVault\Exception\TechnicalActorException;
use Netresearch\NrVault\Security\TechnicalActor;
use Netresearch\NrVault\Security\TechnicalActorContext;
use Netresearch\NrVault\Security\TechnicalActorContextInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\ConnectionPool;

#[CoversClass(TechnicalActorContext::class)]
final class TechnicalActorValidationTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/technical_actors.csv';

    protected ?int $backendUserUid = null;

    #[Test]
    public function deletedUserIsRefusedBeforeTheCallbackRuns(): void
    {
        $context = $this->get(TechnicalActorContextInterface::class);
        $healthy = $context->runAs(
            10,
            static fn (): ?TechnicalActor => $context->getCurrentActor(),
        );
        self::assertInstanceOf(TechnicalActor::class, $healthy);
        self::assertSame(10, $healthy->uid);
        self::assertNull($context->getCurrentActor());

        $connection = $this->get(ConnectionPool::class)->getConnectionForTable('be_users');
        self::assertSame(
            1,
            $connection->update('be_users', ['deleted' => 1], ['uid' => 10]),
        );
        $queryBuilder = $this->get(ConnectionPool::class)->getQueryBuilderForTable('be_users');
        $queryBuilder->getRestrictions()->removeAll();
        $row = $queryBuilder
            ->select('deleted', 'starttime')
            ->from('be_users')
            ->where(
                $queryBuilder->expr()->eq(
                    'uid',
                    $queryBuilder->createNamedParameter(10),
                ),
            )
            ->executeQuery()
            ->fetchAssociative();
        self::assertIsArray($row);
        self::assertSame(1, (int) $row['deleted']);
        self::assertSame(0, (int) $row['starttime']);

        $called = false;
        $caught = null;

        try {
            $context->runAs(
                10,
                static function () use (&$called): void {
                    $called = true;
                },
            );
        } catch (TechnicalActorException $exception) {
            $caught = $exception;
        }

        self::assertInstanceOf(TechnicalActorException::class, $caught);
        self::assertSame(1784000002, $caught->getCode());
        self::assertFalse(
            $called,
            'A deleted backend user must never enter the scope.',
        );
        self::assertNull($context->getCurrentActor());
    }
}
