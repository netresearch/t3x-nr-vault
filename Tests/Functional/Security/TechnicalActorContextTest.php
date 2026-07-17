<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Security;

use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Exception\TechnicalActorException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\TechnicalActorContext;
use Netresearch\NrVault\Security\TechnicalActorContextInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

/**
 * End-to-end coverage of the technical-actor scope against the real DI
 * container and database: proves the container actually injects the shared
 * TechnicalActorContext into AccessControlService (the optional constructor
 * argument must be autowired, not silently null) and that group resolution
 * uses core semantics including subgroup expansion.
 *
 * Fixture: be_users 10 `tech_indexer` (usergroup 6), 11 `tech_disabled`
 * (disabled), 12 `tech_offroot` (pid 5); be_groups 6 `indexers` with
 * subgroup 5 `vault-readers`.
 */
#[CoversClass(TechnicalActorContext::class)]
final class TechnicalActorContextTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/technical_actors.csv';

    /** No ambient backend user: headless-worker reality. */
    protected ?int $backendUserUid = null;

    #[Test]
    public function runAsGrantsOwnerAccessOnlyInsideTheScope(): void
    {
        $accessControl = $this->get(AccessControlServiceInterface::class);
        $context = $this->get(TechnicalActorContextInterface::class);

        $secret = new Secret(identifier: 'tech/owned', ownerUid: 10);

        self::assertFalse($accessControl->canRead($secret), 'no ambient actor: denied');

        $granted = $context->runAs(10, static fn (): bool => $accessControl->canRead($secret));
        self::assertTrue($granted, 'owner semantics inside runAs()');

        self::assertFalse($accessControl->canRead($secret), 'scope exit restores denial');
    }

    #[Test]
    public function runAsResolvesGroupAclIncludingSubgroupExpansion(): void
    {
        $accessControl = $this->get(AccessControlServiceInterface::class);
        $context = $this->get(TechnicalActorContextInterface::class);

        // Readable via group 5, which user 10 only reaches through the
        // subgroup relation of its direct group 6.
        $secret = new Secret(identifier: 'tech/group-read', ownerUid: 999, allowedGroups: [5]);

        $decisions = $context->runAs(10, static fn (): array => [
            'read' => $accessControl->canRead($secret),
            'write' => $accessControl->canWrite($secret),
            'delete' => $accessControl->canDelete($secret),
        ]);

        self::assertTrue($decisions['read'], 'read-tier group via subgroup');
        self::assertFalse($decisions['write'], 'read-tier group must not write');
        self::assertFalse($decisions['delete'], 'group members never delete');
    }

    #[Test]
    public function runAsRefusesDisabledUser(): void
    {
        $context = $this->get(TechnicalActorContextInterface::class);

        $this->expectException(TechnicalActorException::class);
        $this->expectExceptionCode(1784000003);

        $context->runAs(11, static fn (): bool => true);
    }

    #[Test]
    public function runAsRefusesUserOutsideRootLevel(): void
    {
        $context = $this->get(TechnicalActorContextInterface::class);

        $this->expectException(TechnicalActorException::class);
        $this->expectExceptionCode(1784000005);

        $context->runAs(12, static fn (): bool => true);
    }

    #[Test]
    public function auditLogRecordsTheTechnicalActorAsSuch(): void
    {
        $context = $this->get(TechnicalActorContextInterface::class);
        $auditLog = $this->get(AuditLogServiceInterface::class);

        $context->runAs(10, static function () use ($auditLog): void {
            $auditLog->log('tech/audited', 'read', true);
        });

        $entries = $auditLog->query();
        self::assertNotSame([], $entries);

        $entry = $entries[0];
        self::assertSame('tech/audited', $entry->secretIdentifier);
        self::assertSame(10, $entry->actorUid);
        self::assertSame('technical', $entry->actorType);
        self::assertSame('tech_indexer', $entry->actorUsername);
    }
}
