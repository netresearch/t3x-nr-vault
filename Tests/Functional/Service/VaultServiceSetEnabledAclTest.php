<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;

/**
 * The two gates on `VaultService::setEnabled()`, and that each of them
 * genuinely refuses on its own.
 *
 * Disabling a secret revokes access to it for every consumer at once, so it is
 * gated exactly like the other mutations: the per-secret `canWrite()` tier
 * answers "may this actor touch THIS secret", the `secret.manage_policy`
 * operation permission answers "may this actor change availability at all".
 * Each test therefore holds one of the two and lacks the other — a scenario
 * that only fails if the gate under test is the one doing the refusing.
 *
 * A refusal must also leave a trace and no change: an `access_denied` entry in
 * the tamper-evident chain, and the availability exactly as it was.
 */
final class VaultServiceSetEnabledAclTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    /** Holds secret.manage_policy, owns nothing. */
    private const POLICY_HOLDER_UID = 7;

    /** Holds secret.manage_policy and owns the seeded secret. */
    private const OWNER_WITH_POLICY_UID = 8;

    /** Owns the seeded secret but holds no vault permission. */
    private const OWNER_WITHOUT_POLICY_UID = 9;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_manage_policy.csv';

    /** Logged in per test — the scenarios need different actors. */
    protected ?int $backendUserUid = null;

    #[Test]
    public function anActorWithoutWriteAccessToTheSecretIsRefused(): void
    {
        $this->setUpBackendUser(self::POLICY_HOLDER_UID);
        $identifier = $this->seedEnabledSecretOwnedBy(self::OWNER_WITH_POLICY_UID);

        try {
            $this->getVaultService()->setEnabled($identifier, false);
            self::fail('Holding secret.manage_policy must not permit disabling a secret one cannot write.');
        } catch (AccessDeniedException) {
            // expected
        }

        self::assertSame(0, $this->currentHiddenState($identifier), 'The refusal must leave the state untouched.');
        self::assertTrue($this->hasDenialEntry($identifier), 'The refusal must be recorded as access_denied.');
    }

    #[Test]
    public function anActorWithoutTheManagePolicyPermissionIsRefused(): void
    {
        $this->setUpBackendUser(self::OWNER_WITHOUT_POLICY_UID);
        $identifier = $this->seedEnabledSecretOwnedBy(self::OWNER_WITHOUT_POLICY_UID);

        try {
            $this->getVaultService()->setEnabled($identifier, false);
            self::fail('Owning a secret must not by itself permit changing its availability.');
        } catch (AccessDeniedException) {
            // expected
        }

        self::assertSame(0, $this->currentHiddenState($identifier), 'The refusal must leave the state untouched.');
        self::assertTrue($this->hasDenialEntry($identifier), 'The refusal must be recorded as access_denied.');
    }

    /**
     * The counterpart, so the gates are shown to refuse the right actors
     * rather than everyone: holding both permits the change.
     */
    #[Test]
    public function anActorHoldingBothMayChangeTheAvailability(): void
    {
        $this->setUpBackendUser(self::OWNER_WITH_POLICY_UID);
        $identifier = $this->seedEnabledSecretOwnedBy(self::OWNER_WITH_POLICY_UID);

        $this->getVaultService()->setEnabled($identifier, false);

        self::assertSame(1, $this->currentHiddenState($identifier));
        self::assertFalse(
            $this->hasDenialEntry($identifier),
            'A permitted change must not also record a denial.',
        );
    }

    /**
     * A refusal is audited even when the requested state is the one the secret
     * already has — the gates run before the no-op check, so an unauthorized
     * attempt leaves a trace whether or not it would have changed anything.
     */
    #[Test]
    public function aRefusedNoOpIsStillAudited(): void
    {
        $this->setUpBackendUser(self::POLICY_HOLDER_UID);
        $identifier = $this->seedEnabledSecretOwnedBy(self::OWNER_WITH_POLICY_UID);

        try {
            $this->getVaultService()->setEnabled($identifier, true);
            self::fail('The gates must apply regardless of whether the state would change.');
        } catch (AccessDeniedException) {
            // expected
        }

        self::assertTrue($this->hasDenialEntry($identifier));
    }

    private function getVaultService(): VaultServiceInterface
    {
        return $this->get(VaultServiceInterface::class);
    }

    private function seedEnabledSecretOwnedBy(int $ownerUid): string
    {
        $identifier = 'set_enabled_' . bin2hex(random_bytes(4));

        $this->getConnectionPool()
            ->getConnectionForTable(self::SECRET_TABLE)
            ->insert(self::SECRET_TABLE, [
                'pid' => 0,
                'identifier' => $identifier,
                'owner_uid' => $ownerUid,
                'hidden' => 0,
            ]);

        return $identifier;
    }

    private function currentHiddenState(string $identifier): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::SECRET_TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        return (int) $queryBuilder
            ->select('hidden')
            ->from(self::SECRET_TABLE)
            ->where($queryBuilder->expr()->eq('identifier', $queryBuilder->createNamedParameter($identifier)))
            ->executeQuery()
            ->fetchOne();
    }

    private function hasDenialEntry(string $identifier): bool
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::AUDIT_TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        $count = $queryBuilder
            ->count('uid')
            ->from(self::AUDIT_TABLE)
            ->where(
                $queryBuilder->expr()->eq('secret_identifier', $queryBuilder->createNamedParameter($identifier)),
                $queryBuilder->expr()->eq(
                    'action',
                    $queryBuilder->createNamedParameter(AuditAction::AccessDenied->value),
                ),
                $queryBuilder->expr()->eq('success', $queryBuilder->createNamedParameter(0, Connection::PARAM_INT)),
            )
            ->executeQuery()
            ->fetchOne();

        return (int) $count > 0;
    }
}
