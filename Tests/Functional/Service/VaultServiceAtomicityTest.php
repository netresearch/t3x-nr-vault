<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service;

use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditContextInterface;
use Netresearch\NrVault\Audit\AuditLogFilter;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\HashChainVerificationResult;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Exception\AuditWriteException;
use Netresearch\NrVault\Http\VaultHttpClientFactoryInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Service\VaultService;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Fixtures\ConcurrentReadAdapter;
use Netresearch\NrVault\Tests\Functional\Traits\SecretRowTrait;
use PHPUnit\Framework\Attributes\Test;

/**
 * SEC-3 atomicity: a secret mutation and its tamper-evident audit entry must
 * be all-or-nothing. The audit writer owns its own transaction lifecycle
 * (SQLite `BEGIN EXCLUSIVE`/`COMMIT`, MySQL advisory `GET_LOCK`), so a single
 * shared DB transaction cannot wrap both writes. VaultService therefore
 * compensates: if `AuditLogService::log()` throws `AuditWriteException` after
 * the adapter mutation, the mutation is reverted.
 *
 * These tests force the audit write to fail and assert the secret
 * create/update/delete/rotate did NOT persist.
 */
final class VaultServiceAtomicityTest extends AbstractVaultFunctionalTestCase
{
    use SecretRowTrait;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_permissions.csv';

    #[Test]
    public function createIsRolledBackWhenAuditWriteFails(): void
    {
        $service = $this->buildServiceWithFailingAudit();

        try {
            $service->store('atomic_create', 'create-value');
            self::fail(self::FAIL_EXPECTED_AUDIT_EXCEPTION);
        } catch (AuditWriteException) {
            // expected
        }

        // The created record must not have persisted.
        self::assertFalse(
            $this->getAdapter()->exists('atomic_create'),
            'Secret create must be rolled back when the audit write fails',
        );
        self::assertNull($this->getVaultService()->retrieve('atomic_create'));
    }

    #[Test]
    public function updateIsRolledBackWhenAuditWriteFails(): void
    {
        // Baseline: create through the real service so the chain stays valid.
        $this->getVaultService()->store('atomic_update', 'original-value');

        $service = $this->buildServiceWithFailingAudit();

        try {
            $service->store('atomic_update', 'tampered-value');
            self::fail(self::FAIL_EXPECTED_AUDIT_EXCEPTION);
        } catch (AuditWriteException) {
            // expected
        }

        // The prior encrypted value must be restored.
        self::assertSame(
            'original-value',
            $this->getVaultService()->retrieve('atomic_update'),
            'Secret update must be rolled back to the prior value when the audit write fails',
        );
    }

    #[Test]
    public function deleteIsRolledBackWhenAuditWriteFails(): void
    {
        $this->getVaultService()->store('atomic_delete', 'keep-me');

        $service = $this->buildServiceWithFailingAudit();

        try {
            $service->delete('atomic_delete', 'because');
            self::fail(self::FAIL_EXPECTED_AUDIT_EXCEPTION);
        } catch (AuditWriteException) {
            // expected
        }

        // The record must still exist with its original value.
        self::assertTrue(
            $this->getAdapter()->exists('atomic_delete'),
            'Secret delete must be rolled back when the audit write fails',
        );
        self::assertSame('keep-me', $this->getVaultService()->retrieve('atomic_delete'));
    }

    #[Test]
    public function rotateIsRolledBackWhenAuditWriteFails(): void
    {
        $this->getVaultService()->store('atomic_rotate', 'old-value');

        $service = $this->buildServiceWithFailingAudit();

        try {
            $service->rotate('atomic_rotate', 'new-value', 'scheduled');
            self::fail(self::FAIL_EXPECTED_AUDIT_EXCEPTION);
        } catch (AuditWriteException) {
            // expected
        }

        // The pre-rotation value must be restored.
        self::assertSame(
            'old-value',
            $this->getVaultService()->retrieve('atomic_rotate'),
            'Secret rotation must be rolled back to the prior value when the audit write fails',
        );
    }

    /**
     * An availability change is a mutation like any other, and the one whose
     * loss is hardest to notice: an unaudited disable silently revokes access
     * to a secret with nothing in the chain to say who did it or when.
     */
    #[Test]
    public function setEnabledIsRolledBackWhenAuditWriteFails(): void
    {
        $this->getVaultService()->store('atomic_disable', 'still-available');

        $service = $this->buildServiceWithFailingAudit();

        // The failure must surface; `finally` runs the read-back before it
        // propagates into the expectation declared here. That read-back is the
        // assertion that matters — it is the path a disable would have closed.
        $this->expectException(AuditWriteException::class);

        try {
            $service->setEnabled('atomic_disable', false, 'because');
        } finally {
            self::assertSame(
                'still-available',
                $this->getVaultService()->retrieve('atomic_disable'),
                'A disable that could not be audited must not take effect.',
            );
        }
    }

    /**
     * The other direction, because the compensation restores a captured state
     * rather than a fixed one: a re-enable that cannot be audited must leave
     * the secret disabled instead of quietly putting it back into service.
     */
    #[Test]
    public function setEnabledIsRolledBackInBothDirectionsWhenAuditWriteFails(): void
    {
        $vault = $this->getVaultService();
        $vault->store('atomic_enable', 'out-of-service');
        $vault->setEnabled('atomic_enable', false);

        $service = $this->buildServiceWithFailingAudit();

        $this->expectException(AuditWriteException::class);

        try {
            $service->setEnabled('atomic_enable', true);
        } finally {
            self::assertNull(
                $vault->retrieve('atomic_enable'),
                'A re-enable that could not be audited must not take effect.',
            );
        }
    }

    /**
     * The revert is a write like the one it undoes, so it is narrow like it
     * too. With a read committed inside the window (see
     * {@see ConcurrentReadAdapter}), a compensation that restored the whole
     * entity would put the availability back AND roll that read off the
     * record — repairing one control by breaking the accounting of another.
     */
    #[Test]
    public function setEnabledRevertRestoresAvailabilityWithoutTouchingAnythingElse(): void
    {
        $vault = $this->getVaultService();
        $vault->store('atomic_narrow', 'still-available');
        self::assertSame('still-available', $vault->retrieve('atomic_narrow'));

        $before = $this->readSecretRow('atomic_narrow');

        $service = new VaultService(
            new ConcurrentReadAdapter($this->getAdapter()),
            $this->getEncryptionService(),
            $this->get(AccessControlServiceInterface::class),
            $this->createFailingAuditLogService(),
            $this->get(ExtensionConfigurationInterface::class),
            $this->get(VaultHttpClientFactoryInterface::class),
        );

        $this->expectException(AuditWriteException::class);

        try {
            $service->setEnabled('atomic_narrow', false, 'because');
        } finally {
            $after = $this->readSecretRow('atomic_narrow');

            self::assertSame(0, (int) $after['hidden'], 'The unauditable disable must have been reverted.');
            self::assertSame(
                (int) $before['read_count'] + 1,
                (int) $after['read_count'],
                'The compensation must not roll back a read that committed in the window.',
            );

            foreach (['hidden', 'tstamp', 'read_count', 'last_read_at'] as $expected) {
                unset($before[$expected], $after[$expected]);
            }

            self::assertSame($before, $after, 'The compensation must restore availability and nothing else.');
        }
    }

    /**
     * Build a VaultService wired with the real container dependencies except
     * for an audit log service that throws on every successful mutation log,
     * exercising the compensating-rollback path. Access checks pass because
     * the functional test runs as a CLI actor (`canCreate()`/`canWrite()`
     * allow the trusted CLI context).
     */
    private function buildServiceWithFailingAudit(): VaultService
    {
        return new VaultService(
            $this->getAdapter(),
            $this->getEncryptionService(),
            $this->get(AccessControlServiceInterface::class),
            $this->createFailingAuditLogService(),
            $this->get(ExtensionConfigurationInterface::class),
            $this->get(VaultHttpClientFactoryInterface::class),
        );
    }

    /**
     * The real vault adapter (DatabaseVaultAdapter) from the container. Used to
     * assert persistence state directly, bypassing the service layer.
     */
    private function getAdapter(): VaultAdapterInterface
    {
        return $this->get(VaultAdapterInterface::class);
    }

    private function getEncryptionService(): EncryptionServiceInterface
    {
        return $this->get(EncryptionServiceInterface::class);
    }

    /**
     * The real, fully wired VaultService from the container (with the genuine
     * audit logger) — used for baseline writes and read-back assertions.
     */
    private function getVaultService(): VaultServiceInterface
    {
        $service = $this->get(VaultServiceInterface::class);
        self::assertInstanceOf(VaultServiceInterface::class, $service);

        return $service;
    }

    /**
     * An audit log service that throws AuditWriteException on the success log
     * of any mutating action (create/update/delete/rotate), simulating a
     * lock-acquisition timeout or other audit-write failure.
     */
    private function createFailingAuditLogService(): AuditLogServiceInterface
    {
        return new class () implements AuditLogServiceInterface {
            public function log(
                string $secretIdentifier,
                string $action,
                bool $success,
                ?string $errorMessage = null,
                ?string $reason = null,
                ?string $hashBefore = null,
                ?string $hashAfter = null,
                ?AuditContextInterface $context = null,
            ): void {
                $mutating = [
                    AuditAction::Create->value,
                    AuditAction::Update->value,
                    AuditAction::Delete->value,
                    AuditAction::Rotate->value,
                    // The action an availability change writes.
                    AuditAction::MetadataUpdate->value,
                ];
                if ($success && \in_array($action, $mutating, true)) {
                    throw new AuditWriteException('Simulated audit write failure', 9334453097);
                }
            }

            public function query(?AuditLogFilter $filter = null, int $limit = 100, int $offset = 0): array
            {
                return [];
            }

            public function count(?AuditLogFilter $filter = null): int
            {
                return 0;
            }

            public function export(?AuditLogFilter $filter = null): array
            {
                return [];
            }

            public function verifyHashChain(?int $fromUid = null, ?int $toUid = null, ?int $minEpoch = null): HashChainVerificationResult
            {
                return new HashChainVerificationResult(true);
            }

            public function verifyChainForReseal(): ?HashChainVerificationResult
            {
                return null;
            }

            public function getLatestHash(): ?string
            {
                return null;
            }
        };
    }
}
