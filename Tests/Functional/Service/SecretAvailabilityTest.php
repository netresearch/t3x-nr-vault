<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Domain\Dto\SecretMetadata;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;

/**
 * What enabling and disabling a secret actually does.
 *
 * Two halves that have to hold together:
 *
 *  - A DISABLED SECRET IS NOT READABLE. That enforcement is implicit — the TCA
 *    `enablecolumns.disabled` mapping plus the `HiddenRestriction` TYPO3 puts
 *    into every `Connection::createQueryBuilder()` — so no line of this
 *    extension states it and nothing would fail if it stopped being true.
 *    Anyone widening a repository lookup to make a disabled secret reachable
 *    again could switch the control off without noticing. These tests are the
 *    guard: they read through the real service against a real database, which
 *    is the only level at which the behaviour exists at all.
 *
 *  - A DISABLED SECRET IS STILL ADMINISTRABLE. Withdrawing the value must not
 *    withdraw the record: it can be re-enabled, rotated, deleted, and its
 *    metadata read. Without that, disabling would be a one-way door — the row
 *    leaves every listing, so nothing can reach it to turn it back on.
 *
 * The pair is the point. Either alone is easy to satisfy wrongly.
 */
final class SecretAvailabilityTest extends AbstractVaultFunctionalTestCase
{
    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    /** Admin, so the gates pass and the tests are about availability only. */
    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_permissions.csv';

    #[Test]
    public function aDisabledSecretIsNotRetrievable(): void
    {
        $vault = $this->getVaultService();
        $vault->store('availability_read', 'the-plaintext');

        // Assert the positive first: without it, a lookup that always returned
        // null would satisfy the assertion below for the wrong reason.
        self::assertSame('the-plaintext', $vault->retrieve('availability_read'));

        $vault->setEnabled('availability_read', false);

        self::assertNull(
            $vault->retrieve('availability_read'),
            'A disabled secret must resolve to nothing on the backend read path.',
        );
    }

    /**
     * The frontend path is a separate entry point with its own gates, and it
     * reaches the same lookup. A secret marked frontend-accessible is used
     * deliberately: with the flag off, the method refuses before the lookup
     * even matters, and the test would pass without proving anything.
     */
    #[Test]
    public function aDisabledSecretIsNotRetrievableForTheFrontendEither(): void
    {
        $vault = $this->getVaultService();
        $vault->store('availability_frontend', 'the-plaintext', ['frontendAccessible' => true]);

        self::assertSame('the-plaintext', $vault->retrieveForFrontend('availability_frontend'));

        $vault->setEnabled('availability_frontend', false);

        self::assertNull(
            $vault->retrieveForFrontend('availability_frontend'),
            'A disabled secret must resolve to nothing on the frontend read path.',
        );
    }

    #[Test]
    public function aDisabledSecretCanBeReEnabled(): void
    {
        $vault = $this->getVaultService();
        $vault->store('availability_reenable', 'the-plaintext');
        $vault->setEnabled('availability_reenable', false);

        $vault->setEnabled('availability_reenable', true);

        self::assertSame(
            'the-plaintext',
            $vault->retrieve('availability_reenable'),
            'Re-enabling must restore the secret rather than leave an unreachable record.',
        );
    }

    #[Test]
    public function aDisabledSecretCanStillBeRotated(): void
    {
        $vault = $this->getVaultService();
        $vault->store('availability_rotate', 'old-value');
        $vault->setEnabled('availability_rotate', false);

        $vault->rotate('availability_rotate', 'new-value', 'compromised while out of service');

        $vault->setEnabled('availability_rotate', true);
        self::assertSame('new-value', $vault->retrieve('availability_rotate'));
    }

    #[Test]
    public function aDisabledSecretCanStillBeDeleted(): void
    {
        $vault = $this->getVaultService();
        $vault->store('availability_delete', 'the-plaintext');
        $vault->setEnabled('availability_delete', false);

        $vault->delete('availability_delete', 'retired');

        $this->expectException(SecretNotFoundException::class);
        $vault->getMetadata('availability_delete');
    }

    /**
     * Writing a value is not a decision about availability. `store()` has to
     * see the disabled record — the identifier is still taken, so classifying
     * the write as a creation would hit the UNIQUE constraint — but seeing it
     * must not put it back into service behind `secret.manage_policy`'s back.
     */
    #[Test]
    public function writingAValueToADisabledSecretLeavesItDisabled(): void
    {
        $vault = $this->getVaultService();
        $vault->store('availability_store', 'first-value');
        $vault->setEnabled('availability_store', false);

        $vault->store('availability_store', 'second-value');

        self::assertNull(
            $vault->retrieve('availability_store'),
            'Storing a value must not silently re-enable a disabled secret.',
        );
        self::assertFalse($vault->getMetadata('availability_store')->enabled);
    }

    /**
     * Metadata is not the value. Withholding it would hide the record from the
     * edit form that re-enables it, while disclosing nothing the actor could
     * not see before the secret was disabled.
     */
    #[Test]
    public function aDisabledSecretReportsItsStateInItsMetadata(): void
    {
        $vault = $this->getVaultService();
        $vault->store('availability_metadata', 'the-plaintext');

        self::assertTrue($vault->getMetadata('availability_metadata')->enabled);

        $vault->setEnabled('availability_metadata', false);

        self::assertFalse(
            $vault->getMetadata('availability_metadata')->enabled,
            'The DTO must report the state rather than pretend the secret is gone.',
        );
    }

    /**
     * The listing is where a disabled secret becomes reachable again — the
     * toggle only renders per listed row. It stays opt-in so a consumer asking
     * "which secrets are available" keeps the answer it had.
     */
    #[Test]
    public function theListingOmitsADisabledSecretUnlessItIsAskedFor(): void
    {
        $vault = $this->getVaultService();
        $vault->store('availability_listed', 'the-plaintext');
        $vault->setEnabled('availability_listed', false);

        self::assertNotContains(
            'availability_listed',
            $this->identifiersIn($vault->list()),
            'The default listing must not report a secret that is out of service.',
        );

        $included = $vault->list(includeDisabled: true);
        self::assertContains('availability_listed', $this->identifiersIn($included));
        self::assertFalse(
            $this->entryFor($included, 'availability_listed')->enabled,
            'The widened listing must mark the entry disabled, not merely include it.',
        );
    }

    /**
     * Availability is set, not toggled: asking for the state a secret already
     * has changes nothing, so there is nothing to audit. An entry here would
     * put a mutation into the tamper-evident chain that never happened.
     */
    #[Test]
    public function settingTheStateASecretAlreadyHasWritesNoAuditEntry(): void
    {
        $vault = $this->getVaultService();
        $vault->store('availability_noop', 'the-plaintext');
        $vault->setEnabled('availability_noop', false);

        $before = $this->countAuditEntries('availability_noop', AuditAction::MetadataUpdate);
        $vault->setEnabled('availability_noop', false);

        self::assertSame(
            $before,
            $this->countAuditEntries('availability_noop', AuditAction::MetadataUpdate),
            'A no-op must not be recorded as a change.',
        );
    }

    /**
     * The counterpart: a change that DID happen is audited, and as a metadata
     * update — the same action the FormEngine path writes for the same column,
     * so "who ever disabled this secret" has one answer instead of two.
     */
    #[Test]
    public function disablingASecretIsAuditedAsAMetadataUpdate(): void
    {
        $vault = $this->getVaultService();
        $vault->store('availability_audited', 'the-plaintext');

        $vault->setEnabled('availability_audited', false, 'key leaked');

        self::assertSame(
            1,
            $this->countAuditEntries('availability_audited', AuditAction::MetadataUpdate),
            'The availability change must appear exactly once in the chain.',
        );
        self::assertSame(
            'Secret disabled: key leaked',
            $this->latestReasonFor('availability_audited'),
            'The entry must name the direction and carry the operator reason.',
        );
    }

    /**
     * @param list<SecretMetadata> $secrets
     *
     * @return list<string>
     */
    private function identifiersIn(array $secrets): array
    {
        return array_map(static fn (SecretMetadata $s): string => $s->identifier, $secrets);
    }

    /**
     * @param list<SecretMetadata> $secrets
     */
    private function entryFor(array $secrets, string $identifier): SecretMetadata
    {
        foreach ($secrets as $secret) {
            if ($secret->identifier === $identifier) {
                return $secret;
            }
        }

        self::fail('No listing entry for ' . $identifier);
    }

    private function getVaultService(): VaultServiceInterface
    {
        return $this->get(VaultServiceInterface::class);
    }

    private function countAuditEntries(string $identifier, AuditAction $action): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::AUDIT_TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        $count = $queryBuilder
            ->count('uid')
            ->from(self::AUDIT_TABLE)
            ->where(
                $queryBuilder->expr()->eq('secret_identifier', $queryBuilder->createNamedParameter($identifier)),
                $queryBuilder->expr()->eq('action', $queryBuilder->createNamedParameter($action->value)),
                $queryBuilder->expr()->eq('success', $queryBuilder->createNamedParameter(1, Connection::PARAM_INT)),
            )
            ->executeQuery()
            ->fetchOne();

        return (int) $count;
    }

    private function latestReasonFor(string $identifier): string
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::AUDIT_TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        $reason = $queryBuilder
            ->select('reason')
            ->from(self::AUDIT_TABLE)
            ->where(
                $queryBuilder->expr()->eq('secret_identifier', $queryBuilder->createNamedParameter($identifier)),
                $queryBuilder->expr()->eq(
                    'action',
                    $queryBuilder->createNamedParameter(AuditAction::MetadataUpdate->value),
                ),
            )
            ->orderBy('uid', 'DESC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchOne();

        return \is_string($reason) ? $reason : '';
    }
}
