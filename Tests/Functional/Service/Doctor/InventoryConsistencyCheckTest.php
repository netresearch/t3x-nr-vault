<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service\Doctor;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\Check\InventoryConsistencyCheck;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * The inventory comparison against a real database.
 *
 * The unit tests hand the check a mocked `ConnectionPool`, so no QueryBuilder is
 * ever built and no SQL is ever generated, let alone executed. That gap shipped
 * a query nothing could run: `count('DISTINCT audit.secret_identifier')` quotes
 * its whole argument as one identifier, so every platform answered "no such
 * column" and the check reported a comparison it could not perform — visible
 * only in the release-evidence reference posture, after the code was merged.
 *
 * These cases exist to make the SQL itself the thing under test. They are
 * deliberately thin on assertions about wording and thick on the counts,
 * because the counts are what only a real database can produce.
 */
#[CoversClass(InventoryConsistencyCheck::class)]
final class InventoryConsistencyCheckTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    private const READ_TIER_TABLE = 'tx_nrvault_secret_begroups_mm';

    private const WRITE_TIER_TABLE = 'tx_nrvault_secret_writegroups_mm';

    /**
     * No backend user: this check compares tables and asks nobody for
     * permission, so logging one in would add a fixture the cases do not read.
     */
    protected ?int $backendUserUid = null;

    /**
     * The state every installation is in before anyone stores anything: three
     * empty tables, and nothing to report. An inventory check that cannot stay
     * silent here would be useless, because the first thing an operator does
     * after installing is run the doctor.
     */
    #[Test]
    public function anEmptyVaultReportsBothComparisonsAsPassing(): void
    {
        $findings = $this->inventoryFindings();

        self::assertSame(FindingSeverity::Pass, $this->finding($findings, 'inventory.missing_secrets')->severity);
        self::assertSame(FindingSeverity::Pass, $this->finding($findings, 'inventory.orphan_permissions')->severity);
    }

    /**
     * The query runs, and it runs correctly: two identifiers the audit log
     * records as created have no secret row, a third has one. Before the fix
     * this case did not fail on the count — it failed on the SQL.
     */
    #[Test]
    public function identifiersTheAuditLogRemembersWithNoSecretRowAreCounted(): void
    {
        $this->storeSecret('kept');
        $this->recordCreate('kept');
        $this->recordCreate('lost-one');
        $this->recordCreate('lost-two');

        $finding = $this->finding($this->inventoryFindings(), 'inventory.missing_secrets');

        self::assertSame(FindingSeverity::Critical, $finding->severity);
        self::assertSame(2, $finding->details['missingCount'] ?? null);
    }

    /**
     * The distinctness is load-bearing, and only a real database can show it:
     * the question is how many identifiers lost their row, not how many audit
     * rows name one. An identifier stored, deleted and stored again leaves
     * three create entries behind in a long-lived installation.
     */
    #[Test]
    public function anIdentifierCreatedSeveralTimesCountsOnce(): void
    {
        $this->recordCreate('lost');
        $this->recordCreate('lost');
        $this->recordCreate('lost');

        $finding = $this->finding($this->inventoryFindings(), 'inventory.missing_secrets');

        self::assertSame(1, $finding->details['missingCount'] ?? null);
    }

    /**
     * A soft-deleted secret is still a row. The restriction removal is what
     * makes that true in the query, and a functional run is the only place it
     * can be observed, because the deleted restriction is applied by the
     * QueryBuilder the unit tests never build.
     */
    #[Test]
    public function aSoftDeletedSecretStillCountsAsPresent(): void
    {
        $this->storeSecret('archived', deleted: 1);
        $this->recordCreate('archived');

        $finding = $this->finding($this->inventoryFindings(), 'inventory.missing_secrets');

        self::assertSame(FindingSeverity::Pass, $finding->severity);
        self::assertSame(0, $finding->details['missingCount'] ?? null);
    }

    /**
     * Permission rows are summed across both tiers. Counting one table and
     * calling it the answer would under-report by exactly the rows of the other.
     */
    #[Test]
    public function orphanPermissionRowsAreSummedAcrossBothTiers(): void
    {
        $secretUid = $this->storeSecret('granted');

        $this->grant(self::READ_TIER_TABLE, $secretUid, 1);
        $this->grant(self::READ_TIER_TABLE, 9001, 1);
        $this->grant(self::READ_TIER_TABLE, 9002, 2);
        $this->grant(self::WRITE_TIER_TABLE, 9003, 1);

        $finding = $this->finding($this->inventoryFindings(), 'inventory.orphan_permissions');

        self::assertSame(FindingSeverity::Warning, $finding->severity);
        self::assertSame(3, $finding->details['orphanCount'] ?? null);
    }

    /**
     * @return list<Finding>
     */
    private function inventoryFindings(): array
    {
        $check = new InventoryConsistencyCheck($this->get(ConnectionPool::class));

        return $check->run(DoctorContext::forConfiguredProfile(SecurityProfile::Standard));
    }

    /**
     * @param list<Finding> $findings
     */
    private function finding(array $findings, string $id): Finding
    {
        foreach ($findings as $finding) {
            if ($finding->id === $id) {
                return $finding;
            }
        }

        self::fail(\sprintf('No finding with id "%s" among: %s', $id, implode(', ', array_map(
            static fn (Finding $candidate): string => $candidate->id,
            $findings,
        ))));
    }

    private function storeSecret(string $identifier, int $deleted = 0): int
    {
        $connection = $this->get(ConnectionPool::class)->getConnectionForTable(self::SECRET_TABLE);
        $connection->insert(self::SECRET_TABLE, [
            'pid' => 0,
            'identifier' => $identifier,
            'deleted' => $deleted,
        ]);

        return (int) $connection->lastInsertId();
    }

    private function recordCreate(string $identifier): void
    {
        $this->get(ConnectionPool::class)->getConnectionForTable(self::AUDIT_TABLE)->insert(self::AUDIT_TABLE, [
            'pid' => 0,
            'action' => AuditAction::Create->value,
            'secret_identifier' => $identifier,
            'success' => 1,
        ]);
    }

    private function grant(string $table, int $secretUid, int $groupUid): void
    {
        $this->get(ConnectionPool::class)->getConnectionForTable($table)->insert($table, [
            'uid_local' => $secretUid,
            'uid_foreign' => $groupUid,
        ]);
    }
}
