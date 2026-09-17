<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Doctor\Check;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\Check\InventoryConsistencyCheck;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\DoctorFindingTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Database\Query\Restriction\QueryRestrictionContainerInterface;

#[CoversClass(InventoryConsistencyCheck::class)]
final class InventoryConsistencyCheckTest extends TestCase
{
    use DoctorFindingTrait;

    #[Test]
    public function appliesToBothProfiles(): void
    {
        $check = $this->check([0, 0, 0]);

        self::assertTrue($check->appliesTo(SecurityProfile::Standard));
        self::assertTrue($check->appliesTo(SecurityProfile::Hardened));
    }

    /**
     * The case that must not raise an alarm: a vault nobody has used yet.
     *
     * Both comparisons read zero against zero there, which is the reason they
     * were chosen over counting rows and calling an empty table suspicious.
     */
    #[Test]
    public function afreshInstallationPassesBothComparisons(): void
    {
        $findings = $this->check([0, 0, 0])->run($this->doctorContext(SecurityProfile::Standard));

        self::assertSame(
            ['inventory.missing_secrets', 'inventory.orphan_permissions'],
            $this->findingIds($findings),
        );
        $this->assertFindingSeverity(FindingSeverity::Pass, $findings, 'inventory.missing_secrets');
        $this->assertFindingSeverity(FindingSeverity::Pass, $findings, 'inventory.orphan_permissions');
    }

    /**
     * The restore this check exists for: the audit log came back, the secrets
     * did not. Nothing in the extension removes a secret row — a delete sets
     * `deleted = 1` — so a create with no row behind it is a lost row.
     */
    #[Test]
    public function secretsTheAuditLogRemembersButTheTableDoesNotAreCritical(): void
    {
        $findings = $this->check([7, 0, 0])->run($this->doctorContext(SecurityProfile::Standard));

        $finding = $this->findingById($findings, 'inventory.missing_secrets');
        self::assertSame(FindingSeverity::Critical, $finding->severity);
        self::assertStringContainsString('7 secret(s)', $finding->summary);
        self::assertSame(7, $finding->details['missingCount'] ?? null);
        // The operator must not write before restoring: a fresh store under the
        // same identifier would make the loss permanent.
        self::assertStringContainsString('Do not write to the vault', $finding->remediation);
    }

    /**
     * Both permission tiers are read, and their orphans add up: a restore that
     * lost the write tier alone is as much a mismatch as one that lost both.
     */
    #[Test]
    public function orphanPermissionRowsAreCountedAcrossBothTiers(): void
    {
        $findings = $this->check([0, 2, 3])->run($this->doctorContext(SecurityProfile::Standard));

        $finding = $this->findingById($findings, 'inventory.orphan_permissions');
        self::assertSame(FindingSeverity::Warning, $finding->severity);
        self::assertSame(5, $finding->details['orphanCount'] ?? null);
        self::assertStringContainsString('5 access-permission row(s)', $finding->summary);
    }

    /**
     * A comparison that cannot run is not evidence that the inventory is fine.
     *
     * A missing table is one of the states this check looks for, so failing to
     * read it has to be reported rather than passed over — otherwise the very
     * situation the check exists for produces a green report again.
     */
    #[Test]
    public function acomparisonThatCannotRunIsReportedRatherThanPassed(): void
    {
        $pool = $this->pool(static function (): Result {
            throw new RuntimeException('Table not found');
        });

        $findings = (new InventoryConsistencyCheck($pool))->run($this->doctorContext(SecurityProfile::Standard));

        foreach (['inventory.missing_secrets', 'inventory.orphan_permissions'] as $id) {
            $finding = $this->findingById($findings, $id);
            self::assertSame(FindingSeverity::Warning, $finding->severity, $id);
            self::assertStringContainsString('Table not found', (string) ($finding->details['error'] ?? ''));
        }
    }

    /**
     * @param array{int, int, int} $counts missing secrets, read-tier orphans, write-tier orphans
     */
    private function check(array $counts): InventoryConsistencyCheck
    {
        $queue = $counts;

        return new InventoryConsistencyCheck($this->pool(function () use (&$queue): Result {
            $result = self::createStub(Result::class);
            $result->method('fetchOne')->willReturn(array_shift($queue) ?? 0);

            return $result;
        }));
    }

    /**
     * A ConnectionPool whose query builder answers every read with one callback.
     *
     * The builder is a stub rather than a real one because the assertion is
     * about what the check makes of the counts, not about the SQL it builds —
     * that is what the functional suite covers.
     *
     * @param callable(): Result $execute
     */
    private function pool(callable $execute): ConnectionPool
    {
        $expression = self::createStub(ExpressionBuilder::class);
        $expression->method('eq')->willReturn('1=1');
        $expression->method('neq')->willReturn('1=1');
        $expression->method('isNull')->willReturn('1=1');

        $queryBuilder = self::createStub(QueryBuilder::class);
        $queryBuilder->method('getRestrictions')->willReturn(self::createStub(QueryRestrictionContainerInterface::class));
        $queryBuilder->method('expr')->willReturn($expression);
        $queryBuilder->method('quoteIdentifier')->willReturnArgument(0);
        $queryBuilder->method('createNamedParameter')->willReturn(':p');
        $queryBuilder->method('count')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('leftJoin')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('executeQuery')->willReturnCallback($execute);

        $pool = self::createStub(ConnectionPool::class);
        $pool->method('getQueryBuilderForTable')->willReturn($queryBuilder);

        return $pool;
    }
}
