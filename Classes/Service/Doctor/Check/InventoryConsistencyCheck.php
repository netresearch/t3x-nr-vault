<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor\Check;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\DocsLink;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\ReadinessCheckInterface;
use Throwable;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Do the vault's tables still agree with each other?
 *
 * Every other check reads one table, or none. This one reads three and compares
 * them, because the failure it exists for cannot be seen in any single table: a
 * restore that brought back some of them and not the others. The vault then
 * starts, the master key works, every configuration check passes — and
 * `vault:doctor` said "ready" while the secrets were gone or every legitimate
 * user was locked out. That is the one state where a green report does active
 * harm, because it is the report an operator reads immediately after a restore.
 *
 * Two comparisons, chosen because both are zero on a fresh installation and
 * non-zero only when rows are genuinely missing:
 *
 * - **Secrets the audit log remembers.** A delete is a soft delete: the row
 *   stays with `deleted = 1`, and nothing in this extension removes a secret row
 *   outright. So an identifier the log records as created, with no row of any
 *   kind behind it, is a row that was lost rather than deleted. Retention
 *   pruning cannot produce a false alarm here — it removes the create row too.
 * - **Access rows pointing at nothing.** An `uid_local` in either permission
 *   table with no secret behind it means the two were restored from different
 *   moments. The mirror case, a secret whose permission rows are gone, is not
 *   detectable the same way: `vault:store` writes the relation table without the
 *   counter column DataHandler maintains, so a secret with no rows is
 *   indistinguishable from one that grants nothing. It is called out in the
 *   remediation instead, because the documented restore procedure is what
 *   prevents it.
 *
 * No identifier appears in a finding. The JSON report travels into CI logs, and
 * an identifier names a credential; the counts are what an operator acts on.
 */
final readonly class InventoryConsistencyCheck implements ReadinessCheckInterface
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    /**
     * The two permission tiers, read tier first.
     *
     * @var list<string>
     */
    private const PERMISSION_TABLES = [
        'tx_nrvault_secret_begroups_mm',
        'tx_nrvault_secret_writegroups_mm',
    ];

    public function __construct(
        private ConnectionPool $connectionPool,
    ) {}

    public function getId(): string
    {
        return 'inventory';
    }

    public function appliesTo(SecurityProfile $profile): bool
    {
        return true;
    }

    /**
     * @return list<Finding>
     */
    public function run(DoctorContext $context): array
    {
        return [
            $this->checkSecretsTheAuditLogRemembers(),
            $this->checkPermissionRowsPointingAtNothing(),
        ];
    }

    private function checkSecretsTheAuditLogRemembers(): Finding
    {
        $id = 'inventory.missing_secrets';

        try {
            $missing = $this->countCreatedButAbsent();
        } catch (Throwable $throwable) {
            return $this->unreadable($id, 'the audit log against the secret table', $throwable);
        }

        if ($missing === 0) {
            return Finding::pass(
                id: $id,
                summary: 'Every secret the audit log records as created is still stored.',
                details: ['missingCount' => 0],
            );
        }

        return Finding::critical(
            id: $id,
            summary: \sprintf(
                '%d secret(s) the audit log records as created have no row in the secret table.',
                $missing,
            ),
            risk: 'A delete leaves the row in place with deleted = 1, and nothing else removes one, so '
                . 'these rows did not go away through use. The likely cause is a restore that brought '
                . 'back the audit log without the secret table, or a table dropped between the two. '
                . 'Every consumer reading one of those identifiers now fails, and the plaintext exists '
                . 'nowhere else.',
            remediation: 'Do not write to the vault until this is resolved — a fresh store under the same '
                . 'identifier makes the loss permanent. Restore the secret table from the same dump as '
                . 'the audit log, then run vault:doctor again; the count must be zero. The restore '
                . 'procedure lists every table that has to travel together.',
            docsUrl: DocsLink::BACKUP_AND_RESTORE,
            details: ['missingCount' => $missing],
        );
    }

    private function checkPermissionRowsPointingAtNothing(): Finding
    {
        $id = 'inventory.orphan_permissions';

        try {
            $orphans = 0;
            foreach (self::PERMISSION_TABLES as $table) {
                $orphans += $this->countOrphanPermissionRows($table);
            }
        } catch (Throwable $throwable) {
            return $this->unreadable($id, 'the permission tables against the secret table', $throwable);
        }

        if ($orphans === 0) {
            return Finding::pass(
                id: $id,
                summary: 'Every access-permission row belongs to a stored secret.',
                details: ['orphanCount' => 0],
            );
        }

        return Finding::warning(
            id: $id,
            summary: \sprintf('%d access-permission row(s) point at a secret that does not exist.', $orphans),
            risk: 'The permission tables and the secret table were restored from different moments. The '
                . 'rows themselves grant nothing, but the mismatch says the two halves do not belong '
                . 'together — and the opposite half of the same mistake, secrets whose permission rows '
                . 'are missing, cannot be detected from the data and locks every legitimate user out of '
                . 'them.',
            remediation: 'Restore tx_nrvault_secret and both tx_nrvault_secret_*_mm tables from the same '
                . 'dump. Check afterwards that the users who should reach a secret still do — a missing '
                . 'permission row looks exactly like a secret nobody was granted.',
            docsUrl: DocsLink::BACKUP_AND_RESTORE,
            details: ['orphanCount' => $orphans],
        );
    }

    /**
     * Identifiers with a create entry and no row of any kind behind them.
     *
     * The deleted restriction is removed on purpose: a soft-deleted secret is
     * still a row, and the question here is whether the row exists at all.
     */
    private function countCreatedButAbsent(): int
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(self::AUDIT_TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        $count = $queryBuilder
            ->count('DISTINCT audit.secret_identifier')
            ->from(self::AUDIT_TABLE, 'audit')
            ->leftJoin(
                'audit',
                self::SECRET_TABLE,
                'secret',
                $queryBuilder->expr()->eq('secret.identifier', $queryBuilder->quoteIdentifier('audit.secret_identifier')),
            )
            ->where(
                $queryBuilder->expr()->eq(
                    'audit.action',
                    $queryBuilder->createNamedParameter(AuditAction::Create->value),
                ),
                $queryBuilder->expr()->neq(
                    'audit.secret_identifier',
                    $queryBuilder->createNamedParameter(''),
                ),
                $queryBuilder->expr()->isNull('secret.uid'),
            )
            ->executeQuery()
            ->fetchOne();

        return is_numeric($count) ? (int) $count : 0;
    }

    private function countOrphanPermissionRows(string $mmTable): int
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($mmTable);
        $queryBuilder->getRestrictions()->removeAll();

        $count = $queryBuilder
            ->count('mm.uid_local')
            ->from($mmTable, 'mm')
            ->leftJoin(
                'mm',
                self::SECRET_TABLE,
                'secret',
                $queryBuilder->expr()->eq('secret.uid', $queryBuilder->quoteIdentifier('mm.uid_local')),
            )
            ->where($queryBuilder->expr()->isNull('secret.uid'))
            ->executeQuery()
            ->fetchOne();

        return is_numeric($count) ? (int) $count : 0;
    }

    /**
     * A comparison that could not be made is reported, never passed over.
     *
     * The whole point of this check is that a green report must not be the
     * default answer after a restore. A missing table or a refused query is
     * itself a reason to look, so it is a finding rather than a silent pass.
     */
    private function unreadable(string $id, string $what, Throwable $throwable): Finding
    {
        return Finding::warning(
            id: $id,
            summary: \sprintf('Could not compare %s.', $what),
            risk: 'This check exists to catch a half-restored database, so a comparison that cannot run '
                . 'is not evidence that the inventory is intact. A missing table is itself one of the '
                . 'states it looks for.',
            remediation: 'Check that every vault table exists and that the database user may read it, '
                . 'then run vault:doctor again.',
            docsUrl: DocsLink::BACKUP_AND_RESTORE,
            details: ['error' => $throwable->getMessage()],
        );
    }
}
