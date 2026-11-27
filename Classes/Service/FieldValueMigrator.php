<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service;

use Doctrine\DBAL\Exception as DbalException;
use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Types\StringType;
use Doctrine\DBAL\Types\TextType;
use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Domain\Dto\SecretRecordLink;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use RuntimeException;
use Throwable;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Database\Query\Restriction\EndTimeRestriction;
use TYPO3\CMS\Core\Database\Query\Restriction\HiddenRestriction;
use TYPO3\CMS\Core\Database\Query\Restriction\StartTimeRestriction;

use function is_array;
use function is_numeric;
use function is_scalar;
use function is_string;
use function rtrim;
use function sprintf;
use function str_starts_with;
use function strtolower;
use function time;
use function trim;

/**
 * Moves one plaintext column value into the vault and writes the vault
 * identifier into its place. Shared by `vault:migrate-field` and the backend
 * migration wizard, so both protect the plaintext the same way.
 *
 * The value exists in two places only while this runs: the row and the new
 * secret. Every failure path keeps at least one of them:
 *
 * - The secret is stored WITHOUT the record link first. Orphan cleanup only
 *   deletes linked secrets, so a secret kept after a failed write cannot be
 *   deleted behind the operator's back. The link is added once the row
 *   verifiably holds the identifier.
 * - Both UPDATEs name the value the row is expected to hold, so a value an
 *   editor saved in between is never overwritten.
 * - The secret is deleted only when the row verifiably holds the plaintext:
 *   the UPDATE matched no row, or the original value was written back and
 *   read back.
 *
 * @internal shared by the migration command and the migration wizard
 */
final readonly class FieldValueMigrator implements FieldValueMigratorInterface
{
    public function __construct(
        private VaultServiceInterface $vaultService,
        private ConnectionPool $connectionPool,
        private VaultAdapterInterface $adapter,
        private AccessControlServiceInterface $accessControlService,
    ) {}

    /**
     * Find a column by name. DBAL keys the list by the lower-cased,
     * platform-QUOTED name: a reserved word arrives as `key` or "key".
     */
    public function findColumn(string $table, string $field): ?Column
    {
        $connection = $this->connectionPool->getConnectionForTable($table);

        foreach ($connection->createSchemaManager()->listTableColumns($table) as $key => $column) {
            if (trim((string) $key, '`"[]') === strtolower($field)) {
                return $column;
            }
        }

        return null;
    }

    /**
     * Why the column cannot hold an identifier of the given length, or null
     * when it can. A narrower column truncates the identifier (non-strict
     * SQL) or rejects it (strict SQL).
     */
    public function columnProblem(Column $column, int $identifierLength): ?string
    {
        $type = $column->getType();
        if (!$type instanceof StringType && !$type instanceof TextType) {
            return 'it is not a text column';
        }

        $length = $column->getLength();
        if ($length !== null && $length < $identifierLength) {
            return sprintf('it holds at most %d characters, an identifier needs %d', $length, $identifierLength);
        }

        return null;
    }

    /**
     * Number of rows whose key column shares its value with another row, or
     * null when the database gave no usable answer. An UPDATE by such a key
     * would write one identifier into several rows and overwrite their
     * plaintexts.
     */
    public function countRowsWithDuplicateKey(string $table, string $keyField): ?int
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        $counts = $queryBuilder
            ->selectLiteral(
                'COUNT(*) AS total',
                'COUNT(DISTINCT ' . $queryBuilder->quoteIdentifier($keyField) . ') AS distinct_keys',
            )
            ->from($table)
            ->where($queryBuilder->expr()->isNotNull($keyField))
            ->executeQuery()
            ->fetchAssociative();

        $total    = $counts['total'] ?? null;
        $distinct = $counts['distinct_keys'] ?? null;
        if (!is_numeric($total) || !is_numeric($distinct)) {
            return null;
        }

        return (int) $total - (int) $distinct;
    }

    public function restrictToMigratableRows(QueryBuilder $queryBuilder, string $table): void
    {
        $restrictions = $queryBuilder->getRestrictions();
        $restrictions->removeByType(HiddenRestriction::class);
        $restrictions->removeByType(StartTimeRestriction::class);
        $restrictions->removeByType(EndTimeRestriction::class);

        // DeletedRestriction filters on TCA ctrl.delete. A table without it
        // may still carry the conventional column.
        $tca    = $GLOBALS['TCA'] ?? null;
        $ctrl   = is_array($tca) && is_array($tca[$table] ?? null) ? ($tca[$table]['ctrl'] ?? null) : null;
        $delete = is_array($ctrl) ? ($ctrl['delete'] ?? null) : null;
        if ((!is_string($delete) || $delete === '') && $this->findColumn($table, 'deleted') instanceof Column) {
            $queryBuilder->andWhere($queryBuilder->expr()->eq('deleted', 0));
        }
    }

    /**
     * Whether a secret holds the identifier in any state. A disabled secret
     * still owns it: store() would update that secret instead of creating
     * one, and the service's exists() does not see it.
     */
    public function identifierInUse(string $identifier): bool
    {
        return $this->adapter->retrieveIncludingDisabled($identifier) instanceof Secret;
    }

    /**
     * Store the value under the identifier and write the identifier into the
     * row whose key column holds the key. Returns null on success, otherwise
     * what happened to the row and the secret.
     *
     * The record link names the `uid` column, which orphan cleanup looks the
     * record up by. A key from another column would point the cleanup at the
     * wrong record, so such a secret gets no link.
     */
    public function migrate(
        string $table,
        string $field,
        string $keyField,
        string $key,
        string $value,
        string $identifier,
    ): ?string {
        $migratedAt = time();

        try {
            // A secret under this identifier, enabled or not, belongs to
            // someone else: storing would overwrite its value.
            if ($this->identifierInUse($identifier)) {
                return sprintf('a secret with the identifier %s already exists', $identifier);
            }

            $this->vaultService->store($identifier, $value, ['metadata' => ['migrated_at' => $migratedAt]]);
        } catch (Throwable $e) {
            return 'the value could not be stored: ' . $e->getMessage();
        }

        try {
            $affected = $this->writeField($table, $field, $keyField, $key, $identifier, $value);
        } catch (DbalException $e) {
            return $this->afterFailedUpdate($table, $field, $keyField, $key, $value, $identifier, $e->getMessage());
        }

        // The UPDATE matched nothing: the row is gone or holds another value
        // than the one read, either way not the identifier.
        if ($affected === 0) {
            return $this->discard($identifier, 'no row with this key holds the value read before the update (the row changed or is gone)');
        }

        if ($affected !== 1) {
            return sprintf(
                'the update changed %d rows; the secret %s was kept, check the rows with this key',
                $affected,
                $identifier,
            );
        }

        // Non-strict SQL truncates silently: read the field back.
        try {
            $written = $this->readField($table, $field, $keyField, $key);
        } catch (DbalException $e) {
            return sprintf(
                'the field could not be read back (%s); the secret %s was kept, check whether the row holds it',
                $e->getMessage(),
                $identifier,
            );
        }

        if (!$this->holdsIdentifier($written, $identifier)) {
            return $this->restore($table, $field, $keyField, $key, $value, $identifier, $written);
        }

        if ($keyField !== 'uid' || !is_numeric($key)) {
            return null;
        }

        try {
            $this->attachRecordLink($identifier, ['migrated_at' => $migratedAt], SecretRecordLink::forField(
                SecretRecordLink::SOURCE_MIGRATION,
                $table,
                $field,
                (int) $key,
                ['migrated_at' => $migratedAt],
            ));
        } catch (Throwable $e) {
            return sprintf(
                'the field holds the identifier %s, but the record link could not be stored (%s); orphan cleanup will not consider this secret',
                $identifier,
                $e->getMessage(),
            );
        }

        return null;
    }

    /**
     * Add the record link to the secret this run just created. The link is
     * metadata of a creation, not a new value: going through store() again
     * would be an update, gated by secret.rotate and audited a second time.
     * The write is limited to the secret as created here (its metadata still
     * exactly what the creation stored) and to an actor holding the
     * secret.create permission the creation required.
     *
     * @param array<string, mixed> $createdMetadata
     * @param array<string, mixed> $link
     */
    private function attachRecordLink(string $identifier, array $createdMetadata, array $link): void
    {
        if (!$this->accessControlService->isGranted(VaultPermission::SecretCreate)) {
            throw new RuntimeException('missing ' . VaultPermission::SecretCreate->value . ' permission', 5690811857);
        }

        $secret = $this->adapter->retrieveIncludingDisabled($identifier);
        if (!$secret instanceof Secret || $secret->getMetadata() !== $createdMetadata) {
            throw new RuntimeException('the secret changed after it was stored', 6074293625);
        }

        $this->adapter->updateMetadata($identifier, $link);
    }

    /**
     * The UPDATE changed the row, but the row does not hold the identifier.
     * Write the original value back; only when the row verifiably holds it
     * again is the secret redundant.
     */
    private function restore(
        string $table,
        string $field,
        string $keyField,
        string $key,
        string $value,
        string $identifier,
        mixed $written,
    ): string {
        $reason = 'the field does not hold the identifier after the update';

        // A truncating column leaves a prefix of the identifier. Any other
        // value was written by someone else after this run's UPDATE: it is
        // not this run's to replace.
        $truncated = is_scalar($written) && rtrim((string) $written, ' ') !== ''
            && str_starts_with($identifier, rtrim((string) $written, ' '));
        if (!$truncated) {
            return sprintf(
                '%s but another value, so the row was left as it is; the value read before the update is kept in the secret %s',
                $reason,
                $identifier,
            );
        }

        try {
            // Only the value this run wrote is replaced: a row an editor
            // changed since then keeps the editor's value.
            $restored = $this->writeField($table, $field, $keyField, $key, $value, (string) $written) === 1
                && $this->readField($table, $field, $keyField, $key) === $value;
        } catch (DbalException) {
            $restored = false;
        }

        if (!$restored) {
            return sprintf(
                '%s and the original value could not be written back; the value is kept in the secret %s',
                $reason,
                $identifier,
            );
        }

        return $this->discard($identifier, $reason . '; the original value was written back');
    }

    /**
     * A failed statement normally changes no row, but a connection lost after
     * the server applied it gives the same error. Only a read-back that shows
     * the plaintext makes the secret redundant.
     */
    private function afterFailedUpdate(
        string $table,
        string $field,
        string $keyField,
        string $key,
        string $value,
        string $identifier,
        string $error,
    ): string {
        $reason = 'the field could not be updated: ' . $error;

        try {
            $unchanged = $this->readField($table, $field, $keyField, $key) === $value;
        } catch (DbalException) {
            $unchanged = false;
        }

        if ($unchanged) {
            return $this->discard($identifier, $reason);
        }

        return sprintf('%s; the row could not be confirmed to hold its original value, so the secret %s was kept', $reason, $identifier);
    }

    /**
     * The row holds the plaintext, so the secret just stored is referenced by
     * nothing. It has no record link, so orphan cleanup would never remove it.
     */
    private function discard(string $identifier, string $reason): string
    {
        try {
            $this->vaultService->delete($identifier, 'vault migration: ' . $reason);
        } catch (Throwable $e) {
            return sprintf('%s; the stored secret %s could not be deleted: %s', $reason, $identifier, $e->getMessage());
        }

        return $reason . '; the stored secret was deleted again';
    }

    /**
     * A CHAR column pads the value with spaces on platforms that keep the
     * padding (PostgreSQL); the padding is not part of the identifier, which
     * never ends in a space. The checks that allow a delete compare the
     * plaintext exactly instead.
     */
    private function holdsIdentifier(mixed $fieldValue, string $identifier): bool
    {
        return is_scalar($fieldValue) && rtrim((string) $fieldValue, ' ') === $identifier;
    }

    private function readField(string $table, string $field, string $keyField, string $key): mixed
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        return $queryBuilder
            ->select($field)
            ->from($table)
            ->where(
                $queryBuilder->expr()->eq($keyField, $queryBuilder->createNamedParameter($key)),
            )
            ->executeQuery()
            ->fetchOne();
    }

    /**
     * Write $value where the key matches AND the field still holds $expected.
     */
    private function writeField(string $table, string $field, string $keyField, string $key, string $value, string $expected): int
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        return $queryBuilder
            ->update($table)
            ->set($field, $value)
            ->where(
                $queryBuilder->expr()->eq($keyField, $queryBuilder->createNamedParameter($key)),
                $queryBuilder->expr()->eq($field, $queryBuilder->createNamedParameter($expected)),
            )
            ->executeStatement();
    }
}
