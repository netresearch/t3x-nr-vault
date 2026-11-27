<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain\Dto;

use function in_array;
use function is_numeric;
use function is_string;

/**
 * The record link of a secret: which record and field the secret belongs to.
 *
 * A caller that creates a secret for a record passes the link as the
 * `metadata` option of `VaultServiceInterface::store()`, built by
 * {@see self::forField()} or {@see self::forFlexField()}. Orphan cleanup
 * (`OrphanCleanupTask`, `vault:cleanup-orphans`) reads it back with
 * {@see self::referenceFrom()}. Top-level `store()` options named `table`,
 * `field` or `uid` are not metadata and are ignored by the service.
 *
 * Only secrets created with a source from {@see self::ORPHAN_CLEANUP_SOURCES}
 * are cleanup candidates. Secrets created before the link was written under
 * `metadata` carry no link and stay invisible to the cleanup.
 */
final class SecretRecordLink
{
    public const SOURCE_TCA_FIELD = 'tca_field';

    public const SOURCE_RECORD_COPY = 'record_copy';

    public const SOURCE_FLEXFORM_FIELD = 'flexform_field';

    public const SOURCE_FLEXFORM_RECORD_COPY = 'flexform_record_copy';

    public const SOURCE_MIGRATION = 'migration';

    /**
     * Sources whose secrets the orphan cleanup may delete once the linked
     * record is gone. Both cleanups read this list.
     */
    public const ORPHAN_CLEANUP_SOURCES = [
        self::SOURCE_TCA_FIELD,
        self::SOURCE_RECORD_COPY,
        self::SOURCE_FLEXFORM_FIELD,
        self::SOURCE_FLEXFORM_RECORD_COPY,
        self::SOURCE_MIGRATION,
    ];

    /**
     * Link to a plain column: the column holds the secret's identifier.
     *
     * @param array<string, mixed> $extra Additional metadata entries (e.g. `copied_from`)
     *
     * @return array<string, mixed>
     */
    public static function forField(string $source, string $table, string $field, int $uid, array $extra = []): array
    {
        return [
            'source' => $source,
            'table'  => $table,
            'field'  => $field,
            'uid'    => $uid,
        ] + $extra;
    }

    /**
     * Link to a FlexForm column: the column's XML contains the identifier.
     *
     * @param array<string, mixed> $extra Additional metadata entries (e.g. `sheet`, `fieldPath`)
     *
     * @return array<string, mixed>
     */
    public static function forFlexField(string $source, string $table, string $flexField, int $uid, array $extra = []): array
    {
        return [
            'source'    => $source,
            'table'     => $table,
            'flexField' => $flexField,
            'uid'       => $uid,
        ] + $extra;
    }

    /**
     * The cleanup reference stored in a secret's metadata, or null when the
     * secret is no cleanup candidate (other source, no table, no uid).
     *
     * @param array<string, mixed> $metadata
     */
    public static function referenceFrom(array $metadata): ?OrphanReference
    {
        $source = $metadata['source'] ?? '';
        if (!in_array($source, self::ORPHAN_CLEANUP_SOURCES, true)) {
            return null;
        }

        $table = $metadata['table'] ?? '';
        if (!is_string($table) || $table === '') {
            return null;
        }

        $uid = $metadata['uid'] ?? null;
        if (!is_numeric($uid) || (int) $uid <= 0) {
            return null;
        }

        $flexForm = !isset($metadata['field']) && isset($metadata['flexField']);
        $field    = $metadata['field'] ?? $metadata['flexField'] ?? '';

        return new OrphanReference(
            table: $table,
            field: is_string($field) ? $field : '',
            uid: (int) $uid,
            flexForm: $flexForm,
        );
    }
}
