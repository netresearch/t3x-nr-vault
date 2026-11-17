<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Export;

use DateTimeInterface;
use Netresearch\NrVault\Audit\AuditLogFilter;

/**
 * One selection of the audit chain for export, fixed before any row is read.
 *
 * The bounds are taken against `tipUid`, the highest uid when the export
 * started, so rows written during a long export never shift what is counted
 * or exported. `rows` yields the selected rows in ascending uid order as the
 * verbatim hash inputs ({@see AuditChainExporter::exportRow()}).
 *
 * `chainComplete` means the export holds every row of the chain up to the tip:
 * no filter and no truncation. Only such an export can be checked for missing
 * rows and for the link between every pair of neighbours.
 */
final readonly class AuditChainExport
{
    /**
     * @param iterable<array<string, int|string>> $rows
     */
    public function __construct(
        public int $tipUid,
        public int $total,
        public int $count,
        public int $firstUid,
        public int $lastUid,
        public ?AuditLogFilter $filter,
        public ?int $limit,
        public iterable $rows,
    ) {}

    public function isTruncated(): bool
    {
        return $this->count < $this->total;
    }

    public function isChainComplete(): bool
    {
        return !$this->filter instanceof AuditLogFilter && !$this->isTruncated();
    }

    /**
     * The metadata block written in front of the rows.
     *
     * @return array<string, mixed>
     */
    public function metadata(string $generatedAt): array
    {
        return [
            'format'        => AuditChainExporter::FORMAT,
            'version'       => AuditChainExporter::FORMAT_VERSION,
            'generatedAt'   => $generatedAt,
            'tipUid'        => $this->tipUid,
            'total'         => $this->total,
            'count'         => $this->count,
            'firstUid'      => $this->firstUid,
            'lastUid'       => $this->lastUid,
            'chainComplete' => $this->isChainComplete(),
            'truncated'     => $this->isTruncated(),
            'limit'         => $this->limit,
            'filter'        => $this->filter instanceof AuditLogFilter ? $this->describeFilter($this->filter) : null,
        ];
    }

    /**
     * @return array<string, bool|int|string>
     */
    private function describeFilter(AuditLogFilter $filter): array
    {
        return array_filter([
            'secretIdentifier' => $filter->secretIdentifier,
            'action'           => $filter->action,
            'actorUid'         => $filter->actorUid,
            'success'          => $filter->success,
            'since'            => $filter->since instanceof DateTimeInterface ? $filter->since->format(DATE_ATOM) : null,
            'until'            => $filter->until instanceof DateTimeInterface ? $filter->until->format(DATE_ATOM) : null,
        ], static fn (mixed $value): bool => $value !== null);
    }
}
