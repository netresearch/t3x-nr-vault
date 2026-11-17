<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Export;

use Netresearch\NrVault\Audit\AuditLogFilter;

/**
 * Exports the audit chain as the verbatim inputs of its entry hashes, and
 * re-verifies such an export without the database.
 */
interface AuditChainExporterInterface
{
    /**
     * Fix the selection to export: every row up to the current tip that the
     * filter selects, or the newest `$limit` of them.
     *
     * @param int|null $limit null exports every selected row
     */
    public function select(?AuditLogFilter $filter = null, ?int $limit = null): AuditChainExport;

    /**
     * Re-verify a decoded export document (`{"export": {...}, "rows": [...]}`).
     *
     * Rows at HMAC epoch 1 and above need the audit HMAC key, which is derived
     * from the installation's master key and is never exported: the master key
     * must be the one that was in effect when the export was taken.
     *
     * Which rows may be keyless (epoch 0) comes from the installation, not from
     * the document: when it signs its chain with HMAC, an epoch-0 row is
     * accepted only up to the newest epoch-0 row it stores, and at least one row
     * must have been checked with the key.
     *
     * @param array<mixed> $document
     */
    public function verify(array $document): AuditExportVerification;
}
