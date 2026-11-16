<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Export;

/**
 * Outcome of re-verifying an exported audit chain without the database.
 *
 * Valid only by a positive comparison: no error was recorded, at least one row
 * was checked, and the number of rows checked equals the count the export
 * declares. An empty export, an export whose rows were skipped, and one that
 * holds fewer rows than it declares therefore never read as verified.
 */
final readonly class AuditExportVerification
{
    /**
     * @param list<string>    $errors
     * @param array<int, int> $epochCounts rows per hmac_key_epoch
     */
    public function __construct(
        public int $rowsChecked,
        public int $declaredCount,
        public array $errors,
        public array $epochCounts,
        public bool $chainComplete,
        public bool $truncated,
        public int $firstUid,
        public int $lastUid,
    ) {}

    public function isValid(): bool
    {
        return $this->errors === []
            && $this->rowsChecked > 0
            && $this->rowsChecked === $this->declaredCount;
    }
}
