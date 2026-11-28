<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain\Dto;

/**
 * What moving one column value into the vault did to the row.
 *
 * A migrated row may carry a message: the row holds the identifier, but the
 * record link could not be added. A row that was not migrated always carries
 * the reason.
 *
 * @internal returned by FieldValueMigratorInterface::migrate()
 */
final readonly class FieldMigrationOutcome
{
    private function __construct(
        public bool $migrated,
        public ?string $message,
        public bool $secretKept = false,
    ) {}

    public static function migrated(): self
    {
        return new self(true, null);
    }

    public static function migratedUnlinked(string $message): self
    {
        return new self(true, $message);
    }

    public static function failed(string $reason): self
    {
        return new self(false, $reason);
    }

    /**
     * The record failed and the secret just stored was kept, because the row
     * could not be shown to hold its plaintext: the secret may be the only
     * copy of the value. A re-run cannot recover such a row (the identifier
     * is in use), so callers report it in full.
     */
    public static function failedKeepingSecret(string $reason): self
    {
        return new self(false, $reason, true);
    }
}
