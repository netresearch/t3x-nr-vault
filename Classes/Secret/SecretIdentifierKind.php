<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Secret;

/**
 * What kind of identifier is being judged secret-bearing by name.
 *
 * The three namespaces need different rules and must not share one union: a
 * process environment uses terse names where a broad substring rule is right
 * (``PGPASSWORD``, ``DATABASE_URL``), while database columns and configuration
 * keys need suffix anchoring — applying the environment rule to a column would
 * flag ``keyword`` because it contains ``KEY``.
 */
enum SecretIdentifierKind
{
    case DatabaseColumn;
    case ConfigurationKey;
    case EnvironmentVariable;

    /**
     * The hint patterns for this identifier namespace.
     *
     * @return list<string>
     */
    public function hints(): array
    {
        return match ($this) {
            self::DatabaseColumn => SecretPatternLibrary::columnNameHints(),
            self::ConfigurationKey => SecretPatternLibrary::configKeyHints(),
            self::EnvironmentVariable => SecretPatternLibrary::environmentNameHints(),
        };
    }
}
