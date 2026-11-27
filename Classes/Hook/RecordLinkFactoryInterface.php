<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Hook;

/**
 * Builds the `metadata` record link for a secret a DataHandler hook creates,
 * always naming the live record (see {@see RecordLinkFactory}).
 */
interface RecordLinkFactoryInterface
{
    /**
     * @param array<string, mixed> $extra
     *
     * @return array<string, mixed>
     */
    public function forField(string $source, string $table, string $field, int $uid, array $extra = []): array;

    /**
     * @param array<string, mixed> $extra
     *
     * @return array<string, mixed>
     */
    public function forFlexField(string $source, string $table, string $flexField, int $uid, array $extra = []): array;

    /**
     * The live uid of a record: its `t3ver_oid` when the row is a workspace
     * version, the uid itself otherwise.
     */
    public function liveUid(string $table, int $uid): int;
}
