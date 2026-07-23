<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Utility;

/**
 * Neutralizes spreadsheet-formula leaders in CSV cells (CWE-1236).
 *
 * CSV quoting (fputcsv / RFC 4180) protects the CSV grammar but not the
 * consuming spreadsheet application: a cell whose first character is one of
 * = + - @ TAB CR is interpreted as a formula by Excel / LibreOffice / Google
 * Sheets. Attacker-controlled audit data (User-Agent, request id, identifiers)
 * must therefore be neutralized before it is written to any CSV export.
 */
final class CsvFormulaSanitizer
{
    /**
     * Characters that trigger formula evaluation when they are a cell's first
     * byte. Includes TAB (0x09) and CR (0x0D), which some parsers strip before
     * evaluating the following leader.
     *
     * @var list<string>
     */
    private const FORMULA_LEADERS = ['=', '+', '-', '@', "\t", "\r"];

    /**
     * Neutralize a single CSV cell.
     *
     * Prefixes a leading single quote when the first byte is a formula leader;
     * otherwise the value is returned byte-identical. Intended to be applied
     * before the value is handed to fputcsv() (which adds RFC-4180 quoting).
     */
    public static function neutralizeCell(string $value): string
    {
        if ($value === '') {
            return $value;
        }

        if (\in_array($value[0], self::FORMULA_LEADERS, true)) {
            return "'" . $value;
        }

        return $value;
    }

    /**
     * Neutralize every string cell of a row for fputcsv().
     *
     * Non-string cells (bool/int/float/null) are passed through unchanged; keys
     * are preserved.
     *
     * @param array<int|string, bool|float|int|string|null> $row
     *
     * @return array<int|string, bool|float|int|string|null>
     */
    public static function neutralizeRow(array $row): array
    {
        return array_map(
            static fn (bool|float|int|string|null $cell): bool|float|int|string|null
                => \is_string($cell) ? self::neutralizeCell($cell) : $cell,
            $row,
        );
    }

    /**
     * Escape a field for hand-rolled (non-fputcsv) CSV assembly.
     *
     * Neutralizes formula leaders, then applies RFC-4180 quoting when the value
     * contains a comma, double quote or newline.
     */
    public static function escapeField(string $value): string
    {
        $value = self::neutralizeCell($value);

        if (str_contains($value, ',') || str_contains($value, '"') || str_contains($value, "\n")) {
            return '"' . str_replace('"', '""', $value) . '"';
        }

        return $value;
    }
}
