<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor\Check;

use Stringable;

/**
 * An `ext_emconf.php` dependency range, e.g. `13.4.0-14.99.99`.
 *
 * Extracted from {@see VersionCheck} because parsing an operator-editable string
 * is the part with edge cases (missing upper bound, reversed bounds, junk), and a
 * diagnostic that silently mis-parses its own constraint would report a
 * compatible installation as broken. Kept deliberately dumb: `version_compare()`
 * over two bounds, no composer semantics — the authoritative resolution is
 * composer's, and duplicating it here would only create a second answer.
 */
final readonly class Typo3VersionRange implements Stringable
{
    private function __construct(
        public string $minimum,
        public string $maximum,
    ) {}

    public function __toString(): string
    {
        return $this->minimum . '-' . $this->maximum;
    }

    /**
     * Parse an `ext_emconf.php` constraint, or null when it is not a usable range.
     *
     * Null rather than a permissive fallback: "we could not read the constraint"
     * and "every version is allowed" are different statements, and only the
     * caller knows which finding to raise.
     */
    public static function fromConstraint(string $constraint): ?self
    {
        $parts = explode('-', trim($constraint));
        if (\count($parts) !== 2) {
            return null;
        }

        $minimum = trim($parts[0]);
        $maximum = trim($parts[1]);

        if ($minimum === '' || $maximum === '') {
            return null;
        }

        if (version_compare($minimum, $maximum, '>')) {
            return null;
        }

        return new self(minimum: $minimum, maximum: $maximum);
    }

    /**
     * Is `$version` inside the range (inclusive on both bounds)?
     */
    public function contains(string $version): bool
    {
        $version = trim($version);
        if ($version === '') {
            return false;
        }

        return version_compare($version, $this->minimum, '>=')
            && version_compare($version, $this->maximum, '<=');
    }
}
