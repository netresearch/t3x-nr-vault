<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Secret;

/**
 * One recognisable secret shape, in the two forms its consumers need.
 *
 * A scanner asks "is this whole column value a secret?" and needs an ANCHORED
 * pattern. A redactor asks "is a secret hiding inside this free text?" and needs
 * an INLINE pattern. The two differ in strictness on purpose: a scanner that
 * over-matches produces false findings, while a redactor that under-matches
 * leaks. Keeping both forms on one object is what stops them drifting apart —
 * the failure mode this class exists to prevent.
 *
 * Either form may be absent:
 * - inline absent: the shape is too generic to hunt for inside prose (a bare
 *   32-char hex string is a Twilio token, but also every MD5 digest).
 * - anchored absent: the shape only ever appears embedded (a ``Bearer …``
 *   header, credentials inside a URL).
 */
final readonly class SecretPattern
{
    /** Default replacement for a matched secret. */
    public const MASK = '***';

    /**
     * @param string $name Human-readable shape name; surfaced in scan findings
     * @param string|null $anchoredPattern Whole-value regex (``^…$``), or null if the shape is only ever embedded
     * @param string|null $inlinePattern Embedded-occurrence regex, or null if the shape is too generic to redact inline
     * @param string $inlineReplacement Replacement for an inline match; may reference capture groups of $inlinePattern
     */
    public function __construct(
        public string $name,
        public ?string $anchoredPattern = null,
        public ?string $inlinePattern = null,
        public string $inlineReplacement = self::MASK,
    ) {}
}
