<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Anchor;

/**
 * Reads back the most recently published chain-tip anchor.
 *
 * Separate from the sink that writes it, because verification must work even
 * when the file sink is currently disabled: an operator who anchored for months
 * and then turned the sink off must still be able to check the chain against the
 * evidence already on disk. The read path therefore depends only on the
 * configured anchor path, never on sink enablement.
 */
interface AnchorReaderInterface
{
    /**
     * The highest-sequence anchor available, or null when none can be read.
     *
     * Null covers "no anchor file", "empty anchor file" and "no parseable anchor
     * record" alike: all three mean verification has no external baseline, and
     * the caller reports that as its own finding rather than distinguishing
     * causes it cannot act on differently.
     */
    public function readLatestAnchor(): ?ChainTipAnchor;

    /**
     * Whether an anchor source exists and is readable.
     *
     * Lets callers tell "anchoring was never set up" apart from "the anchor
     * store exists but holds nothing usable" — the second is a corruption signal
     * worth reporting differently in operator output.
     */
    public function isAvailable(): bool;
}
