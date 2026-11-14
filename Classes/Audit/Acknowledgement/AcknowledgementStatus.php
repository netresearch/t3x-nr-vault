<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Acknowledgement;

/**
 * Outcome of an acknowledgement attempt. Only {@see self::Acknowledged} wrote
 * anything that counts; every other case is a refusal that left the chain as it
 * was, except {@see self::NotHonoured}, which is explained on the case.
 */
enum AcknowledgementStatus: string
{
    /**
     * The acknowledgement row was written and the verifier now honours it.
     */
    case Acknowledged = 'acknowledged';

    /**
     * The actor is not an administrator with `audit.view`.
     */
    case NotPermitted = 'not_permitted';

    /**
     * The audit HMAC epoch is below 3, where the acknowledgement could be forged or edited.
     */
    case EpochTooLow = 'epoch_too_low';

    /**
     * The mandatory reason is empty or too long.
     */
    case ReasonInvalid = 'reason_invalid';

    /**
     * The chain has no open finding that could be acknowledged.
     */
    case NothingToAcknowledge = 'nothing_to_acknowledge';

    /**
     * The open findings are not the set the administrator was shown.
     */
    case Stale = 'stale';

    /**
     * More findings than one acknowledgement row can carry.
     */
    case TooManyFindings = 'too_many_findings';

    /**
     * The row was written, but a row from a concurrent writer landed between the
     * verification and the write, so the tip binding does not hold and the
     * verifier ignores it. The attempt stays in the log; running it again works.
     */
    case NotHonoured = 'not_honoured';

    /**
     * The row was written, but no external sink accepted a fresh anchor. A
     * finding against the external anchor is resolved by anchoring, not covered
     * by an acknowledgement, so it stays open until an anchor is published
     * (`vault:audit-anchor`).
     */
    case AnchorNotPublished = 'anchor_not_published';
}
