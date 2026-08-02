<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Hook;

/**
 * How the FormEngine creation of a `tx_nrvault_secret` record ended.
 *
 * Two of the three outcomes leave the record without a stored secret value,
 * which is why classifying by that single fact is not enough: "the editor
 * did not enter a value" and "the editor entered a value that was refused"
 * demand opposite handling. The first is a legitimate record whose creation
 * the hook must audit; the second created nothing at all, so its row must be
 * removed again and no success entry may be written for it.
 */
enum RecordCreationOutcome
{
    /**
     * No secret value was submitted — a deliberately value-less record (the
     * editor fills the value in a later save). VaultService never saw this
     * creation, so the hook audits it.
     */
    case ValueLess;

    /**
     * A submitted value was accepted and stored. VaultService audited the
     * creation itself, including its compensating rollback; the hook must
     * not add a second entry.
     */
    case Stored;

    /**
     * A submitted value was refused (per-secret ACL or operation permission)
     * or failed to store. No secret was created — the row DataHandler
     * inserted must not survive, and the refusal VaultService already
     * recorded is the truthful audit trail of the event.
     */
    case Rejected;

    public static function classify(bool $valueSubmitted, bool $valueStored): self
    {
        if (!$valueSubmitted) {
            return self::ValueLess;
        }

        return $valueStored ? self::Stored : self::Rejected;
    }
}
