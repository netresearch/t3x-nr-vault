<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Acknowledgement;

interface AuditFindingAcknowledgerInterface
{
    /**
     * Acknowledge every currently open finding, provided they are exactly the
     * ones the administrator was shown.
     *
     * @param string $displayedFingerprint {@see AuditFindingItem::fingerprint()} of the open items on screen
     * @param string $reason               Mandatory free text, kept in the chain
     * @param string $ticket               Optional ticket reference
     * @param int    $originalUserUid      Backend user behind a switch-user session, 0 otherwise
     */
    public function acknowledge(
        string $displayedFingerprint,
        string $reason,
        string $ticket,
        int $originalUserUid,
    ): AcknowledgementOutcome;
}
