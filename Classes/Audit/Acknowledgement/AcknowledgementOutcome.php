<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Acknowledgement;

/**
 * Result of {@see AuditFindingAcknowledgerInterface::acknowledge()}.
 */
final readonly class AcknowledgementOutcome
{
    /**
     * @param int $acknowledgedCount Findings the written row covers (0 for a refusal)
     * @param int $anchorsPublished  Sinks that accepted the fresh external anchor
     */
    public function __construct(
        public AcknowledgementStatus $status,
        public int $acknowledgedCount = 0,
        public int $anchorsPublished = 0,
    ) {}

    public static function refused(AcknowledgementStatus $status): self
    {
        return new self($status);
    }

    public function isAcknowledged(): bool
    {
        return $this->status === AcknowledgementStatus::Acknowledged;
    }
}
