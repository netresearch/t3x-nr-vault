<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

use JsonSerializable;

/**
 * A single audit-integrity finding, ready to be shipped to a SIEM.
 *
 * Carried by {@see \Netresearch\NrVault\Event\AuditIntegrityAlertEvent} and
 * published through the external sinks. Deliberately free of secret material:
 * `$detail` is written by the verifier / dispatcher, never by a caller holding
 * plaintext, and the sink layer never adds the secret identifier's value.
 */
final readonly class AuditIntegrityAlert implements JsonSerializable
{
    /**
     * @param AuditIntegrityReason $reason Machine-readable reason code
     * @param string $detail Human-readable, secret-free description
     * @param int $timestamp Unix timestamp the finding was raised
     * @param array<string, bool|int|string> $context Scalar-only extra facts
     *                                                (uid, sink identifier, anchored sequence, …).
     *                                                Scalars only so the payload can never smuggle a
     *                                                nested object graph into an external system.
     */
    public function __construct(
        public AuditIntegrityReason $reason,
        public string $detail,
        public int $timestamp,
        public array $context = [],
    ) {}

    /**
     * @param array<string, bool|int|string> $context
     */
    public static function create(AuditIntegrityReason $reason, string $detail, array $context = []): self
    {
        return new self($reason, $detail, time(), $context);
    }

    /**
     * @return array{reason: string, tamperEvidence: bool, detail: string, timestamp: int, context: array<string, bool|int|string>}
     */
    public function toArray(): array
    {
        return [
            'reason' => $this->reason->value,
            'tamperEvidence' => $this->reason->isTamperEvidence(),
            'detail' => $this->detail,
            'timestamp' => $this->timestamp,
            'context' => $this->context,
        ];
    }

    /**
     * @return array{reason: string, tamperEvidence: bool, detail: string, timestamp: int, context: array<string, bool|int|string>}
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
