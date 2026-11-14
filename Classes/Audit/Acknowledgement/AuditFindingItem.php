<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Acknowledgement;

use Netresearch\NrVault\Audit\AuditIntegrityReason;

/**
 * One individually acknowledgeable piece of tamper evidence.
 *
 * Finer than {@see \Netresearch\NrVault\Audit\AuditIntegrityAlert}, which
 * aggregates all rows of a reason code into a single alert. An acknowledgement
 * has to name exactly what the administrator was shown, so each failing row, each
 * uid gap and each anchor mismatch is an item of its own.
 *
 * `$key` is the identity an acknowledgement binds to. It covers the reason code,
 * the position and the stored content of the affected row, so the same row edited
 * again produces a different key and is open again.
 */
final readonly class AuditFindingItem
{
    /**
     * @param string               $key                 sha256 over reason, position and affected row content
     * @param AuditIntegrityReason $reason              Machine-readable reason code
     * @param int                  $rangeStart          First affected uid (0 = chain-level finding)
     * @param int                  $rangeEnd            Last affected uid (equals `$rangeStart` for a single row)
     * @param string               $detail              Human-readable, secret-free description
     * @param int|null             $acknowledgedBy      uid of the acknowledgement row that covers this item
     * @param bool                 $prefixBound         Chain-level item (no row) that an acknowledgement may cover, provided
     *                                                  the chain up to the tip it recorded is unchanged. Chain-level items
     *                                                  without this flag (the in-database anchor errors) are never covered:
     *                                                  re-arming the anchor resolves them, so a later incident of the same
     *                                                  kind cannot inherit an earlier acknowledgement.
     * @param bool                 $requiresFreshAnchor a finding against the external anchor: covered only once an
     *                                                  anchor was published after the acknowledgement
     */
    public function __construct(
        public string $key,
        public AuditIntegrityReason $reason,
        public int $rangeStart,
        public int $rangeEnd,
        public string $detail,
        public ?int $acknowledgedBy = null,
        public bool $prefixBound = false,
        public bool $requiresFreshAnchor = false,
    ) {}

    public function withAcknowledgement(int $acknowledgementUid): self
    {
        return new self($this->key, $this->reason, $this->rangeStart, $this->rangeEnd, $this->detail, $acknowledgementUid, $this->prefixBound, $this->requiresFreshAnchor);
    }

    public function withoutAcknowledgement(): self
    {
        return new self($this->key, $this->reason, $this->rangeStart, $this->rangeEnd, $this->detail, null, $this->prefixBound, $this->requiresFreshAnchor);
    }

    public function isAcknowledged(): bool
    {
        return $this->acknowledgedBy !== null;
    }

    /**
     * Fingerprint of a displayed finding set, so a POST can prove it acts on
     * exactly the findings the administrator saw.
     *
     * @param list<self> $items
     */
    public static function fingerprint(array $items): string
    {
        $keys = array_map(static fn (self $item): string => $item->key, $items);
        sort($keys);

        return hash('sha256', implode(',', $keys));
    }

    /**
     * @return array{key: string, reason: string, rangeStart: int, rangeEnd: int, detail: string, acknowledgedBy: int|null}
     */
    public function toArray(): array
    {
        return [
            'key'            => $this->key,
            'reason'         => $this->reason->value,
            'rangeStart'     => $this->rangeStart,
            'rangeEnd'       => $this->rangeEnd,
            'detail'         => $this->detail,
            'acknowledgedBy' => $this->acknowledgedBy,
        ];
    }
}
