<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain\Dto;

/**
 * Data Transfer Object for secret filtering criteria.
 *
 * Replaces array{owner?: int, prefix?: string, context?: string, scopePid?: int}
 * for type-safe filtering in repository and adapter layers.
 */
readonly class SecretFilters
{
    /**
     * `$includeDisabled` is the only member that is not a narrowing filter:
     * it WIDENS the result set to secrets whose `hidden` flag is set, which
     * every restriction-honouring query drops. It defaults to `false` so
     * existing callers keep exactly the result they had, and belongs to the
     * management surfaces that must be able to see — and therefore re-enable
     * — a disabled secret. It is not a read-path option: the value of a
     * disabled secret stays unreadable regardless of it.
     */
    public function __construct(
        public ?int $owner = null,
        public ?string $prefix = null,
        public ?string $context = null,
        public ?int $scopePid = null,
        public bool $includeDisabled = false,
    ) {}

    /**
     * Create from array (for backwards compatibility).
     *
     * @param array{owner?: int, prefix?: string, context?: string, scopePid?: int, includeDisabled?: bool} $filters
     */
    public static function fromArray(array $filters): self
    {
        return new self(
            owner: $filters['owner'] ?? null,
            prefix: $filters['prefix'] ?? null,
            context: $filters['context'] ?? null,
            scopePid: $filters['scopePid'] ?? null,
            includeDisabled: $filters['includeDisabled'] ?? false,
        );
    }

    /**
     * Check if any NARROWING filter is set.
     *
     * `includeDisabled` is deliberately not counted: it widens the result set
     * rather than restricting it, so a query carrying only that flag is an
     * unfiltered listing that happens to include disabled secrets.
     */
    public function hasFilters(): bool
    {
        return $this->owner !== null
            || $this->prefix !== null
            || $this->context !== null
            || $this->scopePid !== null;
    }

    /**
     * Convert to array for legacy APIs.
     *
     * @return array{owner?: int, prefix?: string, context?: string, scopePid?: int, includeDisabled?: bool}
     */
    public function toArray(): array
    {
        $result = [];
        if ($this->owner !== null) {
            $result['owner'] = $this->owner;
        }

        if ($this->prefix !== null) {
            $result['prefix'] = $this->prefix;
        }

        if ($this->context !== null) {
            $result['context'] = $this->context;
        }

        if ($this->scopePid !== null) {
            $result['scopePid'] = $this->scopePid;
        }

        // Only when set, like every other member: the array form is "what was
        // asked for", and the default is asking for nothing.
        if ($this->includeDisabled) {
            $result['includeDisabled'] = true;
        }

        return $result;
    }
}
