<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

use DateTimeInterface;

/**
 * Filter criteria for querying audit logs.
 *
 * Immutable value object for type-safe audit log filtering.
 */
final readonly class AuditLogFilter
{
    public function __construct(
        public ?string $secretIdentifier = null,
        public ?string $action = null,
        public ?int $actorUid = null,
        public ?bool $success = null,
        public ?DateTimeInterface $since = null,
        public ?DateTimeInterface $until = null,
    ) {}

    /**
     * Create filter for a specific secret.
     */
    public static function forSecret(string $identifier): self
    {
        return new self(secretIdentifier: $identifier);
    }

    /**
     * Create filter for a specific action.
     */
    public static function forAction(string $action): self
    {
        return new self(action: $action);
    }

    /**
     * Create filter for a specific actor.
     */
    public static function forActor(int $actorUid): self
    {
        return new self(actorUid: $actorUid);
    }

    /**
     * Create filter for failed operations only.
     */
    public static function failedOnly(): self
    {
        return new self(success: false);
    }

    /**
     * Create filter for a date range.
     */
    public static function dateRange(DateTimeInterface $since, ?DateTimeInterface $until = null): self
    {
        return new self(since: $since, until: $until);
    }

    /**
     * Return a new filter with an additional constraint.
     */
    public function withSecret(string $identifier): self
    {
        return new self(
            secretIdentifier: $identifier,
            action: $this->action,
            actorUid: $this->actorUid,
            success: $this->success,
            since: $this->since,
            until: $this->until,
        );
    }

    public function withAction(string $action): self
    {
        return new self(
            secretIdentifier: $this->secretIdentifier,
            action: $action,
            actorUid: $this->actorUid,
            success: $this->success,
            since: $this->since,
            until: $this->until,
        );
    }

    public function withActor(int $actorUid): self
    {
        return new self(
            secretIdentifier: $this->secretIdentifier,
            action: $this->action,
            actorUid: $actorUid,
            success: $this->success,
            since: $this->since,
            until: $this->until,
        );
    }

    public function withSuccess(?bool $success): self
    {
        return new self(
            secretIdentifier: $this->secretIdentifier,
            action: $this->action,
            actorUid: $this->actorUid,
            success: $success,
            since: $this->since,
            until: $this->until,
        );
    }

    public function withDateRange(?DateTimeInterface $since, ?DateTimeInterface $until = null): self
    {
        return new self(
            secretIdentifier: $this->secretIdentifier,
            action: $this->action,
            actorUid: $this->actorUid,
            success: $this->success,
            since: $since,
            until: $until,
        );
    }

    /**
     * Check if any filter criteria are set.
     */
    public function isEmpty(): bool
    {
        return $this->secretIdentifier === null
            && $this->action === null
            && $this->actorUid === null
            && $this->success === null
            && !$this->since instanceof DateTimeInterface
            && !$this->until instanceof DateTimeInterface;
    }
}
