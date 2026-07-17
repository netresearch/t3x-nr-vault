<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

/**
 * Thrown when a technical-actor identity cannot be established.
 *
 * Every refusal is fail-closed: `TechnicalActorContext::runAs()` never
 * executes the callable when the requested backend user cannot act as a
 * valid, enabled identity.
 */
final class TechnicalActorException extends VaultException
{
    public static function invalidUid(int $beUserUid): self
    {
        return new self(
            \sprintf('Technical actor uid must be a positive integer, got %d', $beUserUid),
            1784000001,
        );
    }

    public static function userNotFound(int $beUserUid): self
    {
        return new self(
            \sprintf('Technical actor uid %d does not resolve to a non-deleted be_users record', $beUserUid),
            1784000002,
        );
    }

    public static function userDisabled(int $beUserUid): self
    {
        return new self(
            \sprintf('Technical actor uid %d refers to a disabled be_users record', $beUserUid),
            1784000003,
        );
    }

    public static function userNotActive(int $beUserUid): self
    {
        return new self(
            \sprintf('Technical actor uid %d refers to a be_users record outside its start/end time window', $beUserUid),
            1784000004,
        );
    }
}
