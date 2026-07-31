<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

/**
 * Thrown when access to a secret is denied.
 */
final class AccessDeniedException extends VaultException
{
    public static function forIdentifier(string $identifier, string $reason = ''): self
    {
        $message = \sprintf('Access denied to secret "%s"', $identifier);
        if ($reason !== '') {
            $message .= ': ' . $reason;
        }

        return new self($message, 1703800003);
    }

    public static function cliAccessDisabled(): self
    {
        return new self('CLI access to vault is disabled', 1703800004);
    }

    /**
     * Only a real backend admin / system maintainer or a real CLI operator may
     * open or close a break-glass window.
     *
     * Deliberately NOT gated on a `VaultPermission`: break-glass exists to
     * recover from a state where the granular grants are what is missing, so
     * gating it on one of them would make it unreachable exactly when it is
     * needed.
     */
    public static function breakGlassRequiresAdmin(string $operation): self
    {
        return new self(
            \sprintf(
                'Break-glass %s requires an authenticated backend administrator or a CLI context',
                $operation,
            ),
            1753900001,
        );
    }
}
