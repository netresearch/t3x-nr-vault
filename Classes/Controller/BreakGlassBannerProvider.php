<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Controller;

use DateTimeImmutable;
use Netresearch\NrVault\Security\BreakGlassSession;
use Netresearch\NrVault\Security\BreakGlassStateInterface;

/**
 * View model for the break-glass warning banner.
 *
 * Centralised in one collaborator (same reasoning as {@see ModuleAccessGuard})
 * so every vault module renders the identical warning from the identical data,
 * and so the shaping stays unit-testable without booting a backend module.
 */
final readonly class BreakGlassBannerProvider
{
    private const DATE_FORMAT = 'Y-m-d H:i';

    public function __construct(
        private BreakGlassStateInterface $breakGlassState,
    ) {}

    /**
     * Banner data for `Partials/BreakGlassBanner.html`.
     *
     * `active => false` is returned as a complete shape rather than an empty
     * array so the Fluid partial always has every key it reads — a missing key
     * would render as an empty string and could turn a live warning into a
     * half-blank box.
     *
     * @return array{active: bool, username: string, uid: int, reason: string, expiresAt: string, remainingMinutes: int}
     */
    public function forView(): array
    {
        $session = $this->breakGlassState->getActiveSession();
        if (!$session instanceof BreakGlassSession) {
            return [
                'active' => false,
                'username' => '',
                'uid' => 0,
                'reason' => '',
                'expiresAt' => '',
                'remainingMinutes' => 0,
            ];
        }

        $remainingSeconds = $session->remainingSeconds(new DateTimeImmutable());

        return [
            'active' => true,
            'username' => $session->activatedByUsername,
            'uid' => $session->activatedByUid,
            'reason' => $session->reason,
            'expiresAt' => $session->expiresAt->format(self::DATE_FORMAT),
            // Round UP: showing "0 minutes left" while the bypass is still live
            // understates the exposure the operator is being warned about.
            'remainingMinutes' => (int) ceil($remainingSeconds / 60),
        ];
    }
}
