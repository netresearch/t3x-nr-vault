<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor\Check;

use DateTimeImmutable;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Security\BreakGlassSession;
use Netresearch\NrVault\Security\BreakGlassStateInterface;
use Netresearch\NrVault\Service\Doctor\DocsLink;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\ReadinessCheckInterface;

/**
 * Is an emergency-access window open right now?
 *
 * The backend modules already show a banner while a window is open, so this
 * check exists for the surfaces the banner cannot reach: the CLI, a monitoring
 * probe, and a CI deployment gate. A release that ships while an operator's
 * bypass is live is a release nobody can attribute correctly afterwards.
 *
 * Warning rather than critical, on purpose. An open window is a deliberate,
 * justified, time-boxed act, not a misconfiguration — and a critical finding
 * would push operators to close the window in order to get a green gate during
 * the very incident it was opened for. Warning states the fact and lets the
 * human decide.
 */
final readonly class BreakGlassCheck implements ReadinessCheckInterface
{
    private const DATE_FORMAT = 'Y-m-d H:i';

    public function __construct(
        private BreakGlassStateInterface $breakGlassState,
    ) {}

    public function getId(): string
    {
        return 'breakglass';
    }

    public function appliesTo(SecurityProfile $profile): bool
    {
        return true;
    }

    public function run(DoctorContext $context): array
    {
        $id = 'breakglass.window_open';
        $session = $this->breakGlassState->getActiveSession();

        if (!$session instanceof BreakGlassSession) {
            return [
                Finding::pass(
                    id: $id,
                    summary: 'No break-glass window is open.',
                    docsUrl: DocsLink::BREAK_GLASS,
                ),
            ];
        }

        $remainingMinutes = (int) ceil($session->remainingSeconds(new DateTimeImmutable()) / 60);

        return [
            Finding::warning(
                id: $id,
                summary: \sprintf(
                    'A break-glass window is open: %s (uid %d) until %s (%d minute(s) left), reason: %s',
                    $session->activatedByUsername,
                    $session->activatedByUid,
                    $session->expiresAt->format(self::DATE_FORMAT),
                    $remainingMinutes,
                    $session->reason,
                ),
                risk: 'While the window is open the admin override is fully restored: that operator '
                    . 'holds every vault permission and read/write/delete on every secret, regardless of '
                    . 'the hardened profile. Break-glass buys evidence and a time box, not restriction.',
                remediation: \sprintf(
                    'Close it as soon as the work is done: vendor/bin/typo3 vault:break-glass '
                    . '--deactivate --reason "…". It lapses on its own at %s. Review the activation as an '
                    . 'incident, not as routine maintenance.',
                    $session->expiresAt->format(self::DATE_FORMAT),
                ),
                docsUrl: DocsLink::BREAK_GLASS,
                details: [
                    'activatedByUid' => $session->activatedByUid,
                    'activatedByUsername' => $session->activatedByUsername,
                    'reason' => $session->reason,
                    'expiresAt' => $session->expiresAt->getTimestamp(),
                    'remainingMinutes' => $remainingMinutes,
                ],
            ),
        ];
    }
}
