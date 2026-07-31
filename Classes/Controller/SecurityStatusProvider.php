<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Controller;

use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Service\Doctor\VaultDoctorServiceInterface;
use Throwable;

/**
 * View model for the Overview module's security status panel.
 *
 * ## Why a collaborator and not controller code
 *
 * Same reasoning as {@see BreakGlassBannerProvider}: the shaping is real logic
 * with a permission decision in it, and {@see OverviewController} renders a
 * `ModuleTemplate` built from final TYPO3 classes and is therefore excluded from
 * unit coverage. Putting the decision here keeps it unit-testable without booting
 * a backend module.
 *
 * ## What each audience sees
 *
 * The pass ratio and the profile badge are visible to anyone who can open the
 * module. The finding list — which names the exact weakness, the risk it carries
 * and the file to edit — is gated behind {@see VaultPermission::VaultConfigure},
 * the permission that already governs vault configuration. An editor who holds
 * `secret.use` because their forms consume vault-backed credentials has no reason
 * to receive a prioritised list of this installation's weak points; knowing
 * *that* something is unresolved is enough for them to escalate.
 *
 * ## Cost
 *
 * Building this runs every readiness check, which includes a bounded audit-chain
 * pass and an inventory scan. That is acceptable for an admin landing page and it
 * is the honest price of a status panel that cannot go stale — but it is why
 * `vault:doctor` rather than this panel is the surface to put on a schedule or in
 * a monitoring probe.
 *
 * @phpstan-type ShapedFinding array{
 *     id: string,
 *     severity: string,
 *     context: string,
 *     summary: string,
 *     risk: string,
 *     remediation: string,
 *     docsUrl: string,
 * }
 * @phpstan-type SecurityStatusView array{
 *     available: bool,
 *     profile: string,
 *     auditReady: bool,
 *     severity: string,
 *     context: string,
 *     passed: int,
 *     total: int,
 *     criticalCount: int,
 *     warningCount: int,
 *     detailed: bool,
 *     findings: list<ShapedFinding>,
 * }
 */
final readonly class SecurityStatusProvider
{
    public function __construct(
        private VaultDoctorServiceInterface $doctor,
        // The permission authority directly rather than via ModuleAccessGuard:
        // this provider only needs the boolean, never the guard's rendered 403,
        // and the guard's ModuleTemplateFactory dependency is a final core class
        // that cannot be stood up in a unit test.
        private AccessControlServiceInterface $accessControlService,
    ) {}

    /**
     * Status data for `Partials/SecurityStatus.html`.
     *
     * Always returns the complete shape — including on failure — so the Fluid
     * partial never reads a missing key and renders a half-blank panel where a
     * warning belongs.
     *
     * @return SecurityStatusView
     */
    public function forView(): array
    {
        try {
            $report = $this->doctor->run();
        } catch (Throwable) {
            // The doctor service contains per-check crashes itself, so reaching
            // here means the run could not start at all. Report the gap rather
            // than an empty panel: "we could not check" must not look like "there
            // is nothing to report".
            return $this->unavailable();
        }

        $detailed = $this->accessControlService->isGranted(VaultPermission::VaultConfigure);
        $severity = $report->highestSeverity();

        return [
            'available' => true,
            'profile' => $report->context->profile->value,
            'auditReady' => $report->isAuditReady(),
            'severity' => $severity->value,
            'context' => $severity->bootstrapContext(),
            'passed' => $report->passedControls(),
            'total' => $report->totalControls(),
            'criticalCount' => \count($report->findingsOfSeverity(FindingSeverity::Critical)),
            'warningCount' => \count($report->findingsOfSeverity(FindingSeverity::Warning)),
            'detailed' => $detailed,
            'findings' => $detailed ? $this->shapeFindings($report->problems()) : [],
        ];
    }

    /**
     * @param list<Finding> $findings
     *
     * @return list<ShapedFinding>
     */
    private function shapeFindings(array $findings): array
    {
        return array_map(
            static fn (Finding $finding): array => [
                'id' => $finding->id,
                'severity' => $finding->severity->value,
                'context' => $finding->severity->bootstrapContext(),
                'summary' => $finding->summary,
                'risk' => $finding->risk,
                'remediation' => $finding->remediation,
                'docsUrl' => $finding->docsUrl,
            ],
            $findings,
        );
    }

    /**
     * @return SecurityStatusView
     */
    private function unavailable(): array
    {
        return [
            'available' => false,
            'profile' => '',
            'auditReady' => false,
            'severity' => '',
            'context' => 'warning',
            'passed' => 0,
            'total' => 0,
            'criticalCount' => 0,
            'warningCount' => 0,
            'detailed' => false,
            'findings' => [],
        ];
    }
}
