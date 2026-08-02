<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Psr\Log\LoggerInterface;
use Throwable;
use Traversable;

/**
 * Orchestrates the readiness checks behind `vault:doctor` and the backend
 * security status panel.
 *
 * ## Crash containment
 *
 * Every check runs inside its own `try`/`catch`. A check that throws is reported
 * as a `check.crashed` critical finding naming the failing check, and the run
 * continues. The reasoning is the same one that makes a fail-closed provider
 * factory the right default: a diagnostic tool whose output degrades to "no
 * findings" when part of it breaks is worse than no diagnostic tool, because an
 * operator reads the silence as a pass. A crashed check is therefore louder than
 * a failing one, never quieter.
 *
 * The exception message is included, and this is deliberate: `vault:doctor` is
 * reachable only from the CLI and from a `vault.configure`-gated backend panel,
 * and a crash with no message is unactionable. Checks must still not put key
 * material or key paths into their own findings (see {@see Finding}).
 */
final readonly class VaultDoctorService implements VaultDoctorServiceInterface
{
    /**
     * @param Traversable<ReadinessCheckInterface> $checks Tagged
     *                                                     `nr_vault.readiness_check` services, injected as an iterator
     */
    public function __construct(
        private Traversable $checks,
        private ExtensionConfigurationInterface $configuration,
        private LoggerInterface $logger,
    ) {}

    public function run(?SecurityProfile $targetProfile = null, bool $activeProbes = false): DoctorReport
    {
        $configuredProfile = $this->resolveConfiguredProfile();
        $context = new DoctorContext(
            profile: $targetProfile ?? $configuredProfile,
            configuredProfile: $configuredProfile,
            activeProbes: $activeProbes,
        );

        $findings = [];
        foreach ($this->checks as $check) {
            if (!$check->appliesTo($context->profile)) {
                continue;
            }

            foreach ($this->runContained($check, $context) as $finding) {
                $findings[] = $finding;
            }
        }

        return new DoctorReport(context: $context, findings: $findings);
    }

    /**
     * @return list<Finding>
     */
    private function runContained(ReadinessCheckInterface $check, DoctorContext $context): array
    {
        try {
            return $check->run($context);
        } catch (Throwable $e) {
            $this->logger->error('nr-vault readiness check crashed.', [
                'check' => $check->getId(),
                'exception' => $e->getMessage(),
            ]);

            return [
                Finding::critical(
                    id: 'check.crashed',
                    summary: \sprintf(
                        'Readiness check "%s" could not complete: %s',
                        $check->getId(),
                        $e->getMessage(),
                    ),
                    risk: 'The controls in this area were not evaluated. Treat them as unknown, '
                        . 'not as satisfied — an unevaluated control provides no assurance.',
                    remediation: 'Check the TYPO3 log for the full stack trace, then re-run '
                        . 'vendor/bin/typo3 vault:doctor.',
                    details: ['check' => $check->getId()],
                ),
            ];
        }
    }

    /**
     * The configured profile, or Standard when the configured value is not a
     * valid profile.
     *
     * An unknown profile string is a critical finding raised by
     * {@see Check\SecurityProfileCheck}; it must not also decide what the rest
     * of the run asserts. Falling back to Standard keeps the remaining output
     * readable and never lets a typo silently *raise* the bar in a way that
     * buries the real problem under hardened-only findings.
     */
    private function resolveConfiguredProfile(): SecurityProfile
    {
        try {
            return $this->configuration->getSecurityProfile();
        } catch (Throwable) {
            return SecurityProfile::Standard;
        }
    }
}
