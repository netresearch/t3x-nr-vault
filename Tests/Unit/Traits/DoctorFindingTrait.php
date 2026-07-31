<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Traits;

use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;

/**
 * Shared helpers for the `vault:doctor` readiness-check tests.
 *
 * Every check test needs the same three things — build a context, pull one
 * finding out of the returned list by its stable id, and assert its severity —
 * so they live here rather than being re-declared per test class (which is how a
 * duplication gate ends up flagging eight near-identical private helpers).
 */
trait DoctorFindingTrait
{
    protected function doctorContext(SecurityProfile $profile): DoctorContext
    {
        return DoctorContext::forConfiguredProfile($profile);
    }

    /**
     * A context asserting `$target` on an installation configured as
     * `$configured` — the `vault:doctor --profile=…` dry run.
     */
    protected function doctorContextTargeting(
        SecurityProfile $target,
        SecurityProfile $configured,
    ): DoctorContext {
        return new DoctorContext(profile: $target, configuredProfile: $configured);
    }

    /**
     * The finding with this id, failing the test when the check did not emit it.
     *
     * Failing rather than returning null is deliberate: a check that silently
     * stops reporting a control is exactly the regression these tests exist to
     * catch, and a null-safe lookup would let it pass as "no finding, no problem".
     *
     * @param list<Finding> $findings
     */
    protected function findingById(array $findings, string $id): Finding
    {
        foreach ($findings as $finding) {
            if ($finding->id === $id) {
                return $finding;
            }
        }

        self::fail(\sprintf(
            'No finding "%s" among [%s]',
            $id,
            implode(', ', $this->findingIds($findings)),
        ));
    }

    /**
     * @param list<Finding> $findings
     *
     * @return list<string>
     */
    protected function findingIds(array $findings): array
    {
        return array_map(static fn (Finding $finding): string => $finding->id, $findings);
    }

    /**
     * @param list<Finding> $findings
     */
    protected function assertFindingSeverity(
        FindingSeverity $expected,
        array $findings,
        string $id,
    ): Finding {
        $finding = $this->findingById($findings, $id);

        self::assertSame(
            $expected,
            $finding->severity,
            \sprintf('%s severity; summary was: %s', $id, $finding->summary),
        );

        // Anything above a pass has to tell the operator what it costs and what
        // to do — a severity with no risk or remediation text is a dead end.
        if ($expected !== FindingSeverity::Pass) {
            self::assertNotSame('', $finding->risk, $id . ' must state the risk');
            self::assertNotSame('', $finding->remediation, $id . ' must state a remediation');
        }

        return $finding;
    }
}
