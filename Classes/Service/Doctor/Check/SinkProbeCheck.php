<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor\Check;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\Sink\AuditSinkInterface;
use Netresearch\NrVault\Audit\Sink\SinkDeliveryStateRepositoryInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\DocsLink;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\ReadinessCheckInterface;
use Throwable;

/**
 * Active end-to-end verification of every enabled audit sink.
 *
 * The passive checks can only reason about configuration and recorded
 * history; a syntactically valid webhook URL whose collector has been dead
 * for days looks identical to a working one until an event happens to flow.
 * This check removes the guesswork — but only when the operator asked for it
 * (`vault:doctor --active-probes`): it talks to external systems, so it must
 * never run implicitly from the backend status panel or a deployment gate
 * that expected a passive inspection.
 *
 * The probe payload is the CURRENT chain-tip anchor, not a synthetic audit
 * entry: anchors are re-publishable evidence by design (`vault:audit-anchor`
 * does exactly this on a schedule), so the probe pollutes nothing and even
 * refreshes the external anchor. Acceptance is end-to-end: the webhook sink
 * only returns normally when the collector answered 2xx, the file sink when
 * the append actually happened, syslog when the message was handed off.
 */
final readonly class SinkProbeCheck implements ReadinessCheckInterface
{
    /**
     * @param iterable<AuditSinkInterface> $sinks Tagged `nr_vault.audit_sink` collection
     */
    public function __construct(
        private iterable $sinks,
        private ChainTipAnchorServiceInterface $anchorService,
        private ?SinkDeliveryStateRepositoryInterface $deliveryState = null,
    ) {}

    public function getId(): string
    {
        return 'sink-probe';
    }

    public function appliesTo(SecurityProfile $profile): bool
    {
        return true;
    }

    public function run(DoctorContext $context): array
    {
        if (!$context->activeProbes) {
            return [];
        }

        $anchor = $this->anchorService->capture();
        $findings = [];
        $probed = 0;

        foreach ($this->sinks as $sink) {
            if (!$this->isEnabledSafely($sink)) {
                continue;
            }

            ++$probed;
            $identifier = $sink->getIdentifier();
            $id = 'audit.sink_probe.' . $identifier;

            try {
                $sink->publishAnchor($anchor);
                $this->deliveryState?->recordSuccess($identifier);

                $findings[] = Finding::pass(
                    id: $id,
                    summary: \sprintf(
                        'Audit sink "%s" accepted the probe (chain-tip anchor, sequence %d).',
                        $identifier,
                        $anchor->sequence,
                    ),
                    docsUrl: DocsLink::AUDIT_SINKS,
                    details: ['sink' => $identifier, 'anchorSequence' => $anchor->sequence],
                );
            } catch (Throwable $e) {
                $this->deliveryState?->recordFailure($identifier, $e->getMessage());

                $findings[] = Finding::critical(
                    id: $id,
                    summary: \sprintf(
                        'Audit sink "%s" REFUSED the probe: %s',
                        $identifier,
                        $e->getMessage(),
                    ),
                    risk: 'The sink is enabled but demonstrably not accepting evidence right now. '
                        . 'Every audit event since its last successful delivery exists only in the '
                        . 'database the sink is meant to witness externally.',
                    remediation: 'Fix the sink (unreachable collector, full disk, unwritable path), '
                        . 're-run vendor/bin/typo3 vault:doctor --active-probes until the probe '
                        . 'passes, then re-anchor with vendor/bin/typo3 vault:audit-anchor.',
                    docsUrl: DocsLink::AUDIT_SINKS,
                    details: ['sink' => $identifier, 'error' => $e->getMessage()],
                );
            }
        }

        if ($probed === 0) {
            $findings[] = Finding::pass(
                id: 'audit.sink_probe.none',
                summary: 'Active probes requested, but no audit sink is enabled — nothing to probe. '
                    . 'The audit.external_sink finding covers whether that is acceptable.',
                docsUrl: DocsLink::AUDIT_SINKS,
                details: ['probedSinks' => 0],
            );
        }

        return $findings;
    }

    /**
     * Mirrors AuditSinkRegistry::isEnabledSafely(): a sink whose own
     * enablement probe throws is treated as disabled — here that simply means
     * it is not probed (the registry already logs and counts that failure).
     */
    private function isEnabledSafely(AuditSinkInterface $sink): bool
    {
        try {
            return $sink->isEnabled();
        } catch (Throwable) {
            return false;
        }
    }
}
