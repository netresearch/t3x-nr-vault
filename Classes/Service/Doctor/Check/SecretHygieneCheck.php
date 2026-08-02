<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor\Check;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Domain\Dto\StaleSecret;
use Netresearch\NrVault\Domain\StalenessRule;
use Netresearch\NrVault\Service\Analytics\VaultAnalyticsServiceInterface;
use Netresearch\NrVault\Service\Doctor\DocsLink;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\ReadinessCheckInterface;

/**
 * Is the stored inventory itself in good order?
 *
 * The other checks ask whether the vault is configured correctly. This one asks
 * whether what is *in* it should still be there. Every secret is a liability for
 * as long as it exists: an expired credential nobody removed, a token nothing has
 * read in months, a password never rotated since the person who set it left.
 * Reducing the inventory is the cheapest security work available, and it is the
 * work nobody does unless something counts it.
 *
 * The counts come from {@see VaultAnalyticsServiceInterface}, the same source the
 * Analytics module renders, so the CLI gate and the module cannot disagree about
 * how many secrets are stale. No identifier is included in any finding — a
 * secret identifier names a credential and the JSON report travels into CI logs.
 * The Analytics module is where an operator sees which ones.
 */
final readonly class SecretHygieneCheck implements ReadinessCheckInterface
{
    /**
     * Analysis window for the read-activity split, in days.
     *
     * Matched to the longest staleness threshold that exists by default
     * (`staleNeverRotatedDays`, 180) so a secret is not called unread merely
     * because the window was shorter than its usage interval.
     */
    private const WINDOW_DAYS = 180;

    public function __construct(
        private VaultAnalyticsServiceInterface $analytics,
        private ExtensionConfigurationInterface $configuration,
    ) {}

    public function getId(): string
    {
        return 'secrets';
    }

    public function appliesTo(SecurityProfile $profile): bool
    {
        return true;
    }

    public function run(DoctorContext $context): array
    {
        $stats = $this->analytics->getUsageStats(self::WINDOW_DAYS);
        $candidates = $this->analytics->getRedactionCandidates(self::WINDOW_DAYS);

        return [
            $this->checkExpired($stats->expired),
            $this->checkNeverRotated($stats->neverRotated),
            $this->checkDead($this->countByRule($candidates, StalenessRule::Dead)),
        ];
    }

    private function checkExpired(int $expired): Finding
    {
        $id = 'secrets.expired';

        if ($expired === 0) {
            return Finding::pass(
                id: $id,
                summary: 'No expired secrets are stored.',
                details: ['expiredCount' => 0],
            );
        }

        return Finding::warning(
            id: $id,
            summary: \sprintf('%d stored secret(s) are past their expiry date.', $expired),
            risk: 'An expired secret still decrypts, so the credential remains recoverable from a '
                . 'database dump long after it stopped being needed. Consumers that still reference it '
                . 'also fail at an unpredictable moment rather than at the expiry date.',
            remediation: 'Review them in the vault Analytics module and either rotate them with '
                . 'vendor/bin/typo3 vault:rotate, or remove them with vendor/bin/typo3 vault:delete.',
            docsUrl: DocsLink::COMMANDS,
            details: ['expiredCount' => $expired],
        );
    }

    private function checkNeverRotated(int $neverRotated): Finding
    {
        $id = 'secrets.never_rotated';
        $threshold = $this->configuration->getStaleNeverRotatedDays();

        if ($neverRotated === 0) {
            return Finding::pass(
                id: $id,
                summary: \sprintf('Every stored secret was rotated within the last %d days.', $threshold),
                details: ['neverRotatedCount' => 0, 'thresholdDays' => $threshold],
            );
        }

        return Finding::warning(
            id: $id,
            summary: \sprintf(
                '%d stored secret(s) have not been rotated in %d days or more.',
                $neverRotated,
                $threshold,
            ),
            risk: 'The longer a credential lives, the more places it has been copied to and the more '
                . 'former staff have seen it. An unrotated secret means a leak from any point in its '
                . 'history is still live today.',
            remediation: 'Rotate them with vendor/bin/typo3 vault:rotate. Rotate on personnel changes as '
                . 'well as on a schedule — a departure is what makes an old credential dangerous.',
            docsUrl: DocsLink::COMMANDS,
            details: ['neverRotatedCount' => $neverRotated, 'thresholdDays' => $threshold],
        );
    }

    private function checkDead(int $dead): Finding
    {
        $id = 'secrets.dead';

        if ($dead === 0) {
            return Finding::pass(
                id: $id,
                summary: 'No stored secret looks unused.',
                details: ['deadCount' => 0],
            );
        }

        return Finding::warning(
            id: $id,
            summary: \sprintf('%d stored secret(s) show no read activity and look unused.', $dead),
            risk: 'A credential nothing reads is pure liability: it is still decryptable, still in every '
                . 'backup, and nobody would notice if it were used. It also inflates the blast radius of '
                . 'a master-key compromise for no operational benefit.',
            remediation: 'Confirm in the vault Analytics module that nothing consumes them, then delete '
                . 'them with vendor/bin/typo3 vault:delete. Revoke the credential at the issuing system '
                . 'too — removing the vault copy does not invalidate the credential.',
            docsUrl: DocsLink::COMMANDS,
            details: ['deadCount' => $dead],
        );
    }

    /**
     * @param list<StaleSecret> $candidates
     */
    private function countByRule(array $candidates, StalenessRule $rule): int
    {
        $count = 0;
        foreach ($candidates as $candidate) {
            if (\in_array($rule, $candidate->rules, true)) {
                ++$count;
            }
        }

        return $count;
    }
}
