<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;

/**
 * Publishes the current audit chain tip to the external sinks.
 *
 * Run this on a schedule (see
 * {@see \Netresearch\NrVault\Task\AuditAnchorTask}). Each run records, outside
 * the database, that the chain had reached a given sequence with a given tip
 * hash — which is what makes a later full table reset detectable by
 * `vault:audit-verify`. The anchoring interval is the blind window: an attacker
 * who resets the table can only hide entries written since the last anchor.
 *
 * Gated on `vault.configure`, the same permission `vault:audit --reset-anchor`
 * asserts, because publishing an anchor mutates tamper evidence: an actor who
 * truncates the log and then anchors makes the external sink attest the
 * truncated chain — the exact laundering the anchor exists to prevent.
 *
 * `--dry-run` is gated identically rather than as a read. It publishes nothing,
 * but it prints the current chain tip, which is the value a forged anchor has
 * to reproduce; and it is the rehearsal of an administrative operation, not a
 * view of the audit log.
 *
 * Usage:
 *   vendor/bin/typo3 vault:audit-anchor
 *   vendor/bin/typo3 vault:audit-anchor --dry-run
 *   vendor/bin/typo3 vault:audit-anchor --format=json
 */
#[AsCommand(
    name: 'vault:audit-anchor',
    description: 'Publish the audit log chain tip to the external audit sinks',
)]
final class VaultAuditAnchorCommand extends Command
{
    public function __construct(
        private readonly ChainTipAnchorServiceInterface $anchorService,
        private readonly AuditSinkRegistryInterface $sinkRegistry,
        private readonly AccessControlServiceInterface $accessControlService,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'dry-run',
                null,
                InputOption::VALUE_NONE,
                'Show the anchor that would be published without writing it to any sink',
            )
            ->addOption(
                'format',
                'f',
                InputOption::VALUE_REQUIRED,
                'Output format: text (default) or json',
                'text',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $formatOption = $input->getOption('format');
        $json = \is_string($formatOption) && strtolower($formatOption) === 'json';
        $dryRun = (bool) $input->getOption('dry-run');

        // Before the chain tip is even read, so a refusal discloses nothing and
        // publishes nothing.
        if (!$this->accessControlService->isGranted(VaultPermission::VaultConfigure)) {
            $this->fail($io, $output, $json, \sprintf(
                'Access denied: the "%s" permission is required to publish the audit chain tip.',
                VaultPermission::VaultConfigure->value,
            ));

            return Command::FAILURE;
        }

        try {
            $anchor = $this->anchorService->capture();
        } catch (Throwable $e) {
            $this->fail($io, $output, $json, 'Could not read the audit chain tip: ' . $e->getMessage());

            return Command::FAILURE;
        }

        $enabledSinks = $this->sinkRegistry->getEnabledSinkIdentifiers();

        if ($dryRun) {
            $this->render($io, $output, $json, $anchor, $enabledSinks, 0, true);
            if (!$json) {
                $io->note('Dry run — nothing was published.');
            }

            return Command::SUCCESS;
        }

        $published = $this->anchorService->publish($anchor);

        $this->render($io, $output, $json, $anchor, $enabledSinks, $published, false);

        if ($published === 0) {
            // Exit non-zero: an anchoring run that reached no external sink gives
            // no reset protection, and a green scheduler task would misreport
            // that as working tamper evidence.
            if (!$json) {
                $io->error(
                    'The anchor was not accepted by any external sink, so it provides no '
                    . 'table-reset protection. Enable and configure at least one audit sink '
                    . '(auditSinkFileEnabled / auditSinkSyslogEnabled / auditSinkWebhookEnabled).',
                );
            }

            return Command::FAILURE;
        }

        if (!$json) {
            $io->success(\sprintf(
                'Anchored audit chain at sequence %d across %d sink(s).',
                $anchor->sequence,
                $published,
            ));
        }

        return Command::SUCCESS;
    }

    /**
     * @param list<string> $enabledSinks
     */
    private function render(
        SymfonyStyle $io,
        OutputInterface $output,
        bool $json,
        ChainTipAnchor $anchor,
        array $enabledSinks,
        int $published,
        bool $dryRun,
    ): void {
        if ($json) {
            $output->writeln(json_encode([
                'dryRun' => $dryRun,
                'anchor' => $anchor->toArray(),
                'enabledSinks' => $enabledSinks,
                'published' => $published,
            ], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));

            return;
        }

        $io->definitionList(
            ['Sequence (max uid)' => (string) $anchor->sequence],
            ['Chain tip' => $anchor->chainTip !== '' ? $anchor->chainTip : '(empty chain)'],
            ['HMAC epoch' => (string) $anchor->hmacEpoch],
            ['Enabled sinks' => $enabledSinks === [] ? '(none)' : implode(', ', $enabledSinks)],
        );
    }

    private function fail(SymfonyStyle $io, OutputInterface $output, bool $json, string $message): void
    {
        if ($json) {
            $output->writeln(json_encode(['error' => $message], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));

            return;
        }

        $io->error($message);
    }
}
