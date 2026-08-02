<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use DateTimeImmutable;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Security\BreakGlassServiceInterface;
use Netresearch\NrVault\Security\BreakGlassSession;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * CLI command to open, close and inspect a break-glass window.
 *
 * The CLI is the primary surface on purpose: `disableAdminOverride` is meant to
 * be pinned in :file:`config/system/additional.php`, so the recovery path must
 * not depend on a backend module an admin may have just locked themselves out
 * of. A shell on the host is already root-equivalent for the vault.
 *
 * Usage:
 *   vendor/bin/typo3 vault:break-glass --status
 *   vendor/bin/typo3 vault:break-glass --activate --reason "INC-1234 rotate leaked key" --minutes=30
 *   vendor/bin/typo3 vault:break-glass --deactivate --reason "INC-1234 closed"
 */
#[AsCommand(
    name: 'vault:break-glass',
    description: 'Open, close or inspect a time-boxed break-glass window that restores the admin override',
)]
final class VaultBreakGlassCommand extends Command
{
    public function __construct(
        private readonly BreakGlassServiceInterface $breakGlassService,
        private readonly ExtensionConfigurationInterface $configuration,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'activate',
                'a',
                InputOption::VALUE_NONE,
                'Open a break-glass window (requires --reason)',
            )
            ->addOption(
                'deactivate',
                'd',
                InputOption::VALUE_NONE,
                'Close the open break-glass window early (requires --reason)',
            )
            ->addOption(
                'status',
                's',
                InputOption::VALUE_NONE,
                'Show the current break-glass state (default when no action is given)',
            )
            ->addOption(
                'reason',
                'r',
                InputOption::VALUE_REQUIRED,
                'Justification recorded in the audit log — mandatory for --activate and --deactivate',
            )
            ->addOption(
                'minutes',
                'm',
                InputOption::VALUE_REQUIRED,
                \sprintf(
                    'Window length in minutes, clamped to %d..%d',
                    BreakGlassServiceInterface::MIN_TTL_MINUTES,
                    BreakGlassServiceInterface::MAX_TTL_MINUTES,
                ),
                BreakGlassServiceInterface::DEFAULT_TTL_MINUTES,
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $activate = (bool) $input->getOption('activate');
        $deactivate = (bool) $input->getOption('deactivate');
        $status = (bool) $input->getOption('status');

        $actions = \count(array_filter([$activate, $deactivate, $status]));
        if ($actions > 1) {
            $io->error('Choose exactly one of --activate, --deactivate or --status.');

            return Command::INVALID;
        }

        if ($activate) {
            return $this->activate($io, $input);
        }

        if ($deactivate) {
            return $this->deactivate($io, $input);
        }

        // No action given: report state. Reading the state is the safe default
        // for a command whose other modes change the security posture.
        return $this->status($io);
    }

    private function activate(SymfonyStyle $io, InputInterface $input): int
    {
        $reasonOption = $input->getOption('reason');
        $reason = \is_string($reasonOption) ? $reasonOption : '';
        $minutesOption = $input->getOption('minutes');
        $minutes = is_numeric($minutesOption)
            ? (int) $minutesOption
            : BreakGlassServiceInterface::DEFAULT_TTL_MINUTES;

        try {
            $session = $this->breakGlassService->activate($reason, $minutes);
        } catch (VaultException $e) {
            $io->error($e->getMessage());

            return Command::FAILURE;
        }

        $io->warning('Break-glass mode is ACTIVE — the admin override is restored for this window.');
        $this->printSession($io, $session);

        if (!$this->overrideIsEffectivelyDisabled()) {
            $io->note(
                'Note: the admin override was not disabled to begin with '
                . '(disableAdminOverride is off, or the security profile is not "hardened"), '
                . 'so this window grants no additional power. It is still logged.',
            );
        }

        return Command::SUCCESS;
    }

    private function deactivate(SymfonyStyle $io, InputInterface $input): int
    {
        $reasonOption = $input->getOption('reason');
        $reason = \is_string($reasonOption) ? $reasonOption : '';

        $wasActive = $this->breakGlassService->isActive();

        try {
            $this->breakGlassService->deactivate($reason);
        } catch (VaultException $e) {
            $io->error($e->getMessage());

            return Command::FAILURE;
        }

        if ($wasActive) {
            $io->success('Break-glass window closed. The admin override is disabled again.');
        } else {
            $io->text('status: inactive');
            $io->success('No break-glass window was open — nothing to close.');
        }

        return Command::SUCCESS;
    }

    /**
     * Report state. Always exits 0: "no window is open" is a successful answer,
     * not a failure, and a monitoring probe should distinguish the two states by
     * parsing `status:` rather than by an exit code that also means "the command
     * broke".
     */
    private function status(SymfonyStyle $io): int
    {
        $session = $this->breakGlassService->getActiveSession();

        $io->definitionList(
            ['securityProfile' => $this->configuration->getSecurityProfile()->value],
            ['disableAdminOverride' => $this->configuration->isAdminOverrideDisabled() ? 'yes' : 'no'],
            ['adminOverrideDisabledEffective' => $this->overrideIsEffectivelyDisabled() ? 'yes' : 'no'],
        );

        if (!$session instanceof BreakGlassSession) {
            $io->text('status: inactive');

            return Command::SUCCESS;
        }

        $io->text('status: active');
        $this->printSession($io, $session);

        return Command::SUCCESS;
    }

    /**
     * Is the override actually off right now — i.e. is break-glass load-bearing
     * in this installation, or merely recorded?
     *
     * Mirrors the profile gate in
     * `AccessControlService::adminBypassActive()`; the flag alone does nothing
     * outside the hardened profile.
     */
    private function overrideIsEffectivelyDisabled(): bool
    {
        return $this->configuration->isAdminOverrideDisabled()
            && $this->configuration->getSecurityProfile()->isHardened();
    }

    private function printSession(SymfonyStyle $io, BreakGlassSession $session): void
    {
        $remaining = $session->remainingSeconds(new DateTimeImmutable());

        $io->definitionList(
            ['activatedBy' => \sprintf('%s (uid %d)', $session->activatedByUsername, $session->activatedByUid)],
            ['reason' => $session->reason],
            ['activatedAt' => $session->activatedAt->format(DateTimeImmutable::ATOM)],
            ['expiresAt' => $session->expiresAt->format(DateTimeImmutable::ATOM)],
            ['remainingSeconds' => (string) $remaining],
        );
    }
}
