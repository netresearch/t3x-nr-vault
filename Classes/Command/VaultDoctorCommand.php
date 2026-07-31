<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\DoctorReport;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Service\Doctor\VaultDoctorServiceInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;

/**
 * Deployment-readiness gate for the vault.
 *
 * Evaluates every readiness control and reports each one with the risk it
 * carries and the command that fixes it. Designed to be the last step of a
 * deployment pipeline, which drives two decisions:
 *
 * **Exit codes are the contract, not the text.**
 *
 *   0 — every control passed; the configuration is audit-ready
 *   1 — warnings only; deployable, worth fixing before an audit
 *   2 — at least one critical finding
 *
 * Worst-severity-wins (see {@see DoctorReport}), so a long list of passes can
 * never average a critical finding away. `Command::INVALID` (2) coincides with
 * the critical code, which is deliberate: a gate given an unusable `--profile`
 * value must not be readable as "checked and fine".
 *
 * **`--profile` changes the question, never the configuration.** `--profile=
 * hardened` on a standard installation answers "would this pass if we hardened
 * it?" without writing anything, so the migration can be planned from the real
 * finding list instead of by flipping the switch on production and seeing what
 * breaks.
 *
 * Usage:
 *   vendor/bin/typo3 vault:doctor
 *   vendor/bin/typo3 vault:doctor --profile=hardened
 *   vendor/bin/typo3 vault:doctor --format=json
 */
#[AsCommand(
    name: 'vault:doctor',
    description: 'Check the vault configuration for deployment and audit readiness',
)]
final class VaultDoctorCommand extends Command
{
    public function __construct(
        private readonly VaultDoctorServiceInterface $doctor,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'profile',
                'p',
                InputOption::VALUE_REQUIRED,
                'Security profile to check against: standard or hardened. '
                . 'Defaults to the configured profile. Does NOT change any configuration.',
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

        $profileOption = $input->getOption('profile');
        $targetProfile = null;

        if (\is_string($profileOption) && trim($profileOption) !== '') {
            $targetProfile = SecurityProfile::tryFrom(strtolower(trim($profileOption)));

            if (!$targetProfile instanceof SecurityProfile) {
                $this->renderInvalidProfile($io, $output, $profileOption, $json);

                return Command::INVALID;
            }
        }

        try {
            $report = $this->doctor->run($targetProfile);
        } catch (Throwable $e) {
            // A gate that cannot run must never look like a gate that found
            // nothing — same stance as vault:audit-verify.
            $this->renderCrash($io, $output, $e, $json);

            return 2;
        }

        if ($json) {
            $output->writeln(json_encode($report->toArray(), JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));

            return $report->exitCode();
        }

        $this->renderText($io, $report);

        return $report->exitCode();
    }

    private function renderInvalidProfile(
        SymfonyStyle $io,
        OutputInterface $output,
        string $given,
        bool $json,
    ): void {
        $message = \sprintf(
            'Unknown profile "%s". Valid profiles: %s, %s.',
            $given,
            SecurityProfile::Standard->value,
            SecurityProfile::Hardened->value,
        );

        if ($json) {
            $output->writeln(json_encode(
                ['error' => $message, 'exitCode' => Command::INVALID],
                JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR,
            ));

            return;
        }

        $io->error($message);
    }

    private function renderCrash(SymfonyStyle $io, OutputInterface $output, Throwable $e, bool $json): void
    {
        if ($json) {
            $output->writeln(json_encode(
                ['error' => $e->getMessage(), 'exitCode' => 2],
                JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR,
            ));

            return;
        }

        $io->error('vault:doctor could not complete: ' . $e->getMessage());
    }

    private function renderText(SymfonyStyle $io, DoctorReport $report): void
    {
        $io->title('Vault Readiness Report');

        $context = $report->context;
        $definitions = [
            ['Checked against profile' => $context->profile->value],
        ];
        if ($context->isProfileOverridden()) {
            $definitions[] = ['Configured profile' => \sprintf(
                '%s (NOT changed by this command)',
                $context->configuredProfile->value,
            )];
        }
        $definitions[] = ['Controls passed' => \sprintf(
            '%d of %d',
            $report->passedControls(),
            $report->totalControls(),
        )];
        $io->definitionList(...$definitions);

        $problems = $report->problems();

        if ($problems === []) {
            $io->success(\sprintf(
                'All %d controls passed — the configuration is audit-ready for the %s profile.',
                $report->totalControls(),
                $context->profile->value,
            ));

            return;
        }

        foreach ($problems as $finding) {
            $this->renderFinding($io, $finding);
        }

        $criticalCount = \count($report->findingsOfSeverity(FindingSeverity::Critical));
        $warningCount = \count($report->findingsOfSeverity(FindingSeverity::Warning));

        if ($criticalCount > 0) {
            $io->error(\sprintf(
                'NOT audit-ready for the %s profile: %d critical, %d warning.',
                $context->profile->value,
                $criticalCount,
                $warningCount,
            ));

            return;
        }

        $io->warning(\sprintf(
            'Deployable with %d warning(s) — no critical findings for the %s profile.',
            $warningCount,
            $context->profile->value,
        ));
    }

    /**
     * One finding as a labelled block.
     *
     * Sections rather than a table: the remediation text is a shell command an
     * operator has to be able to copy, and table borders wrap it into something
     * unpasteable.
     */
    private function renderFinding(SymfonyStyle $io, Finding $finding): void
    {
        $io->section(\sprintf(
            '[%s] %s',
            strtoupper($finding->severity->value),
            $finding->id,
        ));
        $io->writeln($finding->summary);

        if ($finding->risk !== '') {
            $io->newLine();
            $io->writeln('<comment>Risk:</comment> ' . $finding->risk);
        }

        if ($finding->remediation !== '') {
            $io->newLine();
            $io->writeln('<info>Fix:</info> ' . $finding->remediation);
        }

        if ($finding->docsUrl !== '') {
            $io->newLine();
            $io->writeln('<comment>Docs:</comment> ' . $finding->docsUrl);
        }

        $io->newLine();
    }
}
