<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Command;

use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Command\VaultAuditAnchorCommand;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Traits\AuditSinkSandboxTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * End-to-end tests for `vault:audit-anchor` through CommandTester.
 *
 * Resolving the command from the container also proves its DI registration —
 * an unregistered command would be unreachable from the CLI even though the
 * class exists.
 */
#[CoversClass(VaultAuditAnchorCommand::class)]
final class VaultAuditAnchorCommandTest extends AbstractVaultFunctionalTestCase
{
    use AuditSinkSandboxTrait;

    protected ?string $backendUserFixture = __DIR__ . '/../Fixtures/Users/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 3,
    ];

    protected function setUp(): void
    {
        $this->extensionConfiguration = $this->prepareAuditSinkSandbox($this->extensionConfiguration);

        parent::setUp();
    }

    protected function tearDown(): void
    {
        $this->cleanUpAuditSinkSandbox();

        parent::tearDown();
    }

    #[Test]
    public function anchoringSucceedsAndWritesTheAnchorFile(): void
    {
        $this->get(AuditLogServiceInterface::class)->log('anchor_cmd_secret', 'create', true);

        $tester = new CommandTester($this->get(VaultAuditAnchorCommand::class));
        $exitCode = $tester->execute([]);

        self::assertSame(Command::SUCCESS, $exitCode, $tester->getDisplay());
        self::assertFileExists($this->auditSinkAnchorPath);
    }

    #[Test]
    public function outputReportsTheSequenceAndTheEnabledSink(): void
    {
        $this->get(AuditLogServiceInterface::class)->log('anchor_cmd_secret', 'create', true);

        $tester = new CommandTester($this->get(VaultAuditAnchorCommand::class));
        $tester->execute([]);

        $output = $tester->getDisplay();
        self::assertStringContainsString('file', $output);
        self::assertStringContainsString('1', $output);
    }

    #[Test]
    public function jsonOutputCarriesTheAnchorAndTheSinkCount(): void
    {
        $this->get(AuditLogServiceInterface::class)->log('anchor_cmd_secret', 'create', true);

        $tester = new CommandTester($this->get(VaultAuditAnchorCommand::class));
        $tester->execute(['--format' => 'json']);

        $payload = json_decode($tester->getDisplay(), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($payload);
        self::assertIsArray($payload['anchor']);
        self::assertSame(1, $payload['anchor']['sequence']);
        self::assertSame(3, $payload['anchor']['hmacEpoch']);
        self::assertSame(1, $payload['published']);
        self::assertFalse($payload['dryRun']);
    }

    #[Test]
    public function dryRunWritesNothing(): void
    {
        $this->get(AuditLogServiceInterface::class)->log('anchor_cmd_secret', 'create', true);

        $tester = new CommandTester($this->get(VaultAuditAnchorCommand::class));
        $exitCode = $tester->execute(['--dry-run' => true]);

        self::assertSame(Command::SUCCESS, $exitCode, $tester->getDisplay());
        self::assertFileDoesNotExist($this->auditSinkAnchorPath);
    }

    /**
     * The contract monitoring depends on: an anchor that reached no external sink
     * provides no table-reset protection, so it must exit non-zero rather than
     * reporting a successful run.
     */
    #[Test]
    public function anchoringWithoutAnyEnabledSinkFails(): void
    {
        $this->disableFileSink();
        $this->get(AuditLogServiceInterface::class)->log('anchor_cmd_secret', 'create', true);

        $tester = new CommandTester($this->get(VaultAuditAnchorCommand::class));
        $exitCode = $tester->execute([]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString('no', strtolower($tester->getDisplay()));
    }

    #[Test]
    public function anchoringAnEmptyChainStillSucceeds(): void
    {
        $tester = new CommandTester($this->get(VaultAuditAnchorCommand::class));
        $exitCode = $tester->execute([]);

        // An empty-chain anchor carries no hash to compare against, but it dates
        // the installation — which is worth recording, not an error.
        self::assertSame(Command::SUCCESS, $exitCode, $tester->getDisplay());
        self::assertStringContainsString('empty chain', $tester->getDisplay());
    }

    /**
     * Turn the file sink off after the container was built, mirroring an
     * installation that never enabled a sink.
     */
    private function disableFileSink(): void
    {
        $confVars = \is_array($GLOBALS['TYPO3_CONF_VARS'] ?? null) ? $GLOBALS['TYPO3_CONF_VARS'] : [];
        $extensions = \is_array($confVars['EXTENSIONS'] ?? null) ? $confVars['EXTENSIONS'] : [];
        $nrVault = \is_array($extensions['nr_vault'] ?? null) ? $extensions['nr_vault'] : [];

        $nrVault['auditSinkFileEnabled'] = 0;
        $extensions['nr_vault'] = $nrVault;
        $confVars['EXTENSIONS'] = $extensions;
        $GLOBALS['TYPO3_CONF_VARS'] = $confVars;
    }
}
