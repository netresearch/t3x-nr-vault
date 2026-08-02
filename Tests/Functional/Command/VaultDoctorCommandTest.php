<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Command;

use Netresearch\NrVault\Command\VaultDoctorCommand;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * End-to-end `vault:doctor` runs through the real DI container.
 *
 * What only a functional run can prove, and the reason this file exists on top of
 * the unit tests:
 *
 *  - every readiness check is actually discovered through the
 *    `nr_vault.readiness_check` tag. A check that autowiring silently drops would
 *    make the gate green by omission, and no unit test can catch that;
 *  - the checks work against a real database, a real chain-tip anchor reader and
 *    the real extension configuration;
 *  - the exit-code contract holds end to end.
 *
 * The base class configures the FILE master-key provider with a 0600 key, which
 * is the deployment shape the hardened profile expects.
 */
#[CoversClass(VaultDoctorCommand::class)]
final class VaultDoctorCommandTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../Fixtures/Users/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'masterKeyProvider' => 'file',
    ];

    /**
     * Hardened profile, file provider, and no external audit sink: the gate must
     * refuse the deployment and name the control, because the audit trail would
     * exist only in the database it is meant to protect.
     */
    #[Test]
    public function hardenedWithoutAnExternalSinkExitsTwoAndNamesTheSinkControl(): void
    {
        $this->configure(['securityProfile' => 'hardened']);

        $tester = new CommandTester($this->get(VaultDoctorCommand::class));
        $exitCode = $tester->execute([]);

        self::assertSame(2, $exitCode, $tester->getDisplay());

        $display = $tester->getDisplay();
        self::assertStringContainsString('audit.external_sink', $display);
        self::assertStringContainsString('NOT audit-ready', $display);
    }

    /**
     * The same run in JSON, which is the form a CI gate consumes: the machine-
     * readable finding must carry the stable id and the NO_EXTERNAL_SINK reason
     * code that `vault:audit-verify` uses for the same condition.
     */
    #[Test]
    public function hardenedWithoutAnExternalSinkReportsNoExternalSinkInJson(): void
    {
        $this->configure(['securityProfile' => 'hardened']);

        $tester = new CommandTester($this->get(VaultDoctorCommand::class));
        $exitCode = $tester->execute(['--format' => 'json']);

        self::assertSame(2, $exitCode);

        $payload = $this->decode($tester->getDisplay());

        self::assertSame('hardened', $payload['profile']);
        self::assertFalse($payload['auditReady']);
        self::assertSame(2, $payload['exitCode']);
        self::assertGreaterThan(0, $this->summary($payload)['critical']);

        $sinkFinding = $this->findingById($payload, 'audit.external_sink');
        self::assertSame('critical', $sinkFinding['severity']);
        self::assertIsArray($sinkFinding['details']);
        self::assertSame('NO_EXTERNAL_SINK', $sinkFinding['details']['reasonCode']);

        // The file provider with a 0600 key is the shape hardened expects, so the
        // master-key controls must NOT be among the criticals.
        self::assertSame('pass', $this->findingById($payload, 'provider.configured')['severity']);
        self::assertSame('pass', $this->findingById($payload, 'provider.key_permissions')['severity']);
    }

    /**
     * Every check must be reachable through the DI tag. Asserting the concrete id
     * list rather than a count makes a silently-dropped check a named failure
     * instead of an off-by-one nobody investigates.
     */
    #[Test]
    public function everyReadinessCheckIsDiscoveredThroughTheServiceTag(): void
    {
        $this->configure(['securityProfile' => 'standard']);

        $tester = new CommandTester($this->get(VaultDoctorCommand::class));
        $tester->execute(['--format' => 'json']);

        $ids = array_column($this->findings($this->decode($tester->getDisplay())), 'id');

        foreach ([
            'provider.configured',
            'provider.known',
            'provider.available',
            'provider.master_key_readable',
            'provider.key_permissions',
            'profile.valid',
            'profile.admin_override',
            'breakglass.window_open',
            'audit.reads_logged',
            'audit.retention',
            'audit.hash_chain',
            'audit.external_sink',
            'audit.anchor',
            'audit.sink_delivery',
            'cli.access',
            'secrets.expired',
            'secrets.never_rotated',
            'secrets.dead',
            'environment.production_context',
            'environment.backend_lock_ssl',
            'version.extension',
            'version.typo3_supported',
        ] as $expected) {
            self::assertContains($expected, $ids, 'missing readiness control: ' . $expected);
        }

        self::assertNotContains('check.crashed', $ids, $tester->getDisplay());
    }

    /**
     * A default standard-profile installation must not be red. It carries the
     * documented warnings of a test instance — no backend TLS lock, a non-Production
     * application context is tolerated under standard — but nothing critical, or
     * the gate would be useless as a signal.
     */
    #[Test]
    public function aDefaultStandardInstallationHasNoCriticalFindings(): void
    {
        $this->configure(['securityProfile' => 'standard']);

        $tester = new CommandTester($this->get(VaultDoctorCommand::class));
        $exitCode = $tester->execute(['--format' => 'json']);

        $payload = $this->decode($tester->getDisplay());
        $criticals = array_filter(
            $this->findings($payload),
            static fn (array $finding): bool => $finding['severity'] === 'critical',
        );

        self::assertSame(
            0,
            $this->summary($payload)['critical'],
            'unexpected criticals: ' . json_encode(
                array_column($criticals, 'summary', 'id'),
                JSON_THROW_ON_ERROR,
            ),
        );
        self::assertLessThanOrEqual(1, $exitCode);
    }

    /**
     * `--profile=hardened` must judge a standard installation by the hardened
     * policy while reporting that the configuration is unchanged. This is the dry
     * run that lets a hardening migration be planned from real findings instead of
     * by flipping the switch on production.
     */
    #[Test]
    public function theProfileOverrideJudgesHardenedWithoutChangingTheConfiguration(): void
    {
        $this->configure(['securityProfile' => 'standard']);

        $tester = new CommandTester($this->get(VaultDoctorCommand::class));
        $exitCode = $tester->execute(['--profile' => 'hardened', '--format' => 'json']);

        self::assertSame(2, $exitCode);

        $payload = $this->decode($tester->getDisplay());
        self::assertSame('hardened', $payload['profile']);
        self::assertSame('standard', $payload['configuredProfile']);
        self::assertTrue($payload['profileOverridden']);

        // The live profile is untouched by the dry run.
        self::assertSame(
            'standard',
            $this->get(ExtensionConfigurationInterface::class)->getSecurityProfile()->value,
        );
    }

    #[Test]
    public function anUnknownProfileOptionIsRejected(): void
    {
        $this->configure(['securityProfile' => 'standard']);

        $tester = new CommandTester($this->get(VaultDoctorCommand::class));

        self::assertSame(2, $tester->execute(['--profile' => 'paranoid']));
        self::assertStringContainsString('paranoid', $tester->getDisplay());
    }

    /**
     * Decode a `--format=json` report body.
     *
     * @return array<string, mixed>
     */
    private function decode(string $json): array
    {
        $payload = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($payload);

        /** @var array<string, mixed> $payload */
        return $payload;
    }

    /**
     * @param array<string, mixed> $payload
     *
     * @return array<string, int>
     */
    private function summary(array $payload): array
    {
        $summary = $payload['summary'] ?? null;
        self::assertIsArray($summary);

        /** @var array<string, int> $summary */
        return $summary;
    }

    /**
     * @param array<string, mixed> $payload
     *
     * @return list<array<string, mixed>>
     */
    private function findings(array $payload): array
    {
        $findings = $payload['findings'] ?? null;
        self::assertIsArray($findings);

        /** @var list<array<string, mixed>> $findings */
        return array_values($findings);
    }

    /**
     * @param array<string, mixed> $payload
     *
     * @return array<string, mixed>
     */
    private function findingById(array $payload, string $id): array
    {
        foreach ($this->findings($payload) as $finding) {
            if (($finding['id'] ?? null) === $id) {
                return $finding;
            }
        }

        self::fail('No finding "' . $id . '" in the report');
    }

    /**
     * Merge extra keys into the live extension configuration.
     *
     * Called from the test body, before the first `$this->get()` in that test: the
     * `ExtensionConfiguration` wrapper is a singleton that snapshots the array in
     * its constructor, so a value written after the container has resolved it would
     * not be observed.
     *
     * @param array<string, mixed> $configuration
     */
    private function configure(array $configuration): void
    {
        $confVars = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        self::assertIsArray($confVars);

        $extensions = $confVars['EXTENSIONS'] ?? null;
        self::assertIsArray($extensions);

        $existing = $extensions['nr_vault'] ?? null;
        $extensions['nr_vault'] = array_merge(\is_array($existing) ? $existing : [], $configuration);

        $confVars['EXTENSIONS'] = $extensions;
        $GLOBALS['TYPO3_CONF_VARS'] = $confVars;
    }
}
