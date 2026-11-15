<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Command;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Command\VaultAuditVerifyCommand;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Traits\AuditSinkSandboxTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Authentication\CommandLineUserAuthentication;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * `vault:audit-verify --as-auditor` from the shell a deployment really has: an
 * unauthenticated CLI user, `allowCliAccess` off, and a configured
 * `auditorBeUserUid` whose group carries `tx_nrvault:audit.view`.
 */
#[CoversClass(VaultAuditVerifyCommand::class)]
final class VaultAuditVerifyCommandAuditorTest extends AbstractVaultFunctionalTestCase
{
    use AuditSinkSandboxTrait;

    /** Non-admin holding `audit.view` only (group 41 in the fixture). */
    private const AUDITOR = 3;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_audit_permission.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch'   => 3,
        'auditorBeUserUid' => self::AUDITOR,
    ];

    protected function setUp(): void
    {
        $this->extensionConfiguration = $this->prepareAuditSinkSandbox($this->extensionConfiguration);

        parent::setUp();

        $this->seedChain(3);
        $service = $this->get(ChainTipAnchorServiceInterface::class);
        $service->publish($service->capture());

        $GLOBALS['BE_USER'] = GeneralUtility::makeInstance(CommandLineUserAuthentication::class);
    }

    protected function tearDown(): void
    {
        $this->cleanUpAuditSinkSandbox();

        parent::tearDown();
    }

    #[Test]
    public function asAuditorVerifiesFromAnUnauthenticatedShell(): void
    {
        $tester   = new CommandTester($this->get(VaultAuditVerifyCommand::class));
        $exitCode = $tester->execute(['--as-auditor' => true]);

        self::assertSame(Command::SUCCESS, $exitCode, $tester->getDisplay());
        self::assertStringContainsString('verified', $tester->getDisplay());
    }

    /**
     * Configuring the actor grants nothing to the plain shell: without the flag
     * the command is refused exactly as before.
     */
    #[Test]
    public function withoutTheFlagTheShellIsStillRefused(): void
    {
        $tester = new CommandTester($this->get(VaultAuditVerifyCommand::class));

        self::assertSame(Command::FAILURE, $tester->execute([]));
        self::assertStringContainsString('Access denied', $this->normalize($tester));
    }

    /**
     * The actor is evaluated, not trusted: without `audit.view` on its groups it
     * is refused like any other user.
     */
    #[Test]
    public function anAuditorWithoutAuditViewIsRefused(): void
    {
        $this->get(ConnectionPool::class)->getConnectionForTable('be_users')
            ->update('be_users', ['usergroup' => ''], ['uid' => self::AUDITOR]);

        $tester = new CommandTester($this->get(VaultAuditVerifyCommand::class));

        self::assertSame(Command::FAILURE, $tester->execute(['--as-auditor' => true]));
        self::assertStringContainsString('Access denied', $this->normalize($tester));
        self::assertStringNotContainsString('verified', $tester->getDisplay());
    }

    /**
     * An actor that cannot be entered fails the run; in JSON it reports
     * `valid: false`, so a monitor never reads it as a clean chain.
     */
    #[Test]
    public function aDisabledAuditorFailsAndReportsInvalid(): void
    {
        $this->get(ConnectionPool::class)->getConnectionForTable('be_users')
            ->update('be_users', ['disable' => 1], ['uid' => self::AUDITOR]);

        $tester   = new CommandTester($this->get(VaultAuditVerifyCommand::class));
        $exitCode = $tester->execute(['--as-auditor' => true, '--format' => 'json']);

        self::assertSame(Command::FAILURE, $exitCode);
        $payload = json_decode($tester->getDisplay(), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($payload);
        self::assertFalse($payload['valid']);
        self::assertIsString($payload['error']);
        self::assertStringContainsString('disabled', $payload['error']);
    }

    private function seedChain(int $entries): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        for ($i = 0; $i < $entries; ++$i) {
            $auditService->log('verify_cmd_secret', 'read', true);
        }
    }

    private function normalize(CommandTester $tester): string
    {
        return (string) preg_replace('/\s+/', ' ', $tester->getDisplay());
    }
}
