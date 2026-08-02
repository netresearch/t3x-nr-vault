<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use DateTimeImmutable;
use Netresearch\NrVault\Command\VaultBreakGlassCommand;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Security\BreakGlassServiceInterface;
use Netresearch\NrVault\Security\BreakGlassSession;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

#[CoversClass(VaultBreakGlassCommand::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultBreakGlassCommandTest extends TestCase
{
    private BreakGlassServiceInterface&MockObject $breakGlassService;

    private ExtensionConfigurationInterface&MockObject $configuration;

    private CommandTester $commandTester;

    protected function setUp(): void
    {
        parent::setUp();

        $this->breakGlassService = $this->createMock(BreakGlassServiceInterface::class);
        $this->configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $this->configuration->method('getSecurityProfile')->willReturn(SecurityProfile::Hardened);
        $this->configuration->method('isAdminOverrideDisabled')->willReturn(true);

        $this->commandTester = new CommandTester(new VaultBreakGlassCommand(
            $this->breakGlassService,
            $this->configuration,
        ));
    }

    #[Test]
    public function statusIsTheDefaultActionWhenNoneIsGiven(): void
    {
        // Reading the state is the safe default for a command whose other modes
        // change the security posture.
        $this->breakGlassService->expects(self::once())->method('getActiveSession')->willReturn(null);
        $this->breakGlassService->expects(self::never())->method('activate');
        $this->breakGlassService->expects(self::never())->method('deactivate');

        self::assertSame(Command::SUCCESS, $this->commandTester->execute([]));
        self::assertStringContainsString('status: inactive', $this->commandTester->getDisplay());
    }

    #[Test]
    public function statusExitsZeroWhenAWindowIsOpen(): void
    {
        // Exit 0 for both states on purpose: a probe distinguishes them by
        // parsing `status:`, so a non-zero code stays reserved for "the command
        // broke" rather than overloading it with "a window is open".
        $this->breakGlassService->method('getActiveSession')->willReturn($this->session());

        $exitCode = $this->commandTester->execute(['--status' => true]);

        self::assertSame(Command::SUCCESS, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('status: active', $display);
        self::assertStringContainsString('alice', $display);
        self::assertStringContainsString('INC-4711', $display);
    }

    #[Test]
    public function statusReportsWhetherTheOverrideIsEffectivelyDisabled(): void
    {
        $this->breakGlassService->method('getActiveSession')->willReturn(null);

        $this->commandTester->execute(['--status' => true]);

        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('hardened', $display);
        self::assertMatchesRegularExpression('/adminOverrideDisabledEffective\s+yes/', $display);
    }

    #[Test]
    public function activatePassesTheReasonAndTheClampedMinutes(): void
    {
        $this->breakGlassService
            ->expects(self::once())
            ->method('activate')
            ->with('INC-4711 rotate leaked key', 30)
            ->willReturn($this->session());

        $exitCode = $this->commandTester->execute([
            '--activate' => true,
            '--reason' => 'INC-4711 rotate leaked key',
            '--minutes' => '30',
        ]);

        self::assertSame(Command::SUCCESS, $exitCode);
        self::assertStringContainsString('ACTIVE', $this->commandTester->getDisplay());
    }

    #[Test]
    public function activateFallsBackToTheDefaultTtl(): void
    {
        $this->breakGlassService
            ->expects(self::once())
            ->method('activate')
            ->with('incident', BreakGlassServiceInterface::DEFAULT_TTL_MINUTES)
            ->willReturn($this->session());

        $this->commandTester->execute(['--activate' => true, '--reason' => 'incident']);
    }

    #[Test]
    public function activateFailsWithoutAReason(): void
    {
        $this->breakGlassService
            ->method('activate')
            ->willThrowException(ValidationException::missingReason('break-glass activation'));

        $exitCode = $this->commandTester->execute(['--activate' => true]);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString('reason is required', $this->commandTester->getDisplay());
    }

    #[Test]
    public function activateFailsForANonAdminActor(): void
    {
        $this->breakGlassService
            ->method('activate')
            ->willThrowException(AccessDeniedException::breakGlassRequiresAdmin('activation'));

        $exitCode = $this->commandTester->execute(['--activate' => true, '--reason' => 'incident']);

        self::assertSame(Command::FAILURE, $exitCode);
        self::assertStringContainsString('administrator', $this->commandTester->getDisplay());
    }

    #[Test]
    public function activateWarnsWhenTheOverrideWasNotDisabledAnyway(): void
    {
        // Activating with the override still in place grants nothing extra. Say
        // so, or the operator walks away believing the flag is live.
        $configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $configuration->method('getSecurityProfile')->willReturn(SecurityProfile::Standard);
        $configuration->method('isAdminOverrideDisabled')->willReturn(true);

        $this->breakGlassService->method('activate')->willReturn($this->session());
        $tester = new CommandTester(new VaultBreakGlassCommand($this->breakGlassService, $configuration));

        $tester->execute(['--activate' => true, '--reason' => 'incident']);

        self::assertStringContainsString('grants no additional power', $tester->getDisplay());
    }

    #[Test]
    public function deactivateClosesAnOpenWindow(): void
    {
        $this->breakGlassService->method('isActive')->willReturn(true);
        $this->breakGlassService->expects(self::once())->method('deactivate')->with('INC-4711 closed');

        $exitCode = $this->commandTester->execute([
            '--deactivate' => true,
            '--reason' => 'INC-4711 closed',
        ]);

        self::assertSame(Command::SUCCESS, $exitCode);
        self::assertStringContainsString('closed', $this->commandTester->getDisplay());
    }

    #[Test]
    public function deactivateReportsWhenNothingWasOpen(): void
    {
        $this->breakGlassService->method('isActive')->willReturn(false);

        $exitCode = $this->commandTester->execute(['--deactivate' => true, '--reason' => 'cleanup']);

        self::assertSame(Command::SUCCESS, $exitCode);
        self::assertStringContainsString('No break-glass window was open', $this->commandTester->getDisplay());
    }

    #[Test]
    public function deactivateFailsWithoutAReason(): void
    {
        $this->breakGlassService
            ->method('deactivate')
            ->willThrowException(ValidationException::missingReason('break-glass deactivation'));

        $exitCode = $this->commandTester->execute(['--deactivate' => true]);

        self::assertSame(Command::FAILURE, $exitCode);
    }

    #[Test]
    public function rejectsMoreThanOneAction(): void
    {
        $this->breakGlassService->expects(self::never())->method('activate');
        $this->breakGlassService->expects(self::never())->method('deactivate');

        $exitCode = $this->commandTester->execute([
            '--activate' => true,
            '--deactivate' => true,
            '--reason' => 'incident',
        ]);

        self::assertSame(Command::INVALID, $exitCode);
    }

    private function session(): BreakGlassSession
    {
        return new BreakGlassSession(
            activatedByUid: 7,
            activatedByUsername: 'alice',
            reason: 'INC-4711 rotate leaked key',
            activatedAt: new DateTimeImmutable(),
            expiresAt: (new DateTimeImmutable())->setTimestamp(time() + 900),
        );
    }
}
