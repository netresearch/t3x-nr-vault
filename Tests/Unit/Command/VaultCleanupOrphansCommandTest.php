<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Doctrine\DBAL\Schema\AbstractSchemaManager;
use Netresearch\NrVault\Command\VaultCleanupOrphansCommand;
use Netresearch\NrVault\Domain\Dto\SecretMetadata;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Service\OrphanReferenceChecker;
use Netresearch\NrVault\Service\OrphanReferenceCheckerInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

use function sprintf;
use function str_contains;
use function substr_count;

#[CoversClass(VaultCleanupOrphansCommand::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultCleanupOrphansCommandTest extends TestCase
{
    private const MSG_NO_TCA_SECRETS = 'No TCA-sourced secrets found';

    private const MSG_NO_ORPHANS = 'No orphaned secrets found';

    private const IDENTIFIER = '01937b6e-4b6c-7abc-8def-0123456789ab';

    private const IDENTIFIER_1 = '01937b6e-4b6c-7abc-8def-0123456789a1';

    private const IDENTIFIER_2 = '01937b6e-4b6c-7abc-8def-0123456789a2';

    private VaultServiceInterface&MockObject $vaultService;

    private ConnectionPool&MockObject $connectionPool;

    private OrphanReferenceCheckerInterface&MockObject $checker;

    private CommandTester $commandTester;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService   = $this->createMock(VaultServiceInterface::class);
        $this->connectionPool = $this->createMock(ConnectionPool::class);

        // The command's own logic; what the checker answers is tested in
        // OrphanReferenceCheckerTest and the functional cleanup tests. The
        // cutoff is the real one, minimum age included.
        $this->checker = $this->createMock(OrphanReferenceCheckerInterface::class);
        $this->checker->method('deletionCutoff')->willReturnCallback(
            fn (int $days, int $now): int => (new OrphanReferenceChecker($this->connectionPool))->deletionCutoff($days, $now),
        );

        $command = new VaultCleanupOrphansCommand(
            $this->vaultService,
            $this->checker,
        );

        $application = new Application();
        $application->addCommand($command);

        $this->commandTester = new CommandTester($command);
    }

    #[Test]
    public function hasCorrectName(): void
    {
        $command = new VaultCleanupOrphansCommand(
            $this->vaultService,
            $this->checker,
        );

        self::assertSame('vault:cleanup-orphans', $command->getName());
    }

    #[Test]
    public function succeedsWithNoTcaSecrets(): void
    {
        $this->vaultService->method('list')->willReturn([]);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString(self::MSG_NO_TCA_SECRETS, $this->commandTester->getDisplay());
    }

    #[Test]
    public function skipsNonTcaSecrets(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata('manual_secret', time(), ['source' => 'manual']),
        ]);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString(self::MSG_NO_TCA_SECRETS, $this->commandTester->getDisplay());
    }

    #[Test]
    public function findsNoOrphansWhenRecordsExist(): void
    {
        // Metadata must include table, field, and uid for orphan detection
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->mockRecordExists(true);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString(self::MSG_NO_ORPHANS, $this->commandTester->getDisplay());
    }

    #[Test]
    public function findsOrphansWhenRecordsDeleted(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->mockRecordExists(false);

        $exitCode = $this->commandTester->execute([
            '--dry-run' => true,
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('1', $display);
        self::assertStringContainsString('orphan', strtolower($display));
    }

    #[Test]
    public function respectsRetentionDays(): void
    {
        $recentOrphan = time() - 86400 * 3; // 3 days ago
        $oldOrphan    = time() - 86400 * 30;   // 30 days ago

        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER_1,
                $recentOrphan,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
            $this->createSecretMetadata(
                self::IDENTIFIER_2,
                $oldOrphan,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 2],
            ),
        ]);

        $this->mockRecordDoesNotExist();

        $exitCode = $this->commandTester->execute([
            '--dry-run'        => true,
            '--retention-days' => 7,
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        // Only the old orphan (30 days) should be found, not the recent one (3 days)
        self::assertStringContainsString('1', $display);
    }

    #[Test]
    public function tableFilterLimitsScope(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER_1,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
            $this->createSecretMetadata(
                self::IDENTIFIER_2,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_other', 'field' => 'secret', 'uid' => 1],
            ),
        ]);

        $this->mockRecordDoesNotExist();

        $exitCode = $this->commandTester->execute([
            '--dry-run' => true,
            '--table'   => 'tx_myext',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('tx_myext', $display);
        self::assertStringNotContainsString('tx_other', $display);
    }

    #[Test]
    public function deletesOrphansWhenConfirmed(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->mockRecordDoesNotExist();

        $this->vaultService
            ->expects($this->once())
            ->method('delete')
            ->with(self::IDENTIFIER, 'Orphan cleanup');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Successfully deleted', $this->commandTester->getDisplay());
    }

    /**
     * The orphan list is built before the confirmation prompt. A secret a row
     * holds again by the time the operator confirms is kept: each secret is
     * checked once more right before its delete (#565).
     */
    #[Test]
    public function aSecretReferencedAgainBeforeTheConfirmationIsKept(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        // Orphaned while the list is built, held again when it is deleted.
        $this->checker->expects(self::exactly(2))->method('isOrphaned')->willReturnOnConsecutiveCalls(true, false);
        $this->vaultService->expects(self::never())->method('delete');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        self::assertMatchesRegularExpression('/Kept \(referenced again\)\s*\|?\s*1/', $this->commandTester->getDisplay());
    }

    /**
     * A re-check that fails also answers "not orphaned": the secret is kept,
     * but counted and reported as not checked, with the reason (#565).
     */
    #[Test]
    public function aSecretWhoseRecheckFailsIsReportedAsNotChecked(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $unresolved = [];
        $calls      = 0;
        $this->checker->method('isOrphaned')->willReturnCallback(static function () use (&$unresolved, &$calls): bool {
            ++$calls;
            if ($calls === 1) {
                return true;
            }

            $unresolved[] = ['identifier' => self::IDENTIFIER, 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1, 'reason' => 'could not be resolved: connection lost', 'transient' => true];

            return false;
        });
        $this->checker->method('getUnresolvedReferences')->willReturnCallback(static function () use (&$unresolved): array {
            return $unresolved;
        });
        $this->vaultService->expects(self::never())->method('delete');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([]);

        self::assertSame(1, $exitCode, 'Secrets that could not be checked again must not end as a success');
        $display = (string) preg_replace('/\s+/', ' ', $this->commandTester->getDisplay());
        self::assertMatchesRegularExpression('/Kept \(referenced again\)\s*\|?\s*0/', $display);
        self::assertMatchesRegularExpression('/Kept \(could not be checked\)\s*\|?\s*1/', $display);
        self::assertStringContainsString('Kept ' . self::IDENTIFIER . ': could not be resolved: connection lost', $display);
        self::assertStringContainsString('Exit code 1: the check of 1 kept secret(s) failed on a query or connection error', $display);
    }

    /**
     * A secret whose first-pass check failed on a query or connection error
     * is kept. The run did not do what it was asked for that secret, so it
     * ends with exit code 1 on every path; a link that names an unknown table
     * or field never clears on its own, so it is listed but ends with 0
     * (#565).
     *
     * @return iterable<string, array{list<bool>, array<string, mixed>, list<string>, bool, int}>
     */
    public static function uncheckedFirstPassProvider(): iterable
    {
        // isOrphaned() answers per call: the unchecked secret first, then the
        // other one in the first pass, then the re-check before a delete.
        yield 'no orphans' => [[false, false], [], [], true, 1];
        yield 'dry run' => [[false, true], ['--dry-run' => true], [], true, 1];
        yield 'cancelled' => [[false, true], [], ['no'], true, 1];
        yield 'deleted' => [[false, true, true], [], ['yes'], true, 1];
        yield 'structural, no orphans' => [[false, false], [], [], false, 0];
        yield 'structural, dry run' => [[false, true], ['--dry-run' => true], [], false, 0];
        yield 'structural, cancelled' => [[false, true], [], ['no'], false, 0];
        yield 'structural, deleted' => [[false, true, true], [], ['yes'], false, 0];
    }

    /**
     * @param list<bool>           $answers
     * @param array<string, mixed> $options
     * @param list<string>         $inputs
     */
    #[Test]
    #[DataProvider('uncheckedFirstPassProvider')]
    public function aSecretTheFirstPassCouldNotCheckFailsTheRunOnlyForATransientReason(array $answers, array $options, array $inputs, bool $transient, int $expectedExitCode): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(self::IDENTIFIER_1, time() - 86400 * 30, ['source' => 'tca_field', 'table' => 'tx_gone', 'field' => 'api_key', 'uid' => 1]),
            $this->createSecretMetadata(self::IDENTIFIER_2, time() - 86400 * 30, ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 2]),
        ]);

        $unresolved = [];
        $calls      = 0;
        $this->checker->method('isOrphaned')->willReturnCallback(static function () use (&$unresolved, &$calls, $answers, $transient): bool {
            if (++$calls === 1) {
                $unresolved[] = $transient
                    ? ['identifier' => self::IDENTIFIER_1, 'table' => 'tx_gone', 'field' => 'api_key', 'uid' => 1, 'reason' => 'could not be resolved: connection lost', 'transient' => true]
                    : ['identifier' => self::IDENTIFIER_1, 'table' => 'tx_gone', 'field' => 'api_key', 'uid' => 1, 'reason' => 'names an unknown table', 'transient' => false];
            }

            return $answers[$calls - 1] ?? false;
        });
        $this->checker->method('getUnresolvedReferences')->willReturnCallback(static function () use (&$unresolved): array {
            return $unresolved;
        });

        $this->commandTester->setInputs($inputs);
        $exitCode = $this->commandTester->execute($options);

        self::assertSame($expectedExitCode, $exitCode, 'Only a check that may succeed next time fails the run');
        $display = (string) preg_replace('/\s+/', ' ', $this->commandTester->getDisplay());
        self::assertSame(1, substr_count($display, 'Kept 1 secret(s) whose record link could not be checked'), 'The count is stated once');
        self::assertSame($transient, str_contains($display, 'Exit code 1: the check of 1 kept secret(s) failed on a query or connection error'));
        if ($transient) {
            self::assertStringNotContainsString('[OK]', $display, 'No success banner for a run that exits 1');
        }
    }

    /**
     * A failed delete exits 1 anyway; the secrets the first pass could not
     * check are still named as a reason, or the operator would not learn of
     * them from the result (#565).
     */
    #[Test]
    public function aFailedDeleteStillNamesTheSecretsTheFirstPassCouldNotCheck(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(self::IDENTIFIER_1, time() - 86400 * 30, ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1]),
            $this->createSecretMetadata(self::IDENTIFIER_2, time() - 86400 * 30, ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 2]),
        ]);

        $unresolved = [];
        $calls      = 0;
        $this->checker->method('isOrphaned')->willReturnCallback(static function () use (&$unresolved, &$calls): bool {
            if (++$calls === 1) {
                $unresolved[] = ['identifier' => self::IDENTIFIER_1, 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1, 'reason' => 'could not be resolved: connection lost', 'transient' => true];

                return false;
            }

            return true;
        });
        $this->checker->method('getUnresolvedReferences')->willReturnCallback(static function () use (&$unresolved): array {
            return $unresolved;
        });
        $this->vaultService->method('delete')->willThrowException(new VaultException('Delete failed', 1795000006));

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([]);

        self::assertSame(1, $exitCode);
        $display = (string) preg_replace('/\s+/', ' ', $this->commandTester->getDisplay());
        self::assertStringContainsString('Cleanup completed with 1 errors', $display);
        self::assertStringContainsString('Exit code 1: 1 delete(s) failed, and the check of 1 kept secret(s) failed on a query or connection error', $display, 'Both reasons are named');
    }

    /**
     * The re-check before a delete counts like the first pass: a failure that
     * may clear next time fails the run and is counted in the exit reason; a
     * link that cannot be checked as it stands is kept without failing it
     * (#565).
     *
     * @return iterable<string, array{bool, int}>
     */
    public static function recheckProvider(): iterable
    {
        yield 'transient' => [true, 1];
        yield 'structural' => [false, 0];
    }

    #[Test]
    #[DataProvider('recheckProvider')]
    public function aFailedRecheckFailsTheRunOnlyForATransientReason(bool $transient, int $expectedExitCode): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(self::IDENTIFIER, time() - 86400 * 30, ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1]),
        ]);

        $unresolved = [];
        $calls      = 0;
        $this->checker->method('isOrphaned')->willReturnCallback(static function () use (&$unresolved, &$calls, $transient): bool {
            if (++$calls === 1) {
                return true;
            }

            $unresolved[] = $transient
                ? ['identifier' => self::IDENTIFIER, 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1, 'reason' => 'could not be resolved: connection lost', 'transient' => true]
                : ['identifier' => self::IDENTIFIER, 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1, 'reason' => 'names an unknown table', 'transient' => false];

            return false;
        });
        $this->checker->method('getUnresolvedReferences')->willReturnCallback(static function () use (&$unresolved): array {
            return $unresolved;
        });
        $this->vaultService->expects(self::never())->method('delete');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([]);

        self::assertSame($expectedExitCode, $exitCode);
        $display = (string) preg_replace('/\s+/', ' ', $this->commandTester->getDisplay());
        self::assertMatchesRegularExpression('/Kept \(could not be checked\)\s*\|?\s*1/', $display);
        self::assertSame($transient, str_contains($display, 'Exit code 1: the check of 1 kept secret(s)'));
    }

    #[Test]
    public function handlesDeleteFailures(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->mockRecordDoesNotExist();

        $this->vaultService
            ->method('delete')
            ->willThrowException(new VaultException('Delete failed'));

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('error', strtolower($this->commandTester->getDisplay()));
    }

    #[Test]
    public function cancelsWhenNotConfirmed(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->mockRecordDoesNotExist();

        $this->vaultService->expects($this->never())->method('delete');

        $this->commandTester->setInputs(['no']);
        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('cancelled', $this->commandTester->getDisplay());
    }

    #[Test]
    public function handlesMigrationSourceSecrets(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'migration', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->mockRecordDoesNotExist();

        $exitCode = $this->commandTester->execute([
            '--dry-run' => true,
        ]);

        self::assertSame(0, $exitCode);
        // Migration source should also be checked for orphans
        self::assertStringContainsString('orphan', strtolower($this->commandTester->getDisplay()));
    }

    // =========================================================================
    // Strict boundary tests for retention-days, batch-size and mode strings.
    // =========================================================================

    #[Test]
    public function hasExactCommandName(): void
    {
        $command = new VaultCleanupOrphansCommand(
            $this->vaultService,
            $this->checker,
        );

        self::assertSame('vault:cleanup-orphans', $command->getName());
    }

    #[Test]
    public function hasExactCommandDescription(): void
    {
        $command = new VaultCleanupOrphansCommand(
            $this->vaultService,
            $this->checker,
        );

        self::assertSame('Clean up orphaned vault secrets from deleted TCA records', $command->getDescription());
    }

    #[Test]
    public function hasDryRunOptionWithCorrectDefaults(): void
    {
        $command = new VaultCleanupOrphansCommand(
            $this->vaultService,
            $this->checker,
        );

        $definition = $command->getDefinition();
        self::assertTrue($definition->hasOption('dry-run'));
        self::assertFalse($definition->getOption('dry-run')->acceptValue());
    }

    #[Test]
    public function hasRetentionDaysOptionDefaultZero(): void
    {
        $command = new VaultCleanupOrphansCommand(
            $this->vaultService,
            $this->checker,
        );

        $definition = $command->getDefinition();
        self::assertTrue($definition->hasOption('retention-days'));
        // Kills IncrementInteger/DecrementInteger on default value 0.
        self::assertSame(0, $definition->getOption('retention-days')->getDefault());
    }

    #[Test]
    public function hasBatchSizeOptionDefaultExactly100(): void
    {
        $command = new VaultCleanupOrphansCommand(
            $this->vaultService,
            $this->checker,
        );

        $definition = $command->getDefinition();
        self::assertTrue($definition->hasOption('batch-size'));
        // Kills IncrementInteger/DecrementInteger on default value 100.
        self::assertSame(100, $definition->getOption('batch-size')->getDefault());
    }

    #[Test]
    public function displaysLiveModeWhenDryRunIsFalse(): void
    {
        $this->vaultService->method('list')->willReturn([]);

        $this->commandTester->execute([]);

        // Kills Ternary mutation that swaps 'Dry Run' and 'Live' strings.
        self::assertStringContainsString('Mode: Live', $this->commandTester->getDisplay());
        self::assertStringNotContainsString('Mode: Dry Run', $this->commandTester->getDisplay());
    }

    #[Test]
    public function displaysDryRunModeWhenDryRunIsTrue(): void
    {
        $this->vaultService->method('list')->willReturn([]);

        $this->commandTester->execute(['--dry-run' => true]);

        // Kills Ternary mutation on the dry-run mode string.
        self::assertStringContainsString('Mode: Dry Run', $this->commandTester->getDisplay());
        self::assertStringNotContainsString('Mode: Live', $this->commandTester->getDisplay());
    }

    #[Test]
    public function displaysExactRetentionDaysValueInHeader(): void
    {
        $this->vaultService->method('list')->willReturn([]);

        $this->commandTester->execute(['--retention-days' => 7]);

        // Kill IncrementInteger/DecrementInteger mutations on the retention value —
        // exact "7 days" must appear in the output.
        self::assertStringContainsString('Retention: 7 days', $this->commandTester->getDisplay());
    }

    #[Test]
    public function displaysZeroRetentionDaysWhenNotSpecified(): void
    {
        $this->vaultService->method('list')->willReturn([]);

        $this->commandTester->execute([]);

        // Kill default-value mutations — must display "0 days".
        self::assertStringContainsString('Retention: 0 days', $this->commandTester->getDisplay());
    }

    #[Test]
    public function displaysTableFilterInHeaderWhenSpecified(): void
    {
        $this->vaultService->method('list')->willReturn([]);

        $this->commandTester->execute(['--table' => 'tt_content']);

        // Kill Ternary mutation on the table filter line.
        self::assertStringContainsString('Table filter: tt_content', $this->commandTester->getDisplay());
    }

    #[Test]
    public function omitsTableFilterLineWhenNotSpecified(): void
    {
        $this->vaultService->method('list')->willReturn([]);

        $this->commandTester->execute([]);

        self::assertStringNotContainsString('Table filter:', $this->commandTester->getDisplay());
    }

    #[Test]
    public function returnsSuccessExitCodeZeroWhenNoSecrets(): void
    {
        $this->vaultService->method('list')->willReturn([]);

        $exitCode = $this->commandTester->execute([]);

        // Kills IncrementInteger on Command::SUCCESS (=0).
        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function returnsSuccessExitCodeWhenNoOrphansFound(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordExists(true);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString(self::MSG_NO_ORPHANS, $this->commandTester->getDisplay());
    }

    #[Test]
    public function returnsFailureExitCodeOneWhenDeleteFails(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        $this->vaultService
            ->method('delete')
            ->willThrowException(new VaultException('fail'));

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([]);

        // Kills Increment/Decrement on Command::FAILURE (=1).
        self::assertSame(1, $exitCode);
    }

    /**
     * Kills GreaterThan mutation: `$retentionDays > 0` vs `>= 0`.
     * With retention-days=0, a secret created at time() - 1 (just now) is still
     * included as orphan because retentionCutoff = PHP_INT_MAX.
     *
     * @return iterable<string, array{int, int, int}>
     */
    public static function retentionCutoffProvider(): iterable
    {
        // createdAt = now - (days*86400) seconds
        yield 'no retention (days=0) still keeps a secret younger than the minimum age' => [0, 0, 0];
        yield 'retention=1 keeps 0-day-old orphan' => [1, 0, 0];
        yield 'retention=1 removes 2-day-old orphan' => [1, 2, 1];
        yield 'retention=7 keeps 5-day-old orphan' => [7, 5, 0];
        yield 'retention=7 removes 10-day-old orphan' => [7, 10, 1];
        yield 'retention=30 removes 90-day-old orphan' => [30, 90, 1];
    }

    /**
     * Kills DecrementInteger (86400 -> 86399) and IncrementInteger (86400 -> 86401)
     * on retention-days-to-seconds conversion, and the `> 0` boundary.
     */
    #[Test]
    #[DataProvider('retentionCutoffProvider')]
    public function retentionCutoffEnforcesExactBoundary(int $retentionDays, int $ageDays, int $expectedOrphanCount): void
    {
        $createdAt = $ageDays === 0 ? time() : time() - ($ageDays * 86400);

        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                $createdAt,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);

        $this->mockRecordDoesNotExist();

        $this->commandTester->execute([
            '--dry-run'        => true,
            '--retention-days' => $retentionDays,
        ]);

        $display = $this->commandTester->getDisplay();

        if ($expectedOrphanCount === 0) {
            self::assertStringContainsString(self::MSG_NO_ORPHANS, $display);
        } else {
            self::assertStringContainsString(
                sprintf('Found %d orphaned secrets', $expectedOrphanCount),
                $display,
            );
        }
    }

    /**
     * Kills Ternary mutation on `tcaSources = [...]` array membership check.
     *
     * @return iterable<string, array{string, bool}>
     */
    public static function tcaSourceProvider(): iterable
    {
        yield 'tca_field' => ['tca_field', true];
        yield 'flexform_field' => ['flexform_field', true];
        yield 'record_copy' => ['record_copy', true];
        yield 'flexform_record_copy' => ['flexform_record_copy', true];
        yield 'migration' => ['migration', true];
        yield 'manual' => ['manual', false];
        yield 'api' => ['api', false];
        yield 'empty string' => ['', false];
        yield 'unknown source' => ['some_unknown_src', false];
    }

    #[Test]
    #[DataProvider('tcaSourceProvider')]
    public function onlyExactTcaSourcesAreConsidered(string $source, bool $expectProcessed): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => $source, 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        $this->commandTester->execute(['--dry-run' => true]);

        $display = $this->commandTester->getDisplay();

        if ($expectProcessed) {
            self::assertStringContainsString('Found 1 TCA-sourced', $display);
        } else {
            self::assertStringContainsString(self::MSG_NO_TCA_SECRETS, $display);
        }
    }

    /**
     * Kill Coalesce mutation on `$metadata['table'] ?? ''` — without table
     * metadata the secret is skipped even when the record is gone.
     */
    #[Test]
    public function secretsWithoutTableMetadataAreSkipped(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'uid' => 1], // no 'table' key
            ),
        ]);

        $this->vaultService->expects(self::never())->method('delete');

        $this->commandTester->setInputs(['yes']);
        $this->commandTester->execute([]);

        // A secret without a usable link is no cleanup candidate at all.
        self::assertStringContainsString(self::MSG_NO_TCA_SECRETS, $this->commandTester->getDisplay());
    }

    /**
     * Kill Coalesce mutation on `$metadata['uid'] ?? 0` — uid=0 means skip.
     */
    #[Test]
    public function secretsWithZeroUidMetadataAreSkipped(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 0],
            ),
        ]);

        $this->vaultService->expects(self::never())->method('delete');

        $this->commandTester->setInputs(['yes']);
        $this->commandTester->execute([]);

        // A secret without a usable link is no cleanup candidate at all.
        self::assertStringContainsString(self::MSG_NO_TCA_SECRETS, $this->commandTester->getDisplay());
    }

    /**
     * Kill Coalesce mutation on `flexField` fallback.
     */
    #[Test]
    public function secretsUseFlexFieldFallbackWhenFieldIsMissing(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'flexform_field', 'table' => 'tt_content', 'flexField' => 'pi_flexform', 'uid' => 1],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        $this->commandTester->execute(['--dry-run' => true]);

        $display = $this->commandTester->getDisplay();

        // flexField fallback must surface in the dry-run table.
        self::assertStringContainsString('pi_flexform', $display);
    }

    /**
     * Kill ArrayItemRemoval on the orphan row — uses the exact identifier in output.
     */
    #[Test]
    public function dryRunListsExactIdentifierForOrphan(): void
    {
        $uuid = self::IDENTIFIER;
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                $uuid,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        $this->commandTester->execute(['--dry-run' => true]);

        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString($uuid, $display);
        self::assertStringContainsString('tx_myext', $display);
        self::assertStringContainsString('key', $display);
    }

    /**
     * Kill ConcatOperandRemoval on the error-format string.
     */
    #[Test]
    public function deleteFailureErrorContainsIdentifierAndMessage(): void
    {
        $uuid = self::IDENTIFIER;
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                $uuid,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        $this->vaultService
            ->method('delete')
            ->willThrowException(new VaultException('Something broke'));

        $this->commandTester->setInputs(['yes']);
        $this->commandTester->execute([]);

        $display = $this->commandTester->getDisplay();

        // Kill ConcatOperandRemoval: format is "$identifier: $message".
        self::assertStringContainsString($uuid, $display);
        self::assertStringContainsString('Something broke', $display);
    }

    /**
     * Kill MethodCallRemoval on $vaultService->delete() — MUST be called with
     * exactly the 'Orphan cleanup' reason string.
     */
    #[Test]
    public function deletePassesOrphanCleanupReasonExactly(): void
    {
        $uuid = self::IDENTIFIER;
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                $uuid,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        $this->vaultService
            ->expects(self::once())
            ->method('delete')
            ->with($uuid, 'Orphan cleanup');

        $this->commandTester->setInputs(['yes']);
        $this->commandTester->execute([]);
    }

    /**
     * Kills the batch-size=0 edge case. When batch-size is set to 0, the
     * command uses a fallback of 100 (the default). Passing a positive value
     * must use the given value exactly.
     *
     * @return iterable<string, array{int}>
     */
    public static function validBatchSizeProvider(): iterable
    {
        yield 'batch=1' => [1];
        yield 'batch=50' => [50];
        yield 'batch=99' => [99];
        yield 'batch=100' => [100];
        yield 'batch=101' => [101];
        yield 'batch=500' => [500];
    }

    #[Test]
    #[DataProvider('validBatchSizeProvider')]
    public function acceptsValidBatchSize(int $batchSize): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        $exitCode = $this->commandTester->execute([
            '--dry-run'    => true,
            '--batch-size' => $batchSize,
        ]);

        self::assertSame(0, $exitCode);
    }

    /**
     * Kill GreaterThan mutation on effective-batch-size: `> 0` vs `>= 0`.
     * Zero and negative values must fall back to 100 — still process correctly.
     */
    #[Test]
    public function batchSizeZeroUsesDefault(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        $exitCode = $this->commandTester->execute([
            '--dry-run'    => true,
            '--batch-size' => 0,
        ]);

        self::assertSame(0, $exitCode);
        // With a single secret and fallback batch size, the orphan is found.
        self::assertStringContainsString('Found 1 orphaned', $this->commandTester->getDisplay());
    }

    /**
     * Kill Ternary mutation that swaps dry-run action — dry-run must NEVER call delete().
     */
    #[Test]
    public function dryRunNeverCallsDelete(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        $this->vaultService->expects(self::never())->method('delete');

        $this->commandTester->execute(['--dry-run' => true]);
    }

    /**
     * Kill ArrayItem mutation — summary counters must display exact numbers.
     */
    #[Test]
    public function summaryShowsExactDeletedAndFailedCountsOnMixedOutcome(): void
    {
        $uuid1 = self::IDENTIFIER_1;
        $uuid2 = self::IDENTIFIER_2;

        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                $uuid1,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
            $this->createSecretMetadata(
                $uuid2,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 2],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        $calls = 0;
        $this->vaultService
            ->method('delete')
            ->willReturnCallback(static function () use (&$calls): void {
                ++$calls;
                if ($calls === 2) {
                    throw new VaultException('fail', 3285362926);
                }
            });

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([]);

        // Kill Increment/Decrement on FAILURE code.
        self::assertSame(1, $exitCode);

        $display = $this->commandTester->getDisplay();

        // Summary should show "Orphans found" = 2, "Successfully deleted" = 1, "Failed" = 1.
        self::assertMatchesRegularExpression('/Orphans found\s*:?\s*2/', $display);
        self::assertMatchesRegularExpression('/Successfully deleted\s*:?\s*1/', $display);
        self::assertMatchesRegularExpression('/Failed\s*:?\s*1/', $display);
    }

    /**
     * Kill Ternary mutation on dry-run branch selection.
     */
    #[Test]
    public function liveModeDisplaysSuccessMessageAfterDeletion(): void
    {
        $uuid = self::IDENTIFIER;
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                $uuid,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        // Kill ConcatOperandRemoval on 'Successfully deleted %d orphaned secrets'.
        self::assertStringContainsString('Successfully deleted 1 orphaned secrets', $this->commandTester->getDisplay());
    }

    /**
     * Kill MethodCallRemoval on line 90 — $io->title('Vault Orphan Cleanup') is called.
     */
    #[Test]
    public function displaysTitleOnExecution(): void
    {
        $this->vaultService->method('list')->willReturn([]);

        $this->commandTester->execute([]);

        // Kill MethodCallRemoval — title must appear in output.
        self::assertStringContainsString('Vault Orphan Cleanup', $this->commandTester->getDisplay());
    }

    /**
     * Kill ConcatOperandRemoval in mode-header string: 'Mode: Dry Run' or 'Mode: Live'.
     */
    #[Test]
    public function displaysDryRunModeHeader(): void
    {
        $this->vaultService->method('list')->willReturn([]);

        $this->commandTester->execute(['--dry-run' => true]);

        // Kills Ternary branch + ConcatOperandRemoval on the 'Mode: %s' format.
        self::assertStringContainsString('Dry Run', $this->commandTester->getDisplay());
    }

    #[Test]
    public function displaysLiveModeHeader(): void
    {
        $this->vaultService->method('list')->willReturn([]);

        $this->commandTester->execute([]);

        self::assertStringContainsString('Live', $this->commandTester->getDisplay());
    }

    /**
     * Kill ConcatOperandRemoval on 'Retention: %d days' format string.
     */
    #[Test]
    public function displaysRetentionDaysHeader(): void
    {
        $this->vaultService->method('list')->willReturn([]);

        $this->commandTester->execute(['--retention-days' => 42]);

        self::assertStringContainsString('Retention', $this->commandTester->getDisplay());
        self::assertStringContainsString('42', $this->commandTester->getDisplay());
        self::assertStringContainsString('days', $this->commandTester->getDisplay());
    }

    /**
     * Kill MethodCallRemoval on line 110 — 'Checking for orphaned secrets...' is shown.
     */
    #[Test]
    public function displaysCheckingSectionWhenSecretsPresent(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                'secret1',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordExists(true);

        $this->commandTester->execute([]);

        self::assertStringContainsString('Checking for orphaned secrets', $this->commandTester->getDisplay());
    }

    /**
     * Kill LessThan mutation on line 139 — strictly less than cutoff.
     * 30-day-old orphan with retention 7 days must be detected.
     */
    #[Test]
    public function detectsOrphanWhenCreatedAtIsStrictlyBeforeCutoff(): void
    {
        $createdAt = time() - 86400 * 30;  // 30 days old
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                'orphan',
                $createdAt,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['--retention-days' => 7]);

        self::assertSame(0, $exitCode);
        // 1 orphan was found.
        self::assertMatchesRegularExpression('/Orphans found\s*:?\s*1/', $this->commandTester->getDisplay());
    }

    /**
     * Kill IncrementInteger on line 88 — default batch size is 100 (not 101).
     * When invalid batch size is provided, use default 100.
     */
    #[Test]
    public function succeedsWithDefaultBatchSizeForNonNumericInput(): void
    {
        $this->vaultService->method('list')->willReturn([]);
        $exitCode = $this->commandTester->execute(['--batch-size' => 'not-a-number']);

        self::assertSame(0, $exitCode);
    }

    /**
     * Kill IncrementInteger on line 84/88 — non-numeric retention defaults to 0.
     */
    #[Test]
    public function succeedsWithDefaultRetentionForNonNumericInput(): void
    {
        $this->vaultService->method('list')->willReturn([]);
        $this->commandTester->execute(['--retention-days' => 'not-a-number']);

        // Mode line always shown — retention should be 0 when non-numeric.
        self::assertStringContainsString('0 days', $this->commandTester->getDisplay());
    }

    /**
     * Kill ConcatOperandRemoval on 'Found X TCA-sourced secrets to check'.
     */
    #[Test]
    public function displaysCountMessage(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                'secret1',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordExists(true);

        $this->commandTester->execute([]);

        self::assertStringContainsString('Found', $this->commandTester->getDisplay());
        self::assertStringContainsString('TCA-sourced secrets to check', $this->commandTester->getDisplay());
    }

    /**
     * Kill ConcatOperandRemoval on 'Found X orphaned secrets' message.
     */
    #[Test]
    public function displaysOrphansFoundMessage(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                'orphan1',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        $this->commandTester->execute(['--dry-run' => true]);

        self::assertStringContainsString('Found', $this->commandTester->getDisplay());
        self::assertStringContainsString('orphaned secrets', $this->commandTester->getDisplay());
    }

    /**
     * Kill MethodCallRemoval on `$io->section('Deleting orphaned secrets...')`.
     */
    #[Test]
    public function displaysDeletingSectionOnLiveRun(): void
    {
        $uuid = self::IDENTIFIER;
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                $uuid,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        $this->commandTester->setInputs(['yes']);
        $this->commandTester->execute([]);

        self::assertStringContainsString('Deleting orphaned secrets', $this->commandTester->getDisplay());
    }

    /**
     * Kill ConcatOperandRemoval on 'Cleanup cancelled' message.
     */
    #[Test]
    public function displaysCancelledMessageOnNoConfirmation(): void
    {
        $uuid = self::IDENTIFIER;
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                $uuid,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        // User answers 'no'.
        $this->commandTester->setInputs(['no']);
        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Cleanup cancelled', $this->commandTester->getDisplay());
        // delete must NOT be called.
        $this->vaultService->expects(self::never())->method('delete');
    }

    /**
     * Kill MethodCallRemoval on line 167 — dry-run shows 'Orphaned secrets
     * that would be deleted:' section.
     */
    #[Test]
    public function dryRunDisplaysWouldBeDeletedSection(): void
    {
        $uuid = self::IDENTIFIER;
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                $uuid,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordDoesNotExist();

        $this->commandTester->execute(['--dry-run' => true]);

        self::assertStringContainsString('Orphaned secrets that would be deleted', $this->commandTester->getDisplay());
        // delete MUST NOT be called in dry run.
        $this->vaultService->expects(self::never())->method('delete');
    }

    /**
     * The command fails closed like the scheduler task: a table it cannot
     * resolve proves nothing about the record, so the secret stays (#565).
     * Before, the command read "unknown table" as "record gone" and deleted.
     */
    #[Test]
    public function keepsTheSecretWhenTheReferencedTableDoesNotExist(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_dropped', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $schemaManager = $this->createMock(AbstractSchemaManager::class);
        $schemaManager->method('tablesExist')->willReturn(false);
        $connection = $this->createMock(Connection::class);
        $connection->method('createSchemaManager')->willReturn($schemaManager);
        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $this->vaultService->expects(self::never())->method('delete');

        $tester = new CommandTester(new VaultCleanupOrphansCommand($this->vaultService, new OrphanReferenceChecker($this->connectionPool)));
        $tester->setInputs(['yes']);

        $exitCode = $tester->execute([]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString(self::MSG_NO_ORPHANS, $tester->getDisplay());
        self::assertStringContainsString('delete the secret by hand (vault:delete), or restore the table or field', (string) preg_replace('/\s+/', ' ', $tester->getDisplay()));
    }

    /**
     * Another row still holds the identifier: the secret is in use whatever
     * happened to the linked uid (published workspace version, shared
     * translation field, copy).
     */
    #[Test]
    public function keepsTheSecretWhenAnotherRowStillHoldsTheIdentifier(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(
                self::IDENTIFIER,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);
        $this->checker->expects(self::once())->method('isOrphaned')->willReturn(false);
        $this->vaultService->expects(self::never())->method('delete');

        $this->commandTester->setInputs(['yes']);
        $this->commandTester->execute([]);

        self::assertStringContainsString(self::MSG_NO_ORPHANS, $this->commandTester->getDisplay());
    }

    /**
     * Each run starts from a clean checker: caches and unresolved references
     * of an earlier run must not leak into this one.
     */
    #[Test]
    public function eachRunResetsTheChecker(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(self::IDENTIFIER, time() - 86400 * 30, ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1]),
        ]);
        $this->checker->expects(self::exactly(2))->method('reset');

        $this->commandTester->execute(['--dry-run' => true]);
        $this->commandTester->execute(['--dry-run' => true]);
    }

    /**
     * A secret younger than the minimum age is kept even with 0 retention
     * days: its record may not be written yet (#565).
     */
    #[Test]
    public function noRetentionStillKeepsASecretYoungerThanTheMinimumAge(): void
    {
        $this->vaultService->method('list')->willReturn([
            $this->createSecretMetadata(self::IDENTIFIER, time() - 60, ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1]),
        ]);
        $this->mockRecordDoesNotExist();
        $this->checker->expects(self::never())->method('isOrphaned');

        $this->commandTester->execute(['--dry-run' => true, '--retention-days' => 0]);

        self::assertStringContainsString(self::MSG_NO_ORPHANS, $this->commandTester->getDisplay());
    }

    private function mockRecordExists(bool $exists): void
    {
        $this->checker->method('isOrphaned')->willReturn(!$exists);
    }

    private function mockRecordDoesNotExist(): void
    {
        $this->checker->method('isOrphaned')->willReturn(true);
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function createSecretMetadata(
        string $identifier,
        int $createdAt,
        array $metadata = [],
    ): SecretMetadata {
        return new SecretMetadata(
            identifier: $identifier,
            ownerUid: 1,
            createdAt: $createdAt,
            updatedAt: $createdAt,
            readCount: 0,
            lastReadAt: null,
            description: '',
            version: 1,
            metadata: $metadata,
        );
    }
}
