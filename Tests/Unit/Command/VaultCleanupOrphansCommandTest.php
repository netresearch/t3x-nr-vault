<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Doctrine\DBAL\Result;
use Doctrine\DBAL\Schema\AbstractSchemaManager;
use Netresearch\NrVault\Command\VaultCleanupOrphansCommand;
use Netresearch\NrVault\Domain\Dto\SecretMetadata;
use Netresearch\NrVault\Exception\VaultException;
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
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Database\Query\Restriction\QueryRestrictionContainerInterface;

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

    private CommandTester $commandTester;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->connectionPool = $this->createMock(ConnectionPool::class);

        $command = new VaultCleanupOrphansCommand(
            $this->vaultService,
            $this->connectionPool,
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
            $this->connectionPool,
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

        $this->mockRecordExists(1, true);

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

        $this->mockRecordExists(1, false);

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
        $oldOrphan = time() - 86400 * 30;   // 30 days ago

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
            '--dry-run' => true,
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
            '--table' => 'tx_myext',
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
            $this->connectionPool,
        );

        self::assertSame('vault:cleanup-orphans', $command->getName());
    }

    #[Test]
    public function hasExactCommandDescription(): void
    {
        $command = new VaultCleanupOrphansCommand(
            $this->vaultService,
            $this->connectionPool,
        );

        self::assertSame('Clean up orphaned vault secrets from deleted TCA records', $command->getDescription());
    }

    #[Test]
    public function hasDryRunOptionWithCorrectDefaults(): void
    {
        $command = new VaultCleanupOrphansCommand(
            $this->vaultService,
            $this->connectionPool,
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
            $this->connectionPool,
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
            $this->connectionPool,
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
        $this->mockRecordExists(1, true);

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
        yield 'no retention (days=0) — all orphans collected' => [0, 0, 1];
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
            '--dry-run' => true,
            '--retention-days' => $retentionDays,
        ]);

        $display = $this->commandTester->getDisplay();

        if ($expectedOrphanCount === 0) {
            self::assertStringContainsString(self::MSG_NO_ORPHANS, $display);
        } else {
            self::assertStringContainsString(
                \sprintf('Found %d orphaned secrets', $expectedOrphanCount),
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

        self::assertStringContainsString(self::MSG_NO_ORPHANS, $this->commandTester->getDisplay());
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

        self::assertStringContainsString(self::MSG_NO_ORPHANS, $this->commandTester->getDisplay());
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
            '--dry-run' => true,
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
            '--dry-run' => true,
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
                $calls++;
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
        $this->mockRecordExists(1, true);

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
        $this->mockRecordExists(1, true);

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

    private function mockRecordExists(int $uid, bool $exists): void
    {
        $schemaManager = $this->createMock(AbstractSchemaManager::class);
        $schemaManager->method('tablesExist')->willReturn(true);

        $connection = $this->createMock(Connection::class);
        $connection->method('createSchemaManager')->willReturn($schemaManager);

        $this->connectionPool
            ->method('getConnectionByName')
            ->willReturn($connection);

        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn($exists ? 1 : 0);

        $restrictions = $this->createMock(QueryRestrictionContainerInterface::class);

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->method('eq')->willReturn('uid = ' . $uid);

        $queryBuilder = $this->createMock(QueryBuilder::class);
        $queryBuilder->method('count')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('getRestrictions')->willReturn($restrictions);
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder->method('createNamedParameter')->willReturn(':dcValue1');
        $queryBuilder->method('executeQuery')->willReturn($result);

        $this->connectionPool
            ->method('getQueryBuilderForTable')
            ->willReturn($queryBuilder);
    }

    private function mockRecordDoesNotExist(): void
    {
        $schemaManager = $this->createMock(AbstractSchemaManager::class);
        $schemaManager->method('tablesExist')->willReturn(true);

        $connection = $this->createMock(Connection::class);
        $connection->method('createSchemaManager')->willReturn($schemaManager);

        $this->connectionPool
            ->method('getConnectionByName')
            ->willReturn($connection);

        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn(0);

        $restrictions = $this->createMock(QueryRestrictionContainerInterface::class);

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->method('eq')->willReturn('uid = 1');

        $queryBuilder = $this->createMock(QueryBuilder::class);
        $queryBuilder->method('count')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('getRestrictions')->willReturn($restrictions);
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder->method('createNamedParameter')->willReturn(':dcValue1');
        $queryBuilder->method('executeQuery')->willReturn($result);

        $this->connectionPool
            ->method('getQueryBuilderForTable')
            ->willReturn($queryBuilder);
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
