<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Audit\AuditChainRekeyServiceInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\HashChainVerificationResult;
use Netresearch\NrVault\Command\VaultRotateMasterKeyCommand;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Crypto\EnvelopeCodecInterface;
use Netresearch\NrVault\Crypto\EnvelopeRotationContext;
use Netresearch\NrVault\Crypto\ForeignEnvelopeRotatorInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderFactoryInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Crypto\ReEncryptedDek;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Event\MasterKeyRotatedEvent;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Tests\Unit\TestCase;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\EventDispatcher\EventDispatcherInterface;
use RuntimeException;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

#[CoversClass(VaultRotateMasterKeyCommand::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultRotateMasterKeyCommandTest extends TestCase
{
    /** Operator-facing fragments asserted in more than one test. */
    private const OUTPUT_NO_SECRETS = 'No secrets found';

    private const OUTPUT_UNEXPECTED_ERROR = 'Unexpected error';

    private SecretRepositoryInterface&MockObject $secretRepository;

    private EncryptionServiceInterface&MockObject $encryptionService;

    private MasterKeyProviderFactoryInterface&MockObject $masterKeyProviderFactory;

    private ConnectionPool&MockObject $connectionPool;

    private AuditLogServiceInterface&MockObject $auditLogService;

    private AuditChainRekeyServiceInterface&MockObject $auditChainRekeyService;

    private EnvelopeCodecInterface&MockObject $envelopeCodec;

    private AccessControlServiceInterface&MockObject $accessControlService;

    private EventDispatcherInterface&MockObject $eventDispatcher;

    private CommandTester $commandTester;

    protected function setUp(): void
    {
        parent::setUp();

        $this->secretRepository = $this->createMock(SecretRepositoryInterface::class);
        // `save()` now returns Secret (was void). PHPUnit cannot auto-generate
        // a return value for `final readonly` Secret, so install a passthrough
        // default at setUp() so individual tests don't have to repeat it.
        // Per-test `->expects()` overrides still take effect.
        $this->secretRepository
            ->method('save')
            ->willReturnArgument(0);

        $this->encryptionService = $this->createMock(EncryptionServiceInterface::class);
        $this->masterKeyProviderFactory = $this->createMock(MasterKeyProviderFactoryInterface::class);
        $this->connectionPool = $this->createMock(ConnectionPool::class);
        $this->auditLogService = $this->createMock(AuditLogServiceInterface::class);
        // `HashChainVerificationResult` is final and cannot be auto-mocked;
        // default to a valid chain so the pre-rotation verification passes.
        $this->auditLogService
            ->method('verifyHashChain')
            ->willReturn(HashChainVerificationResult::valid());
        $this->auditChainRekeyService = $this->createMock(AuditChainRekeyServiceInterface::class);
        $this->envelopeCodec = $this->createMock(EnvelopeCodecInterface::class);
        $this->accessControlService = $this->createMock(AccessControlServiceInterface::class);
        // The command asserts `master_key.rotate` before doing anything. Grant
        // it by default so the rotation-mechanics tests reach their subject;
        // `refusesRotationWithoutMasterKeyRotatePermission()` withholds it.
        $this->accessControlService
            ->method('isGranted')
            ->willReturn(true);
        $this->eventDispatcher = $this->createMock(EventDispatcherInterface::class);

        $command = $this->createCommand();

        $application = new Application();
        $application->addCommand($command);

        $this->commandTester = new CommandTester($command);
    }

    #[Test]
    public function hasCorrectName(): void
    {
        self::assertSame('vault:rotate-master-key', $this->createCommand()->getName());
    }

    #[Test]
    public function warnsWhenNoSecretsFound(): void
    {
        $this->mockMasterKeyProvider(str_repeat('a', 32));

        $this->secretRepository
            ->method('findIdentifiers')
            ->willReturn([]);

        $exitCode = $this->commandTester->execute([
            '--old-key' => $this->createKeyFile('old', str_repeat('a', 32)),
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString(self::OUTPUT_NO_SECRETS, $this->commandTester->getDisplay());
    }

    #[Test]
    public function failsWhenKeysAreIdentical(): void
    {
        $keyContent = str_repeat('x', 32);

        $exitCode = $this->commandTester->execute([
            '--old-key' => $this->createKeyFile('old', $keyContent),
            '--new-key' => $this->createKeyFile('new', $keyContent),
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('identical', $this->commandTester->getDisplay());
    }

    #[Test]
    public function failsWithoutConfirmOption(): void
    {
        $this->mockMasterKeyProvider(str_repeat('a', 32));

        $this->secretRepository
            ->method('findIdentifiers')
            ->willReturn(['secret-1']);

        $exitCode = $this->commandTester->execute([
            '--old-key' => $this->createKeyFile('old', str_repeat('a', 32)),
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('--confirm', $this->commandTester->getDisplay());
    }

    #[Test]
    public function dryRunShowsNoChanges(): void
    {
        $secret = $this->createTestSecret('test-secret');

        $this->secretRepository
            ->method('findIdentifiers')
            ->willReturn(['test-secret']);

        $this->secretRepository
            ->method('findByIdentifier')
            ->willReturn($secret);

        $this->encryptionService
            ->method('reEncryptDek')
            ->willReturn(new ReEncryptedDek('new-dek', 'new-nonce'));

        $exitCode = $this->commandTester->execute([
            '--old-key' => $this->createKeyFile('old', str_repeat('a', 32)),
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
            '--dry-run' => true,
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('DRY RUN', $display);
        self::assertStringContainsString('Would re-encrypt', $display);
    }

    #[Test]
    public function failsWhenOldKeyFileNotFound(): void
    {
        $exitCode = $this->commandTester->execute([
            '--old-key' => '/nonexistent/key.file',
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('not found', $this->commandTester->getDisplay());
    }

    #[Test]
    public function failsWhenKeyHasInvalidLength(): void
    {
        $exitCode = $this->commandTester->execute([
            '--old-key' => $this->createKeyFile('old', 'short'),
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Invalid master key', $this->commandTester->getDisplay());
    }

    #[Test]
    public function failsWhenDecryptionFails(): void
    {
        $secret = $this->createTestSecret('failing-secret');

        $this->secretRepository
            ->method('findIdentifiers')
            ->willReturn(['failing-secret']);

        $this->secretRepository
            ->method('findByIdentifier')
            ->willReturn($secret);

        $this->encryptionService
            ->method('reEncryptDek')
            ->willThrowException(EncryptionException::decryptionFailed());

        $exitCode = $this->commandTester->execute([
            '--old-key' => $this->createKeyFile('old', str_repeat('a', 32)),
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
            '--confirm' => true,
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Failed to decrypt', $this->commandTester->getDisplay());
    }

    #[Test]
    public function handlesBase64EncodedKeys(): void
    {
        $rawKey = str_repeat('k', 32);
        $base64Key = base64_encode($rawKey);

        $secret = $this->createTestSecret('b64-secret');

        $this->secretRepository
            ->method('findIdentifiers')
            ->willReturn(['b64-secret']);

        $this->secretRepository
            ->method('findByIdentifier')
            ->willReturn($secret);

        $this->encryptionService
            ->method('reEncryptDek')
            ->willReturn(new ReEncryptedDek('new-dek', 'new-nonce'));

        // Base64 keys should work
        $exitCode = $this->commandTester->execute([
            '--old-key' => $this->createKeyFile('old', $base64Key),
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
            '--dry-run' => true,
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function failsWhenFirstSecretNotFound(): void
    {
        $this->secretRepository
            ->method('findIdentifiers')
            ->willReturn(['nonexistent-secret']);

        $this->secretRepository
            ->method('findByIdentifier')
            ->willReturn(null);

        $exitCode = $this->commandTester->execute([
            '--old-key' => $this->createKeyFile('old', str_repeat('a', 32)),
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
            '--confirm' => true,
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Failed to load first secret', $this->commandTester->getDisplay());
    }

    #[Test]
    public function usesDefaultKeyWhenOldKeyNotProvided(): void
    {
        $this->mockMasterKeyProvider(str_repeat('d', 32));

        $this->secretRepository
            ->method('findIdentifiers')
            ->willReturn([]);

        $exitCode = $this->commandTester->execute([
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
        ]);

        // Success (no secrets) means the default key was used
        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function usesDefaultKeyWhenNewKeyNotProvided(): void
    {
        $this->mockMasterKeyProvider(str_repeat('d', 32));

        $this->secretRepository
            ->method('findIdentifiers')
            ->willReturn([]);

        $exitCode = $this->commandTester->execute([
            '--old-key' => $this->createKeyFile('old', str_repeat('a', 32)),
        ]);

        // Success (no secrets) means the default key was used
        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function successfulRotationWithConfirm(): void
    {
        $secret = $this->createTestSecret('test-secret');

        $this->secretRepository
            ->method('findIdentifiers')
            ->willReturn(['test-secret']);

        $this->secretRepository
            ->method('findByIdentifier')
            ->willReturn($secret);

        $this->encryptionService
            ->method('reEncryptDek')
            ->willReturn(new ReEncryptedDek('new-encrypted-dek', 'new-nonce'));

        // Success path: outer transaction + the audit-lock savepoint around
        // the chain re-key → two begins, two commits, no rollback. The
        // (non-SQLite) advisory lock acquire issues `SELECT GET_LOCK(...)`
        // which must yield 1.
        $lockResult = $this->createStub(Result::class);
        $lockResult->method('fetchOne')->willReturn(1);

        $connection = $this->createMock(Connection::class);
        $connection->expects(self::exactly(2))->method('beginTransaction');
        $connection->expects(self::exactly(2))->method('commit');
        $connection->expects(self::never())->method('rollBack');
        $connection->method('executeQuery')->willReturn($lockResult);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        // The audit chain MUST be re-keyed in the same operation.
        $this->auditChainRekeyService
            ->expects(self::once())
            ->method('rekeyChain')
            ->with($connection, self::isString())
            ->willReturn(3);

        // `withReEncryptedDek()` returns a NEW Secret instance, so the
        // saved entity is a different object from `$secret`. Match on the
        // re-encrypted DEK envelope instead of object identity.
        $this->secretRepository
            ->expects(self::once())
            ->method('save')
            ->with(self::callback(static fn (Secret $s): bool => $s->getIdentifier() === 'test-secret'
                && $s->getEncryptedDek() === 'new-encrypted-dek'
                && $s->getDekNonce() === 'new-nonce'))
            ->willReturnArgument(0);

        $exitCode = $this->commandTester->execute([
            '--old-key' => $this->createKeyFile('old', str_repeat('a', 32)),
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
            '--confirm' => true,
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Successfully rotated', $this->commandTester->getDisplay());
        self::assertStringContainsString('Audit chain re-keyed', $this->commandTester->getDisplay());
    }

    #[Test]
    public function refusesRotationWhenAuditChainVerificationFails(): void
    {
        $secret = $this->createTestSecret('test-secret');

        $this->secretRepository
            ->method('findIdentifiers')
            ->willReturn(['test-secret']);

        $this->secretRepository
            ->method('findByIdentifier')
            ->willReturn($secret);

        $this->encryptionService
            ->method('reEncryptDek')
            ->willReturn(new ReEncryptedDek('new', 'n'));

        // Re-build the command with an INVALID chain verification result:
        // re-keying a tampered chain would launder the tampering, so the
        // rotation must refuse before any state change.
        $auditLogService = $this->createMock(AuditLogServiceInterface::class);
        $auditLogService
            ->method('verifyHashChain')
            ->willReturn(HashChainVerificationResult::invalid([5 => 'Entry hash mismatch - possible tampering']));

        $connection = $this->createMock(Connection::class);
        $connection->expects(self::never())->method('beginTransaction');
        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        $this->auditChainRekeyService
            ->expects(self::never())
            ->method('rekeyChain');

        $commandTester = new CommandTester($this->createCommand($auditLogService));

        $exitCode = $commandTester->execute([
            '--old-key' => $this->createKeyFile('old', str_repeat('a', 32)),
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
            '--confirm' => true,
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('verification FAILED', $commandTester->getDisplay());
    }

    #[Test]
    public function rollsBackOnPartialFailure(): void
    {
        $secret1 = $this->createTestSecret('secret-1');
        $secret2 = $this->createTestSecret('secret-2');

        $this->secretRepository
            ->method('findIdentifiers')
            ->willReturn(['secret-1', 'secret-2']);

        $this->secretRepository
            ->method('findByIdentifier')
            ->willReturnCallback(static fn (string $id): Secret => $id === 'secret-1' ? $secret1 : $secret2);

        $callCount = 0;
        $this->encryptionService
            ->method('reEncryptDek')
            ->willReturnCallback(static function () use (&$callCount): ReEncryptedDek {
                ++$callCount;
                if ($callCount === 1) {
                    // First call (verification) succeeds
                    return new ReEncryptedDek('new', 'n');
                }

                if ($callCount === 2) {
                    // Second call succeeds
                    return new ReEncryptedDek('new', 'n');
                }

                // Third call (secret-2) fails
                throw EncryptionException::decryptionFailed();
            });

        $connection = $this->createMock(Connection::class);
        $connection->expects(self::once())->method('beginTransaction');
        $connection->expects(self::once())->method('rollBack');
        $connection->expects(self::never())->method('commit');

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        $exitCode = $this->commandTester->execute([
            '--old-key' => $this->createKeyFile('old', str_repeat('a', 32)),
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
            '--confirm' => true,
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('rolled back', $this->commandTester->getDisplay());
    }

    #[Test]
    public function skipsSecretNotFoundDuringRotation(): void
    {
        $secret = $this->createTestSecret('existing-secret');

        $this->secretRepository
            ->method('findIdentifiers')
            ->willReturn(['existing-secret', 'missing-secret']);

        $callCount = 0;
        $this->secretRepository
            ->method('findByIdentifier')
            ->willReturnCallback(function (string $id) use ($secret, &$callCount): ?Secret {
                ++$callCount;
                // Return secret for verification
                if ($callCount <= 2 && $id === 'existing-secret') {
                    return $secret;
                }

                // Return null for missing-secret
                return $id === 'existing-secret' ? $secret : null;
            });

        $this->encryptionService
            ->method('reEncryptDek')
            ->willReturn(new ReEncryptedDek('new', 'n'));

        $connection = $this->createMock(Connection::class);
        $connection->expects(self::once())->method('beginTransaction');
        $connection->expects(self::once())->method('rollBack');

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        $exitCode = $this->commandTester->execute([
            '--old-key' => $this->createKeyFile('old', str_repeat('a', 32)),
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
            '--confirm' => true,
        ]);

        // Fails because of 'Not found' error
        self::assertSame(1, $exitCode);
    }

    #[Test]
    public function handlesKeyWithTrailingNewline(): void
    {
        $rawKey = str_repeat('t', 32);
        $keyWithNewline = $rawKey . "\n";

        $secret = $this->createTestSecret('test-secret');

        $this->secretRepository
            ->method('findIdentifiers')
            ->willReturn(['test-secret']);

        $this->secretRepository
            ->method('findByIdentifier')
            ->willReturn($secret);

        $this->encryptionService
            ->method('reEncryptDek')
            ->willReturn(new ReEncryptedDek('new-dek', 'new-nonce'));

        // Key with trailing newline should be trimmed
        $exitCode = $this->commandTester->execute([
            '--old-key' => $this->createKeyFile('old', $keyWithNewline),
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
            '--dry-run' => true,
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function rollsBackOnUnexpectedThrowableDuringRotation(): void
    {
        $secret = $this->createTestSecret('test-secret');

        $this->secretRepository
            ->method('findIdentifiers')
            ->willReturn(['test-secret']);

        $callCount = 0;
        $this->secretRepository
            ->method('findByIdentifier')
            ->willReturn($secret);

        $this->encryptionService
            ->method('reEncryptDek')
            ->willReturnCallback(static function () use (&$callCount): ReEncryptedDek {
                ++$callCount;
                if ($callCount === 1) {
                    // Verification call — succeeds
                    return new ReEncryptedDek('new', 'n');
                }

                // Actual rotation — unexpected exception
                throw new RuntimeException('Unexpected error', 6436183956);
            });

        $connection = $this->createMock(Connection::class);
        $connection->expects(self::once())->method('beginTransaction');
        $connection->expects(self::once())->method('rollBack');
        $connection->expects(self::never())->method('commit');

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);

        $exitCode = $this->commandTester->execute([
            '--old-key' => $this->createKeyFile('old', str_repeat('a', 32)),
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
            '--confirm' => true,
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString(self::OUTPUT_UNEXPECTED_ERROR, $this->commandTester->getDisplay());
    }

    // ---------------------------------------------------------------------
    // Consumer-owned envelope rotation (ADR-033)
    //
    // Before this, `seal()`-ing a payload in another extension produced data
    // that silently became undecryptable at the next master-key rotation:
    // rotation walked tx_nrvault_secret only, and MasterKeyRotatedEvent was
    // declared and documented but never dispatched.
    // ---------------------------------------------------------------------

    #[Test]
    public function aRegisteredConsumerHasItsEnvelopesRewrappedAndReported(): void
    {
        $this->givenOneRotatableSecret();
        $rotator = $this->createRotator(envelopes: 7);
        $rotator->expects(self::once())->method('rewrapAll')->with(
            self::isInstanceOf(EnvelopeRotationContext::class),
        )->willReturn(7);

        $tester = new CommandTester($this->createCommand(foreignRotators: [$rotator]));
        $exitCode = $tester->execute($this->rotationInput());

        self::assertSame(0, $exitCode);
        $display = $tester->getDisplay();
        self::assertStringContainsString('nr-test: sealed payloads: 7 envelope(s)', $display);
        self::assertStringContainsString('re-wrapped 7 envelope(s)', $display);
        self::assertStringContainsString('Consumer-owned envelopes re-wrapped: 7.', $display);
    }

    /**
     * A consumer failure must take the vault's own secrets down with it: half a
     * rotation leaves data wrapped under a key that will not be kept.
     */
    #[Test]
    public function aConsumerFailureRollsTheWholeRotationBack(): void
    {
        $this->givenOneRotatableSecret(expectRollback: true);

        $rotator = $this->createRotator(envelopes: 3);
        $rotator->method('rewrapAll')->willThrowException(new RuntimeException('consumer exploded'));

        $this->auditChainRekeyService->expects(self::never())->method('rekeyChain');
        $this->eventDispatcher->expects(self::never())->method('dispatch');

        $tester = new CommandTester($this->createCommand(foreignRotators: [$rotator]));
        $exitCode = $tester->execute($this->rotationInput());

        self::assertSame(1, $exitCode);
        self::assertStringContainsString(self::OUTPUT_UNEXPECTED_ERROR, $tester->getDisplay());
    }

    /**
     * A vault holding no secrets of its own may still be the key authority for a
     * consumer's envelopes, so it must not shortcut to "nothing to do".
     */
    #[Test]
    public function rotationProceedsWhenOnlyAConsumerHoldsEnvelopes(): void
    {
        $this->secretRepository->method('findIdentifiers')->willReturn([]);

        $lockResult = $this->createStub(Result::class);
        $lockResult->method('fetchOne')->willReturn(1);
        $connection = $this->createMock(Connection::class);
        $connection->expects(self::never())->method('rollBack');
        $connection->method('executeQuery')->willReturn($lockResult);
        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);
        $this->auditChainRekeyService->method('rekeyChain')->willReturn(0);

        $rotator = $this->createRotator(envelopes: 4);
        $rotator->expects(self::once())->method('rewrapAll')->willReturn(4);

        $tester = new CommandTester($this->createCommand(foreignRotators: [$rotator]));
        $exitCode = $tester->execute($this->rotationInput());

        self::assertSame(0, $exitCode);
        $display = $tester->getDisplay();
        self::assertStringNotContainsString(self::OUTPUT_NO_SECRETS, $display);
        // With no vault secret to smoke-test against, the operator is told the
        // old key could not be verified up front rather than being left to guess.
        self::assertStringContainsString('smoke-tested', $display);
        self::assertStringContainsString('Consumer-owned envelopes re-wrapped: 4.', $display);
    }

    #[Test]
    public function nothingAnywhereStillReportsNothingToDo(): void
    {
        $this->secretRepository->method('findIdentifiers')->willReturn([]);

        $tester = new CommandTester($this->createCommand(foreignRotators: [
            $this->createRotator(envelopes: 0),
        ]));
        $exitCode = $tester->execute($this->rotationInput());

        self::assertSame(0, $exitCode);
        self::assertStringContainsString(self::OUTPUT_NO_SECRETS, $tester->getDisplay());
    }

    #[Test]
    public function dryRunCountsConsumerEnvelopesWithoutRewrappingThem(): void
    {
        $this->secretRepository->method('findIdentifiers')->willReturn(['test-secret']);
        $this->secretRepository->method('findByIdentifier')->willReturn($this->createTestSecret('test-secret'));
        $this->encryptionService->method('reEncryptDek')->willReturn(new ReEncryptedDek('dek', 'nonce'));

        $rotator = $this->createRotator(envelopes: 12);
        $rotator->expects(self::never())->method('rewrapAll');

        $tester = new CommandTester($this->createCommand(foreignRotators: [$rotator]));
        $exitCode = $tester->execute([
            '--old-key' => $this->createKeyFile('old', str_repeat('a', 32)),
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
            '--dry-run' => true,
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Would re-wrap 12 consumer-owned envelope(s).', $tester->getDisplay());
    }

    /**
     * "One transaction" is a fiction across two database connections, so the
     * command refuses rather than risk committing half a rotation. Mirrors the
     * pre-existing precondition on the audit-log table.
     */
    #[Test]
    public function rotationIsRefusedWhenAConsumerTableIsOnAnotherConnection(): void
    {
        $this->secretRepository->method('findIdentifiers')->willReturn(['test-secret']);
        $this->secretRepository->method('findByIdentifier')->willReturn($this->createTestSecret('test-secret'));
        $this->encryptionService->method('reEncryptDek')->willReturn(new ReEncryptedDek('dek', 'nonce'));

        $vaultConnection = $this->createMock(Connection::class);
        $vaultConnection->expects(self::never())->method('beginTransaction');
        $otherConnection = $this->createMock(Connection::class);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturnCallback(static fn (string $table): Connection => $table === 'tx_nrtest_payload'
                ? $otherConnection
                : $vaultConnection);

        $rotator = $this->createRotator(envelopes: 1);
        $rotator->expects(self::never())->method('rewrapAll');

        $tester = new CommandTester($this->createCommand(foreignRotators: [$rotator]));
        $exitCode = $tester->execute($this->rotationInput());

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('tx_nrtest_payload', $tester->getDisplay());
    }

    /**
     * Not knowing what a rotation is about to touch is a reason to refuse it.
     */
    #[Test]
    public function rotationIsRefusedWhenAConsumerCannotBeInventoried(): void
    {
        $this->secretRepository->method('findIdentifiers')->willReturn(['test-secret']);

        $rotator = $this->createMock(ForeignEnvelopeRotatorInterface::class);
        $rotator->method('getIdentifier')->willReturn('nr-test: sealed payloads');
        $rotator->method('countEnvelopes')->willThrowException(new RuntimeException('table missing'));
        $rotator->expects(self::never())->method('rewrapAll');

        $tester = new CommandTester($this->createCommand(foreignRotators: [$rotator]));
        $exitCode = $tester->execute($this->rotationInput());

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('inventory', $tester->getDisplay());
    }

    #[Test]
    public function theRotatedEventIsDispatchedAfterCommitWithBothCounts(): void
    {
        $this->givenOneRotatableSecret();
        $this->accessControlService->method('getCurrentActorUid')->willReturn(42);

        $rotator = $this->createRotator(envelopes: 5, rewrapped: 5);

        $dispatched = null;
        $this->eventDispatcher
            ->expects(self::once())
            ->method('dispatch')
            ->willReturnCallback(static function (object $event) use (&$dispatched): object {
                $dispatched = $event;

                return $event;
            });

        $tester = new CommandTester($this->createCommand(foreignRotators: [$rotator]));

        self::assertSame(0, $tester->execute($this->rotationInput()));
        self::assertInstanceOf(MasterKeyRotatedEvent::class, $dispatched);
        self::assertSame(1, $dispatched->getSecretsReEncrypted());
        self::assertSame(5, $dispatched->getForeignEnvelopesReEncrypted());
        self::assertSame(42, $dispatched->getActorUid());
    }

    #[Test]
    public function withoutAnyRegisteredRotatorTheOperatorIsToldSo(): void
    {
        $this->givenOneRotatableSecret();

        $tester = new CommandTester($this->createCommand());

        self::assertSame(0, $tester->execute($this->rotationInput()));
        self::assertStringContainsString('No consumer-owned envelope rotators registered', $tester->getDisplay());
    }

    /**
     * A rotator that re-wraps FEWER envelopes than it inventoried must not
     * commit. Committing would print success and then send the operator to
     * "securely archive or destroy the old master key", which makes the missed
     * envelopes permanently unreadable — the exact silent loss this seam exists
     * to prevent.
     */
    #[Test]
    public function aShortfallAgainstTheInventoryRollsTheRotationBack(): void
    {
        $this->givenOneRotatableSecret(expectRollback: true);

        $rotator = $this->createRotator(envelopes: 10);
        $rotator->method('rewrapAll')->willReturn(7);

        $this->auditChainRekeyService->expects(self::never())->method('rekeyChain');
        $this->eventDispatcher->expects(self::never())->method('dispatch');

        $tester = new CommandTester($this->createCommand(foreignRotators: [$rotator]));
        $exitCode = $tester->execute($this->rotationInput());

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('inventoried 10', $tester->getDisplay());
    }

    #[Test]
    public function moreEnvelopesThanInventoriedIsNotTreatedAsAFailure(): void
    {
        // Rows added between the inventory and the transaction are benign.
        $this->givenOneRotatableSecret();

        $rotator = $this->createRotator(envelopes: 3);
        $rotator->method('rewrapAll')->willReturn(5);

        $tester = new CommandTester($this->createCommand(foreignRotators: [$rotator]));

        self::assertSame(0, $tester->execute($this->rotationInput()));
    }

    /**
     * The rotation has already committed when the event fires, so a listener that
     * throws must not be able to swallow the operator instructions — without them
     * the installation sits with every secret wrapped under a key the
     * configuration does not yet reference.
     */
    #[Test]
    public function aThrowingListenerCannotSuppressThePostRotationInstructions(): void
    {
        $this->givenOneRotatableSecret();
        $this->eventDispatcher
            ->method('dispatch')
            ->willThrowException(new RuntimeException('listener exploded'));

        $tester = new CommandTester($this->createCommand());

        try {
            $tester->execute($this->rotationInput());
        } catch (RuntimeException) {
            // The listener failure is deliberately NOT swallowed.
        }

        $display = $tester->getDisplay();
        self::assertStringContainsString('Successfully rotated', $display);
        self::assertStringContainsString('Update your configuration', $display);
    }

    /**
     * Rotating the master key rewrites every envelope in the store, so the
     * command refuses to start without `master_key.rotate` — before it reads
     * any key material or touches the repository.
     */
    #[Test]
    public function refusesRotationWithoutMasterKeyRotatePermission(): void
    {
        $accessControlService = $this->createMock(AccessControlServiceInterface::class);
        $accessControlService
            ->method('isGranted')
            ->willReturnCallback(
                // Every other vault permission granted — only the master-key one missing.
                static fn (VaultPermission $permission): bool => $permission !== VaultPermission::MasterKeyRotate,
            );

        $this->secretRepository
            ->expects(self::never())
            ->method('findIdentifiers');

        $command = new VaultRotateMasterKeyCommand(
            $this->secretRepository,
            $this->encryptionService,
            $this->masterKeyProviderFactory,
            $this->connectionPool,
            $this->auditLogService,
            $this->auditChainRekeyService,
            $this->envelopeCodec,
            $accessControlService,
            $this->eventDispatcher,
        );
        $tester = new CommandTester($command);

        $exitCode = $tester->execute(['--confirm' => true]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('master_key.rotate', $tester->getDisplay());
    }

    /**
     * @param iterable<ForeignEnvelopeRotatorInterface> $foreignRotators
     */
    private function createCommand(
        ?AuditLogServiceInterface $auditLogService = null,
        iterable $foreignRotators = [],
    ): VaultRotateMasterKeyCommand {
        return new VaultRotateMasterKeyCommand(
            $this->secretRepository,
            $this->encryptionService,
            $this->masterKeyProviderFactory,
            $this->connectionPool,
            $auditLogService ?? $this->auditLogService,
            $this->auditChainRekeyService,
            $this->envelopeCodec,
            $this->accessControlService,
            $this->eventDispatcher,
            $foreignRotators,
        );
    }

    /**
     * Mock setup for a vault holding exactly one re-encryptable secret on a
     * single connection, mirroring {@see successfulRotationWithConfirm()}.
     */
    private function givenOneRotatableSecret(bool $expectRollback = false): void
    {
        $this->secretRepository->method('findIdentifiers')->willReturn(['test-secret']);
        $this->secretRepository->method('findByIdentifier')->willReturn($this->createTestSecret('test-secret'));
        $this->encryptionService->method('reEncryptDek')->willReturn(new ReEncryptedDek('new-dek', 'new-nonce'));

        $lockResult = $this->createStub(Result::class);
        $lockResult->method('fetchOne')->willReturn(1);

        $connection = $this->createMock(Connection::class);
        $connection->method('executeQuery')->willReturn($lockResult);
        if ($expectRollback) {
            $connection->expects(self::atLeastOnce())->method('rollBack');
        } else {
            $connection->expects(self::never())->method('rollBack');
        }

        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);
        $this->auditChainRekeyService->method('rekeyChain')->willReturn(1);
    }

    private function createRotator(int $envelopes, ?int $rewrapped = null): ForeignEnvelopeRotatorInterface&MockObject
    {
        $rotator = $this->createMock(ForeignEnvelopeRotatorInterface::class);
        $rotator->method('getIdentifier')->willReturn('nr-test: sealed payloads');
        $rotator->method('getTables')->willReturn(['tx_nrtest_payload']);
        $rotator->method('countEnvelopes')->willReturn($envelopes);
        if ($rewrapped !== null) {
            $rotator->method('rewrapAll')->willReturn($rewrapped);
        }

        return $rotator;
    }

    /**
     * @return array<string, string|bool>
     */
    private function rotationInput(): array
    {
        return [
            '--old-key' => $this->createKeyFile('old', str_repeat('a', 32)),
            '--new-key' => $this->createKeyFile('new', str_repeat('b', 32)),
            '--confirm' => true,
        ];
    }

    private function createKeyFile(string $name, string $content): string
    {
        static $root = null;
        if ($root === null) {
            $root = vfsStream::setup('keys');
        }

        vfsStream::newFile($name . '.key')
            ->withContent($content)
            ->at($root);

        return vfsStream::url('keys/' . $name . '.key');
    }

    private function createTestSecret(string $identifier): Secret
    {
        // The ctor enforces the full-envelope crypto invariant: encryptedValue,
        // encryptedDek, dekNonce, valueNonce, and valueChecksum must all be
        // set or all be empty. The master-key rotation only re-encrypts the
        // DEK envelope, but the entity still requires a consistent envelope.
        return new Secret(
            identifier: $identifier,
            encryptedValue: 'encrypted-value',
            encryptedDek: 'encrypted-dek',
            dekNonce: 'dek-nonce',
            valueNonce: 'value-nonce',
            valueChecksum: 'value-checksum',
        );
    }

    private function mockMasterKeyProvider(string $key): void
    {
        $provider = $this->createMock(MasterKeyProviderInterface::class);
        $provider->method('getMasterKey')->willReturn($key);
        $this->masterKeyProviderFactory
            ->method('getAvailableProvider')
            ->willReturn($provider);
    }
}
