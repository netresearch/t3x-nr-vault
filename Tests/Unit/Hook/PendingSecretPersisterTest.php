<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Hook;

use Error;
use Exception;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Hook\Dto\PendingSecret;
use Netresearch\NrVault\Hook\PendingSecretPersister;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use ReflectionProperty;
use RuntimeException;
use Throwable;
use TYPO3\CMS\Core\Messaging\FlashMessage;
use TYPO3\CMS\Core\Messaging\FlashMessageQueue;
use TYPO3\CMS\Core\Messaging\FlashMessageService;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;

/**
 * The persister is the last decision point before a secret is written or
 * removed. The tests assert which vault call each pending shape maps to (a
 * mis-dispatch either loses the audit trail of a rotation or deletes an entry
 * that was never cleared), and that the failure path surfaces the error without
 * carrying plaintext into the backend flash message.
 */
#[CoversClass(PendingSecretPersister::class)]
#[AllowMockObjectsWithoutExpectations]
final class PendingSecretPersisterTest extends TestCase
{
    private const IDENTIFIER = '01937b6e-4b6c-7abc-8def-0123456789ab';

    private const DELETE_REASON = 'Field cleared in record 42';

    private const ROTATE_REASON = 'Field updated in record 42';

    private const REDACTED_MESSAGE = 'Vault operation failed: [REDACTED]';

    private PendingSecretPersister $subject;

    private VaultServiceInterface&MockObject $vaultService;

    private FlashMessageService&MockObject $flashMessageService;

    /** @var list<FlashMessage> */
    private array $flashMessages = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->flashMessageService = $this->createMock(FlashMessageService::class);

        $queue = $this->createMock(FlashMessageQueue::class);
        $queue->method('addMessage')->willReturnCallback(
            function (FlashMessage $message): void {
                $this->flashMessages[] = $message;
            },
        );
        $this->flashMessageService->method('getMessageQueueByIdentifier')->willReturn($queue);

        $this->subject = new PendingSecretPersister($this->vaultService, $this->flashMessageService);
    }

    #[Test]
    public function newPendingIsStoredWithTheGivenMetadata(): void
    {
        $plaintext = $this->fakeSecret();
        $options = ['table' => 'tx_test', 'field' => 'api_key'];

        $this->vaultService
            ->expects(self::once())
            ->method('store')
            ->with(self::IDENTIFIER, $plaintext, $options);
        $this->vaultService->expects(self::never())->method('rotate');
        $this->vaultService->expects(self::never())->method('delete');

        $error = $this->subject->persist(
            PendingSecret::createNew($plaintext, self::IDENTIFIER),
            $options,
            self::DELETE_REASON,
            self::ROTATE_REASON,
            $this->redactingMessage(),
        );

        self::assertNull($error);
    }

    /**
     * An existing secret is replaced via rotate(), never via store(): rotate is
     * what records the before/after hashes in the audit chain.
     */
    #[Test]
    public function existingPendingIsRotatedWithTheAuditReason(): void
    {
        $plaintext = $this->fakeSecret();

        $this->vaultService
            ->expects(self::once())
            ->method('rotate')
            ->with(self::IDENTIFIER, $plaintext, self::ROTATE_REASON);
        $this->vaultService->expects(self::never())->method('store');
        $this->vaultService->expects(self::never())->method('delete');

        $error = $this->subject->persist(
            PendingSecret::createUpdate($plaintext, self::IDENTIFIER, 'previous-checksum'),
            [],
            self::DELETE_REASON,
            self::ROTATE_REASON,
            $this->redactingMessage(),
        );

        self::assertNull($error);
    }

    #[Test]
    public function emptyValueWithAnIdentifierDeletesWithTheAuditReason(): void
    {
        $this->vaultService
            ->expects(self::once())
            ->method('delete')
            ->with(self::IDENTIFIER, self::DELETE_REASON);
        $this->vaultService->expects(self::never())->method('store');
        $this->vaultService->expects(self::never())->method('rotate');

        $error = $this->subject->persist(
            PendingSecret::createUpdate('', self::IDENTIFIER, ''),
            [],
            self::DELETE_REASON,
            self::ROTATE_REASON,
            $this->redactingMessage(),
        );

        self::assertNull($error);
    }

    /**
     * Issue #223: the identifier — not the checksum, which the clear control
     * blanks — is the "a secret existed" signal. Without one there is nothing
     * to delete, and the persister must not invent a target.
     */
    #[Test]
    public function emptyValueWithoutAnIdentifierNeverTouchesTheVault(): void
    {
        $this->vaultService->expects(self::never())->method('delete');
        $this->vaultService->expects(self::never())->method('store');
        $this->vaultService->expects(self::never())->method('rotate');

        $error = $this->subject->persist(
            PendingSecret::createUpdate('', '', ''),
            [],
            self::DELETE_REASON,
            self::ROTATE_REASON,
            $this->redactingMessage(),
        );

        self::assertNull($error);
        self::assertSame([], $this->flashMessages);
    }

    #[Test]
    public function persistenceFailureIsReturnedToTheCaller(): void
    {
        $thrown = new VaultException('Adapter unreachable');
        $this->vaultService->method('store')->willThrowException($thrown);

        $error = $this->subject->persist(
            PendingSecret::createNew($this->fakeSecret(), self::IDENTIFIER),
            [],
            self::DELETE_REASON,
            self::ROTATE_REASON,
            $this->redactingMessage(),
        );

        self::assertSame($thrown, $error, 'The caller needs the original throwable for hook-specific logging');
    }

    /**
     * `catch (Throwable)` — an Error raised deep in an adapter must be turned
     * into a reported failure too, not escape into the DataHandler.
     */
    #[Test]
    public function nonExceptionThrowableIsAlsoCaughtAndReported(): void
    {
        $thrown = new Error('Adapter contract violated');
        $this->vaultService->method('rotate')->willThrowException($thrown);

        $error = $this->subject->persist(
            PendingSecret::createUpdate($this->fakeSecret(), self::IDENTIFIER, 'previous-checksum'),
            [],
            self::DELETE_REASON,
            self::ROTATE_REASON,
            $this->redactingMessage(),
        );

        self::assertSame($thrown, $error);
        self::assertCount(1, $this->flashMessages);
    }

    #[Test]
    public function failureEmitsAnErrorFlashMessageBuiltFromTheThrowable(): void
    {
        $this->vaultService->method('delete')->willThrowException(new RuntimeException('Delete failed'));

        $this->subject->persist(
            PendingSecret::createUpdate('', self::IDENTIFIER, ''),
            [],
            self::DELETE_REASON,
            self::ROTATE_REASON,
            static fn (Throwable $e): string => 'Could not clear the secret: ' . $e->getMessage(),
        );

        self::assertCount(1, $this->flashMessages);
        $message = $this->flashMessages[0];
        self::assertSame('Could not clear the secret: Delete failed', $message->getMessage());
        self::assertSame('Vault Error', $message->getTitle());
        // `getSeverity()` is @internal in TYPO3, so the property is read
        // directly rather than through the accessor.
        self::assertSame(
            ContextualFeedbackSeverity::ERROR,
            (new ReflectionProperty(FlashMessage::class, 'severity'))->getValue($message),
        );
    }

    /**
     * The flash message body is entirely the caller's to build — the persister
     * adds nothing of its own, so the plaintext it was handed can never reach
     * the backend UI unless the caller puts it there.
     */
    #[Test]
    public function flashMessageCarriesNoPlaintextOfTheFailedSecret(): void
    {
        $plaintext = $this->fakeSecret();
        $this->vaultService->method('store')->willThrowException(new VaultException('Adapter unreachable'));

        $this->subject->persist(
            PendingSecret::createNew($plaintext, self::IDENTIFIER),
            ['table' => 'tx_test'],
            self::DELETE_REASON,
            self::ROTATE_REASON,
            $this->redactingMessage(),
        );

        self::assertCount(1, $this->flashMessages);
        self::assertSame(self::REDACTED_MESSAGE, $this->flashMessages[0]->getMessage());
        self::assertStringNotContainsString($plaintext, $this->flashMessages[0]->getMessage());
    }

    /**
     * The rollback restores the record field to its pre-save state; it has to
     * run before the user is told anything, so the message never describes a
     * state the record is not yet in.
     */
    #[Test]
    public function rollbackRunsBeforeTheFlashMessageIsEmitted(): void
    {
        $this->vaultService->method('store')->willThrowException(new VaultException('Adapter unreachable'));

        $sequence = [];
        $queue = $this->createMock(FlashMessageQueue::class);
        $queue->method('addMessage')->willReturnCallback(
            static function () use (&$sequence): void {
                $sequence[] = 'flash';
            },
        );
        $flashMessageService = $this->createMock(FlashMessageService::class);
        $flashMessageService->method('getMessageQueueByIdentifier')->willReturn($queue);

        $subject = new PendingSecretPersister($this->vaultService, $flashMessageService);
        $subject->persist(
            PendingSecret::createNew($this->fakeSecret(), self::IDENTIFIER),
            [],
            self::DELETE_REASON,
            self::ROTATE_REASON,
            $this->redactingMessage(),
            static function () use (&$sequence): void {
                $sequence[] = 'rollback';
            },
        );

        self::assertSame(['rollback', 'flash'], $sequence);
    }

    #[Test]
    public function rollbackIsNotRunOnSuccess(): void
    {
        $rollbackRuns = 0;

        $error = $this->subject->persist(
            PendingSecret::createNew($this->fakeSecret(), self::IDENTIFIER),
            [],
            self::DELETE_REASON,
            self::ROTATE_REASON,
            $this->redactingMessage(),
            static function () use (&$rollbackRuns): void {
                ++$rollbackRuns;
            },
        );

        self::assertNull($error);
        self::assertSame(0, $rollbackRuns);
    }

    #[Test]
    public function failureWithoutARollbackCallbackStillReportsTheError(): void
    {
        $thrown = new VaultException('Adapter unreachable');
        $this->vaultService->method('store')->willThrowException($thrown);

        $error = $this->subject->persist(
            PendingSecret::createNew($this->fakeSecret(), self::IDENTIFIER),
            [],
            self::DELETE_REASON,
            self::ROTATE_REASON,
            $this->redactingMessage(),
        );

        self::assertSame($thrown, $error);
        self::assertCount(1, $this->flashMessages);
    }

    /**
     * There is no flash-message queue on the CLI. The reporting attempt must
     * not replace the original vault failure with a messaging failure.
     */
    #[Test]
    public function unavailableFlashMessageServiceDoesNotMaskTheVaultFailure(): void
    {
        $thrown = new VaultException('Adapter unreachable');
        $this->vaultService->method('store')->willThrowException($thrown);

        $flashMessageService = $this->createMock(FlashMessageService::class);
        $flashMessageService
            ->method('getMessageQueueByIdentifier')
            ->willThrowException(new Exception('No flash message queue in this context'));

        $subject = new PendingSecretPersister($this->vaultService, $flashMessageService);
        $error = $subject->persist(
            PendingSecret::createNew($this->fakeSecret(), self::IDENTIFIER),
            [],
            self::DELETE_REASON,
            self::ROTATE_REASON,
            $this->redactingMessage(),
        );

        self::assertSame($thrown, $error);
    }

    /**
     * A message builder that behaves like the production hooks: it reports the
     * failure without echoing anything it was given about the secret.
     *
     * @return callable(Throwable): string
     */
    private function redactingMessage(): callable
    {
        return static fn (Throwable $e): string => self::REDACTED_MESSAGE;
    }

    /**
     * A clearly synthetic, runtime-generated stand-in for secret material.
     */
    private function fakeSecret(): string
    {
        return 'FAKE-TEST-SECRET-' . bin2hex(random_bytes(8));
    }
}
