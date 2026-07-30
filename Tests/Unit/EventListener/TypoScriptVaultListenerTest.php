<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\EventListener;

use Netresearch\NrVault\EventListener\TypoScriptVaultListener;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use RuntimeException;
use TYPO3\CMS\Frontend\ContentObject\ContentObjectRenderer;
use TYPO3\CMS\Frontend\ContentObject\Event\AfterStdWrapFunctionsExecutedEvent;

#[CoversClass(TypoScriptVaultListener::class)]
#[AllowMockObjectsWithoutExpectations]
final class TypoScriptVaultListenerTest extends TestCase
{
    private VaultServiceInterface&MockObject $vaultService;

    private LoggerInterface&MockObject $logger;

    private TypoScriptVaultListener $listener;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->listener = new TypoScriptVaultListener($this->vaultService, $this->logger);
    }

    #[Test]
    public function skipsProcessingWhenContentIsNull(): void
    {
        $event = $this->createEvent(null);

        $this->vaultService->expects($this->never())->method('retrieveForFrontend');

        ($this->listener)($event);

        $this->assertNull($event->getContent());
    }

    #[Test]
    public function skipsProcessingWhenNoVaultReferences(): void
    {
        $content = 'Regular content without vault references';
        $event = $this->createEvent($content);

        $this->vaultService->expects($this->never())->method('retrieveForFrontend');

        ($this->listener)($event);

        $this->assertSame($content, $event->getContent());
    }

    #[Test]
    public function resolvesSimpleVaultReference(): void
    {
        $event = $this->createEvent('%vault(api_key)%');

        // retrieve() decides against the ambient actor, so a request carrying a
        // backend session would resolve secrets withheld from the frontend.
        $this->vaultService->expects($this->never())->method('retrieve');

        $this->vaultService
            ->expects($this->once())
            ->method('retrieveForFrontend')
            ->with('api_key')
            ->willReturn('secret_value');

        ($this->listener)($event);

        $this->assertSame('secret_value', $event->getContent());
    }

    #[Test]
    public function preservesPlaceholderWhenSecretIsNotFrontendAccessible(): void
    {
        $event = $this->createEvent('%vault(smtp_password)%');

        $this->vaultService
            ->method('retrieveForFrontend')
            ->willThrowException(AccessDeniedException::forIdentifier('smtp_password', 'not frontend accessible'));

        ($this->listener)($event);

        $this->assertSame('%vault(smtp_password)%', $event->getContent());
    }

    #[Test]
    public function resolvesMultipleVaultReferences(): void
    {
        $event = $this->createEvent('Key: %vault(key1)%, Token: %vault(key2)%');

        $this->vaultService
            ->method('retrieveForFrontend')
            ->willReturnMap([
                ['key1', 'value1'],
                ['key2', 'value2'],
            ]);

        ($this->listener)($event);

        $this->assertSame('Key: value1, Token: value2', $event->getContent());
    }

    #[Test]
    public function preservesUnresolvedPlaceholderOnError(): void
    {
        $event = $this->createEvent('%vault(missing_key)%');

        $this->vaultService
            ->method('retrieveForFrontend')
            ->willThrowException(new RuntimeException('Secret not found'));

        $this->logger
            ->expects($this->once())
            ->method('warning')
            ->with(
                'Failed to resolve vault reference in TypoScript',
                $this->callback(static fn (array $context): bool => $context['identifier'] === 'missing_key'
                    && str_contains((string) $context['error'], 'Secret not found')),
            );

        ($this->listener)($event);

        // Original placeholder should be preserved
        $this->assertSame('%vault(missing_key)%', $event->getContent());
    }

    #[Test]
    public function handlesMixedContentWithVaultReferences(): void
    {
        $event = $this->createEvent('Bearer %vault(auth_token)%');

        $this->vaultService
            ->method('retrieveForFrontend')
            ->with('auth_token')
            ->willReturn('eyJhbGciOiJIUzI1NiJ9');

        ($this->listener)($event);

        $this->assertSame('Bearer eyJhbGciOiJIUzI1NiJ9', $event->getContent());
    }

    #[Test]
    public function handlesIdentifiersWithSpecialCharacters(): void
    {
        $event = $this->createEvent('%vault(my-api_key.v2)%');

        $this->vaultService
            ->method('retrieveForFrontend')
            ->with('my-api_key.v2')
            ->willReturn('special_secret');

        ($this->listener)($event);

        $this->assertSame('special_secret', $event->getContent());
    }

    #[Test]
    public function doesNotProcessNonStringContent(): void
    {
        // The event content is always string|null, but we test the type check
        $event = $this->createEvent('');

        $this->vaultService->expects($this->never())->method('retrieveForFrontend');

        ($this->listener)($event);

        $this->assertSame('', $event->getContent());
    }

    #[Test]
    public function resolvesPartiallyFailingReferences(): void
    {
        $event = $this->createEvent('%vault(good_key)% and %vault(bad_key)%');

        $this->vaultService
            ->method('retrieveForFrontend')
            ->willReturnCallback(static function (string $identifier): string {
                if ($identifier === 'good_key') {
                    return 'resolved';
                }

                throw new RuntimeException('Not found: ' . $identifier, 2156755499);
            });

        ($this->listener)($event);

        // Good key resolved, bad key preserved
        $this->assertSame('resolved and %vault(bad_key)%', $event->getContent());
    }

    /**
     * Create a mock AfterStdWrapFunctionsExecutedEvent with the given content.
     */
    private function createEvent(?string $content): AfterStdWrapFunctionsExecutedEvent
    {
        $cObj = $this->createMock(ContentObjectRenderer::class);

        return new AfterStdWrapFunctionsExecutedEvent(
            content: $content,
            configuration: [],
            contentObjectRenderer: $cObj,
        );
    }
}
