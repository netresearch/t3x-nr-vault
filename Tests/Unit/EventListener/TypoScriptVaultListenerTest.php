<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\EventListener;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\EventListener\TypoScriptVaultListener;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Security\FrontendPlaceholderPolicy;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use RuntimeException;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Frontend\ContentObject\ContentObjectRenderer;
use TYPO3\CMS\Frontend\ContentObject\Event\AfterStdWrapFunctionsExecutedEvent;

#[CoversClass(TypoScriptVaultListener::class)]
#[AllowMockObjectsWithoutExpectations]
final class TypoScriptVaultListenerTest extends TestCase
{
    private VaultServiceInterface&MockObject $vaultService;

    private LoggerInterface&MockObject $logger;

    private FrontendPlaceholderPolicy $policy;

    private TypoScriptVaultListener $listener;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->logger = $this->createMock(LoggerInterface::class);

        // A real policy, at its shipped defaults — including a strict CLI,
        // which is what PHPUnit runs as. Every case below therefore publishes
        // the identifiers it expects to resolve through the real A4 grant
        // (`allowIdentifier()`); see createEvent(). What is under test here is
        // the listener's own behaviour once the gate has opened — the gate
        // itself is FrontendPlaceholderPolicyTest's subject.
        $extensionConfiguration = $this->createMock(ExtensionConfigurationInterface::class);
        $extensionConfiguration->method('isFrontendPlaceholderLegacyCliEnabled')->willReturn(false);

        $this->policy = new FrontendPlaceholderPolicy($extensionConfiguration);
        $this->listener = new TypoScriptVaultListener(
            $this->vaultService,
            $this->logger,
            $this->policy,
        );
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
        $event = $this->createEvent('%vault(api_key)%', 'api_key');

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
        $event = $this->createEvent('%vault(smtp_password)%', 'smtp_password');

        $this->vaultService
            ->method('retrieveForFrontend')
            ->willThrowException(AccessDeniedException::forIdentifier('smtp_password', 'not frontend accessible'));

        ($this->listener)($event);

        $this->assertSame('%vault(smtp_password)%', $event->getContent());
    }

    #[Test]
    public function resolvesMultipleVaultReferences(): void
    {
        $event = $this->createEvent('Key: %vault(key1)%, Token: %vault(key2)%', 'key1', 'key2');

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
        $event = $this->createEvent('%vault(missing_key)%', 'missing_key');

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
        $event = $this->createEvent('Bearer %vault(auth_token)%', 'auth_token');

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
        $event = $this->createEvent('%vault(my-api_key.v2)%', 'my-api_key.v2');

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
        $event = $this->createEvent('%vault(good_key)% and %vault(bad_key)%', 'good_key', 'bad_key');

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
     * The CLI is strict at the shipped defaults, and PHPUnit *is* the CLI: an
     * identifier nobody published stays literal and never reaches the vault,
     * so it produces no audit row either.
     */
    #[Test]
    public function unpublishedIdentifierStaysLiteralAndNeverReachesTheVault(): void
    {
        $event = $this->createEvent('%vault(editor_planted_key)%');

        $this->vaultService->expects($this->never())->method('retrieveForFrontend');

        ($this->listener)($event);

        $this->assertSame('%vault(editor_planted_key)%', $event->getContent());
    }

    /**
     * Create an AfterStdWrapFunctionsExecutedEvent with the given content,
     * rendering in a frontend request that publishes the named identifiers.
     *
     * The grant goes through `allowIdentifier()` — the documented A4 escape
     * hatch, keyed on the very request the renderer carries. No test-only seam
     * is involved: an identifier this method does not name is rejected by the
     * same gate a production render applies.
     */
    private function createEvent(?string $content, string ...$publishedIdentifiers): AfterStdWrapFunctionsExecutedEvent
    {
        $request = (new ServerRequest('https://example.com/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_FE);

        foreach ($publishedIdentifiers as $identifier) {
            $this->policy->allowIdentifier($identifier, $request);
        }

        $cObj = $this->createMock(ContentObjectRenderer::class);
        $cObj->method('getRequest')->willReturn($request);

        return new AfterStdWrapFunctionsExecutedEvent(
            content: $content,
            configuration: [],
            contentObjectRenderer: $cObj,
        );
    }
}
