<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\EventListener;

use Netresearch\NrVault\EventListener\TypoScriptVaultListener;
use Netresearch\NrVault\Security\FrontendPlaceholderPolicyInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Frontend\ContentObject\ContentObjectRenderer;
use TYPO3\CMS\Frontend\ContentObject\Event\AfterStdWrapFunctionsExecutedEvent;

/**
 * Functional tests for TypoScriptVaultListener.
 *
 * Verifies that %vault(identifier)% placeholders in TypoScript content
 * are resolved to the actual secret values via the event listener.
 */
#[CoversClass(TypoScriptVaultListener::class)]
final class TypoScriptVaultListenerTest extends AbstractVaultFunctionalTestCase
{
    private const REASON_TEST_CLEANUP = 'test cleanup';

    /** @var array<string, bool> Store options marking a secret resolvable in the frontend. */
    private const FRONTEND_ACCESSIBLE = ['frontendAccessible' => true];

    /** @var list<string> */
    protected array $coreExtensionsToLoad = [
        'backend',
        'frontend',
    ];

    protected ?string $backendUserFixture = __DIR__ . '/../Fixtures/Users/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 1,
    ];

    #[Test]
    public function listenerResolvesVaultPlaceholderInContent(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = 'ts_apikey_' . bin2hex(random_bytes(4));
        $vaultService->store($identifier, 'resolved-typoscript-secret', self::FRONTEND_ACCESSIBLE);

        $listener = $this->get(TypoScriptVaultListener::class);
        $event = $this->createEvent(\sprintf('%%vault(%s)%%', $identifier), $identifier);

        $listener($event);

        self::assertSame('resolved-typoscript-secret', $event->getContent());

        // Cleanup
        $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
    }

    #[Test]
    public function listenerResolvesVaultPlaceholderEmbeddedInLargerContent(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = 'ts_embedded_' . bin2hex(random_bytes(4));
        $vaultService->store($identifier, 'my-api-key', self::FRONTEND_ACCESSIBLE);

        $listener = $this->get(TypoScriptVaultListener::class);
        $content = \sprintf('Bearer %%vault(%s)%%', $identifier);
        $event = $this->createEvent($content, $identifier);

        $listener($event);

        self::assertSame('Bearer my-api-key', $event->getContent());

        // Cleanup
        $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
    }

    #[Test]
    public function listenerDoesNotResolveSecretWithoutFrontendAccess(): void
    {
        // The base test case logs in the admin backend user (uid 1), i.e. the
        // frontend renders with an ambient backend session that grants read
        // access to every secret. A secret withheld from the frontend must
        // still not be resolved into the (cacheable) page output.
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = 'ts_private_' . bin2hex(random_bytes(4));
        $vaultService->store($identifier, 'smtp-password-never-in-frontend');

        $listener = $this->get(TypoScriptVaultListener::class);
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);
        $event = $this->createEvent($placeholder, $identifier);

        $listener($event);

        self::assertSame(
            $placeholder,
            $event->getContent(),
            'A secret that is not frontend_accessible must stay unresolved even with a backend session',
        );

        // Cleanup
        $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
    }

    #[Test]
    public function listenerSkipsContentWithNoVaultPlaceholders(): void
    {
        $listener = $this->get(TypoScriptVaultListener::class);
        $originalContent = 'No vault references here, plain text content.';
        $event = $this->createEvent($originalContent);

        $listener($event);

        self::assertSame($originalContent, $event->getContent(), 'Content without vault refs must be unchanged');
    }

    #[Test]
    public function listenerPreservesPlaceholderWhenSecretNotFound(): void
    {
        $listener = $this->get(TypoScriptVaultListener::class);
        $placeholder = '%vault(nonexistent/identifier/xyz)%';
        $event = $this->createEvent($placeholder, 'nonexistent/identifier/xyz');

        $listener($event);

        // Unresolvable placeholder must be preserved
        self::assertSame($placeholder, $event->getContent(), 'Unresolvable placeholder must be preserved');
    }

    #[Test]
    public function listenerResolvesMultipleVaultPlaceholders(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $prefix = 'ts_multi_' . bin2hex(random_bytes(4));
        $id1 = $prefix . '_k1';
        $id2 = $prefix . '_k2';
        $vaultService->store($id1, 'first-value', self::FRONTEND_ACCESSIBLE);
        $vaultService->store($id2, 'second-value', self::FRONTEND_ACCESSIBLE);

        $listener = $this->get(TypoScriptVaultListener::class);
        $content = \sprintf('%%vault(%s)%%:%%vault(%s)%%', $id1, $id2);
        $event = $this->createEvent($content, $id1, $id2);

        $listener($event);

        self::assertSame('first-value:second-value', $event->getContent());

        // Cleanup
        $vaultService->delete($id1, self::REASON_TEST_CLEANUP);
        $vaultService->delete($id2, self::REASON_TEST_CLEANUP);
    }

    #[Test]
    public function listenerSkipsNullContent(): void
    {
        $listener = $this->get(TypoScriptVaultListener::class);
        $event = $this->createEvent(null);

        $listener($event);

        self::assertNull($event->getContent(), 'Null content must remain null');
    }

    /**
     * Create an AfterStdWrapFunctionsExecutedEvent with the given content,
     * rendering in a frontend request that publishes the named identifiers.
     *
     * PHPUnit runs on the CLI, which enforces the ADR-035 allow-set like any
     * frontend request, so an identifier has to be published for the listener
     * to reach the vault at all. The grant goes through `allowIdentifier()` —
     * the documented A4 escape hatch, keyed on the request the renderer
     * carries. What these cases are about is the listener's own behaviour once
     * the gate has opened; the gate is
     * {@see TypoScriptVaultListenerFrontendScopeTest}'s subject.
     */
    private function createEvent(?string $content, string ...$publishedIdentifiers): AfterStdWrapFunctionsExecutedEvent
    {
        /** @phpstan-ignore new.internalClass */
        $request = (new ServerRequest('https://example.com/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_FE);

        $policy = $this->get(FrontendPlaceholderPolicyInterface::class);
        foreach ($publishedIdentifiers as $identifier) {
            $policy->allowIdentifier($identifier, $request);
        }

        $contentObjectRenderer = GeneralUtility::makeInstance(ContentObjectRenderer::class);
        /** @phpstan-ignore method.internal */
        $contentObjectRenderer->setRequest($request);

        /** @phpstan-ignore new.internalClass */
        return new AfterStdWrapFunctionsExecutedEvent($content, [], $contentObjectRenderer);
    }
}
