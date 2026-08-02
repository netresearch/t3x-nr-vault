<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\EventListener;

use Netresearch\NrVault\Security\FrontendPlaceholderPolicy;
use Netresearch\NrVault\Security\FrontendPlaceholderPolicyInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Utility\IdentifierValidator;
use Psr\Log\LoggerInterface;
use Throwable;
use TYPO3\CMS\Core\Attribute\AsEventListener;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Frontend\ContentObject\ContentObjectRenderer;
use TYPO3\CMS\Frontend\ContentObject\Event\AfterStdWrapFunctionsExecutedEvent;

/**
 * PSR-14 event listener that resolves %vault(identifier)% placeholders in TypoScript content.
 *
 * Listens to AfterStdWrapFunctionsExecutedEvent to process vault references after
 * all stdWrap functions have been applied. This allows secrets to be used in
 * TypoScript configurations like:
 *
 *   page.10 = TEXT
 *   page.10.value = %vault(api_key)%
 *
 * Security considerations:
 * - This listener runs on the output of *every* stdWrap call, so editor-authored
 *   fields and reflected request parameters are resolution sites too. In a frontend
 *   request FrontendPlaceholderPolicy therefore restricts resolution to identifiers
 *   the integrator published into an admin-only source; see ADR-035
 * - Only secrets marked as `frontend_accessible = 1` can be resolved. Resolution goes
 *   through VaultServiceInterface::retrieveForFrontend(), which enforces that flag for
 *   every caller — a request carrying a backend session resolves no more than an
 *   anonymous one, so a privileged render cannot put a withheld secret into the page
 *   cache that is shared with anonymous visitors
 * - Resolved values are frontend-readable by definition and may be cached - use USER_INT
 *   or disable caching for content that must not be stored
 * - Unresolved placeholders remain visible in output
 */
#[AsEventListener(identifier: 'nr-vault/typoscript-vault')]
final readonly class TypoScriptVaultListener
{
    public function __construct(
        private VaultServiceInterface $vaultService,
        private LoggerInterface $logger,
        private FrontendPlaceholderPolicyInterface $placeholderPolicy,
    ) {}

    public function __invoke(AfterStdWrapFunctionsExecutedEvent $event): void
    {
        $content = $event->getContent();

        // Quick check - skip if no vault references or not a string
        if (!\is_string($content) || !str_contains($content, '%vault(')) {
            return;
        }

        /** @phpstan-ignore method.internal */
        $resolved = $this->resolveVaultReferences($content, $event->getContentObjectRenderer());
        $event->setContent($resolved);
    }

    /**
     * Replace all vault references in content with their resolved values.
     */
    private function resolveVaultReferences(string $content, ContentObjectRenderer $contentObjectRenderer): string
    {
        return (string) preg_replace_callback(
            FrontendPlaceholderPolicy::VAULT_PATTERN,
            fn (array $matches): string => $this->resolveIdentifier($matches[1], $contentObjectRenderer)
                ?? $matches[0],
            $content,
        );
    }

    /**
     * Resolve a single vault identifier to its secret value.
     *
     * Returns null if the identifier is not resolvable in this context or if
     * resolution fails (secret not found, not frontend accessible, access
     * denied, etc.), which causes the original placeholder to be preserved.
     */
    private function resolveIdentifier(string $identifier, ContentObjectRenderer $contentObjectRenderer): ?string
    {
        $identifier = trim($identifier);
        if ($identifier === '') {
            return null;
        }

        // Gate runs *before* retrieveForFrontend(): a rejected identifier
        // reaches neither the vault nor the audit log.
        if (!$this->placeholderPolicy->isResolvable($identifier, $contentObjectRenderer)) {
            $this->logSkippedIdentifier($identifier, $contentObjectRenderer);

            return null;
        }

        try {
            return $this->vaultService->retrieveForFrontend($identifier);
        } catch (Throwable $e) {
            // Bounded per request, never per process: claimLogSlot() keys its
            // latch on the request and does not latch at all in legacy context,
            // so one failed resolution cannot silence the next request — or the
            // rest of a long-running CLI process.
            if ($this->placeholderPolicy->claimLogSlot($contentObjectRenderer)) {
                $this->logger->warning('Failed to resolve vault reference in TypoScript', [
                    'identifier' => $identifier,
                    'error' => $e->getMessage(),
                ]);
            }

            return null;
        }
    }

    /**
     * Report a rejected identifier once per request, in Development only.
     *
     * Production writes nothing on this path — the only volume unauthenticated
     * input provably cannot raise. The identifier is echoed only when it passes
     * IdentifierValidator, so no attacker-controlled bytes (newlines, unbounded
     * length) reach the log. Never a secret value.
     */
    private function logSkippedIdentifier(string $identifier, ContentObjectRenderer $contentObjectRenderer): void
    {
        if (!$this->isDevelopmentContext()) {
            return;
        }

        if (!$this->placeholderPolicy->claimLogSlot($contentObjectRenderer)) {
            return;
        }

        $this->logger->notice(
            'Vault placeholder not resolved: the identifier is not published for frontend resolution.'
            . ' Publish it in TypoScript setup, in site configuration, via'
            . ' plugin.tx_nrvault.frontendResolvableIdentifiers, or via'
            . ' FrontendPlaceholderPolicyInterface::allowIdentifier(). Further occurrences in this'
            . ' request are not reported.',
            ['identifier' => IdentifierValidator::isValid($identifier) ? $identifier : '[invalid]'],
        );
    }

    /**
     * `Environment::getContext()` reads an untyped static that only
     * `Environment::initialize()` populates; in a process that never ran it a
     * `TypeError` would escape into `stdWrap()`. Same defensive shape as
     * `FrontendPlaceholderPolicy::isCli()`. Fail-closed: no context, no record.
     */
    private function isDevelopmentContext(): bool
    {
        try {
            return Environment::getContext()->isDevelopment();
        } catch (Throwable) {
            return false;
        }
    }
}
