<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\EventListener;

use Netresearch\NrVault\Service\VaultServiceInterface;
use Psr\Log\LoggerInterface;
use Throwable;
use TYPO3\CMS\Core\Attribute\AsEventListener;
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
    private const VAULT_PATTERN = '/%vault\(([^)]+)\)%/';

    public function __construct(
        private VaultServiceInterface $vaultService,
        private LoggerInterface $logger,
    ) {}

    public function __invoke(AfterStdWrapFunctionsExecutedEvent $event): void
    {
        $content = $event->getContent();

        // Quick check - skip if no vault references or not a string
        if (!\is_string($content) || !str_contains($content, '%vault(')) {
            return;
        }

        $resolved = $this->resolveVaultReferences($content);
        $event->setContent($resolved);
    }

    /**
     * Replace all vault references in content with their resolved values.
     */
    private function resolveVaultReferences(string $content): string
    {
        return (string) preg_replace_callback(
            self::VAULT_PATTERN,
            fn (array $matches): string => $this->resolveIdentifier($matches[1]) ?? $matches[0],
            $content,
        );
    }

    /**
     * Resolve a single vault identifier to its secret value.
     *
     * Returns null if resolution fails (secret not found, not frontend
     * accessible, access denied, etc.), which causes the original placeholder
     * to be preserved.
     */
    private function resolveIdentifier(string $identifier): ?string
    {
        $identifier = trim($identifier);
        if ($identifier === '') {
            return null;
        }

        try {
            return $this->vaultService->retrieveForFrontend($identifier);
        } catch (Throwable $e) {
            $this->logger->warning('Failed to resolve vault reference in TypoScript', [
                'identifier' => $identifier,
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }
}
