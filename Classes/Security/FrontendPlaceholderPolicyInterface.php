<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Frontend\ContentObject\ContentObjectRenderer;

/**
 * Decides which %vault(identifier)% placeholders TypoScriptVaultListener may
 * resolve in a frontend request.
 *
 * In a frontend context, on the CLI, and in any not-positively-identified web
 * context the listener resolves an identifier only when the integrator
 * published it through an admin-only source: frontend TypoScript, site
 * configuration / settings, the
 * `plugin.tx_nrvault.frontendResolvableIdentifiers` list, or
 * {@see self::allowIdentifier()}. Everything else keeps the literal
 * placeholder. See ADR-035.
 *
 * `allowIdentifier()` is the documented escape hatch for integrator PHP
 * (userFunc, DataProcessor, eID handler); the service is registered `public`
 * so it can be fetched with `GeneralUtility::makeInstance()`.
 *
 * The implementation is a container singleton, so every piece of mutable state
 * it holds MUST be keyed on the request object its caller carries. Both
 * request-scoped methods below therefore take the scope with them, and neither
 * accepts `$GLOBALS['TYPO3_REQUEST']` as that key: core never unsets it, so in
 * a worker SAPI it would collapse every request onto one key and make a grant
 * — and a claimed log slot — visible to the next request.
 */
interface FrontendPlaceholderPolicyInterface
{
    /**
     * Publish an identifier as resolvable for the given request, and for that
     * request only.
     *
     * Pass the request you are handling, and `setRequest()` the same object on
     * the content object renderer you render with: the grant is stored against
     * that object in a `\WeakMap` and matched by object identity against the
     * renderer's own request. `$GLOBALS['TYPO3_REQUEST']` is never consulted for
     * it — TYPO3 sets that global and never unsets it, so in a FrankenPHP or
     * RoadRunner worker it outlives the request that set it, and keying on it
     * would hand one request's grant to the next. A renderer carrying a
     * different request, or none, resolves nothing.
     *
     * Trust primitive: never pass request-derived data as `$identifier`. Doing
     * so re-opens the hole this policy closes. Prefer
     * `VaultServiceInterface::retrieveForFrontend()`, which returns the value
     * instead of widening the allow-set.
     */
    public function allowIdentifier(string $identifier, ServerRequestInterface $request): void;

    /**
     * Whether the given identifier may be resolved in the current context.
     *
     * @internal consumed by TypoScriptVaultListener
     */
    public function isResolvable(string $identifier, ContentObjectRenderer $contentObjectRenderer): bool;

    /**
     * Claim the single log slot of the request the renderer is working in.
     * Returns true exactly once per request.
     *
     * A latch, not a counter: attacker-controlled input cannot drive log
     * volume, because N rejections still yield at most one record. The latch is
     * keyed on the request object, so a rejection in one render can never
     * silence a record in the next one.
     *
     * On the CLI, and in LEGACY context (a positively backend-typed request),
     * it always returns true. Logging there stays byte-for-byte as it was
     * before ADR-035, so a long-running `scheduler:run` keeps every warning:
     * such a process handles many renders under one request object, and a latch
     * keyed on that object would be a process-wide log blackout an attacker
     * could trigger with a single planted placeholder. That holds on the CLI
     * whether or not the allow-set is enforced there.
     *
     * @internal consumed by TypoScriptVaultListener
     */
    public function claimLogSlot(ContentObjectRenderer $contentObjectRenderer): bool;
}
