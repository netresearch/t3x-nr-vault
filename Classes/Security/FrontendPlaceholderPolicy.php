<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\Http\ApplicationType;
use TYPO3\CMS\Core\Site\Entity\Site;
use TYPO3\CMS\Core\TypoScript\FrontendTypoScript;
use TYPO3\CMS\Frontend\ContentObject\ContentObjectRenderer;
use WeakMap;

/**
 * Per-request allow-set of vault identifiers that may be resolved in a
 * frontend request (ADR-035).
 *
 * `TypoScriptVaultListener` runs on every `stdWrap()` call, so any string that
 * reaches `stdWrap()` — editor-authored `tt_content` fields, `data = GP:…`
 * request parameters — is a resolution site. Authorising the *content* is
 * impossible (the listener cannot tell where a byte came from), so this policy
 * authorises the *identifier*: only identifiers the integrator published into
 * a source an editor cannot write are resolvable.
 *
 * The gate is a pure conjunction with everything that was already required, so
 * the set of resolvable identifiers can only shrink — no string becomes a
 * resolution site that was not one before, and no new call reaches the vault.
 *
 * Context rule (fail-closed):
 *
 *   LEGACY (pre-ADR-035 behaviour, byte for byte) iff the CLI opt-in
 *          `frontendPlaceholderLegacyCli` is on and this is the CLI, or a
 *          request is obtainable and is positively *not* a frontend request.
 *   STRICT (allow-set enforced) in every other case — frontend render, eID,
 *          the CLI at its default setting, and any web context that cannot be
 *          positively identified.
 *
 * `$GLOBALS['TYPO3_REQUEST']` is deliberately not the only source: it is
 * assigned in `cms-frontend`'s `RequestHandler`, i.e. the innermost handler,
 * which an eID request never reaches (`EidHandler::process()` dispatches
 * directly). Detecting context solely through it would leave eID — the
 * unauthenticated surface — ungated.
 *
 * Request scoping — the structural invariant
 * -------------------------------------------
 * This service is a container singleton (`Configuration/Services.yaml` sets no
 * `shared: false`, and the listener that consumes it is a singleton too), so it
 * outlives any single request in a worker SAPI (FrankenPHP, RoadRunner) and for
 * the whole process on the CLI. **Every mutable field here is therefore a
 * `\WeakMap`, and the two request-scoped ones are keyed on the request object
 * the caller carries** — see `scopeRequest()`:
 *
 * - a grant made by `allowIdentifier()` is keyed on the request that was passed
 *   in, so it is addressable only from that request;
 * - a log slot is keyed on the request the renderer carries, so a claim in one
 *   render cannot silence a record in the next.
 *
 * `$GLOBALS['TYPO3_REQUEST']` is never read here — not as a key, and not as the
 * signal that picks the mode. Core assigns it (in both the frontend and the
 * backend `RequestHandler`) and never unsets it, so in a worker SAPI it outlives
 * its own request. As a key it would collapse every subsequent request onto one;
 * as a mode signal a leftover backend-typed request would put the next anonymous
 * frontend render into LEGACY, which is the pre-ADR-035 hole itself. A render
 * that cannot establish its own request therefore fails closed, whatever the
 * global holds.
 *
 * The property therefore holds by construction rather than by an obligation on
 * a caller: there is no field, and no key, that a later request can reach. Weak
 * keys also mean the entries disappear with the request instead of accumulating.
 */
final class FrontendPlaceholderPolicy implements FrontendPlaceholderPolicyInterface
{
    /**
     * Shared with TypoScriptVaultListener.
     *
     * Both sides MUST use this constant and the same `trim()`: a harvester
     * laxer than the listener would be bypassable, a stricter one would
     * over-block.
     */
    public const VAULT_PATTERN = '/%vault\(([^)]+)\)%/';

    /** Setup-array path of the A3 opt-in list (comma-separated identifiers). */
    private const A3_SETUP_PATH = ['plugin.', 'tx_nrvault.', 'frontendResolvableIdentifiers'];

    /** Recursion guard for the setup/site array walks. */
    private const MAX_DEPTH = 32;

    /** Upper bound on harvested identifiers per source. */
    private const MAX_IDENTIFIERS = 1000;

    /**
     * A1 + A3, memoised on the FrontendTypoScript instance. Weak keys: a
     * long-running SAPI cannot serve one request's set to the next, because
     * the owning object is a distinct instance per request.
     *
     * @var WeakMap<FrontendTypoScript, array<string, true>>
     */
    private WeakMap $setupIdentifiers;

    /**
     * A2, memoised on the Site instance.
     *
     * @var WeakMap<Site, array<string, true>>
     */
    private WeakMap $siteIdentifiers;

    /**
     * A4 — identifiers published by integrator PHP, keyed on the request they
     * were published for. Weak keys, so a grant cannot outlive its request.
     *
     * @var WeakMap<ServerRequestInterface, array<string, true>>
     */
    private WeakMap $runtimeAllowed;

    /**
     * The claimed log slot of a request. Weak keys, so a claim cannot silence
     * the next request's records.
     *
     * @var WeakMap<ServerRequestInterface, true>
     */
    private WeakMap $logClaimed;

    public function __construct(
        private readonly ExtensionConfigurationInterface $extensionConfiguration,
    ) {
        /** @var WeakMap<FrontendTypoScript, array<string, true>> $setupIdentifiers */
        $setupIdentifiers = new WeakMap();
        $this->setupIdentifiers = $setupIdentifiers;

        /** @var WeakMap<Site, array<string, true>> $siteIdentifiers */
        $siteIdentifiers = new WeakMap();
        $this->siteIdentifiers = $siteIdentifiers;

        /** @var WeakMap<ServerRequestInterface, array<string, true>> $runtimeAllowed */
        $runtimeAllowed = new WeakMap();
        $this->runtimeAllowed = $runtimeAllowed;

        /** @var WeakMap<ServerRequestInterface, true> $logClaimed */
        $logClaimed = new WeakMap();
        $this->logClaimed = $logClaimed;
    }

    public function allowIdentifier(string $identifier, ServerRequestInterface $request): void
    {
        $identifier = trim($identifier);
        if ($identifier === '') {
            return;
        }

        $granted = $this->runtimeAllowed[$request] ?? [];
        $granted[$identifier] = true;
        $this->runtimeAllowed[$request] = $granted;
    }

    public function isResolvable(string $identifier, ContentObjectRenderer $contentObjectRenderer): bool
    {
        $scope = $this->scopeRequest($contentObjectRenderer);

        if ($this->isLegacyContext($scope)) {
            return true;
        }

        if (!$scope instanceof ServerRequestInterface) {
            // Strict, and no request object to scope a grant on: nothing is
            // resolvable. A4 needs a request, which is what makes the grant
            // un-shareable between requests.
            return false;
        }

        // A4 — the only source available in eID, where neither the frontend
        // TypoScript nor the site attribute exists.
        $granted = $this->runtimeAllowed[$scope] ?? [];
        if (isset($granted[$identifier])) {
            return true;
        }

        return isset($this->collectFromTypoScript($scope)[$identifier])
            || isset($this->collectFromSite($scope)[$identifier]);
    }

    public function claimLogSlot(ContentObjectRenderer $contentObjectRenderer): bool
    {
        // The CLI never latches, whether or not the allow-set is enforced
        // there. A long-running `scheduler:run` or Messenger consumer handles
        // many renders under one request object, so a latch keyed on that
        // object is effectively process-wide: one placeholder planted in an
        // early-rendered `tt_content` field would silence every later warning
        // of that run — the attacker-triggered log blackout ADR-035 rejects.
        // Unlatched CLI logging is exactly the pre-ADR-035 volume, so making
        // resolution strict here adds no capability on the logging side.
        if ($this->isCli()) {
            return true;
        }

        $scope = $this->scopeRequest($contentObjectRenderer);

        // LEGACY is byte-for-byte the pre-ADR-035 behaviour, logging included.
        if ($this->isLegacyContext($scope)) {
            return true;
        }

        if (!$scope instanceof ServerRequestInterface) {
            // No request object to key a latch on. Not latching is the safe
            // direction: a lost record is worse than a repeated one, and this
            // branch is unreachable for the pre-existing warning because
            // isResolvable() resolves nothing without a request.
            return true;
        }

        if (isset($this->logClaimed[$scope])) {
            return false;
        }

        $this->logClaimed[$scope] = true;

        return true;
    }

    /**
     * The object every request-scoped entry is keyed on: the request the
     * renderer itself carries, and nothing else.
     *
     * `$GLOBALS['TYPO3_REQUEST']` must never become that key. Core assigns it in
     * `cms-frontend`'s `RequestHandler` and **never unsets it** — four
     * assignments and zero unsets across the whole core tree — so in a worker
     * SAPI (FrankenPHP, RoadRunner) it survives the end of the request that set
     * it. Keying on it makes every following request in that worker share one
     * key: a grant published by request N is then readable by request N+1, and a
     * log slot claimed by N silences N+1. That is the identity bug, not a
     * freshness bug, and it cannot be fixed by any obligation on the caller.
     *
     * `getRequest()` has its own fallback to that global (deprecated in v14),
     * which would smuggle the same object back in whenever a renderer carries no
     * request of its own. The global is therefore removed for the duration of
     * the call: the renderer either answers with the request it was given, or
     * `getRequest()` throws `ContentRenderingException` 1607172972 and we fail
     * closed. Removing it also means the v14 deprecation branch is never
     * entered, so no `E_USER_DEPRECATED` escapes into `stdWrap()`.
     */
    private function scopeRequest(ContentObjectRenderer $contentObjectRenderer): ?ServerRequestInterface
    {
        $hasGlobal = \array_key_exists('TYPO3_REQUEST', $GLOBALS);
        $global = $GLOBALS['TYPO3_REQUEST'] ?? null;
        unset($GLOBALS['TYPO3_REQUEST']);

        try {
            /** @phpstan-ignore method.internal */
            return $contentObjectRenderer->getRequest();
        } catch (Throwable) {
            return null;
        } finally {
            if ($hasGlobal) {
                $GLOBALS['TYPO3_REQUEST'] = $global;
            }
        }
    }

    /**
     * Every positively non-frontend request keeps the pre-ADR-035 behaviour
     * unchanged. Anything else — including "no request at all", and including
     * the CLI — is strict.
     *
     * The CLI is *not* legacy by default. `scheduler:run` authenticates the
     * `_cli_` admin user, so the admin bypass grants the read and the allow-set
     * is the only remaining gate on editor-authored content rendered by a
     * scheduled job (newsletter, export). An installation whose internal render
     * jobs genuinely need the old behaviour opts back into it with
     * `frontendPlaceholderLegacyCli`, which restores this branch byte for byte.
     *
     * The question is answered here rather than through the request rule
     * because a CLI process usually carries a CLI-typed request, which
     * `isFrontend()` reports as false — i.e. the request rule alone would put
     * every scheduled render back into legacy and close nothing.
     *
     * The argument is the *scope* request and nothing else. An earlier revision
     * fell back to `$GLOBALS['TYPO3_REQUEST']` for this decision alone, on the
     * argument that a stale read can only move a render between modes and never
     * make one request's state addressable from another. Moving a render into
     * LEGACY *is* the whole vulnerability: `cms-backend`'s `RequestHandler`
     * assigns that global too and core never unsets it, so in a worker SAPI a
     * finished backend request leaves a backend-typed object behind, and the
     * next anonymous frontend render through a renderer that carries no request
     * of its own reads it, concludes "not frontend", and resolves every
     * frontend-accessible identifier an editor can name.
     */
    private function isLegacyContext(?ServerRequestInterface $request): bool
    {
        if ($this->isCli()) {
            return $this->isLegacyCliEnabled();
        }

        if (!$request instanceof ServerRequestInterface) {
            return false;
        }

        try {
            return !ApplicationType::fromRequest($request)->isFrontend();
        } catch (Throwable) {
            // No `applicationType` attribute: not positively non-frontend.
            return false;
        }
    }

    /**
     * `Environment::isCli()` is core's answer, but its backing property is only
     * populated by `Environment::initialize()`. In a bare unit-test process
     * that never ran, and the getter raises a `TypeError`; fall back to the
     * same fact core itself derives the flag from. Not attacker-reachable: any
     * real TYPO3 entry point initialises `Environment` before routing.
     */
    private function isCli(): bool
    {
        try {
            return Environment::isCli();
        } catch (Throwable) {
            return \PHP_SAPI === 'cli';
        }
    }

    /**
     * The explicit opt-in that restores the pre-ADR-035 CLI bypass.
     *
     * Read on every call rather than memoised in the constructor: this is a
     * container singleton, and a cached "the gate is open" is one process
     * restart away from outliving the configuration change that closed it.
     * Reading a settings array the wrapper already holds costs nothing.
     *
     * Fails closed on any error — an unreadable configuration must not open the
     * gate, and no exception may escape into `stdWrap()`.
     */
    private function isLegacyCliEnabled(): bool
    {
        try {
            return $this->extensionConfiguration->isFrontendPlaceholderLegacyCliEnabled();
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * A1 (placeholders authored into the frontend setup array) and A3
     * (`plugin.tx_nrvault.frontendResolvableIdentifiers`).
     *
     * `sys_template` is `ctrl.adminOnly`, and site TypoScript lives on disk, so
     * an editor cannot write either. Page and `tt_content` data reach
     * TypoScript only as condition-matcher variables that *select* authored
     * blocks; they never become setup leaves.
     *
     * @return array<string, true>
     */
    private function collectFromTypoScript(ServerRequestInterface $request): array
    {
        $frontendTypoScript = $request->getAttribute('frontend.typoscript');
        if (!$frontendTypoScript instanceof FrontendTypoScript) {
            return [];
        }

        if (isset($this->setupIdentifiers[$frontendTypoScript])) {
            return $this->setupIdentifiers[$frontendTypoScript];
        }

        $identifiers = [];

        try {
            // No hasSetup() precondition: that method reports on the setup
            // *tree*, a different field from the setup *array*, and gating on
            // it would drop legitimately published identifiers. getSetupArray()
            // throws 1666513645 when the array is absent, which is caught here.
            /** @phpstan-ignore method.internal */
            $setup = $frontendTypoScript->getSetupArray();
            $this->harvest($setup, $identifiers);
            $this->addOptInList($setup, $identifiers);
        } catch (Throwable) {
            // Every failure mode yields a smaller set, never an open gate and
            // never an exception escaping stdWrap().
            $identifiers = [];
        }

        $this->setupIdentifiers[$frontendTypoScript] = $identifiers;

        return $identifiers;
    }

    /**
     * A2 — site configuration and site settings. Both are on-disk YAML edited
     * through an admin-only backend module.
     *
     * @todo Re-evaluate when core implements `access=user` on the site
     *       settings module; if site settings become editable by non-admins,
     *       this source must be dropped.
     *
     * @return array<string, true>
     */
    private function collectFromSite(ServerRequestInterface $request): array
    {
        $site = $request->getAttribute('site');
        if (!$site instanceof Site) {
            return [];
        }

        if (isset($this->siteIdentifiers[$site])) {
            return $this->siteIdentifiers[$site];
        }

        $identifiers = [];

        try {
            $this->harvest($site->getConfiguration(), $identifiers);
            $this->harvest($site->getSettings()->getAllFlat(), $identifiers);
        } catch (Throwable) {
            $identifiers = [];
        }

        $this->siteIdentifiers[$site] = $identifiers;

        return $identifiers;
    }

    /**
     * Read the comma-separated A3 opt-in list out of the setup array.
     *
     * @param array<mixed> $setup
     * @param array<string, true> $identifiers
     */
    private function addOptInList(array $setup, array &$identifiers): void
    {
        $node = $setup;
        foreach (self::A3_SETUP_PATH as $segment) {
            if (!\is_array($node) || !isset($node[$segment])) {
                return;
            }

            $node = $node[$segment];
        }

        if (!\is_string($node)) {
            return;
        }

        foreach (explode(',', $node) as $candidate) {
            $candidate = trim($candidate);
            if ($candidate === '') {
                continue;
            }

            if (\count($identifiers) >= self::MAX_IDENTIFIERS) {
                continue;
            }

            $identifiers[$candidate] = true;
        }
    }

    /**
     * Collect every %vault(id)% identifier appearing in a string leaf, using
     * the same pattern and the same trim() the listener applies.
     *
     * @param array<mixed> $node
     * @param array<string, true> $identifiers
     */
    private function harvest(array $node, array &$identifiers, int $depth = 0): void
    {
        if ($depth >= self::MAX_DEPTH || \count($identifiers) >= self::MAX_IDENTIFIERS) {
            return;
        }

        foreach ($node as $value) {
            if (\is_array($value)) {
                $this->harvest($value, $identifiers, $depth + 1);

                continue;
            }

            if (!\is_string($value)) {
                continue;
            }

            if (!str_contains($value, '%vault(')) {
                continue;
            }

            if (preg_match_all(self::VAULT_PATTERN, $value, $matches) < 1) {
                continue;
            }

            foreach ($matches[1] as $identifier) {
                $identifier = trim($identifier);
                if ($identifier === '') {
                    continue;
                }

                if (\count($identifiers) >= self::MAX_IDENTIFIERS) {
                    continue;
                }

                $identifiers[$identifier] = true;
            }
        }
    }
}
