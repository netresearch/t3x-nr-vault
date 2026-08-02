<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Security;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\EventListener\TypoScriptVaultListener;
use Netresearch\NrVault\Security\FrontendPlaceholderPolicy;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use TYPO3\CMS\Core\Core\ApplicationContext;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Core\Site\Entity\Site;
use TYPO3\CMS\Core\TypoScript\AST\Node\RootNode;
use TYPO3\CMS\Core\TypoScript\FrontendTypoScript;
use TYPO3\CMS\Frontend\ContentObject\ContentObjectRenderer;
use TYPO3\CMS\Frontend\ContentObject\Event\AfterStdWrapFunctionsExecutedEvent;

/**
 * Unit coverage for the allow-set harvester: the hardening caps, the
 * memoisation, the log latch, and the regex parity that makes the gate
 * un-bypassable.
 *
 * Environment is re-initialised as a non-CLI web context so each case states
 * the SAPI it is about; the cases that are about the CLI switch it back
 * themselves.
 */
#[CoversClass(FrontendPlaceholderPolicy::class)]
#[AllowMockObjectsWithoutExpectations]
final class FrontendPlaceholderPolicyTest extends TestCase
{
    private const IDENTIFIER = 'published_key';

    private FrontendPlaceholderPolicy $subject;

    protected function setUp(): void
    {
        parent::setUp();

        $this->initializeWebEnvironment();

        // Start from a clean global so each case states its own premise. The
        // three cases that matter for cross-request scoping set it *on purpose*
        // to a stale request — that is the branch the attack uses, and a
        // blanket unset() here would put them on the branch that cannot fail.
        unset($GLOBALS['TYPO3_REQUEST']);

        $this->subject = $this->policy();
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['TYPO3_REQUEST']);

        // Environment has process-wide static state and cannot be returned to
        // "never initialised". Leave it initialised as a CLI context, which is
        // what the rest of the unit suite observes anyway (the policy falls
        // back to PHP_SAPI when the class was never initialised).
        $this->initializeWebEnvironment(cli: true);

        parent::tearDown();
    }

    #[Test]
    public function identifierPublishedInSetupArrayIsResolvable(): void
    {
        $cObj = $this->contentObjectRenderer($this->frontendRequest([
            'lib.' => ['apiKey.' => ['value' => '%vault(' . self::IDENTIFIER . ')%']],
        ]));

        self::assertTrue($this->subject->isResolvable(self::IDENTIFIER, $cObj));
        self::assertFalse($this->subject->isResolvable('never_published', $cObj));
    }

    #[Test]
    public function siteSettingsPublishIdentifiers(): void
    {
        $site = new Site('acme', 1, [
            'base' => 'https://example.com/',
            'settings' => ['payment' => ['key' => '%vault(' . self::IDENTIFIER . ')%']],
        ]);
        $cObj = $this->contentObjectRenderer($this->frontendRequest()->withAttribute('site', $site));

        self::assertTrue($this->subject->isResolvable(self::IDENTIFIER, $cObj));
    }

    #[Test]
    public function optInListPublishesIdentifiers(): void
    {
        $cObj = $this->contentObjectRenderer($this->frontendRequest([
            'plugin.' => ['tx_nrvault.' => ['frontendResolvableIdentifiers' => ' first ,' . self::IDENTIFIER . ', ']],
        ]));

        self::assertTrue($this->subject->isResolvable(self::IDENTIFIER, $cObj));
        self::assertTrue($this->subject->isResolvable('first', $cObj));
        self::assertFalse($this->subject->isResolvable('', $cObj));
    }

    #[Test]
    public function allowIdentifierPublishesAndTrims(): void
    {
        $request = $this->frontendRequest();
        $cObj = $this->contentObjectRenderer($request);

        $this->subject->allowIdentifier('  ' . self::IDENTIFIER . '  ', $request);
        $this->subject->allowIdentifier('   ', $request);

        self::assertTrue($this->subject->isResolvable(self::IDENTIFIER, $cObj));
        self::assertFalse($this->subject->isResolvable('', $cObj));
    }

    #[Test]
    public function aSecondGrantDoesNotDropTheFirst(): void
    {
        $request = $this->frontendRequest();
        $cObj = $this->contentObjectRenderer($request);

        $this->subject->allowIdentifier('first_grant', $request);
        $this->subject->allowIdentifier('second_grant', $request);

        self::assertTrue($this->subject->isResolvable('first_grant', $cObj), 'the earlier grant must survive');
        self::assertTrue($this->subject->isResolvable('second_grant', $cObj));
    }

    /**
     * `scopeRequest()` removes `$GLOBALS['TYPO3_REQUEST']` for the duration of
     * the call so `getRequest()` cannot smuggle it back in. It must put back
     * exactly what it found: leaving the global emptied would change the
     * behaviour of every later consumer in the same request.
     */
    #[Test]
    public function scopingRestoresTheGlobalRequestItTemporarilyRemoved(): void
    {
        $stale = $this->backendRequest();
        $GLOBALS['TYPO3_REQUEST'] = $stale;

        $this->subject->isResolvable(self::IDENTIFIER, $this->contentObjectRenderer($this->frontendRequest()));

        self::assertSame($stale, $GLOBALS['TYPO3_REQUEST'] ?? null);
    }

    #[Test]
    public function scopingDoesNotInventAGlobalRequestWhereThereWasNone(): void
    {
        unset($GLOBALS['TYPO3_REQUEST']);

        $this->subject->isResolvable(self::IDENTIFIER, $this->contentObjectRenderer($this->frontendRequest()));

        self::assertArrayNotHasKey('TYPO3_REQUEST', $GLOBALS);
    }

    /**
     * The policy is a container singleton, so a grant that is not bound to the
     * request object outlives the request. In a worker SAPI that means an eID
     * handler's `allowIdentifier()` on request 1 would still authorise request
     * 2 — an anonymous frontend render, possibly on a different site, whose
     * output goes into the shared page cache.
     *
     * Keyed on the request in a `\WeakMap`, the grant is unreachable from any
     * other request by construction.
     */
    #[Test]
    public function grantDoesNotCrossRequestBoundaries(): void
    {
        $firstRequest = $this->frontendRequest();
        $secondRequest = $this->frontendRequest();

        $this->subject->allowIdentifier('stripe_secret', $firstRequest);

        self::assertTrue(
            $this->subject->isResolvable('stripe_secret', $this->contentObjectRenderer($firstRequest)),
            'The granting request must see its own grant',
        );
        self::assertFalse(
            $this->subject->isResolvable('stripe_secret', $this->contentObjectRenderer($secondRequest)),
            'A later request on the same policy instance must not inherit the grant',
        );
    }

    /**
     * The attack sequence, verbatim.
     *
     * R1 is a frontend request that has finished. Core assigns
     * `$GLOBALS['TYPO3_REQUEST']` in `cms-frontend`'s `RequestHandler` and
     * **never unsets it** (a whole-tree grep of `.Build/vendor/typo3` finds four
     * assignments and zero unsets), so in a worker SAPI the global still points
     * at R1's object while E2 and E3 are handled.
     *
     * E2 is an eID request that follows the documented A4 remedy: it grants
     * `stripe_secret` for **its own** request object. E3 is the next eID request
     * in the same worker.
     *
     * If any part of the policy keys on the global rather than on the request it
     * was handed, E2's grant is stored against R1 and E3 — which also sees R1 —
     * reads it. That is the leak, and it is invisible to any test that unsets
     * the global in `setUp()`.
     */
    #[Test]
    public function grantIsInvisibleToTheNextRequestWhileTheGlobalRequestIsStale(): void
    {
        $GLOBALS['TYPO3_REQUEST'] = $this->frontendRequest();

        $grantingRequest = $this->eidRequest();
        $this->subject->allowIdentifier('stripe_secret', $grantingRequest);

        self::assertTrue(
            $this->subject->isResolvable('stripe_secret', $this->contentObjectRenderer($grantingRequest)),
            'The granting request must see its own grant',
        );

        $laterRequest = $this->eidRequest();

        self::assertFalse(
            $this->subject->isResolvable('stripe_secret', $this->contentObjectRenderer($laterRequest)),
            'A grant must not be visible to a request other than the one that created it,'
            . ' not even while a stale $GLOBALS[TYPO3_REQUEST] survives from an earlier request',
        );
    }

    /**
     * The other half of the same sequence: E2 claims the log slot, E3 must still
     * have its own. Keyed on a stale global, E2's claim silences E3.
     */
    #[Test]
    public function logSlotIsNotSharedAcrossRequestsWhileTheGlobalRequestIsStale(): void
    {
        $GLOBALS['TYPO3_REQUEST'] = $this->frontendRequest();

        $claiming = $this->contentObjectRenderer($this->eidRequest());
        $later = $this->contentObjectRenderer($this->eidRequest());

        self::assertTrue($this->subject->claimLogSlot($claiming));
        self::assertFalse($this->subject->claimLogSlot($claiming), 'One record per request, not per rejection');
        self::assertTrue(
            $this->subject->claimLogSlot($later),
            'A claim must not silence a request other than the one that made it,'
            . ' not even while a stale $GLOBALS[TYPO3_REQUEST] survives from an earlier request',
        );
    }

    /**
     * A stale global must not stand in for the renderer's own request when the
     * renderer has none — neither as the key of a grant nor as the signal that
     * picks the mode. Fail closed instead.
     *
     * The **backend-typed** case is the one the attack uses, and it is a
     * different branch from the frontend-typed one: `cms-backend`'s
     * `RequestHandler` assigns the same global that `cms-frontend`'s does, and
     * core never unsets it. In a worker SAPI a backend request therefore leaves
     * a backend-typed object behind, and the anonymous frontend render that
     * follows it — through a renderer that carries no request of its own — reads
     * that object, concludes "not a frontend request", and drops into legacy
     * mode. Legacy is precisely the pre-ADR-035 hole: every frontend-accessible
     * identifier resolves, including one an editor typed into `tt_content`.
     *
     * A frontend-typed stale global lands in strict mode either way, so a test
     * that plants only that one asserts the claim on the branch where it cannot
     * fail.
     *
     * @param 'be'|'fe' $staleType
     */
    #[Test]
    #[DataProvider('staleGlobalRequestProvider')]
    public function rendererWithoutItsOwnRequestFailsClosedDespiteAStaleGlobal(string $staleType): void
    {
        $GLOBALS['TYPO3_REQUEST'] = $staleType === 'be'
            ? $this->backendRequest()
            : $this->frontendRequest(['lib.' => ['x' => '%vault(' . self::IDENTIFIER . ')%']]);

        $cObj = $this->createMock(ContentObjectRenderer::class);
        $cObj->method('getRequest')->willThrowException(
            new RuntimeException('PSR-7 request is missing in ContentObjectRenderer.', 1607172972),
        );

        self::assertFalse($this->subject->isResolvable(self::IDENTIFIER, $cObj));

        // The same sequence through the listener: an editor-authored string
        // reaching stdWrap() in that render must keep its literal, and the
        // vault must not be touched at all.
        $vaultService = $this->createMock(VaultServiceInterface::class);
        $vaultService->expects(self::never())->method('retrieveForFrontend');

        $content = 'editor typed %vault(' . self::IDENTIFIER . ')% here';
        $event = new AfterStdWrapFunctionsExecutedEvent($content, [], $cObj);
        (new TypoScriptVaultListener($vaultService, new NullLogger(), $this->subject))($event);

        self::assertSame($content, $event->getContent());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function staleGlobalRequestProvider(): iterable
    {
        yield 'backend-typed stale global' => ['be'];
        yield 'frontend-typed stale global' => ['fe'];
    }

    /**
     * Two renders inside one request share the latch; a second request starts
     * with an unclaimed one. Without this, the pre-existing "Failed to resolve
     * vault reference" warning becomes a one-shot for the whole process: one
     * planted placeholder early in a worker's life silences every later
     * warning, including genuine misconfiguration.
     */
    #[Test]
    public function logSlotIsNotSharedAcrossRequests(): void
    {
        $firstRequest = $this->contentObjectRenderer($this->frontendRequest());
        $secondRequest = $this->contentObjectRenderer($this->frontendRequest());

        self::assertTrue($this->subject->claimLogSlot($firstRequest));
        self::assertFalse($this->subject->claimLogSlot($firstRequest), 'One record per request, not per rejection');
        self::assertTrue($this->subject->claimLogSlot($secondRequest), 'The next request must get its own slot');
    }

    /**
     * In legacy context the policy is a no-op and logging must stay exactly as
     * it was before ADR-035 — a `scheduler:run` rendering many items keeps
     * every warning.
     */
    #[Test]
    public function legacyContextNeverLatchesTheLogSlot(): void
    {
        $this->initializeWebEnvironment(cli: true);

        $cObj = $this->contentObjectRenderer($this->frontendRequest());

        self::assertTrue($this->subject->claimLogSlot($cObj));
        self::assertTrue($this->subject->claimLogSlot($cObj));
        self::assertTrue($this->subject->claimLogSlot($cObj));
    }

    #[Test]
    public function walkStopsAtTheDepthCap(): void
    {
        $shallow = $this->nest('%vault(shallow_key)%', 5);
        $deep = $this->nest('%vault(deep_key)%', 40);
        $cObj = $this->contentObjectRenderer($this->frontendRequest(['a.' => $shallow, 'b.' => $deep]));

        self::assertTrue($this->subject->isResolvable('shallow_key', $cObj));
        self::assertFalse($this->subject->isResolvable('deep_key', $cObj), 'Beyond the depth cap the set only shrinks');
    }

    #[Test]
    public function harvestStopsAtTheIdentifierCap(): void
    {
        $setup = [];
        for ($i = 0; $i < 1100; ++$i) {
            $setup['key' . $i] = \sprintf('%%vault(id_%04d)%%', $i);
        }
        $cObj = $this->contentObjectRenderer($this->frontendRequest($setup));

        self::assertTrue($this->subject->isResolvable('id_0000', $cObj));
        self::assertFalse($this->subject->isResolvable('id_1099', $cObj), 'Beyond 1000 identifiers the set only shrinks');
    }

    /**
     * The caps are exact, not approximate. One level or one identifier of
     * slack is a level or an identifier an integrator never published.
     */
    #[Test]
    public function theDepthCapIsExact(): void
    {
        $cObj = $this->contentObjectRenderer($this->frontendRequest([
            'a.' => $this->nest('%vault(at_the_cap)%', 30),
            'b.' => $this->nest('%vault(past_the_cap)%', 31),
        ]));

        self::assertTrue($this->subject->isResolvable('at_the_cap', $cObj), 'the last level inside the cap');
        self::assertFalse($this->subject->isResolvable('past_the_cap', $cObj), 'the first level beyond it');
    }

    #[Test]
    public function theIdentifierCapIsExact(): void
    {
        $setup = [];
        for ($i = 0; $i < 1000; ++$i) {
            $setup['key' . $i] = \sprintf('%%vault(id_%04d)%%', $i);
        }

        // Both harvest sources meet the full set and must refuse to add to it.
        $setup['overflow'] = '%vault(leaf_overflow)%';
        $setup['plugin.'] = ['tx_nrvault.' => ['frontendResolvableIdentifiers' => 'optin_overflow']];

        $cObj = $this->contentObjectRenderer($this->frontendRequest($setup));

        self::assertTrue($this->subject->isResolvable('id_0999', $cObj), 'the thousandth identifier still fits');
        self::assertFalse($this->subject->isResolvable('leaf_overflow', $cObj), 'the 1001st from a setup leaf');
        self::assertFalse($this->subject->isResolvable('optin_overflow', $cObj), 'the 1001st from the opt-in list');
    }

    /**
     * The walk must visit every sibling. A nested node and a leaf without a
     * placeholder are both things to skip over, not places to stop — an
     * integrator's identifier further down the same array would silently stop
     * being resolvable.
     */
    #[Test]
    public function harvestContinuesPastNestedNodesAndPlaceholderFreeLeaves(): void
    {
        $cObj = $this->contentObjectRenderer($this->frontendRequest([
            'nested.' => ['value' => '%vault(nested_key)%'],
            'plain' => 'nothing to resolve here',
            'later' => '%vault(sibling_key)%',
        ]));

        self::assertTrue($this->subject->isResolvable('nested_key', $cObj));
        self::assertTrue($this->subject->isResolvable('sibling_key', $cObj), 'a later sibling must still be harvested');
    }

    #[Test]
    public function optInListSkipsEmptyEntriesInsteadOfStoppingAtThem(): void
    {
        $cObj = $this->contentObjectRenderer($this->frontendRequest([
            'plugin.' => ['tx_nrvault.' => ['frontendResolvableIdentifiers' => ', ,' . self::IDENTIFIER]],
        ]));

        self::assertTrue($this->subject->isResolvable(self::IDENTIFIER, $cObj));
    }

    /**
     * A2 has two halves and neither is redundant: the site *configuration*
     * carries identifiers that are not settings at all.
     */
    #[Test]
    public function siteConfigurationOutsideSettingsPublishesIdentifiers(): void
    {
        $site = new Site('acme', 1, [
            'base' => 'https://example.com/',
            'websiteTitle' => '%vault(' . self::IDENTIFIER . ')%',
        ]);
        $cObj = $this->contentObjectRenderer($this->frontendRequest()->withAttribute('site', $site));

        self::assertTrue($this->subject->isResolvable(self::IDENTIFIER, $cObj));
    }

    /**
     * …and the flat settings view reaches leaves the configuration walk cannot:
     * settings are merged back into the configuration as a *tree*, so a deeply
     * nested one sits past the depth cap there while `getAllFlat()` presents it
     * one level down.
     */
    #[Test]
    public function deeplyNestedSiteSettingsAreStillHarvestedThroughTheFlatView(): void
    {
        $tree = ['value' => '%vault(' . self::IDENTIFIER . ')%'];
        for ($i = 0; $i < 40; ++$i) {
            $tree = ['level' => $tree];
        }

        $site = new Site('acme', 1, ['base' => 'https://example.com/', 'settings' => $tree]);
        $cObj = $this->contentObjectRenderer($this->frontendRequest()->withAttribute('site', $site));

        self::assertTrue($this->subject->isResolvable(self::IDENTIFIER, $cObj));
    }

    #[Test]
    public function everyIdentifierOfASitePublishesNotJustTheFirst(): void
    {
        $site = new Site('acme', 1, [
            'base' => 'https://example.com/',
            'first' => '%vault(first_site_key)%',
            'second' => '%vault(second_site_key)%',
        ]);
        $cObj = $this->contentObjectRenderer($this->frontendRequest()->withAttribute('site', $site));

        // Asked for before the first one, so a truncated set cannot be masked
        // by the memo that is filled on the way out.
        self::assertTrue($this->subject->isResolvable('second_site_key', $cObj));
        self::assertTrue($this->subject->isResolvable('first_site_key', $cObj));
    }

    #[Test]
    public function memoIsRebuiltForEachFrontendTypoScriptInstance(): void
    {
        $first = $this->contentObjectRenderer($this->frontendRequest([
            'a.' => ['value' => '%vault(first_key)%'],
        ]));
        $second = $this->contentObjectRenderer($this->frontendRequest([
            'a.' => ['value' => '%vault(second_key)%'],
        ]));

        // Same policy instance, two distinct FrontendTypoScript objects.
        self::assertTrue($this->subject->isResolvable('first_key', $first));
        self::assertTrue($this->subject->isResolvable('second_key', $second));
        self::assertFalse($this->subject->isResolvable('second_key', $first));
        self::assertFalse($this->subject->isResolvable('first_key', $second));
    }

    #[Test]
    public function unavailableSetupArrayYieldsAnEmptySetWithoutThrowing(): void
    {
        // getSetupArray() throws 1666513645 when the array was never set.
        $request = (new ServerRequest('https://example.com/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_FE)
            ->withAttribute('frontend.typoscript', new FrontendTypoScript(new RootNode(), [], [], []));

        self::assertFalse($this->subject->isResolvable(self::IDENTIFIER, $this->contentObjectRenderer($request)));
    }

    #[Test]
    public function requestWithoutTypoScriptOrSiteResolvesNothing(): void
    {
        $request = (new ServerRequest('https://example.com/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_FE);

        self::assertFalse($this->subject->isResolvable(self::IDENTIFIER, $this->contentObjectRenderer($request)));
    }

    #[Test]
    public function contextWithoutAnyRequestFailsClosed(): void
    {
        $cObj = $this->createMock(ContentObjectRenderer::class);
        $cObj->method('getRequest')->willThrowException(new RuntimeException('no request', 1607172972));

        self::assertFalse($this->subject->isResolvable(self::IDENTIFIER, $cObj));
    }

    #[Test]
    public function backendTypedRequestKeepsLegacyBehaviour(): void
    {
        $cObj = $this->contentObjectRenderer($this->backendRequest());

        self::assertTrue($this->subject->isResolvable('anything_at_all', $cObj));
    }

    /**
     * The CLI is strict at the default setting. `scheduler:run` authenticates
     * the `_cli_` admin user, so the admin bypass grants the read and this
     * allow-set is the only gate left on editor-authored content that a
     * scheduled newsletter or export job renders.
     */
    #[Test]
    public function cliEnforcesTheAllowSet(): void
    {
        $this->initializeWebEnvironment(cli: true);

        $cObj = $this->contentObjectRenderer($this->frontendRequest([
            'lib.' => ['apiKey.' => ['value' => '%vault(' . self::IDENTIFIER . ')%']],
        ]));

        self::assertTrue($this->subject->isResolvable(self::IDENTIFIER, $cObj), 'a published identifier still resolves');
        self::assertFalse($this->subject->isResolvable('anything_at_all', $cObj));
    }

    /**
     * A CLI-typed request is what the console application actually carries.
     * `ApplicationType::isFrontend()` reports false for it, so a rule that
     * asked only the request would put every scheduled render back into
     * legacy — the CLI question has to be asked separately.
     */
    #[Test]
    public function cliTypedRequestIsStrictRatherThanLegacy(): void
    {
        $this->initializeWebEnvironment(cli: true);

        $request = (new ServerRequest('https://example.com/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_CLI);

        self::assertFalse($this->subject->isResolvable('anything_at_all', $this->contentObjectRenderer($request)));
    }

    #[Test]
    public function cliWithoutAnyRequestResolvesNothing(): void
    {
        $this->initializeWebEnvironment(cli: true);

        $cObj = $this->createMock(ContentObjectRenderer::class);
        $cObj->method('getRequest')->willThrowException(new RuntimeException('no request', 1607172972));

        self::assertFalse($this->subject->isResolvable('anything_at_all', $cObj));
    }

    /**
     * The documented escape hatch for an operator whose internal render jobs
     * genuinely need the old behaviour: `frontendPlaceholderLegacyCli = 1`
     * restores the pre-ADR-035 CLI bypass byte for byte.
     */
    #[Test]
    public function legacyCliOptInRestoresTheBypass(): void
    {
        $this->initializeWebEnvironment(cli: true);

        $subject = $this->policy(legacyCli: true);
        $request = (new ServerRequest('https://example.com/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_FE);

        self::assertTrue($subject->isResolvable('anything_at_all', $this->contentObjectRenderer($request)));
    }

    /**
     * The opt-in is a CLI-only escape hatch. Turning it on must not weaken a
     * web frontend request, which is the surface ADR-035 is about.
     */
    #[Test]
    public function legacyCliOptInDoesNotWeakenAWebFrontendRequest(): void
    {
        $subject = $this->policy(legacyCli: true);

        self::assertFalse(
            $subject->isResolvable('anything_at_all', $this->contentObjectRenderer($this->frontendRequest())),
        );
    }

    /**
     * Reading the setting must not be able to open the gate through a failure,
     * and no exception may escape into `stdWrap()`.
     */
    #[Test]
    public function anUnreadableLegacyCliSettingFailsClosed(): void
    {
        $this->initializeWebEnvironment(cli: true);

        $extensionConfiguration = $this->createMock(ExtensionConfigurationInterface::class);
        $extensionConfiguration->method('isFrontendPlaceholderLegacyCliEnabled')
            ->willThrowException(new RuntimeException('configuration unavailable', 1754000001));

        $subject = new FrontendPlaceholderPolicy($extensionConfiguration);
        $request = (new ServerRequest('https://example.com/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_FE);

        self::assertFalse($subject->isResolvable('anything_at_all', $this->contentObjectRenderer($request)));
    }

    /**
     * The latch stays off on the CLI whatever the opt-in says. A long-running
     * `scheduler:run` handles many renders under one request object, so a latch
     * keyed on that object would be a process-wide log blackout an attacker
     * triggers with one planted placeholder.
     */
    #[Test]
    #[DataProvider('legacyCliSettingProvider')]
    public function cliNeverLatchesTheLogSlot(bool $legacyCli): void
    {
        $this->initializeWebEnvironment(cli: true);

        $subject = $this->policy(legacyCli: $legacyCli);
        $cObj = $this->contentObjectRenderer($this->frontendRequest());

        self::assertTrue($subject->claimLogSlot($cObj));
        self::assertTrue($subject->claimLogSlot($cObj), 'the CLI must keep every warning of a long-running process');
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function legacyCliSettingProvider(): iterable
    {
        yield 'strict CLI' => [false];
        yield 'legacy CLI opt-in' => [true];
    }

    #[Test]
    public function logSlotIsClaimedExactlyOncePerRequest(): void
    {
        $cObj = $this->contentObjectRenderer($this->frontendRequest());

        self::assertTrue($this->subject->claimLogSlot($cObj));
        self::assertFalse($this->subject->claimLogSlot($cObj));
        self::assertFalse($this->subject->claimLogSlot($cObj));
    }

    /**
     * Regex parity is the bypass surface: whatever identifier the listener
     * extracts from a string, the harvester must extract from the same string.
     * A laxer harvester would over-block, a stricter one would be bypassable.
     */
    #[Test]
    #[DataProvider('trickyPlaceholderProvider')]
    public function listenerAndHarvesterExtractTheSameIdentifiers(string $content): void
    {
        // The very same string is the authored setup leaf and the rendered
        // content, so every placeholder the listener sees is published.
        $cObj = $this->contentObjectRenderer($this->frontendRequest(['lib.' => ['x' => $content]]));

        $vaultService = $this->createMock(VaultServiceInterface::class);
        $vaultService->method('retrieveForFrontend')->willReturn('RESOLVED');

        $listener = new TypoScriptVaultListener($vaultService, new NullLogger(), $this->subject);
        $event = new AfterStdWrapFunctionsExecutedEvent($content, [], $cObj);
        $listener($event);

        self::assertStringNotContainsString(
            '%vault(',
            (string) $event->getContent(),
            'The harvester missed an identifier the listener matched',
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function trickyPlaceholderProvider(): iterable
    {
        yield 'plain' => ['%vault(plain_key)%'];
        yield 'surrounding whitespace' => ['%vault(  spaced_key  )%'];
        yield 'two on one line' => ['%vault(a_key)% and %vault(b_key)%'];
        yield 'dots and dashes' => ['%vault(my-api_key.v2)%'];
        yield 'uuid v7' => ['%vault(0195b2c1-0f3a-7c2b-9e11-a1b2c3d4e5f6)%'];
        yield 'inside markup' => ['<script>var k = "%vault(embedded_key)%";</script>'];
        yield 'percent noise' => ['100%% %vault(noisy_key)% %'];
        yield 'adjacent' => ['%vault(one_key)%%vault(two_key)%'];
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /**
     * A policy wired to an extension configuration that reports the given
     * `frontendPlaceholderLegacyCli` value — the real opt-in, not a test seam.
     */
    private function policy(bool $legacyCli = false): FrontendPlaceholderPolicy
    {
        $extensionConfiguration = $this->createMock(ExtensionConfigurationInterface::class);
        $extensionConfiguration->method('isFrontendPlaceholderLegacyCliEnabled')->willReturn($legacyCli);

        return new FrontendPlaceholderPolicy($extensionConfiguration);
    }

    /**
     * @param array<mixed> $setup
     */
    private function frontendRequest(array $setup = []): ServerRequestInterface
    {
        $frontendTypoScript = new FrontendTypoScript(new RootNode(), [], [], []);
        $frontendTypoScript->setSetupArray($setup);

        return (new ServerRequest('https://example.com/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_FE)
            ->withAttribute('frontend.typoscript', $frontendTypoScript);
    }

    /**
     * What `cms-backend`'s `RequestHandler` leaves in
     * `$GLOBALS['TYPO3_REQUEST']` after a backend request, and what a backend
     * renderer carries.
     */
    private function backendRequest(): ServerRequestInterface
    {
        return (new ServerRequest('https://example.com/typo3/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_BE);
    }

    /**
     * The eID shape: frontend-typed, no `frontend.typoscript`, no `site`. A4 is
     * the only allow-set source there.
     */
    private function eidRequest(): ServerRequestInterface
    {
        return (new ServerRequest('https://example.com/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_FE);
    }

    private function contentObjectRenderer(ServerRequestInterface $request): ContentObjectRenderer
    {
        $cObj = $this->createMock(ContentObjectRenderer::class);
        $cObj->method('getRequest')->willReturn($request);

        return $cObj;
    }

    /**
     * @return array<string, mixed>
     */
    private function nest(string $leaf, int $depth): array
    {
        $node = ['value' => $leaf];
        for ($i = 0; $i < $depth; ++$i) {
            $node = ['level.' => $node];
        }

        return $node;
    }

    private function initializeWebEnvironment(bool $cli = false): void
    {
        $projectPath = \dirname(__DIR__, 3);

        Environment::initialize(
            new ApplicationContext('Testing'),
            $cli,
            false,
            $projectPath,
            $projectPath . '/.Build/public',
            $projectPath . '/.Build/var',
            $projectPath . '/.Build/config',
            $projectPath . '/.Build/public/index.php',
            'UNIX',
        );
    }
}
