<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\EventListener;

use Netresearch\NrVault\EventListener\TypoScriptVaultListener;
use Netresearch\NrVault\Security\FrontendPlaceholderPolicy;
use Netresearch\NrVault\Security\FrontendPlaceholderPolicyInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Core\Core\ApplicationContext;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Core\Site\Entity\Site;
use TYPO3\CMS\Core\TypoScript\AST\Node\RootNode;
use TYPO3\CMS\Core\TypoScript\FrontendTypoScript;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Frontend\Cache\CacheInstruction;
use TYPO3\CMS\Frontend\ContentObject\ContentObjectRenderer;

/**
 * Drives the real ContentObjectRenderer::stdWrap() / TextContentObject::render()
 * path — not a hand-built event — to pin which %vault()% placeholders resolve in
 * which context.
 *
 * The two pre-existing listener test files hand-build the event under PHPUnit,
 * where `Environment::isCli()` is true, so the policy reports LEGACY and those
 * files stay green without covering anything below. Every strict-mode case here
 * therefore re-initialises `Environment` with `cli = false` for the duration of
 * one closure.
 *
 * @see FrontendPlaceholderPolicy
 */
#[CoversClass(TypoScriptVaultListener::class)]
#[CoversClass(FrontendPlaceholderPolicy::class)]
final class TypoScriptVaultListenerFrontendScopeTest extends AbstractVaultFunctionalTestCase
{
    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    private const SECRET_VALUE = 'super-secret-frontend-value';

    /** @var array<string, bool> */
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

    /** @var array<string, mixed> */
    private array $environmentBackup = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->environmentBackup = [
            'context' => Environment::getContext(),
            'isCli' => Environment::isCli(),
            'composerMode' => Environment::isComposerMode(),
            'projectPath' => Environment::getProjectPath(),
            'publicPath' => Environment::getPublicPath(),
            'varPath' => Environment::getVarPath(),
            'configPath' => Environment::getConfigPath(),
            'currentScript' => Environment::getCurrentScript(),
            'isWindows' => Environment::isWindows(),
        ];
    }

    protected function tearDown(): void
    {
        $this->restoreEnvironment();
        unset($GLOBALS['TYPO3_REQUEST']);

        parent::tearDown();
    }

    // -----------------------------------------------------------------
    // Must FAIL against the pre-fix listener — these demonstrate the fix.
    // -----------------------------------------------------------------

    /**
     * T-F1 — the exploit. An editor-authored `tt_content` field carrying a
     * placeholder for a frontend-accessible secret whose identifier appears
     * nowhere in an admin-only source.
     */
    #[Test]
    public function editorAuthoredPlaceholderDoesNotResolveInFrontendRequest(): void
    {
        $identifier = $this->storeSecret('leaked_key_', self::FRONTEND_ACCESSIBLE);
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);
        $auditRowsBefore = $this->countAuditRows($identifier);

        $output = $this->inWebContext(fn (): string => $this->renderText(
            ['field' => 'bodytext'],
            $this->frontendRequest(['lib.' => ['unrelated' => 'nothing to see']]),
            ['bodytext' => $placeholder],
        ));

        self::assertSame($placeholder, $output, 'Editor content must not be a resolution site');
        self::assertSame($auditRowsBefore, $this->countAuditRows($identifier), 'The vault must not be reached at all');
    }

    /**
     * T-F2 — reflected request data. `data = GP:q` puts an unauthenticated
     * query parameter through stdWrap.
     */
    #[Test]
    public function reflectedRequestParameterDoesNotResolveInFrontendRequest(): void
    {
        $identifier = $this->storeSecret('reflected_key_', self::FRONTEND_ACCESSIBLE);
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);
        $auditRowsBefore = $this->countAuditRows($identifier);

        $request = $this->frontendRequest()->withQueryParams(['q' => $placeholder]);

        $output = $this->inWebContext(fn (): string => $this->renderText(['data' => 'GP:q'], $request));

        self::assertSame($placeholder, $output, 'Reflected request data must not be a resolution site');
        self::assertSame($auditRowsBefore, $this->countAuditRows($identifier), 'The vault must not be reached at all');
    }

    /**
     * T-F3 — bounded cost. 100 rejected occurrences naming a secret that
     * exists but is not frontend-accessible must add no audit rows at all and
     * must not consume the single log slot in a non-Development context.
     *
     * Pre-fix this is 100 `AccessDenied` INSERTs (each taking the audit chain
     * lock) and 100 warning records.
     */
    #[Test]
    public function hundredRejectionsWriteNoAuditRowsAndEmitNoRecordOutsideDevelopment(): void
    {
        $identifier = $this->storeSecret('withheld_key_');
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);

        $before = $this->countAuditRows($identifier);
        $request = $this->frontendRequest();

        /** @var array{0: string, 1: bool} $result */
        $result = $this->inWebContext(fn (): array => [
            $this->renderText(
                ['field' => 'bodytext'],
                $request,
                ['bodytext' => str_repeat($placeholder, 100)],
            ),
            $this->claimLogSlotFor($request),
        ]);

        self::assertSame(str_repeat($placeholder, 100), $result[0]);
        self::assertSame($before, $this->countAuditRows($identifier), '100 rejections must add 0 audit rows');
        self::assertTrue(
            $result[1],
            'Outside Development the skip path must emit no record, so this request\'s log slot is still unclaimed',
        );
    }

    /**
     * T-F3b — in Development the same input yields exactly one record: the
     * latch is claimed once and never again *within that request*. A second
     * request gets its own slot, so a planted placeholder cannot black out the
     * rest of a worker process.
     */
    #[Test]
    public function hundredRejectionsEmitAtMostOneRecordInDevelopmentWithoutSilencingTheNextRequest(): void
    {
        $identifier = $this->storeSecret('withheld_dev_key_');
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);

        $firstRequest = $this->frontendRequest();

        $slotAfterFirstRequest = $this->inWebContext(function () use ($firstRequest, $placeholder): bool {
            $this->renderText(
                ['field' => 'bodytext'],
                $firstRequest,
                ['bodytext' => str_repeat($placeholder, 100)],
            );

            return $this->claimLogSlotFor($firstRequest);
        }, 'Development');

        self::assertFalse(
            $slotAfterFirstRequest,
            'Exactly one record for any number of rejections — this request\'s latch is already claimed',
        );

        $secondRequest = $this->frontendRequest();
        $slotOfSecondRequest = $this->inWebContext(fn (): bool => $this->claimLogSlotFor($secondRequest), 'Development');

        self::assertTrue(
            $slotOfSecondRequest,
            'The next request must still be able to log — the latch is per request, not per process',
        );
    }

    /**
     * The A4 grant is bound to the request it was made for. On a shared policy
     * instance — which is what DI hands out — a grant from an earlier request
     * must not authorise a later, anonymous one.
     */
    #[Test]
    public function allowIdentifierGrantDoesNotSurviveIntoTheNextRequest(): void
    {
        $identifier = $this->storeSecret('scoped_runtime_key_', self::FRONTEND_ACCESSIBLE);
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);

        $grantingRequest = $this->eidShapedRequest();
        $this->get(FrontendPlaceholderPolicyInterface::class)->allowIdentifier($identifier, $grantingRequest);

        $granted = $this->inWebContext(fn (): string => $this->renderText(
            ['field' => 'bodytext'],
            $grantingRequest,
            ['bodytext' => $placeholder],
        ));

        self::assertSame(self::SECRET_VALUE, $granted, 'The granting request resolves its own grant');

        $laterRequest = $this->eidShapedRequest();
        $later = $this->inWebContext(fn (): string => $this->renderText(
            ['field' => 'bodytext'],
            $laterRequest,
            ['bodytext' => $placeholder],
        ));

        self::assertSame($placeholder, $later, 'A later request must not inherit the previous request\'s grant');
    }

    /**
     * The reproduced attack sequence, through the real `stdWrap()`.
     *
     * R1 is a frontend request that has finished. Core assigns
     * `$GLOBALS['TYPO3_REQUEST']` in `cms-frontend`'s `RequestHandler` and never
     * unsets it, so in a worker SAPI it still points at R1 while E2 and E3 are
     * handled — this test leaves it set for exactly that reason.
     *
     * E2 is an eID request applying the documented A4 remedy for its own
     * request. E3 is the next eID request in the same worker; it must see
     * neither E2's grant nor E2's claimed log slot.
     */
    #[Test]
    public function grantAndLogSlotDoNotReachTheNextRequestWhileTheGlobalRequestIsStale(): void
    {
        $identifier = $this->storeSecret('stale_global_key_', self::FRONTEND_ACCESSIBLE);
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);

        // R1 ended; its request object survives in the global.
        $GLOBALS['TYPO3_REQUEST'] = $this->frontendRequest();

        $grantingRequest = $this->eidShapedRequestKeepingTheGlobal();
        $this->get(FrontendPlaceholderPolicyInterface::class)->allowIdentifier($identifier, $grantingRequest);

        $granted = $this->inWebContext(fn (): string => $this->renderText(
            ['field' => 'bodytext'],
            $grantingRequest,
            ['bodytext' => $placeholder],
        ));

        self::assertSame(self::SECRET_VALUE, $granted, 'The granting request resolves its own grant');
        self::assertTrue($this->inWebContext(fn (): bool => $this->claimLogSlotFor($grantingRequest)));
        self::assertFalse(
            $this->inWebContext(fn (): bool => $this->claimLogSlotFor($grantingRequest)),
            'One record per request, not per rejection',
        );

        $laterRequest = $this->eidShapedRequestKeepingTheGlobal();

        $later = $this->inWebContext(fn (): string => $this->renderText(
            ['field' => 'bodytext'],
            $laterRequest,
            ['bodytext' => $placeholder],
        ));

        self::assertSame(
            $placeholder,
            $later,
            'A grant must not be visible to a request other than the one that created it,'
            . ' not even while a stale $GLOBALS[TYPO3_REQUEST] survives',
        );
        self::assertTrue(
            $this->inWebContext(fn (): bool => $this->claimLogSlotFor($laterRequest)),
            'A claim must not silence a request other than the one that made it',
        );
    }

    /**
     * T-F4 — the eID shape: a frontend-typed request that carries neither
     * `frontend.typoscript` nor `site`, with `$GLOBALS['TYPO3_REQUEST']` unset.
     * Fail-closed.
     */
    #[Test]
    public function frontendRequestWithoutTypoScriptOrSiteResolvesNothing(): void
    {
        $identifier = $this->storeSecret('eid_key_', self::FRONTEND_ACCESSIBLE);
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);
        $auditRowsBefore = $this->countAuditRows($identifier);

        unset($GLOBALS['TYPO3_REQUEST']);
        /** @phpstan-ignore new.internalClass, method.internalClass, classConstant.internalClass */
        $request = (new ServerRequest('https://example.com/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_FE);

        $output = $this->inWebContext(fn (): string => $this->renderText(['value' => $placeholder, 'stdWrap.' => ['noTrimWrap' => '||']], $request));

        self::assertSame($placeholder, $output, 'An unidentifiable frontend context must fail closed');
        self::assertSame($auditRowsBefore, $this->countAuditRows($identifier));
    }

    // -----------------------------------------------------------------
    // Must PASS before and after — regression gates.
    // -----------------------------------------------------------------

    /**
     * T-A1 — the Attempt-1 gate. The documented `stdWrap.cache.disable = 1`
     * snippet, driven through the real TextContentObject::render(), which
     * `unset()`s `value` before the surviving `stdWrap.` sub-array reaches
     * `stdWrap()`. Any gate that reads the cObj configuration breaks here.
     */
    #[Test]
    public function documentedCacheDisableSnippetStillResolves(): void
    {
        $identifier = $this->storeSecret('documented_key_', self::FRONTEND_ACCESSIBLE);
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);

        $conf = [
            'value' => $placeholder,
            'stdWrap.' => ['cache.' => ['disable' => '1']],
        ];

        // The identifier is a string leaf of the setup array — exactly what the
        // integrator authored in `lib.apiKey.value`.
        $request = $this->frontendRequest(['lib.' => ['apiKey' => 'TEXT', 'apiKey.' => $conf]]);

        $output = $this->inWebContext(fn (): string => $this->renderText($conf, $request));

        self::assertSame(self::SECRET_VALUE, $output);
    }

    /**
     * T-C1 — characterization of a pre-existing docs defect: a bare
     * `lib.x.value = %vault(k)%` with no other property never reaches
     * `stdWrap()` at all, because `TextContentObject::render()` unsets `value`
     * and then finds an empty `$conf`. Unchanged by this fix; pinned so the
     * documentation correction is provably a docs fix.
     */
    #[Test]
    public function bareValueOnlySnippetNeverReachedStdWrapAndStaysLiteral(): void
    {
        $identifier = $this->storeSecret('bare_value_key_', self::FRONTEND_ACCESSIBLE);
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);

        $request = $this->frontendRequest(['lib.' => ['x.' => ['value' => $placeholder]]]);

        $output = $this->inWebContext(fn (): string => $this->renderText(['value' => $placeholder], $request));

        self::assertSame($placeholder, $output, 'No stdWrap call, so the listener never runs');
    }

    /**
     * T-B1 — a backend-typed request keeps today's behaviour.
     */
    #[Test]
    public function backendTypedRequestResolvesAsBefore(): void
    {
        $identifier = $this->storeSecret('backend_key_', self::FRONTEND_ACCESSIBLE);
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);

        /** @phpstan-ignore new.internalClass, method.internalClass, classConstant.internalClass */
        $request = (new ServerRequest('https://example.com/typo3/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_BE);

        $output = $this->inWebContext(fn (): string => $this->renderText(
            ['field' => 'bodytext'],
            $request,
            ['bodytext' => $placeholder],
        ));

        self::assertSame(self::SECRET_VALUE, $output, 'Backend scope stays LEGACY (residual R-7)');
    }

    /**
     * T-B2 — CLI (scheduler, Messenger, PHPUnit) keeps today's behaviour.
     */
    #[Test]
    public function cliContextResolvesAsBefore(): void
    {
        $identifier = $this->storeSecret('cli_key_', self::FRONTEND_ACCESSIBLE);
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);

        // No inWebContext() wrapper: Environment::isCli() is true under PHPUnit.
        $output = $this->renderText(['field' => 'bodytext'], $this->frontendRequest(), ['bodytext' => $placeholder]);

        self::assertSame(self::SECRET_VALUE, $output);
    }

    // -----------------------------------------------------------------
    // New-path coverage: the four allow-set sources.
    // -----------------------------------------------------------------

    /**
     * A1 — the identifier is a string leaf of the frontend setup array.
     */
    #[Test]
    public function identifierPublishedInTypoScriptSetupResolves(): void
    {
        $identifier = $this->storeSecret('setup_key_', self::FRONTEND_ACCESSIBLE);
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);

        $request = $this->frontendRequest(['page.' => ['10.' => ['value' => $placeholder]]]);

        $output = $this->inWebContext(fn (): string => $this->renderText(
            ['field' => 'bodytext'],
            $request,
            ['bodytext' => $placeholder],
        ));

        self::assertSame(self::SECRET_VALUE, $output);
    }

    /**
     * A2 — the identifier is published through site configuration / settings.
     */
    #[Test]
    public function identifierPublishedInSiteConfigurationResolves(): void
    {
        $identifier = $this->storeSecret('site_key_', self::FRONTEND_ACCESSIBLE);
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);

        $site = new Site('acme', 1, [
            'base' => 'https://example.com/',
            'rootPageId' => 1,
            'settings' => ['payment' => ['stripeSecretKey' => $placeholder]],
        ]);
        $request = $this->frontendRequest()->withAttribute('site', $site);

        $output = $this->inWebContext(fn (): string => $this->renderText(
            ['field' => 'bodytext'],
            $request,
            ['bodytext' => $placeholder],
        ));

        self::assertSame(self::SECRET_VALUE, $output);
    }

    /**
     * A3 — the explicit `plugin.tx_nrvault.frontendResolvableIdentifiers` list.
     */
    #[Test]
    public function identifierPublishedInOptInListResolves(): void
    {
        $identifier = $this->storeSecret('optin_key_', self::FRONTEND_ACCESSIBLE);
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);

        $request = $this->frontendRequest([
            'plugin.' => [
                'tx_nrvault.' => ['frontendResolvableIdentifiers' => 'other_one, ' . $identifier],
            ],
        ]);

        $output = $this->inWebContext(fn (): string => $this->renderText(
            ['field' => 'bodytext'],
            $request,
            ['bodytext' => $placeholder],
        ));

        self::assertSame(self::SECRET_VALUE, $output);
    }

    /**
     * A4 — integrator PHP publishes the identifier for this request.
     */
    #[Test]
    public function identifierPublishedViaAllowIdentifierResolves(): void
    {
        $identifier = $this->storeSecret('runtime_key_', self::FRONTEND_ACCESSIBLE);
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);

        // No frontend.typoscript and no site — the eID shape, where A4 is the
        // only available source.
        $request = $this->eidShapedRequest();
        $this->get(FrontendPlaceholderPolicyInterface::class)->allowIdentifier($identifier, $request);

        $output = $this->inWebContext(fn (): string => $this->renderText(
            ['field' => 'bodytext'],
            $request,
            ['bodytext' => $placeholder],
        ));

        self::assertSame(self::SECRET_VALUE, $output);
    }

    /**
     * A `FrontendTypoScript` that claims a setup but cannot produce it must
     * yield a smaller set, never an exception escaping stdWrap().
     */
    #[Test]
    public function unavailableSetupArrayFailsClosedWithoutThrowing(): void
    {
        $identifier = $this->storeSecret('unavailable_key_', self::FRONTEND_ACCESSIBLE);
        $placeholder = \sprintf('%%vault(%s)%%', $identifier);

        // getSetupArray() throws 1666513645 when setSetupArray() was never called.
        /** @phpstan-ignore new.internalClass */
        $frontendTypoScript = new FrontendTypoScript(new RootNode(), [], [], []);
        /** @phpstan-ignore new.internalClass, method.internalClass, classConstant.internalClass */
        $request = (new ServerRequest('https://example.com/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_FE)
            ->withAttribute('frontend.typoscript', $frontendTypoScript);
        unset($GLOBALS['TYPO3_REQUEST']);

        $output = $this->inWebContext(fn (): string => $this->renderText(
            ['field' => 'bodytext'],
            $request,
            ['bodytext' => $placeholder],
        ));

        self::assertSame($placeholder, $output);
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /**
     * @param array<string, bool> $options
     */
    private function storeSecret(string $prefix, array $options = []): string
    {
        $identifier = $prefix . bin2hex(random_bytes(4));
        $this->get(VaultServiceInterface::class)->store($identifier, self::SECRET_VALUE, $options);

        return $identifier;
    }

    /**
     * Build a frontend-typed request carrying a real FrontendTypoScript whose
     * setup array is the given tree.
     *
     * @param array<mixed> $setup
     */
    private function frontendRequest(array $setup = []): ServerRequestInterface
    {
        $frontendTypoScript = new FrontendTypoScript(new RootNode(), [], [], []);
        $frontendTypoScript->setSetupArray($setup);
        // stdWrap's `cache.` implementation reads `config.`; without it the
        // T-A1 snippet cannot run at all.
        $frontendTypoScript->setConfigArray([]);

        $request = (new ServerRequest('https://example.com/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_FE)
            ->withAttribute('frontend.cache.instruction', new CacheInstruction())
            ->withAttribute('frontend.typoscript', $frontendTypoScript);

        // The listener must work off the request the cObj carries; make sure a
        // stale global cannot answer for it.
        unset($GLOBALS['TYPO3_REQUEST']);

        return $request;
    }

    /**
     * A frontend-typed request carrying neither `frontend.typoscript` nor
     * `site`, with `$GLOBALS['TYPO3_REQUEST']` unset — the eID shape, where A4
     * is the only allow-set source.
     */
    private function eidShapedRequest(): ServerRequestInterface
    {
        unset($GLOBALS['TYPO3_REQUEST']);

        return (new ServerRequest('https://example.com/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_FE)
            ->withAttribute('frontend.cache.instruction', new CacheInstruction());
    }

    /**
     * The eID shape, but without touching `$GLOBALS['TYPO3_REQUEST']` — the
     * caller has deliberately left a stale request there.
     */
    private function eidShapedRequestKeepingTheGlobal(): ServerRequestInterface
    {
        return (new ServerRequest('https://example.com/'))
            ->withAttribute('applicationType', SystemEnvironmentBuilder::REQUESTTYPE_FE)
            ->withAttribute('frontend.cache.instruction', new CacheInstruction());
    }

    /**
     * Ask the shared policy instance for the log slot of one specific request.
     */
    private function claimLogSlotFor(ServerRequestInterface $request): bool
    {
        $contentObjectRenderer = GeneralUtility::makeInstance(ContentObjectRenderer::class);
        /** @phpstan-ignore method.internal */
        $contentObjectRenderer->setRequest($request);

        return $this->get(FrontendPlaceholderPolicyInterface::class)->claimLogSlot($contentObjectRenderer);
    }

    /**
     * Render a TEXT content object through the real ContentObjectRenderer.
     *
     * @param array<mixed> $conf
     * @param array<string, mixed> $data
     */
    private function renderText(array $conf, ServerRequestInterface $request, array $data = []): string
    {
        $contentObjectRenderer = GeneralUtility::makeInstance(ContentObjectRenderer::class);
        /** @phpstan-ignore method.internal */
        $contentObjectRenderer->setRequest($request);
        $contentObjectRenderer->start($data, 'tt_content');

        return (string) $contentObjectRenderer->cObjGetSingle('TEXT', $conf);
    }

    /**
     * Run the callback with `Environment::isCli()` forced false, i.e. in a web
     * context. PHPUnit itself always runs on the CLI SAPI, so without this the
     * policy reports LEGACY and no strict-mode assertion means anything.
     *
     * @template T
     *
     * @param callable(): T $callback
     *
     * @return T
     */
    private function inWebContext(callable $callback, string $context = 'Testing')
    {
        Environment::initialize(
            new ApplicationContext($context),
            false,
            $this->environmentBackup['composerMode'],
            $this->environmentBackup['projectPath'],
            $this->environmentBackup['publicPath'],
            $this->environmentBackup['varPath'],
            $this->environmentBackup['configPath'],
            $this->environmentBackup['currentScript'],
            $this->environmentBackup['isWindows'] ? 'WINDOWS' : 'UNIX',
        );

        try {
            return $callback();
        } finally {
            $this->restoreEnvironment();
        }
    }

    private function restoreEnvironment(): void
    {
        if ($this->environmentBackup === []) {
            return;
        }

        Environment::initialize(
            $this->environmentBackup['context'],
            $this->environmentBackup['isCli'],
            $this->environmentBackup['composerMode'],
            $this->environmentBackup['projectPath'],
            $this->environmentBackup['publicPath'],
            $this->environmentBackup['varPath'],
            $this->environmentBackup['configPath'],
            $this->environmentBackup['currentScript'],
            $this->environmentBackup['isWindows'] ? 'WINDOWS' : 'UNIX',
        );
    }

    private function countAuditRows(string $identifier): int
    {
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)
            ->getQueryBuilderForTable(self::AUDIT_TABLE);

        return (int) $queryBuilder
            ->count('uid')
            ->from(self::AUDIT_TABLE)
            ->where(
                $queryBuilder->expr()->eq(
                    'secret_identifier',
                    $queryBuilder->createNamedParameter($identifier),
                ),
            )
            ->executeQuery()
            ->fetchOne();
    }
}
