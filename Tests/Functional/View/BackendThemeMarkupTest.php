<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\View;

use DOMDocument;
use DOMElement;
use DOMNodeList;
use DOMXPath;
use PHPUnit\Framework\Attributes\DataProvider;
use TYPO3\CMS\Core\Cache\CacheManager;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;
use TYPO3\CMS\Core\Page\AssetCollector;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\View\ViewFactoryData;
use TYPO3\CMS\Core\View\ViewFactoryInterface;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * Pins the markup that makes the module follow the TYPO3 backend colour scheme.
 *
 * The backend decides light or dark through its own tokens (`--typo3-*`), and
 * only core component classes read them. Bootstrap utilities such as `.bg-*`,
 * `.text-bg-*`, `.alert`, `.progress` or `.accordion` either keep one colour pair
 * in both schemes or are not part of the core backend CSS at all, so each
 * assertion here names the core class a view must use and the one it must not.
 */
final class BackendThemeMarkupTest extends FunctionalTestCase
{
    private const OVERVIEW = 'Overview/Index';

    private const REVIEW = 'Migration/Review';

    /**
     * Stand-in for the core `Module` layout: renders the `Content` section only.
     * The core layout needs a module request, and the markup under test is ours.
     * Written at runtime so no Fluid file outside Resources/Private reaches the
     * HTML analysers, which read Fluid as a standalone page.
     */
    private const MODULE_LAYOUT = '<html xmlns:f="http://typo3.org/ns/TYPO3/CMS/Fluid/ViewHelpers" data-namespace-typo3-fluid="true">'
        . '<f:render section="Content" /></html>';

    /** @var array<non-empty-string> */
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
    ];

    /** @var array<non-empty-string> */
    protected array $coreExtensionsToLoad = [
        'backend',
        'fluid',
    ];

    public function testTheBreakGlassBannerIsACoreDangerCallout(): void
    {
        $html = $this->renderPartial('BreakGlassBanner', [
            'breakGlass' => [
                'active' => true,
                'username' => 'admin',
                'reason' => 'incident 42',
                'expiresAt' => '2026-09-27 12:00',
                'remainingMinutes' => 30,
            ],
        ]);

        self::assertStringContainsString('class="callout callout-danger mb-4"', $html);
        self::assertStringContainsString('<h2 class="callout-title">', $html);
        self::assertStringContainsString('class="callout-body"', $html);
        self::assertStringNotContainsString('alert', str_replace('role="alert"', '', $html));
        // The icon core's ContextualFeedbackSeverity::ERROR gives danger callouts
        // (13.4.35 and 14.3.7), inside the callout-icon slot f:be.infobox renders.
        $iconSlot = $this->between($html, 'class="callout-icon"', 'class="callout-content"');
        self::assertStringContainsString('actions-close', $iconSlot);
        self::assertStringNotContainsString('actions-exclamation-triangle', $iconSlot);
    }

    public function testTheSubmoduleCardIconsAreInlinedSoTheyTakeTheTextColour(): void
    {
        $html = $this->renderTemplate(self::OVERVIEW, $this->overviewVariables());

        // As <img>, a currentColor glyph cannot inherit anything and paints black:
        // dominant ink #080808 on the dark card, 1.18:1, measured with a screenshot
        // of the card icon on TYPO3 14.3.7. Inline, it takes the card's text colour.
        self::assertStringContainsString('<svg', $this->between($html, 'class="card-icon"', 'class="card-header-body"'));
        self::assertStringNotContainsString('<img', $this->between($html, 'class="card-icon"', 'class="card-header-body"'));
    }

    public function testTheOverviewUsesCoreCalloutsTablesAndAnExistingIcon(): void
    {
        $html = $this->renderTemplate(self::OVERVIEW, $this->overviewVariables(masterKeyAvailable: false));

        // The help link in the health callout targets the overview submodule's
        // help route: TYPO3 13.4 reroutes `admin_vault.help` to a submodule.
        self::assertStringContainsString('/module/admin/vault/overview/help', $html);

        self::assertStringContainsString('class="callout callout-danger mb-4"', $html);
        self::assertStringContainsString('<h2 class="callout-title">', $html);
        self::assertStringNotContainsString('<h4', $html);
        self::assertStringNotContainsString('alert-', $html);
        self::assertStringNotContainsString('table-sm', $html);
        self::assertStringNotContainsString('text-body-secondary', $html);
        // `mimetypes-x-content-site-config` is not a core icon: it rendered the
        // red default-not-found glyph.
        self::assertStringNotContainsString('default-not-found', $html);
    }

    public function testTheHealthyStateIsACoreSuccessCallout(): void
    {
        $html = $this->renderTemplate(self::OVERVIEW, $this->overviewVariables());

        self::assertStringContainsString('class="callout callout-success mb-4"', $html);
        self::assertStringNotContainsString('alert-', $html);
    }

    public function testEveryDistributionBarHasAnAccessibleNameAndNoBootstrapProgress(): void
    {
        $html = $this->renderTemplate('Analytics/Index', [
            'windowOptions' => [],
            'stats' => [
                'total' => 2, 'expired' => 0, 'frontendAccessible' => 0, 'neverRotated' => 0,
                'automatedReads' => 0, 'manualReveals' => 0,
                'byAdapter' => [['label' => 'local', 'value' => 2, 'percent' => 100]],
                'byContext' => [['label' => 'payment', 'value' => 1, 'percent' => 50]],
            ],
            'candidateCount' => 0,
            'candidates' => [],
        ]);

        // Native <progress>: it carries the progressbar role, the value, the
        // range and the name itself, so no element may carry them by ARIA.
        $bars = $this->progressBars($html);
        self::assertSame([
            ['value' => '100', 'max' => '100', 'name' => 'local', 'valuetext' => '2 (100%)'],
            ['value' => '50', 'max' => '100', 'name' => 'payment', 'valuetext' => '1 (50%)'],
        ], $bars);
        self::assertStringNotContainsString('role="progressbar"', $html);
        self::assertStringNotContainsString('aria-valuenow', $html);
        self::assertStringNotContainsString('class="progress', $html);
        self::assertStringNotContainsString('text-body-secondary', $html);
    }

    public function testTheFaqUsesNativeDisclosureWidgets(): void
    {
        $html = $this->renderTemplate('Overview/Help', ['dashboardUrl' => '/typo3/module/dashboard']);

        self::assertSame(4, substr_count($html, '<details class="vault-faq'));
        self::assertSame(4, substr_count($html, '<summary>'));
        // One shared name: opening an item closes the others, as the accordion did.
        self::assertSame(4, substr_count($html, 'name="vault-faq"'));
        self::assertStringNotContainsString('class="accordion', $html);
        self::assertStringNotContainsString('data-bs-toggle', $html);
    }

    public function testTheSecretsListPaintsStatusWithCoreBadges(): void
    {
        $html = $this->renderTemplate('Secrets/List', [
            'breakGlass' => ['active' => false],
            'filters' => [],
            'ownerOptions' => [],
            'totalCount' => 2,
            'canReveal' => false, 'canManagePolicy' => false, 'canRotate' => false, 'canDelete' => false,
            'secrets' => [
                $this->secretRow('api_active', hidden: false),
                $this->secretRow('api_disabled', hidden: true),
            ],
        ]);

        self::assertStringContainsString('class="badge badge-info" aria-label="2 secrets found"', $html);
        self::assertSame('badge badge-success', $this->badgeClassFor($html, 'Active'));
        self::assertSame('badge badge-default', $this->badgeClassFor($html, 'Disabled'));
        $this->assertNoFixedColourBadge($html);
    }

    public function testMigrationScanMapsEachSeverityToItsCoreBadge(): void
    {
        $item = static fn (string $pattern, int $count): array => ['patterns' => [$pattern], 'source' => 'database', 'count' => $count];
        $html = $this->renderTemplate('Migration/Scan', [
            'totalCount' => 4, 'databaseCount' => 4, 'configCount' => 0,
            'groupedSecrets' => [
                'critical' => ['tx_a.password' => $item('password', 3)],
                'high' => ['tx_b.api_key' => $item('api_key', 5)],
                'medium' => ['tx_c.token' => $item('token', 7)],
                'low' => ['tx_d.secret' => $item('secret', 9)],
            ],
        ]);

        self::assertSame('badge badge-danger', $this->badgeClassFor($html, 'Critical'));
        self::assertSame('badge badge-warning', $this->badgeClassFor($html, 'High'));
        self::assertSame('badge badge-info', $this->badgeClassFor($html, 'Medium'));
        self::assertSame('badge badge-default', $this->badgeClassFor($html, 'Low'));
        self::assertSame('badge badge-default', $this->badgeClassFor($html, 'password'));
        self::assertSame('badge badge-primary', $this->badgeClassFor($html, '3 records'));
        $this->assertNoFixedColourBadge($html);
    }

    public function testMigrationReviewMapsEachSeverityToItsCoreBadge(): void
    {
        $secret = static fn (string $column, string $severity, string $pattern): array => [
            'table' => 'tx_demo', 'column' => $column, 'count' => 1, 'severity' => $severity, 'patterns' => [$pattern],
        ];
        $html = $this->renderTemplate(self::REVIEW, [
            'secrets' => [
                'tx_demo.a' => $secret('a', 'critical', 'password'),
                'tx_demo.b' => $secret('b', 'high', 'api_key'),
                'tx_demo.c' => $secret('c', 'medium', 'token'),
                'tx_demo.d' => $secret('d', 'low', 'secret'),
            ],
        ]);

        self::assertSame('badge badge-danger', $this->badgeClassFor($html, 'Critical'));
        self::assertSame('badge badge-warning', $this->badgeClassFor($html, 'High'));
        self::assertSame('badge badge-info', $this->badgeClassFor($html, 'Medium'));
        self::assertSame('badge badge-default', $this->badgeClassFor($html, 'Low'));
        self::assertSame('badge badge-default', $this->badgeClassFor($html, 'password'));
        $this->assertNoFixedColourBadge($html);
    }

    /**
     * The review step's "select all" script is an ES module from the import
     * map, not an inline `<f:asset.script>`: an inline script needs a CSP nonce,
     * requested by `useNonce` on 13.4 and by `csp` on 14.3, where `useNonce`
     * is deprecated. A module needs neither on both versions.
     */
    public function testTheReviewSelectAllScriptIsAJavaScriptModuleNotAnInlineScript(): void
    {
        $assets = $this->get(AssetCollector::class);
        $this->renderTemplate(self::REVIEW, [
            'secrets' => ['tx_demo.a' => ['table' => 'tx_demo', 'column' => 'a', 'count' => 1, 'severity' => 'low', 'patterns' => []]],
        ]);

        self::assertContains('@netresearch/nr-vault/MigrationReview.js', $assets->getJavaScriptModules());
        self::assertSame([], $assets->getInlineJavaScripts());
        self::assertFileExists(__DIR__ . '/../../../Resources/Public/JavaScript/MigrationReview.js');
    }

    /**
     * Each wizard step hands core's progress tracker a `stages` attribute that
     * JSON.parse() accepts and a 1-based `active` step. The attribute used to be
     * cut off by an escaped quote, so Lit's Array converter produced null and
     * the element threw "Cannot read properties of null (reading 'length')".
     *
     * @return iterable<string, array{string, array<string, mixed>, int}>
     */
    public static function wizardSteps(): iterable
    {
        yield 'scan' => ['Migration/Scan', ['totalCount' => 0, 'databaseCount' => 0, 'configCount' => 0, 'groupedSecrets' => []], 1];
        yield 'review' => [self::REVIEW, ['secrets' => []], 2];
        yield 'configure' => ['Migration/Configure', ['migrations' => []], 3];
        yield 'verify' => ['Migration/Verify', ['totalMigrated' => 0, 'totalFailed' => 0, 'clearOriginals' => false, 'results' => []], 5];
    }

    /**
     * @param array<string, mixed> $variables
     */
    #[DataProvider('wizardSteps')]
    public function testTheWizardProgressTrackerGetsParseableStagesAndItsOwnStep(string $template, array $variables, int $step): void
    {
        $html = $this->renderTemplate($template, $variables);

        self::assertSame(1, preg_match('/<typo3-backend-progress-tracker\s+active="(\d+)"\s+stages="([^"]*)"/', $html, $match), 'tracker rendered');
        $stages = json_decode(html_entity_decode($match[2], ENT_QUOTES | ENT_HTML5), true, 4, JSON_THROW_ON_ERROR);
        self::assertSame(['Scan', 'Review', 'Configure', 'Execute', 'Verify'], $stages);
        self::assertSame((string) $step, $match[1]);
    }

    /**
     * Labels come from translation files an integrator can override, so the
     * JSON must survive whatever a label holds. Each hostile label is fed
     * through a real locallang override and must come back out of the
     * parsed `stages` attribute byte for byte.
     */
    public function testTheWizardProgressTrackerCarriesHostileLabelsUnchanged(): void
    {
        $labels = [
            'migration.scan' => 'Scan "quoted" & \'single\'',
            'migration.review' => '<script>alert(1)</script> Review',
            'migration.configure' => 'Konfigurieren – äöüß 日本語',
            'migration.verify' => 'Verify \\ back/slash </typo3-backend-progress-tracker>',
        ];
        $this->overrideModuleLabels($labels);

        try {
            $html = $this->renderTemplate('Migration/Scan', ['totalCount' => 0, 'databaseCount' => 0, 'configCount' => 0, 'groupedSecrets' => []]);
        } finally {
            // The labels must not leak into the other tests of this class.
            $this->overrideModuleLabels([]);
        }

        $document = new DOMDocument();
        $previous = libxml_use_internal_errors(true);
        $document->loadHTML('<?xml encoding="utf-8"?>' . $html);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);
        $tracker = $document->getElementsByTagName('typo3-backend-progress-tracker')->item(0);
        self::assertInstanceOf(DOMElement::class, $tracker);

        // What the element's Lit Array converter does: JSON.parse() of the
        // attribute value as the browser decoded it.
        $stages = json_decode($tracker->getAttribute('stages'), true, 4, JSON_THROW_ON_ERROR);
        self::assertSame(
            [$labels['migration.scan'], $labels['migration.review'], $labels['migration.configure'], 'Execute', $labels['migration.verify']],
            $stages,
        );
        self::assertStringNotContainsString('<script>alert(1)</script>', $html);
    }

    public function testMigrationVerifyMapsEachOutcomeToItsCoreBadge(): void
    {
        $result = static fn (string $column, int $failed, string $error): array => [
            'table' => 'tx_demo', 'column' => $column, 'migrated' => 1, 'skipped' => 0, 'failed' => $failed, 'error' => $error,
        ];
        $html = $this->renderTemplate('Migration/Verify', [
            'totalMigrated' => 3, 'totalFailed' => 2, 'clearOriginals' => false,
            'results' => [$result('a', 1, 'boom'), $result('b', 1, ''), $result('c', 0, '')],
        ]);

        self::assertSame('badge badge-danger', $this->badgeClassFor($html, 'Error'));
        self::assertSame('badge badge-warning', $this->badgeClassFor($html, 'Partial'));
        self::assertSame('badge badge-success', $this->badgeClassFor($html, 'Complete'));
        $this->assertNoFixedColourBadge($html);
    }

    public function testTheAuditLogUsesCoreBadgesForCountsAndActions(): void
    {
        $entry = [
            'time' => '12:00:00', 'secretIdentifier' => 'api_key', 'action' => 'delete', 'actionBadgeClass' => 'danger',
            'success' => true, 'errorMessage' => '', 'reason' => '', 'actorUsername' => 'admin', 'actorType' => 'backend',
            'ipAddress' => '127.0.0.1', 'entryHash' => str_repeat('a', 64), 'entryHashShort' => 'aaaaaaaa...',
        ];
        $html = $this->renderTemplate('Audit/List', [
            'filters' => ['_form' => []],
            'actions' => ['delete'],
            'entries' => [$entry],
            'groupedEntries' => ['2026-09-27' => [$entry]],
            'totalCount' => 1, 'currentPage' => 1, 'totalPages' => 1,
        ]);

        self::assertSame('badge badge-info', $this->badgeClassFor($html, '1 entries'));
        self::assertSame('badge badge-default', $this->badgeClassFor($html, 'Page 1 of 1'));
        self::assertStringContainsString('class="badge badge-danger" data-testid="audit-cell-action">delete<', $html);
        $this->assertNoFixedColourBadge($html);
    }

    private function setLabelOverride(string $section, string $option, string $key, ?string $file): void
    {
        $configuration = \is_array($GLOBALS['TYPO3_CONF_VARS'] ?? null) ? $GLOBALS['TYPO3_CONF_VARS'] : [];
        $sectionConfiguration = \is_array($configuration[$section] ?? null) ? $configuration[$section] : [];
        $overrides = \is_array($sectionConfiguration[$option] ?? null) ? $sectionConfiguration[$option] : [];

        if ($file === null) {
            unset($overrides[$key]);
        } else {
            $overrides[$key] = [$file];
        }

        $sectionConfiguration[$option] = $overrides;
        $configuration[$section] = $sectionConfiguration;
        $GLOBALS['TYPO3_CONF_VARS'] = $configuration;
    }

    /**
     * Override locallang_mod.xlf labels through the integrator mechanism of
     * the running major: LANG.resourceOverrides on 14.3,
     * SYS.locallangXMLOverride on 13.4. An empty list removes the override.
     *
     * @param array<string, string> $labels
     */
    private function overrideModuleLabels(array $labels): void
    {
        $units = '';
        foreach ($labels as $id => $source) {
            $units .= '<trans-unit id="' . htmlspecialchars($id, ENT_XML1 | ENT_QUOTES) . '"><source>'
                . htmlspecialchars($source, ENT_XML1 | ENT_QUOTES) . '</source></trans-unit>';
        }

        $file = $this->instancePath . '/typo3temp/var/tests/nr_vault-labels/locallang_mod.xlf';
        GeneralUtility::mkdir_deep(\dirname($file));
        GeneralUtility::writeFile(
            $file,
            '<?xml version="1.0" encoding="UTF-8"?><xliff version="1.2" xmlns="urn:oasis:names:tc:xliff:document:1.2">'
            . '<file source-language="en" datatype="plaintext" original="messages"><body>' . $units . '</body></file></xliff>',
        );

        $key = 'EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf';
        $this->setLabelOverride('LANG', 'resourceOverrides', $key, $labels === [] ? null : $file);
        $this->setLabelOverride('SYS', 'locallangXMLOverride', $key, $labels === [] ? null : $file);

        $cacheManager = $this->get(CacheManager::class);
        $cacheManager->getCache('l10n')->flush();
        $cacheManager->getCache('runtime')->flush();
    }

    /**
     * @return array<string, mixed>
     */
    private function overviewVariables(bool $masterKeyAvailable = true): array
    {
        return [
            'breakGlass' => ['active' => false],
            'healthChecks' => [
                'hasIssues' => !$masterKeyAvailable,
                'masterKeyAvailable' => $masterKeyAvailable,
                'encryptionWorking' => $masterKeyAvailable,
                'masterKeyProvider' => 'typo3',
            ],
            'securityStatus' => ['available' => false, 'context' => 'warning'],
            'stats' => ['totalSecrets' => 1, 'activeSecrets' => 1, 'disabledSecrets' => 0],
            'submodules' => [
                [
                    'route' => 'admin_vault_secrets',
                    'icon' => 'module-vault-secrets',
                    'title' => 'Secrets',
                    'description' => 'Manage secrets',
                ],
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function secretRow(string $identifier, bool $hidden): array
    {
        return [
            'identifier' => $identifier, 'description' => '', 'hidden' => $hidden, 'owner_name' => 'admin',
            'created' => '2026-09-27', 'read_count' => 0, 'last_read' => '',
        ];
    }

    /**
     * The class attribute of the one badge whose whitespace-normalised text is $text.
     * Parsed as a DOM, because some badges nest an icon <span>.
     */
    private function badgeClassFor(string $html, string $text): string
    {
        $document = new DOMDocument();
        $previous = libxml_use_internal_errors(true);
        $document->loadHTML('<?xml encoding="utf-8"?>' . $html);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        $found = [];
        $badges = (new DOMXPath($document))->query('//*[contains(concat(" ", normalize-space(@class), " "), " badge ")]');
        self::assertInstanceOf(DOMNodeList::class, $badges);
        foreach ($badges as $badge) {
            if ($badge instanceof DOMElement && trim((string) preg_replace('/\s+/', ' ', $badge->textContent)) === $text) {
                $found[] = $badge->getAttribute('class');
            }
        }

        self::assertCount(1, $found, 'Expected exactly one badge reading "' . $text . '"');

        return $found[0];
    }

    /**
     * @return list<array{value: string, max: string, name: string, valuetext: string}>
     */
    private function progressBars(string $html): array
    {
        $document = new DOMDocument();
        $previous = libxml_use_internal_errors(true);
        $document->loadHTML('<?xml encoding="utf-8"?>' . $html);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        $bars = [];
        foreach ($document->getElementsByTagName('progress') as $bar) {
            $bars[] = [
                'value' => $bar->getAttribute('value'),
                'max' => $bar->getAttribute('max'),
                'name' => $bar->getAttribute('aria-label'),
                'valuetext' => $bar->getAttribute('aria-valuetext'),
            ];
        }

        return $bars;
    }

    private function assertNoFixedColourBadge(string $html): void
    {
        self::assertStringNotContainsString('vault-badge', $html);
        self::assertDoesNotMatchRegularExpression('/\b(text-bg|bg)-(primary|secondary|success|info|warning|danger|dark|light)\b/', $html);
    }

    private function between(string $html, string $from, string $to): string
    {
        $start = strpos($html, $from);
        self::assertIsInt($start, $from . ' not rendered');
        $end = strpos($html, $to, $start);
        self::assertIsInt($end, $to . ' not rendered');

        return substr($html, $start, $end - $start);
    }

    /**
     * @param array<string, mixed> $variables
     */
    private function renderPartial(string $name, array $variables): string
    {
        return $this->render(['EXT:nr_vault/Resources/Private/Partials/'], $name, $variables);
    }

    /**
     * @param array<string, mixed> $variables
     */
    private function renderTemplate(string $name, array $variables): string
    {
        return $this->render(['EXT:nr_vault/Resources/Private/Templates/'], $name, $variables);
    }

    /**
     * Same approach as {@see SecurityStatusPartialTest::render()}, with the
     * `Module` layout replaced by {@see self::MODULE_LAYOUT}.
     *
     * @param list<string> $templateRootPaths
     * @param array<string, mixed> $variables
     */
    private function render(array $templateRootPaths, string $name, array $variables): string
    {
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->createFromUserPreferences(null);

        $layoutPath = $this->instancePath . '/typo3temp/var/tests/nr_vault-layouts/';
        GeneralUtility::mkdir_deep($layoutPath);
        GeneralUtility::writeFile($layoutPath . 'Module.html', self::MODULE_LAYOUT);

        $view = $this->get(ViewFactoryInterface::class)->create(new ViewFactoryData(
            templateRootPaths: $templateRootPaths,
            partialRootPaths: ['EXT:nr_vault/Resources/Private/Partials/'],
            layoutRootPaths: [$layoutPath],
        ));

        return $view->assignMultiple($variables)->render($name);
    }
}
