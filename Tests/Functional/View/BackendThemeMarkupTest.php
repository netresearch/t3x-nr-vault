<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\View;

use TYPO3\CMS\Core\Localization\LanguageServiceFactory;
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
    }

    public function testTheSubmoduleCardIconsAreInlinedSoTheyTakeTheTextColour(): void
    {
        $html = $this->renderTemplate('Overview/Index', $this->overviewVariables());

        // As <img>, a currentColor glyph cannot inherit anything and paints black,
        // 1.23:1 on the dark card. Inline, it takes the card's text colour.
        self::assertStringContainsString('<svg', $this->between($html, 'class="card-icon"', 'class="card-header-body"'));
        self::assertStringNotContainsString('<img', $this->between($html, 'class="card-icon"', 'class="card-header-body"'));
    }

    public function testTheOverviewUsesCoreCalloutsTablesAndAnExistingIcon(): void
    {
        $html = $this->renderTemplate('Overview/Index', $this->overviewVariables(masterKeyAvailable: false));

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
        $html = $this->renderTemplate('Overview/Index', $this->overviewVariables());

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

        self::assertSame(2, substr_count($html, 'role="progressbar"'));
        self::assertStringContainsString('role="progressbar" aria-label="local"', $html);
        self::assertStringContainsString('role="progressbar" aria-label="payment"', $html);
        self::assertStringContainsString('class="vault-bar-fill"', $html);
        self::assertStringNotContainsString('class="progress', $html);
        self::assertStringNotContainsString('text-body-secondary', $html);
    }

    public function testTheFaqUsesNativeDisclosureWidgets(): void
    {
        $html = $this->renderTemplate('Overview/Help', ['dashboardUrl' => '/typo3/module/dashboard']);

        self::assertSame(4, substr_count($html, '<details class="vault-faq'));
        self::assertSame(4, substr_count($html, '<summary>'));
        self::assertStringNotContainsString('class="accordion', $html);
        self::assertStringNotContainsString('data-bs-toggle', $html);
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
     * Same approach as {@see SecurityStatusPartialTest::render()}. The `Module`
     * layout is replaced by a stub that renders only the `Content` section: the
     * core layout needs a module request, and the markup under test is ours.
     *
     * @param list<string> $templateRootPaths
     * @param array<string, mixed> $variables
     */
    private function render(array $templateRootPaths, string $name, array $variables): string
    {
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->createFromUserPreferences(null);

        $view = $this->get(ViewFactoryInterface::class)->create(new ViewFactoryData(
            templateRootPaths: $templateRootPaths,
            partialRootPaths: ['EXT:nr_vault/Resources/Private/Partials/'],
            layoutRootPaths: [__DIR__ . '/Fixtures/Layouts/'],
        ));

        return $view->assignMultiple($variables)->render($name);
    }
}
