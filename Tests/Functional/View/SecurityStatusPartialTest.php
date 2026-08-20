<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\View;

use Netresearch\NrVault\Controller\SecurityStatusProvider;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;
use TYPO3\CMS\Core\View\ViewFactoryData;
use TYPO3\CMS\Core\View\ViewFactoryInterface;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * Renders `Partials/SecurityStatus.html` on its own.
 *
 * `OverviewControllerTest` deliberately stops at the DI graph — the full module
 * render needs a routing context that does not belong in a functional test — and
 * the Playwright suite only runs against a live DDEV instance. That leaves a Fluid
 * parse error or a wrong variable path in this partial able to reach a release
 * while every PHP test stays green, and the symptom would be an exception on the
 * module's landing page.
 *
 * Rendering the partial in isolation closes that gap cheaply. It asserts the
 * permission gate too, from the view side: the finding text must not appear in the
 * markup when {@see SecurityStatusProvider} withheld it.
 */
final class SecurityStatusPartialTest extends FunctionalTestCase
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

    public function testRendersTheProfileBadgeAndPassRatio(): void
    {
        $html = $this->render([
            'available' => true,
            'profile' => 'hardened',
            'auditReady' => false,
            'severity' => 'warning',
            'context' => 'warning',
            'passed' => 19,
            'total' => 22,
            'criticalCount' => 0,
            'warningCount' => 3,
            'detailed' => false,
            'findings' => [],
        ]);

        self::assertStringContainsString('vault-security-status', $html);
        self::assertStringContainsString('Hardened profile', $html);
        self::assertStringContainsString('19 of 22 controls passed', $html);
        self::assertStringContainsString('badge bg-warning', $html);
    }

    public function testRendersTheStandardProfileLabelForAnyNonHardenedValue(): void
    {
        $html = $this->render($this->view(profile: 'standard'));

        self::assertStringContainsString('Standard profile', $html);
        self::assertStringNotContainsString('LLL:EXT:nr_vault', $html);
    }

    public function testACleanReportRendersTheAuditReadyCallout(): void
    {
        $html = $this->render($this->view(auditReady: true, context: 'success'));

        self::assertStringContainsString('vault-security-ready', $html);
        self::assertStringContainsString('audit-ready', $html);
        self::assertStringNotContainsString('vault-security-finding', $html);
    }

    public function testFindingsAreRenderedWithRiskRemediationAndDocsLink(): void
    {
        $html = $this->render($this->view(
            auditReady: false,
            context: 'danger',
            detailed: true,
            criticalCount: 1,
            findings: [
                [
                    'id' => 'audit.external_sink',
                    'severity' => 'critical',
                    'context' => 'danger',
                    'summary' => 'No external audit sink is enabled.',
                    'risk' => 'The audit trail exists only in the database it protects.',
                    'remediation' => 'Enable auditSinkFileEnabled.',
                    'docsUrl' => 'https://example.org/docs/sinks',
                ],
            ],
        ));

        self::assertStringContainsString('vault-security-finding', $html);
        self::assertStringContainsString('alert-danger', $html);
        self::assertStringContainsString('audit.external_sink', $html);
        self::assertStringContainsString('No external audit sink is enabled.', $html);
        self::assertStringContainsString('The audit trail exists only in the database it protects.', $html);
        self::assertStringContainsString('Enable auditSinkFileEnabled.', $html);
        self::assertStringContainsString('https://example.org/docs/sinks', $html);
        self::assertStringContainsString('vault:doctor', $html);
    }

    /**
     * The permission gate seen from the view: with `detailed => false` the markup
     * must carry the counts and nothing that names the weakness.
     */
    public function testWithheldFindingsRenderTheRestrictedNoticeInstead(): void
    {
        $html = $this->render($this->view(
            auditReady: false,
            context: 'danger',
            detailed: false,
            criticalCount: 2,
            warningCount: 1,
            // Populated on purpose: the provider empties this list, and the template
            // must not render it even if a future caller forgets to.
            findings: [
                [
                    'id' => 'audit.external_sink',
                    'severity' => 'critical',
                    'context' => 'danger',
                    'summary' => 'No external audit sink is enabled.',
                    'risk' => 'leaked risk text',
                    'remediation' => 'leaked remediation text',
                    'docsUrl' => 'https://example.org/docs/sinks',
                ],
            ],
        ));

        self::assertStringContainsString('vault-security-restricted', $html);
        self::assertStringNotContainsString('vault-security-finding', $html);
        self::assertStringNotContainsString('leaked risk text', $html);
        self::assertStringNotContainsString('leaked remediation text', $html);
        self::assertStringContainsString('2 critical and 1 advisory', $html);
    }

    public function testAnUnavailableRunRendersAWarningRatherThanABlankPanel(): void
    {
        $html = $this->render([
            'available' => false,
            'profile' => '',
            'auditReady' => false,
            'severity' => '',
            'context' => 'warning',
            'passed' => 0,
            'total' => 0,
            'criticalCount' => 0,
            'warningCount' => 0,
            'detailed' => false,
            'findings' => [],
        ]);

        self::assertStringContainsString('vault-security-unavailable', $html);
        self::assertStringContainsString('could not be evaluated', $html);
        self::assertStringContainsString('vault:doctor', $html);
        self::assertStringNotContainsString('controls passed', $html);
    }

    /**
     * Secret plaintext never reaches this panel, but finding text is
     * operator-supplied prose that must still be escaped like any other value.
     */
    public function testFindingTextIsHtmlEscaped(): void
    {
        $html = $this->render($this->view(
            auditReady: false,
            context: 'danger',
            detailed: true,
            criticalCount: 1,
            findings: [
                [
                    'id' => 'audit.external_sink',
                    'severity' => 'critical',
                    'context' => 'danger',
                    'summary' => '<script>alert(1)</script>',
                    'risk' => '',
                    'remediation' => '',
                    'docsUrl' => '',
                ],
            ],
        ));

        self::assertStringNotContainsString('<script>alert(1)</script>', $html);
        self::assertStringContainsString('&lt;script&gt;', $html);
    }

    public function testTheBadgeLineIsTheDisclosureControlForTheFindings(): void
    {
        // The findings are the bulk of this panel on any instance that has some,
        // and the ratio is the summary a reader wants first. The line therefore
        // doubles as the control that hides them — which only counts as a
        // control if it says so to assistive technology.
        $html = $this->render([
            'available' => true,
            'profile' => 'standard',
            'auditReady' => false,
            'severity' => 'warning',
            'context' => 'warning',
            'passed' => 20,
            'total' => 24,
            'criticalCount' => 1,
            'warningCount' => 3,
            'detailed' => true,
            'findings' => [
                [
                    'id' => 'audit.hash_chain',
                    'context' => 'danger',
                    'summary' => 'Hash chain verification failed.',
                    'risk' => '',
                    'remediation' => '',
                    'docsUrl' => '',
                ],
            ],
        ]);

        self::assertStringContainsString('data-bs-toggle="collapse"', $html);
        self::assertStringContainsString('data-bs-target="#vault-security-details"', $html);
        self::assertStringContainsString('aria-controls="vault-security-details"', $html);
        self::assertStringContainsString('aria-expanded="true"', $html);

        // Expanded by default: a live finding must not be hidden by a default
        // nobody chose. Collapsing is the reader's decision, not the panel's.
        self::assertStringContainsString('id="vault-security-details"', $html);
        self::assertStringContainsString('collapse show', $html);

        // And the findings really do sit inside the collapsible region.
        $regionStart = strpos($html, 'id="vault-security-details"');
        $findingPos = strpos($html, 'vault-security-finding"');
        self::assertIsInt($regionStart);
        self::assertIsInt($findingPos);
        self::assertGreaterThan($regionStart, $findingPos);
    }

    /**
     * A complete view shape with per-test overrides, mirroring
     * {@see SecurityStatusProvider::forView()}.
     *
     * @param list<array<string, string>> $findings
     *
     * @return array<string, mixed>
     */
    private function view(
        string $profile = 'hardened',
        bool $auditReady = false,
        string $context = 'warning',
        bool $detailed = false,
        int $criticalCount = 0,
        int $warningCount = 0,
        array $findings = [],
    ): array {
        return [
            'available' => true,
            'profile' => $profile,
            'auditReady' => $auditReady,
            'severity' => $auditReady ? 'pass' : 'warning',
            'context' => $context,
            'passed' => 19,
            'total' => 22,
            'criticalCount' => $criticalCount,
            'warningCount' => $warningCount,
            'detailed' => $detailed,
            'findings' => $findings,
        ];
    }

    /**
     * Render the partial through the public view factory.
     *
     * The Partials directory is handed over as the TEMPLATE root path: a partial and
     * a template are the same file format, and `ViewInterface::render()` is the only
     * public entry point (`renderPartial()` lives on an `@internal` Fluid class).
     * Rendering it as a template exercises the identical parse-and-render path the
     * module takes.
     *
     * @param array<string, mixed> $securityStatus
     */
    private function render(array $securityStatus): string
    {
        // The LanguageService that f:translate resolves through: a view-only
        // functional test gets no backend user, so nothing sets it up.
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->createFromUserPreferences(null);

        $view = $this->get(ViewFactoryInterface::class)->create(new ViewFactoryData(
            templateRootPaths: ['EXT:nr_vault/Resources/Private/Partials/'],
        ));

        return $view->assign('securityStatus', $securityStatus)->render('SecurityStatus');
    }
}
