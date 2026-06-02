<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Controller;

use GuzzleHttp\Psr7\Uri;
use Netresearch\NrVault\Controller\AnalyticsController;
use Netresearch\NrVault\Domain\Dto\StaleSecret;
use Netresearch\NrVault\Domain\StalenessRule;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use ReflectionClass;
use TYPO3\CMS\Backend\Routing\UriBuilder as BackendUriBuilder;
use TYPO3\CMS\Core\Localization\LanguageService;

/**
 * Unit tests for AnalyticsController's request/presentation logic.
 *
 * The full backend-module render (indexAction wiring ModuleTemplateFactory)
 * is covered by the Playwright E2E suite (Tests/E2E/analytics.spec.ts), mirroring
 * how the other vault module controllers are exercised. These tests cover the
 * pure logic that does not need a module context — window resolution, the
 * window-selector options, and the StaleSecret -> row mapping (including the
 * "translation missing -> enum label" fallback) — through the private-method
 * seam, the same reflection approach used by OverviewControllerTest.
 */
#[CoversClass(AnalyticsController::class)]
#[AllowMockObjectsWithoutExpectations]
final class AnalyticsControllerTest extends TestCase
{
    private AnalyticsController $subject;

    private BackendUriBuilder&MockObject $backendUriBuilder;

    /** @var ReflectionClass<AnalyticsController> */
    private ReflectionClass $reflection;

    protected function setUp(): void
    {
        parent::setUp();

        $this->backendUriBuilder = $this->createMock(BackendUriBuilder::class);
        $this->backendUriBuilder
            ->method('buildUriFromRoute')
            ->willReturnCallback(static fn (string $route): UriInterface => new Uri('https://example.test/typo3/' . $route));

        // Build without the constructor (it pulls in final readonly TYPO3
        // services we don't need) and inject only the URI-builder seam the
        // tested private methods consult.
        $this->reflection = new ReflectionClass(AnalyticsController::class);
        $this->subject = $this->reflection->newInstanceWithoutConstructor();
        $this->reflection->getProperty('backendUriBuilder')->setValue($this->subject, $this->backendUriBuilder);
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['LANG']);
        parent::tearDown();
    }

    /**
     * @return iterable<string, array{mixed, int}>
     */
    public static function windowProvider(): iterable
    {
        yield 'absent falls back to default' => [null, 90];
        yield 'valid 30' => ['30', 30];
        yield 'valid 180' => ['180', 180];
        yield 'valid 365' => ['365', 365];
        yield 'out-of-set falls back to default' => ['999', 90];
        yield 'non-numeric falls back to default' => ['abc', 90];
        yield 'zero falls back to default' => ['0', 90];
    }

    #[Test]
    #[DataProvider('windowProvider')]
    public function resolveWindowValidatesAgainstTheAllowedSet(mixed $raw, int $expected): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn($raw === null ? [] : ['window' => $raw]);

        $method = $this->reflection->getMethod('resolveWindow');

        self::assertSame($expected, $method->invoke($this->subject, $request));
    }

    #[Test]
    public function buildWindowOptionsCoversTheAllowedSetAndMarksTheActiveOne(): void
    {
        $method = $this->reflection->getMethod('buildWindowOptions');

        /** @var list<array{days: int, url: string, active: bool}> $options */
        $options = $method->invoke($this->subject, 30);

        self::assertSame([30, 90, 180, 365], array_column($options, 'days'));

        $active = array_values(array_filter($options, static fn (array $o): bool => $o['active']));
        self::assertCount(1, $active, 'exactly one window is active');
        self::assertSame(30, $active[0]['days']);
        self::assertNotSame('', $options[0]['url'], 'each option carries a navigation URL');
    }

    #[Test]
    public function toRowMapsSecretAndFallsBackToEnumLabelWhenTranslationMissing(): void
    {
        // sL() returns the raw "LLL:" key when a label is missing -> fallback.
        $lang = $this->createMock(LanguageService::class);
        $lang->method('sL')->willReturnArgument(0);
        $GLOBALS['LANG'] = $lang;

        $secret = new StaleSecret(
            uid: 7,
            identifier: 'legacy_smtp_password',
            context: 'mail',
            adapter: 'local',
            lastReadAt: null,
            automatedReads: 0,
            manualReveals: 3,
            ageDays: 320,
            rules: [StalenessRule::NeverRotated, StalenessRule::AutomationStale],
        );

        /** @var array{uid: int, identifier: string, context: string, adapter: string, lastReadAt: int|null, automatedReads: int, manualReveals: int, ageDays: int, severity: string, rules: list<array{key: string, severity: string, label: string}>, editUrl: string} $row */
        $row = $this->reflection->getMethod('toRow')->invoke($this->subject, $secret);

        self::assertSame(7, $row['uid']);
        self::assertSame('legacy_smtp_password', $row['identifier']);
        self::assertSame('mail', $row['context']);
        self::assertNull($row['lastReadAt']);
        self::assertSame(0, $row['automatedReads']);
        self::assertSame(3, $row['manualReveals']);
        self::assertSame('warning', $row['severity'], 'both rules are warning-level');
        self::assertCount(2, $row['rules']);
        self::assertSame('never_rotated', $row['rules'][0]['key']);
        self::assertSame('warning', $row['rules'][0]['severity']);
        self::assertSame('Never rotated', $row['rules'][0]['label'], 'falls back to the enum label');
        self::assertNotSame('', $row['editUrl']);
    }

    #[Test]
    public function toRowUsesTheTranslatedLabelAndDangerSeverityWhenPresent(): void
    {
        $lang = $this->createMock(LanguageService::class);
        $lang->method('sL')->willReturn('Translated label');
        $GLOBALS['LANG'] = $lang;

        $secret = new StaleSecret(
            uid: 1,
            identifier: 'dead_key',
            context: '',
            adapter: 'local',
            lastReadAt: 0,
            automatedReads: 0,
            manualReveals: 0,
            ageDays: 200,
            rules: [StalenessRule::Dead],
        );

        /** @var array{uid: int, identifier: string, context: string, adapter: string, lastReadAt: int|null, automatedReads: int, manualReveals: int, ageDays: int, severity: string, rules: list<array{key: string, severity: string, label: string}>, editUrl: string} $row */
        $row = $this->reflection->getMethod('toRow')->invoke($this->subject, $secret);

        self::assertSame('danger', $row['severity']);
        self::assertSame('Translated label', $row['rules'][0]['label']);
    }
}
