<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Form\Element;

use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Form\Element\VaultSecretInputElement;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use Psr\Container\ContainerInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use TYPO3\CMS\Core\Cache\Frontend\FrontendInterface;
use TYPO3\CMS\Core\Imaging\Icon;
use TYPO3\CMS\Core\Imaging\IconFactory;
use TYPO3\CMS\Core\Imaging\IconRegistry;
use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * The SUT is excluded from unit coverage in Build/phpunit.xml, so this test is
 * `CoversNothing`: with CoversClass, PHPUnit 12 raises "not a valid target for
 * code coverage" in coverage runs, which `failOnWarning=true` turns into a
 * failure (seen in CI, Unit Tests 8.3/^13.4).
 */
#[CoversNothing]
#[AllowMockObjectsWithoutExpectations]
final class VaultSecretInputElementTest extends TestCase
{
    protected bool $resetSingletonInstances = true;

    protected function tearDown(): void
    {
        unset($GLOBALS['LANG']);
        GeneralUtility::purgeInstances();
        parent::tearDown();
    }

    /**
     * An existing record whose secret is not in the vault shows a notice above
     * the input. It is core callout markup, the structure f:be.infobox renders,
     * so it follows the backend scheme; Bootstrap's `.alert` is not a core
     * component.
     */
    #[Test]
    public function theNoSecretNoticeIsACoreInfoCallout(): void
    {
        $languageService = $this->createMock(LanguageService::class);
        $languageService->method('sL')->willReturn('');
        $GLOBALS['LANG'] = $languageService;

        $vaultService = $this->createMock(VaultServiceInterface::class);
        $vaultService->method('getMetadata')->willThrowException(new SecretNotFoundException('missing', 1790000000));
        GeneralUtility::addInstance(VaultServiceInterface::class, $vaultService);

        $icon = $this->createMock(Icon::class);
        $icon->method('render')->willReturn('<span class="icon"></span>');
        $runtimeCache = $this->createMock(FrontendInterface::class);
        $runtimeCache->method('get')->willReturn($icon);
        $iconFactory = new IconFactory(
            $this->createMock(EventDispatcherInterface::class),
            $this->createMock(IconRegistry::class),
            $this->createMock(ContainerInterface::class),
            $runtimeCache,
        );

        $subject = new VaultSecretInputElement($iconFactory);
        $subject->setData([
            'parameterArray' => [
                'itemFormElName' => 'data[tx_nrvault_secret][7][secret]',
                'fieldConf' => ['config' => []],
            ],
            'databaseRow' => ['uid' => 7, 'identifier' => 'orphaned_key'],
        ]);

        $html = $subject->render()['html'];

        self::assertIsString($html);
        self::assertStringContainsString('<div class="callout callout-info mb-2">', $html);
        self::assertStringContainsString('<div class="callout-icon"><span class="icon-emphasized">', $html);
        self::assertStringContainsString('<div class="callout-content"><div class="callout-body">', $html);
        self::assertStringContainsString('No secret value stored.', $html);
        self::assertStringNotContainsString('alert', $html);
    }
}
