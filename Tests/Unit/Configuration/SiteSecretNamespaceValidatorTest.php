<?php

/* Copyright (c) 2026 Netresearch DTT GmbH; SPDX-License-Identifier: GPL-2.0-or-later */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Configuration;

use Netresearch\NrVault\Configuration\SiteSecretNamespaceValidator;
use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Exception\SiteNotFoundException;
use TYPO3\CMS\Core\Site\Entity\Site;
use TYPO3\CMS\Core\Site\SiteFinder;

#[CoversClass(SiteSecretNamespaceValidator::class)]
final class SiteSecretNamespaceValidatorTest extends TestCase
{
    #[Test]
    public function ordinaryIdentifiersNeverRequireSiteLookup(): void
    {
        $finder = $this->createMock(SiteFinder::class);
        $finder->expects(self::never())->method('getSiteByIdentifier');
        (new SiteSecretNamespaceValidator($finder))->validateNewIdentifier(
            'api_key',
        );
    }

    #[Test]
    public function validatesTheExactConfiguredSite(): void
    {
        $site = new Site('Main-01', 1, []);
        $finder = $this->createMock(SiteFinder::class);
        $finder
            ->expects(self::once())
            ->method('getSiteByIdentifier')
            ->with('Main-01')
            ->willReturn($site);
        (new SiteSecretNamespaceValidator($finder))->validateNewIdentifier(
            'site:Main-01:api_key',
        );
    }

    #[Test]
    public function unavailableSiteIsRejected(): void
    {
        $finder = $this->createMock(SiteFinder::class);
        $finder
            ->expects(self::once())
            ->method('getSiteByIdentifier')
            ->with('missing')
            ->willThrowException(new SiteNotFoundException('missing'));
        $this->expectException(ValidationException::class);
        (new SiteSecretNamespaceValidator($finder))->validateNewIdentifier(
            'site:missing:api_key',
        );
    }

    #[Test]
    public function differentlySpelledSiteResultIsRejected(): void
    {
        $finder = $this->createMock(SiteFinder::class);
        $finder
            ->expects(self::once())
            ->method('getSiteByIdentifier')
            ->with('main')
            ->willReturn(new Site('Main', 1, []));
        $this->expectException(ValidationException::class);
        (new SiteSecretNamespaceValidator($finder))->validateNewIdentifier(
            'site:main:api_key',
        );
    }
}
