<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Configuration;

use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Utility\IdentifierValidator;
use TYPO3\CMS\Core\Exception\SiteNotFoundException;
use TYPO3\CMS\Core\Site\SiteFinder;

/**
 * Site existence is a creation condition, never an ongoing custody condition.
 */
final readonly class SiteSecretNamespaceValidator
{
    public function __construct(private SiteFinder $siteFinder) {}

    public function validateNewIdentifier(string $identifier): void
    {
        IdentifierValidator::validateForStorage($identifier);
        $siteIdentifier = IdentifierValidator::getSiteIdentifier($identifier);
        if ($siteIdentifier === null) {
            return;
        }

        try {
            $site = $this->siteFinder->getSiteByIdentifier($siteIdentifier);
        } catch (SiteNotFoundException) {
            throw ValidationException::invalidIdentifier(
                $identifier,
                'the exact namespace site is not configured',
            );
        }

        if ($site->getIdentifier() !== $siteIdentifier) {
            throw ValidationException::invalidIdentifier(
                $identifier,
                'the namespace must use the exact configured site name',
            );
        }
    }
}
