<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Configuration;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Schema\SearchableSchemaFieldsCollector;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * The backend search scope of tx_nrvault_secret on the running TYPO3 version.
 *
 * TYPO3 v13 derives it from `ctrl.searchFields` (set by
 * Configuration/TCA/Overrides/tx_nrvault_secret.php), TYPO3 v14 from the
 * per-column `searchable` flag in the base TCA. The core collector is the
 * one place both versions answer, so the same list is asserted on both.
 */
#[CoversNothing]
final class SecretSearchScopeTest extends FunctionalTestCase
{
    protected array $coreExtensionsToLoad = [
        'install',
    ];

    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
    ];

    #[Test]
    public function secretTableIsSearchedByIdentifierDescriptionAndContextOnly(): void
    {
        $collector = $this->get(SearchableSchemaFieldsCollector::class);
        self::assertInstanceOf(SearchableSchemaFieldsCollector::class, $collector);

        $fields = $collector->getFieldNames('tx_nrvault_secret');
        sort($fields);

        self::assertSame(['context', 'description', 'identifier'], $fields);
    }
}
