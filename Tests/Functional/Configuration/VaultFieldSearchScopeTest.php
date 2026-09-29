<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Configuration;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Information\Typo3Version;
use TYPO3\CMS\Core\Schema\SearchableSchemaFieldsCollector;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * A column built with VaultFieldHelper is never part of the backend search
 * scope of the consumer's table.
 *
 * TYPO3 v14 searches every input column whose config does not say
 * `searchable => false`, so the helper has to say it. The fixture table
 * builds its three vault columns through the helper, as integrators are told
 * to; the core collector is what the backend search asks.
 *
 * TYPO3 v13 ignores the flag and takes the scope from the consumer's
 * `ctrl.searchFields`, which nr_vault does not own.
 */
#[CoversNothing]
final class VaultFieldSearchScopeTest extends FunctionalTestCase
{
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
        __DIR__ . '/../Fixtures/Extensions/nr_vault_test',
    ];

    #[Test]
    public function vaultColumnsAreNotSearchedButOrdinaryInputColumnsAre(): void
    {
        if ((new Typo3Version())->getMajorVersion() < 14) {
            self::markTestSkipped('TYPO3 v13 ignores the per-column searchable flag.');
        }

        $collector = $this->get(SearchableSchemaFieldsCollector::class);
        self::assertInstanceOf(SearchableSchemaFieldsCollector::class, $collector);

        $fields = $collector->getFieldNames('tx_nrvaulttest_record');

        self::assertContains('title', $fields, 'The ordinary input column must stay searchable.');
        self::assertNotContains('api_key', $fields);
        self::assertNotContains('api_secret', $fields);
        self::assertNotContains('api_token', $fields);
    }
}
