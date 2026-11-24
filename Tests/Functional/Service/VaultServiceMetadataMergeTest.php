<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service;

use Netresearch\NrVault\Service\VaultService;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Fixtures\QueryRecorder\QueryRecordingMiddleware;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

/**
 * #570: `mergeMetadata` reads the map it merges into only inside the store's
 * own transaction. On the stock wiring that transaction runs under the vault
 * mutation lock, which is what keeps a concurrent vault write from landing
 * between the read and the write.
 *
 * The statements are observed below the adapter, through a driver
 * middleware, because a decorator around the adapter would make the service
 * skip its transaction and the test would observe a different path.
 */
#[CoversClass(VaultService::class)]
final class VaultServiceMetadataMergeTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = ['auditHmacEpoch' => 1];

    /** @var array<string, mixed> */
    protected array $configurationToUseInTestInstance = [
        'DB' => [
            'Connections' => [
                'Default' => [
                    'driverMiddlewares' => [
                        'nr-vault-test-query-recorder' => [
                            'target' => QueryRecordingMiddleware::class,
                        ],
                    ],
                ],
            ],
        ],
    ];

    #[Test]
    public function theMergeReadsTheStoredMapOnlyInsideTheStoresTransaction(): void
    {
        $service = $this->get(VaultServiceInterface::class);
        $service->store('merge_in_transaction', 'first', ['metadata' => ['team' => 'a', 'note' => 'old']]);

        QueryRecordingMiddleware::start();

        try {
            $service->store('merge_in_transaction', 'second', ['mergeMetadata' => ['note' => 'new']]);
        } finally {
            $queries = QueryRecordingMiddleware::stop();
        }

        $reads = array_values(array_filter(
            $queries,
            static fn (array $query): bool => str_starts_with(strtoupper(ltrim($query['sql'])), 'SELECT')
                && str_contains($query['sql'], 'tx_nrvault_secret'),
        ));

        self::assertNotSame([], $reads, 'The recorder must see the reads of the store, or this test checks nothing.');
        foreach ($reads as $read) {
            self::assertTrue($read['inTransaction'], 'Read outside the store transaction: ' . $read['sql']);
        }

        self::assertSame(['team' => 'a', 'note' => 'new'], $service->getMetadata('merge_in_transaction')->metadata);
    }
}
