<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service;

use Netresearch\NrVault\Domain\Dto\OrphanReference;
use Netresearch\NrVault\Service\OrphanReferenceChecker;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Fixtures\QueryRecorder\QueryRecordingMiddleware;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\ConnectionPool;

use function count;

/**
 * The checker's queries against a real schema, and what each further secret
 * costs (#565): one primary-key read, plus the authoritative count when the
 * linked row does not hold the secret. Table and column introspection happen
 * once per run, so the difference between a run over N secrets and a run
 * over one secret is (N - 1) times that cost, whatever the platform's
 * introspection costs.
 */
#[CoversClass(OrphanReferenceChecker::class)]
final class OrphanReferenceCheckerTest extends AbstractVaultFunctionalTestCase
{
    private const TABLE = 'tx_nrvaulttest_record';

    private const SECRETS = 5;

    /** The checker needs no backend user. */
    protected ?int $backendUserUid = null;

    /** @var list<string> */
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
        __DIR__ . '/../Fixtures/Extensions/nr_vault_test',
    ];

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

    /**
     * @return iterable<string, array{bool, bool}>
     */
    public static function holderProvider(): iterable
    {
        yield 'each linked row holds its secret' => [true, false];
        yield 'another row holds each secret' => [false, false];
        yield 'no row holds any secret' => [false, true];
    }

    #[Test]
    #[DataProvider('holderProvider')]
    public function eachFurtherSecretCostsOneQuery(bool $linkedRowHolds, bool $expectOrphans): void
    {
        $references = [];
        for ($i = 0; $i < self::SECRETS; ++$i) {
            $identifier = $this->generateUuidV7();
            $connection = $this->get(ConnectionPool::class)->getConnectionForTable(self::TABLE);
            $connection->insert(self::TABLE, [
                'pid'     => 1,
                'title'   => 'Holder ' . $i,
                'api_key' => $expectOrphans ? '' : $identifier,
            ]);
            $uid = (int) $connection->lastInsertId();

            // The link names the holder itself, or a uid that does not exist.
            $references[] = [new OrphanReference(self::TABLE, 'api_key', $linkedRowHolds ? $uid : 900000 + $i), $identifier];
        }

        $single = $this->queriesFor(array_slice($references, 0, 1), $expectOrphans);
        $all    = $this->queriesFor($references, $expectOrphans);

        // A secret its linked row holds costs the primary-key read; any other
        // secret also costs the authoritative count.
        $perSecret = $linkedRowHolds ? 1 : 2;
        self::assertSame((self::SECRETS - 1) * $perSecret, $all - $single, sprintf('%d secrets took %d queries, one secret %d', self::SECRETS, $all, $single));
    }

    /**
     * @param list<array{OrphanReference, string}> $references
     */
    private function queriesFor(array $references, bool $expectOrphans): int
    {
        $checker = new OrphanReferenceChecker($this->get(ConnectionPool::class));

        QueryRecordingMiddleware::start();

        try {
            foreach ($references as [$reference, $identifier]) {
                self::assertSame($expectOrphans, $checker->isOrphaned($reference, $identifier));
            }
        } finally {
            $queries = QueryRecordingMiddleware::stop();
        }

        self::assertSame([], $checker->getUnresolvedReferences());

        return count($queries);
    }
}
