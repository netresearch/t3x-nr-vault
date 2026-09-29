<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Adapter;

use Netresearch\NrVault\Adapter\LocalEncryptionAdapter;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Tests\Functional\Traits\SecretRowTrait;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * What `updateMetadata()` writes, under the interleaving that makes the answer
 * matter.
 *
 * The method is read-then-write by nature: it has to load the record to merge
 * into its existing metadata. That opens a window, and the contract on
 * {@see \Netresearch\NrVault\Adapter\VaultAdapterInterface::updateMetadata()}
 * — "without changing the secret value" — is a claim about what the write at
 * the end of that window touches. Persisting the whole entity satisfies the
 * merge while restoring every scalar column to the state the read at the top
 * saw, so anything that committed in between is silently rolled back: a
 * `retrieve()`'s read-count increment, or a `rotate()`'s new envelope.
 *
 * The test creates that interleaving deterministically by decorating the
 * repository the adapter is built on — the read hands back the record and
 * commits a read-count increment on the way out, exactly as another request
 * calling `retrieve()` would. Everything the adapter actually calls is the
 * container's real repository behind that decoration, so the write under test
 * is a genuine one.
 */
final class LocalEncryptionAdapterMetadataTest extends FunctionalTestCase
{
    use SecretRowTrait;

    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
    ];

    protected array $coreExtensionsToLoad = [
        'backend',
    ];

    private SecretRepositoryInterface $repository;

    protected function setUp(): void
    {
        parent::setUp();

        $this->importCSVDataSet(__DIR__ . '/../Fixtures/Users/be_users.csv');
        $this->setUpBackendUser(1);

        $this->repository = $this->get(SecretRepositoryInterface::class);
    }

    #[Test]
    public function updatingMetadataMergesIntoWhatTheRecordAlreadyHas(): void
    {
        $this->saveSecret('metadata_merge', ['existing' => 'value']);

        $this->buildAdapterWithConcurrentRead()->updateMetadata('metadata_merge', ['new' => 'data']);

        $secret = $this->repository->findByIdentifier('metadata_merge');
        self::assertNotNull($secret);
        self::assertSame(['existing' => 'value', 'new' => 'data'], $secret->getMetadata());
    }

    #[Test]
    public function updatingMetadataWritesNothingButTheMetadataColumn(): void
    {
        $this->saveSecret('metadata_narrow', ['existing' => 'value']);
        $before = $this->readSecretRow('metadata_narrow');

        $this->buildAdapterWithConcurrentRead()->updateMetadata('metadata_narrow', ['new' => 'data']);

        $after = $this->readSecretRow('metadata_narrow');

        self::assertSame(
            (int) $before['read_count'] + 1,
            (int) $after['read_count'],
            'A read committed while the metadata change was in flight must survive it.',
        );

        // `tstamp` moves by design (the record changed); `metadata` is the
        // change; `read_count` and `last_read_at` were moved by the concurrent
        // read and asserted above.
        foreach (['metadata', 'tstamp', 'read_count', 'last_read_at'] as $expected) {
            unset($before[$expected], $after[$expected]);
        }

        self::assertSame(
            $before,
            $after,
            'A metadata change must leave every other column exactly as it found it.',
        );
    }

    /**
     * The real adapter on the real repository, with one addition: the lookup
     * it merges from commits a read-count increment on its way out — the
     * concurrent `retrieve()`, landing inside the adapter's window. The
     * increment goes through the repository's own targeted statement, so it is
     * a genuine committed row change rather than a test-only shortcut.
     */
    private function buildAdapterWithConcurrentRead(): LocalEncryptionAdapter
    {
        $real = $this->repository;

        $decorated = self::createStub(SecretRepositoryInterface::class);
        $decorated->method('findByIdentifier')->willReturnCallback(
            static function (string $identifier) use ($real): ?Secret {
                $secret = $real->findByIdentifier($identifier);
                $uid = $secret?->getUid();
                if ($uid !== null) {
                    $real->incrementReadCount($uid);
                }

                return $secret;
            },
        );
        $decorated->method('setMetadata')->willReturnCallback($real->setMetadata(...));
        $decorated->method('save')->willReturnCallback($real->save(...));

        return new LocalEncryptionAdapter($decorated);
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function saveSecret(string $identifier, array $metadata): void
    {
        $this->repository->save(new Secret(
            identifier: $identifier,
            encryptedValue: 'encrypted',
            encryptedDek: 'dek',
            dekNonce: 'n1',
            valueNonce: 'n2',
            valueChecksum: str_repeat('c', 64),
            metadata: $metadata,
            cruserId: 1,
        ));
    }
}
