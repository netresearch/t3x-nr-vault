<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Domain\Repository;

use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Domain\Repository\SecretRepository;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * Functional tests for SecretRepository with real database operations.
 *
 * Entity-level unit tests for {@see Secret} (setters/getters, isExpired,
 * fromDatabaseRow, toDatabaseRow) live in
 * `Tests/Unit/Domain/Model/SecretTest.php`. This suite only exercises the
 * repository against a real database.
 */
#[CoversClass(SecretRepository::class)]
#[CoversClass(Secret::class)]
#[CoversClass(SecretFilters::class)]
final class SecretRepositoryTest extends FunctionalTestCase
{
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
    ];

    protected array $coreExtensionsToLoad = [
        'backend',
    ];

    private SecretRepositoryInterface $subject;

    protected function setUp(): void
    {
        parent::setUp();

        $this->importCSVDataSet(__DIR__ . '/../../Fixtures/Users/be_users.csv');
        $this->setUpBackendUser(1);

        $this->subject = $this->get(SecretRepositoryInterface::class);
    }

    #[Test]
    public function saveCreatesNewSecret(): void
    {
        $secret = $this->newSecret('test_secret_1', encryptedValue: 'encrypted_value_data');

        $saved = $this->subject->save($secret);

        self::assertGreaterThan(0, $saved->getUid());

        // Verify we can retrieve it
        $retrieved = $this->subject->findByIdentifier('test_secret_1');
        self::assertNotNull($retrieved);
        self::assertSame('test_secret_1', $retrieved->getIdentifier());
    }

    #[Test]
    public function findByIdentifierReturnsNullForNonExistent(): void
    {
        $result = $this->subject->findByIdentifier('non_existent_secret');

        self::assertNull($result);
    }

    #[Test]
    public function findByUidReturnsCorrectSecret(): void
    {
        $secret = $this->newSecret('uid_test_secret');

        $saved = $this->subject->save($secret);
        $uid = $saved->getUid();
        self::assertNotNull($uid);

        $retrieved = $this->subject->findByUid($uid);

        self::assertNotNull($retrieved);
        self::assertSame('uid_test_secret', $retrieved->getIdentifier());
    }

    #[Test]
    public function findByUidReturnsNullForNonExistent(): void
    {
        $result = $this->subject->findByUid(999999);

        self::assertNull($result);
    }

    #[Test]
    public function existsReturnsTrueForExistingSecret(): void
    {
        $this->subject->save($this->newSecret('exists_test'));

        self::assertTrue($this->subject->exists('exists_test'));
    }

    #[Test]
    public function existsReturnsFalseForNonExistent(): void
    {
        self::assertFalse($this->subject->exists('does_not_exist'));
    }

    #[Test]
    public function deleteRemovesSecret(): void
    {
        $saved = $this->subject->save($this->newSecret('to_delete'));
        self::assertTrue($this->subject->exists('to_delete'));

        $this->subject->delete($saved);

        self::assertFalse($this->subject->exists('to_delete'));
    }

    #[Test]
    public function saveUpdatesExistingSecret(): void
    {
        $original = $this->newSecret('update_test', encryptedValue: 'original_value');

        $inserted = $this->subject->save($original);
        $originalUid = $inserted->getUid();
        self::assertNotNull($originalUid);

        // Update: build a fresh Secret with the same UID and the desired
        // field changes (no setters on the readonly entity).
        $updated = new Secret(
            identifier: 'update_test',
            uid: $originalUid,
            encryptedValue: 'updated_value',
            encryptedDek: 'dek',
            dekNonce: 'n1',
            valueNonce: 'n2',
            version: 2,
            cruserId: 1,
        );
        $this->subject->save($updated);

        // Verify the update
        $retrieved = $this->subject->findByIdentifier('update_test');
        self::assertNotNull($retrieved);
        self::assertSame($originalUid, $retrieved->getUid());
        self::assertSame('updated_value', $retrieved->getEncryptedValue());
        self::assertSame(2, $retrieved->getVersion());
    }

    #[Test]
    public function findIdentifiersReturnsAllIdentifiers(): void
    {
        // Create multiple secrets
        for ($i = 1; $i <= 3; $i++) {
            $this->subject->save($this->newSecret("list_test_{$i}", encryptedValue: "value_{$i}"));
        }

        $identifiers = $this->subject->findIdentifiers();

        self::assertContains('list_test_1', $identifiers);
        self::assertContains('list_test_2', $identifiers);
        self::assertContains('list_test_3', $identifiers);
    }

    #[Test]
    public function findIdentifiersWithFiltersByContext(): void
    {
        $this->subject->save($this->newSecret(
            'context_api',
            encryptedValue: 'v1',
            context: 'api',
        ));
        $this->subject->save($this->newSecret(
            'context_db',
            encryptedValue: 'v2',
            context: 'database',
        ));

        $apiSecrets = $this->subject->findIdentifiers(new SecretFilters(context: 'api'));

        self::assertContains('context_api', $apiSecrets);
        self::assertNotContains('context_db', $apiSecrets);
    }

    /**
     * Build a Secret with sensible defaults for repository round-trip tests.
     */
    private function newSecret(
        string $identifier,
        string $encryptedValue = 'encrypted',
        string $context = '',
        int $version = 1,
    ): Secret {
        return new Secret(
            identifier: $identifier,
            encryptedValue: $encryptedValue,
            encryptedDek: 'dek',
            dekNonce: 'n1',
            valueNonce: 'n2',
            context: $context,
            version: $version,
            cruserId: 1,
        );
    }
}
