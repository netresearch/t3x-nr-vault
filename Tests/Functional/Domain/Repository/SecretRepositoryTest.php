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
use Netresearch\NrVault\Tests\Functional\Traits\SecretRowTrait;
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
    use SecretRowTrait;

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

    /**
     * The control this pair implements: `hidden` is TCA's `disabled` enable
     * column, so every restriction-honouring query drops the record. Pinning
     * the blind side is the point — a later "fix" that widened `findByUid()`
     * itself would switch the control off wholesale, and this test is what
     * says so.
     */
    #[Test]
    public function findByUidDoesNotSeeADisabledSecret(): void
    {
        $uid = $this->saveDisabledSecret('disabled_uid_secret');

        self::assertNull($this->subject->findByUid($uid));
    }

    #[Test]
    public function findByUidIncludingDisabledSeesADisabledSecret(): void
    {
        $uid = $this->saveDisabledSecret('disabled_uid_secret_visible');

        $retrieved = $this->subject->findByUidIncludingDisabled($uid);

        self::assertNotNull($retrieved);
        self::assertSame('disabled_uid_secret_visible', $retrieved->getIdentifier());
    }

    /**
     * Only `HiddenRestriction` is lifted. A soft-deleted record must stay
     * invisible to the widened lookup too — the write-path guards built on it
     * decide `undelete` among other things, and a lookup that resurrected
     * deleted rows would answer that question with the wrong record.
     */
    #[Test]
    public function findByUidIncludingDisabledDoesNotSeeADeletedSecret(): void
    {
        $saved = $this->subject->save($this->newSecret('deleted_uid_secret'));
        $uid = $saved->getUid();
        self::assertNotNull($uid);

        $this->subject->delete($saved);

        self::assertNull($this->subject->findByUidIncludingDisabled($uid));
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
            valueChecksum: str_repeat('c', 64),
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
     * The column set of the primitive itself: `metadata` and the record
     * timestamp, nothing else. Whether the write is narrow ENOUGH — that it
     * cannot roll back a change committed inside a caller's read-then-write
     * window — is a property of the caller and is pinned where that window
     * exists, in
     * `Tests/Functional/Adapter/LocalEncryptionAdapterMetadataTest.php`.
     */
    #[Test]
    public function setMetadataWritesNothingButTheMetadataColumn(): void
    {
        $uid = $this->saveSecretReturningUid('metadata_narrow');
        $this->subject->incrementReadCount($uid);

        $before = $this->readSecretRow('metadata_narrow');

        $this->subject->setMetadata($uid, ['source' => 'cron']);

        $after = $this->readSecretRow('metadata_narrow');

        self::assertIsString($after['metadata']);
        self::assertSame('{"source":"cron"}', $after['metadata'], 'The change itself must have landed.');
        // `tstamp` moves by design (the record changed); `metadata` is the
        // change and is asserted above.
        foreach (['metadata', 'tstamp'] as $expected) {
            unset($before[$expected], $after[$expected]);
        }

        self::assertSame(
            $before,
            $after,
            'A metadata change must leave every other column exactly as it found it.',
        );
    }

    /**
     * Persist a secret and return its UID.
     */
    private function saveSecretReturningUid(string $identifier, bool $hidden = false): int
    {
        $saved = $this->subject->save($this->newSecret($identifier, hidden: $hidden));
        $uid = $saved->getUid();
        self::assertNotNull($uid);

        return $uid;
    }

    /**
     * Persist a disabled secret and return its UID.
     */
    private function saveDisabledSecret(string $identifier): int
    {
        return $this->saveSecretReturningUid($identifier, hidden: true);
    }

    /**
     * Build a Secret with sensible defaults for repository round-trip tests.
     */
    private function newSecret(
        string $identifier,
        string $encryptedValue = 'encrypted',
        string $context = '',
        int $version = 1,
        bool $hidden = false,
    ): Secret {
        return new Secret(
            identifier: $identifier,
            encryptedValue: $encryptedValue,
            encryptedDek: 'dek',
            dekNonce: 'n1',
            valueNonce: 'n2',
            valueChecksum: str_repeat('c', 64),
            context: $context,
            version: $version,
            cruserId: 1,
            hidden: $hidden,
        );
    }
}
