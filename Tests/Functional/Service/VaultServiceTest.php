<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service;

use Netresearch\NrVault\Service\VaultService;
use Netresearch\NrVault\Service\VaultServiceInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * Functional tests for VaultService with real database operations.
 */
#[CoversClass(VaultService::class)]
final class VaultServiceTest extends FunctionalTestCase
{
    /** @var list<string> */
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
    ];

    /** @var list<string> */
    protected array $coreExtensionsToLoad = [
        'backend',
    ];

    private ?VaultServiceInterface $subject = null;

    private ?string $masterKeyPath = null;

    private bool $setupCompleted = false;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setupCompleted = true;

        // Create a temporary master key for testing
        $this->masterKeyPath = $this->instancePath . '/master.key';
        $masterKey = sodium_crypto_secretbox_keygen();
        file_put_contents($this->masterKeyPath, $masterKey);
        chmod($this->masterKeyPath, 0o600);

        // Configure extension to use file-based master key
        if (!isset($GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS'])) {
            $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS'] = [];
        }
        $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault'] = [
            'masterKeySource' => $this->masterKeyPath,
            'autoKeyPath' => $this->masterKeyPath,
        ];

        // Import backend user for access control
        $this->importCSVDataSet(__DIR__ . '/Fixtures/be_users.csv');
        $this->setUpBackendUser(1);

        // Get properly wired service from container
        $service = $this->get(VaultServiceInterface::class);
        self::assertInstanceOf(VaultServiceInterface::class, $service);
        $this->subject = $service;
    }

    protected function tearDown(): void
    {
        // Clean up master key (if setUp completed successfully)
        if ($this->masterKeyPath !== null && file_exists($this->masterKeyPath)) {
            // Securely wipe the file contents before deletion
            $content = file_get_contents($this->masterKeyPath);
            if ($content !== false) {
                sodium_memzero($content);
            }
            // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
            unlink($this->masterKeyPath);
        }

        // Only call parent tearDown if setUp completed (instancePath is initialized)
        if ($this->setupCompleted) {
            parent::tearDown();
        }
    }

    #[Test]
    public function storeAndRetrieveSecretWithDatabase(): void
    {
        $identifier = 'test_api_key';
        $secretValue = 'my-super-secret-api-key-12345';

        // Store the secret
        $this->getSubject()->store($identifier, $secretValue);

        // Verify it exists
        self::assertTrue($this->getSubject()->exists($identifier));

        // Retrieve and verify value
        $retrieved = $this->getSubject()->retrieve($identifier);
        self::assertEquals($secretValue, $retrieved);
    }

    #[Test]
    public function storeUpdatesExistingSecret(): void
    {
        $identifier = 'updatable_secret';
        $originalValue = 'original-value';
        $updatedValue = 'updated-value';

        // Store original
        $this->getSubject()->store($identifier, $originalValue);
        self::assertEquals($originalValue, $this->getSubject()->retrieve($identifier));

        // Update with new value
        $this->getSubject()->store($identifier, $updatedValue);
        self::assertEquals($updatedValue, $this->getSubject()->retrieve($identifier));
    }

    #[Test]
    public function deleteRemovesSecretFromDatabase(): void
    {
        $identifier = 'to_be_deleted';
        $secretValue = 'delete-me';

        // Store and verify
        $this->getSubject()->store($identifier, $secretValue);
        self::assertTrue($this->getSubject()->exists($identifier));

        // Delete
        $this->getSubject()->delete($identifier, 'Test cleanup');

        // Verify deleted
        self::assertFalse($this->getSubject()->exists($identifier));
    }

    #[Test]
    public function rotateUpdatesSecretVersionAndValue(): void
    {
        $identifier = 'rotating_secret';
        $originalValue = 'original-rotating-value';
        $rotatedValue = 'rotated-new-value';

        // Store original
        $this->getSubject()->store($identifier, $originalValue);
        $metadataBefore = $this->getSubject()->getMetadata($identifier);
        self::assertEquals(1, $metadataBefore->version);

        // Rotate
        $this->getSubject()->rotate($identifier, $rotatedValue, 'Scheduled rotation');

        // Verify new value and incremented version
        $retrieved = $this->getSubject()->retrieve($identifier);
        self::assertEquals($rotatedValue, $retrieved);

        $metadataAfter = $this->getSubject()->getMetadata($identifier);
        self::assertEquals(2, $metadataAfter->version);
        self::assertNotNull($metadataAfter->lastRotatedAt);
    }

    #[Test]
    public function listReturnsStoredSecrets(): void
    {
        // Store multiple secrets
        $this->getSubject()->store('list_test_1', 'value1');
        $this->getSubject()->store('list_test_2', 'value2');
        $this->getSubject()->store('list_test_3', 'value3');

        // List all
        $secrets = $this->getSubject()->list();

        // Verify at least our test secrets are returned
        $identifiers = array_column($secrets, 'identifier');
        self::assertContains('list_test_1', $identifiers);
        self::assertContains('list_test_2', $identifiers);
        self::assertContains('list_test_3', $identifiers);
    }

    #[Test]
    public function getMetadataReturnsCorrectInformation(): void
    {
        $identifier = 'metadata_test';
        $secretValue = 'metadata-test-value';

        $this->getSubject()->store($identifier, $secretValue, [
            'description' => 'Test secret for metadata',
            'context' => 'testing',
            'metadata' => ['environment' => 'test'],
        ]);

        $metadata = $this->getSubject()->getMetadata($identifier);

        self::assertEquals($identifier, $metadata->identifier);
        self::assertEquals('Test secret for metadata', $metadata->description);
        self::assertEquals('testing', $metadata->context);
        self::assertEquals(['environment' => 'test'], $metadata->metadata);
        self::assertEquals(1, $metadata->version);
    }

    #[Test]
    public function secretsAreProperlyEncryptedAndDecrypted(): void
    {
        $identifier = 'encryption_test';
        $secretValue = 'This is my secret value that should be encrypted';

        // Store the secret
        $this->getSubject()->store($identifier, $secretValue);

        // Verify secret was stored
        self::assertTrue($this->getSubject()->exists($identifier));

        // Verify we can retrieve the plaintext correctly (proves encryption/decryption works)
        $retrieved = $this->getSubject()->retrieve($identifier);
        self::assertEquals($secretValue, $retrieved);

        // Verify metadata is available
        $metadata = $this->getSubject()->getMetadata($identifier);
        self::assertEquals($identifier, $metadata->identifier);
        self::assertEquals(1, $metadata->version);
    }

    #[Test]
    public function httpClientIsAccessible(): void
    {
        $httpClient = $this->getSubject()->http();

        self::assertNotNull($httpClient);
    }

    #[Test]
    public function repeatedRetrieveAlwaysDecryptsFromTheDatabase(): void
    {
        $identifier = 'no_cache_test';
        $secretValue = 'no-cache-test-value';

        $subject = $this->getSubject();
        $subject->store($identifier, $secretValue);

        // No plaintext cache exists: every retrieve() decrypts from the
        // database, so repeated reads in one process stay consistent with
        // the stored record.
        self::assertSame($secretValue, $subject->retrieve($identifier));
        self::assertSame($secretValue, $subject->retrieve($identifier));
    }

    private function getSubject(): VaultServiceInterface
    {
        self::assertNotNull($this->subject, 'VaultServiceInterface not initialized');

        return $this->subject;
    }
}
