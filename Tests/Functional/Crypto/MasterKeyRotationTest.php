<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Crypto;

use Netresearch\NrVault\Crypto\EncryptionService;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Throwable;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * Functional tests for master key rotation.
 *
 * Tests the full rotation workflow including storing secrets with one key,
 * rotating the master key, and verifying secrets remain accessible.
 */
#[CoversClass(EncryptionService::class)]
final class MasterKeyRotationTest extends FunctionalTestCase
{
    private const NEW_KEY_FILENAME = '/master-new.key';

    private const REASON_TEST_CLEANUP = 'Test cleanup';

    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
    ];

    protected array $coreExtensionsToLoad = [
        'backend',
    ];

    protected array $configurationToUseInTestInstance = [
        'EXTENSIONS' => [
            'nr_vault' => [
                'masterKeyProvider' => 'file',
                'enableCache' => false,
            ],
        ],
    ];

    private ?string $masterKeyPath = null;

    protected function setUp(): void
    {
        parent::setUp();

        // Create a temporary master key for testing at the default auto-key path
        $this->masterKeyPath = $this->instancePath . '/var/secrets/vault-master.key';
        $dir = \dirname($this->masterKeyPath);
        if (!is_dir($dir)) {
            mkdir($dir, 0o700, true);
        }
        $masterKey = sodium_crypto_secretbox_keygen();
        file_put_contents($this->masterKeyPath, $masterKey);
        chmod($this->masterKeyPath, 0o600);

        // Also configure the source path via GLOBALS (read lazily by ExtensionConfiguration)
        $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault']['masterKeySource'] = $this->masterKeyPath;
        $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault']['autoKeyPath'] = $this->masterKeyPath;

        // Create backend admin user
        $this->importCSVDataSet(__DIR__ . '/../Hook/Fixtures/be_users.csv');
        $this->setUpBackendUser(1);
    }

    protected function tearDown(): void
    {
        // Clear the static key cache to prevent cross-test interference
        FileMasterKeyProvider::clearCachedKey();

        if ($this->masterKeyPath !== null && file_exists($this->masterKeyPath)) {
            $content = file_get_contents($this->masterKeyPath);
            if ($content !== false) {
                sodium_memzero($content);
            }
            // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
            unlink($this->masterKeyPath);
        }

        parent::tearDown();
    }

    #[Test]
    public function fullRotationWorkflowKeepsSecretsAccessible(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $encryptionService = $this->get(EncryptionServiceInterface::class);
        $secretRepository = $this->get(SecretRepositoryInterface::class);

        // Store multiple secrets with the original master key
        $secrets = [];
        for ($i = 0; $i < 3; ++$i) {
            $identifier = $this->generateUuidV7();
            $value = 'secret-value-' . $i;
            $vaultService->store($identifier, $value);
            $secrets[$identifier] = $value;
        }

        // Create a new key file
        $newKeyPath = $this->instancePath . self::NEW_KEY_FILENAME;
        $newKey = sodium_crypto_secretbox_keygen();
        file_put_contents($newKeyPath, $newKey);

        // Re-encrypt all DEKs with the new master key
        foreach (array_keys($secrets) as $identifier) {
            $secret = $secretRepository->findByIdentifier($identifier);
            self::assertNotNull($secret, 'Secret must exist: ' . $identifier);

            // Clear the static cache and re-read from file each iteration
            // because reEncryptDek zeroes the key parameters via sodium_memzero
            FileMasterKeyProvider::clearCachedKey();
            $oldKeyFromFile = $this->readKeyFromFile($this->masterKeyPath);
            $newKeyFromFile = $this->readKeyFromFile($newKeyPath);

            $reEncrypted = $encryptionService->reEncryptDek(
                $secret->getEncryptedDek(),
                $secret->getDekNonce(),
                $secret->getIdentifier(),
                $oldKeyFromFile,
                $newKeyFromFile,
                $secret->getEncryptionVersion(),
                $secret->getEncryptionAlgorithm(),
            );

            $secretRepository->save(
                $secret->withReEncryptedDek($reEncrypted->encryptedDek, $reEncrypted->nonce),
            );
        }

        // Switch to the new master key file
        copy($newKeyPath, $this->masterKeyPath);

        // Clear cached keys so the provider re-reads from disk
        FileMasterKeyProvider::clearCachedKey();
        $vaultService->clearCache();

        // Verify all secrets are still retrievable with the new key
        foreach ($secrets as $identifier => $expectedValue) {
            $retrieved = $vaultService->retrieve($identifier);
            self::assertSame($expectedValue, $retrieved, 'Secret must be retrievable after rotation: ' . $identifier);
        }

        // Cleanup
        foreach (array_keys($secrets) as $identifier) {
            $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
        }
        if (file_exists($newKeyPath)) {
            // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
            unlink($newKeyPath);
        }
    }

    #[Test]
    public function midRotationFailureKeepsSecretsAccessibleWithOriginalKey(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $encryptionService = $this->get(EncryptionServiceInterface::class);
        $secretRepository = $this->get(SecretRepositoryInterface::class);

        // Store secrets with original master key
        $identifier1 = $this->generateUuidV7();
        $identifier2 = $this->generateUuidV7();
        $vaultService->store($identifier1, 'secret-1');
        $vaultService->store($identifier2, 'secret-2');

        // Create a new key file
        $newKeyPath = $this->instancePath . self::NEW_KEY_FILENAME;
        $newKey = sodium_crypto_secretbox_keygen();
        file_put_contents($newKeyPath, $newKey);

        // Re-encrypt only the first secret (simulating mid-rotation failure)
        $secret1 = $secretRepository->findByIdentifier($identifier1);
        self::assertNotNull($secret1);

        FileMasterKeyProvider::clearCachedKey();
        $oldKeyFromFile = $this->readKeyFromFile($this->masterKeyPath);
        $newKeyFromFile = $this->readKeyFromFile($newKeyPath);

        $encryptionService->reEncryptDek(
            $secret1->getEncryptedDek(),
            $secret1->getDekNonce(),
            $secret1->getIdentifier(),
            $oldKeyFromFile,
            $newKeyFromFile,
            $secret1->getEncryptionVersion(),
            $secret1->getEncryptionAlgorithm(),
        );

        // Do NOT save the re-encrypted DEK (simulating rollback after failure)
        // The original key file is still in place, so both secrets should be accessible

        // Clear caches and verify both secrets are still accessible with the original key
        FileMasterKeyProvider::clearCachedKey();
        $vaultService->clearCache();

        $retrieved1 = $vaultService->retrieve($identifier1);
        self::assertSame('secret-1', $retrieved1, 'First secret must remain accessible after failed rotation');

        $retrieved2 = $vaultService->retrieve($identifier2);
        self::assertSame('secret-2', $retrieved2, 'Second secret must remain accessible after failed rotation');

        // Cleanup
        $vaultService->delete($identifier1, self::REASON_TEST_CLEANUP);
        $vaultService->delete($identifier2, self::REASON_TEST_CLEANUP);
        if (file_exists($newKeyPath)) {
            // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
            unlink($newKeyPath);
        }
    }

    #[Test]
    public function keyRotationUpdatesAllSecretDeks(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $encryptionService = $this->get(EncryptionServiceInterface::class);
        $secretRepository = $this->get(SecretRepositoryInterface::class);

        // Store secrets
        $identifiers = [];
        for ($i = 0; $i < 3; ++$i) {
            $identifier = $this->generateUuidV7();
            $vaultService->store($identifier, 'value-' . $i);
            $identifiers[] = $identifier;
        }

        // Record original DEKs
        $originalDeks = [];
        foreach ($identifiers as $identifier) {
            $secret = $secretRepository->findByIdentifier($identifier);
            self::assertNotNull($secret);
            $originalDeks[$identifier] = $secret->getEncryptedDek();
        }

        // Create a new key file
        $newKeyPath = $this->instancePath . self::NEW_KEY_FILENAME;
        $newKey = sodium_crypto_secretbox_keygen();
        file_put_contents($newKeyPath, $newKey);

        // Re-encrypt all DEKs
        foreach ($identifiers as $identifier) {
            $secret = $secretRepository->findByIdentifier($identifier);
            self::assertNotNull($secret);

            FileMasterKeyProvider::clearCachedKey();
            $oldKeyFromFile = $this->readKeyFromFile($this->masterKeyPath);
            $newKeyFromFile = $this->readKeyFromFile($newKeyPath);

            $reEncrypted = $encryptionService->reEncryptDek(
                $secret->getEncryptedDek(),
                $secret->getDekNonce(),
                $secret->getIdentifier(),
                $oldKeyFromFile,
                $newKeyFromFile,
                $secret->getEncryptionVersion(),
                $secret->getEncryptionAlgorithm(),
            );

            $secretRepository->save(
                $secret->withReEncryptedDek($reEncrypted->encryptedDek, $reEncrypted->nonce),
            );
        }

        // Verify all DEKs have changed
        foreach ($identifiers as $identifier) {
            $secret = $secretRepository->findByIdentifier($identifier);
            self::assertNotNull($secret);
            self::assertNotSame(
                $originalDeks[$identifier],
                $secret->getEncryptedDek(),
                'Encrypted DEK must change after rotation for: ' . $identifier,
            );
        }

        // Switch to new key and verify retrieval works
        copy($newKeyPath, $this->masterKeyPath);
        FileMasterKeyProvider::clearCachedKey();
        $vaultService->clearCache();

        foreach ($identifiers as $i => $identifier) {
            $retrieved = $vaultService->retrieve($identifier);
            self::assertSame('value-' . $i, $retrieved, 'Secret must be retrievable after DEK rotation');
        }

        // Cleanup
        foreach ($identifiers as $identifier) {
            $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
        }
        if (file_exists($newKeyPath)) {
            // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
            unlink($newKeyPath);
        }
    }

    /**
     * Atomicity property under failure: after a mid-rotation failure, the
     * observable state MUST be all-or-nothing — every secret decryptable
     * either under the old key OR under the new key, never a mix.
     *
     * Strategy: mirror the approach in VaultRotateMasterKeyCommand — wrap the
     * whole rotation in a DB transaction, catch the failure on secret #3
     * (induced by swapping in a DELIBERATELY WRONG old key) and rollBack().
     * After rollback we must be able to decrypt every one of the 5 seeded
     * secrets with the original key.
     */
    #[Test]
    public function masterKeyRotationIsAtomicUnderFailure(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $encryptionService = $this->get(EncryptionServiceInterface::class);
        $secretRepository = $this->get(SecretRepositoryInterface::class);
        $connectionPool = $this->get(ConnectionPool::class);

        // Seed 5 secrets with the original master key.
        $seeded = [];
        for ($i = 0; $i < 5; ++$i) {
            $identifier = $this->generateUuidV7();
            $value = 'atomic-rot-value-' . $i;
            $vaultService->store($identifier, $value);
            $seeded[$identifier] = $value;
        }

        $identifiers = array_keys($seeded);

        // Prepare the target new key.
        $newKeyPath = $this->instancePath . '/master-new-atomic.key';
        $newKey = sodium_crypto_secretbox_keygen();
        file_put_contents($newKeyPath, $newKey);

        FileMasterKeyProvider::clearCachedKey();
        $oldKeyFromFile = $this->readKeyFromFile($this->masterKeyPath);
        $newKeyFromFile = $this->readKeyFromFile($newKeyPath);

        // A DELIBERATELY WRONG "old" key used for secret #3 onwards — this
        // forces reEncryptDek() to throw because it cannot decrypt the DEK.
        $bogusOldKey = sodium_crypto_secretbox_keygen();

        // Use the secrets table connection's transaction scope. The production
        // rotate command uses the same pattern (see
        // VaultRotateMasterKeyCommand::execute()).
        $connection = $connectionPool->getConnectionForTable('tx_nrvault_secret');
        $connection->beginTransaction();

        $caught = null;

        try {
            foreach ($identifiers as $index => $identifier) {
                $secret = $secretRepository->findByIdentifier($identifier);
                self::assertInstanceOf(Secret::class, $secret);

                // On the 3rd iteration, swap the old key for a bogus one so
                // the re-encryption fails mid-flight.
                $oldKeyForThisIter = $index === 2
                    ? $bogusOldKey
                    : $oldKeyFromFile;

                $reEncrypted = $encryptionService->reEncryptDek(
                    $secret->getEncryptedDek(),
                    $secret->getDekNonce(),
                    $secret->getIdentifier(),
                    $oldKeyForThisIter,
                    $newKeyFromFile,
                    $secret->getEncryptionVersion(),
                    $secret->getEncryptionAlgorithm(),
                );

                // reEncryptDek zeroes its key params; re-read from file for
                // the next iteration.
                FileMasterKeyProvider::clearCachedKey();
                $oldKeyFromFile = $this->readKeyFromFile($this->masterKeyPath);
                $newKeyFromFile = $this->readKeyFromFile($newKeyPath);

                $secretRepository->save(
                    $secret->withReEncryptedDek($reEncrypted->encryptedDek, $reEncrypted->nonce),
                );
            }

            self::fail('Rotation should have failed on the 3rd secret due to bogus old key');
        } catch (EncryptionException $e) {
            // Expected: reEncryptDek() rejects the bogus old key.
            $connection->rollBack();
            $caught = $e;
        } catch (Throwable $e) {
            $connection->rollBack();

            throw $e;
        }

        self::assertInstanceOf(
            EncryptionException::class,
            $caught,
            'Expected EncryptionException from bogus-key reEncryptDek',
        );

        // === ATOMICITY PROPERTY ===
        //
        // After the rollback every seeded secret MUST still be retrievable
        // with the original key. A mix (some under new, some under old) is
        // a failure of atomicity.
        FileMasterKeyProvider::clearCachedKey();
        $vaultService->clearCache();

        foreach ($seeded as $identifier => $expectedValue) {
            $retrieved = $vaultService->retrieve($identifier);
            self::assertSame(
                $expectedValue,
                $retrieved,
                \sprintf(
                    'Secret "%s" MUST still decrypt with original master key after rollback — '
                    . 'rotation is not atomic if we see a mixed state.',
                    $identifier,
                ),
            );
        }

        // Cleanup
        foreach ($identifiers as $identifier) {
            try {
                $vaultService->delete($identifier, 'atomicity test cleanup');
            } catch (Throwable) {
                // ignore cleanup errors
            }
        }
        if (file_exists($newKeyPath)) {
            // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
            unlink($newKeyPath);
        }
        sodium_memzero($bogusOldKey);
    }

    /**
     * Read a raw master key from a file.
     *
     * Mirrors the FileMasterKeyProvider logic for reading keys.
     */
    private function readKeyFromFile(string $path): string
    {
        $raw = file_get_contents($path);
        self::assertIsString($raw, 'Key file must be readable: ' . $path);

        $trimmed = trim($raw);
        if (\strlen($trimmed) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            return $trimmed;
        }

        $decoded = base64_decode($trimmed, true);
        if ($decoded !== false && \strlen($decoded) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            return $decoded;
        }

        if (\strlen($raw) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            return $raw;
        }

        self::fail('Invalid key length in file: ' . $path);
    }

    /**
     * Generate a UUID v7 for testing.
     */
    private function generateUuidV7(): string
    {
        $timestamp = (int) (microtime(true) * 1000);
        $timestampHex = str_pad(dechex($timestamp), 12, '0', STR_PAD_LEFT);
        $randomBytes = random_bytes(10);
        $randomHex = bin2hex($randomBytes);

        return \sprintf(
            '%s-%s-7%s-%s%s-%s',
            substr($timestampHex, 0, 8),
            substr($timestampHex, 8, 4),
            substr($randomHex, 0, 3),
            dechex(8 + random_int(0, 3)),
            substr($randomHex, 3, 3),
            substr($randomHex, 6, 12),
        );
    }
}
