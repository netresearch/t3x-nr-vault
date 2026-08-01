<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Crypto;

use Netresearch\NrVault\Crypto\EncryptionService;
use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Restoring a vault under the WRONG master key.
 *
 * The disaster-recovery scenario: a database backup is restored on a host whose
 * master key is not the one the secrets were sealed with — a stale key file, the
 * wrong environment's key, or a zeroed/placeholder key. Every read must then fail
 * closed, and it must fail as a clean domain exception rather than returning a
 * truncated or garbage plaintext that a caller would happily write to a config
 * file or send to a third party.
 *
 * {@see MasterKeyRotationTest} proves the happy path (secrets survive a key
 * change when the DEKs are re-wrapped) and the unit suite covers wrong-key
 * decryption at the {@see EncryptionService} boundary with stub providers. What
 * is asserted here is the end-to-end operator-visible behaviour through
 * {@see VaultServiceInterface} against real stored rows, plus the property that
 * matters most for recovery: a failed decrypt under the wrong key is
 * NON-DESTRUCTIVE — putting the correct key back makes every secret readable
 * again.
 */
#[CoversClass(EncryptionService::class)]
final class WrongMasterKeyRestoreTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_COUNT = 3;

    protected ?string $backendUserFixture = __DIR__ . '/../Hook/Fixtures/be_users.csv';

    /**
     * Pin the file provider — the `masterKeyProvider` setting defaults to
     * `typo3`, so without this the key file written by the base class would not
     * be the key the secrets are sealed with and swapping it would prove nothing.
     *
     * @var array<string, mixed>
     */
    protected array $extensionConfiguration = [
        'masterKeyProvider' => 'file',
    ];

    /**
     * Wrong keys that are all structurally VALID (exactly 32 bytes), so the
     * failure has to come from authentication and not from a length check.
     *
     * @return iterable<string, array{string}>
     */
    public static function wrongMasterKeyProvider(): iterable
    {
        yield 'a different random key' => [sodium_crypto_secretbox_keygen()];
        yield 'all-zero key' => [str_repeat("\x00", SODIUM_CRYPTO_SECRETBOX_KEYBYTES)];
        yield 'all-0xff key' => [str_repeat("\xff", SODIUM_CRYPTO_SECRETBOX_KEYBYTES)];
    }

    #[Test]
    #[DataProvider('wrongMasterKeyProvider')]
    public function readingSecretsUnderAWrongMasterKeyFailsCleanly(string $wrongKey): void
    {
        $seeded = $this->seedSecrets();

        $this->installMasterKey($wrongKey);

        $vaultService = $this->get(VaultServiceInterface::class);

        foreach ($seeded as $identifier => $plaintext) {
            try {
                $leaked = $vaultService->retrieve($identifier);

                self::fail(\sprintf(
                    'Reading "%s" under a wrong master key must throw, but it returned %s',
                    $identifier,
                    $leaked === null ? 'null' : 'a value of ' . \strlen($leaked) . ' bytes',
                ));
            } catch (EncryptionException $exception) {
                self::assertStringNotContainsString(
                    $plaintext,
                    $exception->getMessage(),
                    'A failed decrypt must not echo the protected value in its message',
                );
                self::assertStringNotContainsString(
                    $wrongKey,
                    $exception->getMessage(),
                    'A failed decrypt must not echo key material in its message',
                );
            }
        }
    }

    /**
     * The recovery property: a wrong-key read must not mutate anything, so
     * restoring the correct key restores access. If a failed decrypt damaged the
     * stored envelope — or a read-counter update ran before authentication — this
     * is what would catch it.
     */
    #[Test]
    public function restoringTheCorrectMasterKeyMakesEverySecretReadableAgain(): void
    {
        $seeded = $this->seedSecrets();

        self::assertIsString($this->masterKeyPath);
        $correctKey = (string) file_get_contents($this->masterKeyPath);
        $storedBefore = $this->snapshotEnvelopeColumns();

        $this->installMasterKey(sodium_crypto_secretbox_keygen());

        $vaultService = $this->get(VaultServiceInterface::class);
        foreach (array_keys($seeded) as $identifier) {
            try {
                $vaultService->retrieve($identifier);
                self::fail('Expected the wrong key to be refused for ' . $identifier);
            } catch (EncryptionException) {
                // Expected.
            }
        }

        self::assertSame(
            $storedBefore,
            $this->snapshotEnvelopeColumns(),
            'A failed decrypt must not modify the stored envelope',
        );

        $this->installMasterKey($correctKey);

        foreach ($seeded as $identifier => $plaintext) {
            self::assertSame(
                $plaintext,
                $this->get(VaultServiceInterface::class)->retrieve($identifier),
                'Restoring the correct master key must make "' . $identifier . '" readable again',
            );
        }
    }

    /**
     * "Audit every access" applies to the failures too: a read that could not be
     * decrypted must leave a failed entry behind, otherwise a wrong-key restore
     * is invisible to whoever reviews the log.
     *
     * The hash chain itself is deliberately NOT verified here — the chain HMAC is
     * derived from the master key, so entries written while the wrong key is
     * configured are expected to be keyed differently. Chain integrity across a
     * key change is {@see MasterKeyRotationTest}'s subject.
     */
    #[Test]
    public function aFailedDecryptIsRecordedInTheAuditLog(): void
    {
        $seeded = $this->seedSecrets();
        $identifier = array_key_first($seeded);
        self::assertIsString($identifier);

        $failuresBefore = $this->countFailedAuditEntries($identifier);

        $this->installMasterKey(sodium_crypto_secretbox_keygen());

        try {
            $this->get(VaultServiceInterface::class)->retrieve($identifier);
            self::fail('Expected the wrong key to be refused');
        } catch (EncryptionException) {
            // Expected.
        }

        self::assertGreaterThan(
            $failuresBefore,
            $this->countFailedAuditEntries($identifier),
            'A decryption failure must be recorded as a failed audit entry',
        );
    }

    /**
     * Store the test secrets under the ORIGINAL master key.
     *
     * @return array<string, string>
     */
    private function seedSecrets(): array
    {
        $vaultService = $this->get(VaultServiceInterface::class);

        $seeded = [];
        for ($i = 0; $i < self::SECRET_COUNT; ++$i) {
            $identifier = $this->generateUuidV7();
            $value = 'restore-canary-value-' . $i;
            $vaultService->store($identifier, $value);
            $seeded[$identifier] = $value;
        }

        return $seeded;
    }

    /**
     * Write $key to the configured key file and drop every cache, so the next
     * read genuinely resolves the new key instead of a memoised one.
     */
    private function installMasterKey(string $key): void
    {
        self::assertIsString($this->masterKeyPath);
        file_put_contents($this->masterKeyPath, $key);
        chmod($this->masterKeyPath, 0o600);

        FileMasterKeyProvider::clearCachedKey();
    }

    /**
     * Snapshot the stored envelope columns of every secret.
     *
     * @return list<array<string, mixed>>
     */
    private function snapshotEnvelopeColumns(): array
    {
        return $this->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_secret')
            ->fetchAllAssociative(
                'SELECT identifier, encrypted_value, encrypted_dek, dek_nonce, value_nonce, '
                . 'encryption_version, encryption_algorithm, value_checksum '
                . 'FROM tx_nrvault_secret WHERE deleted = 0 ORDER BY uid',
            );
    }

    private function countFailedAuditEntries(string $identifier): int
    {
        return (int) $this->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_audit_log')
            ->fetchOne(
                'SELECT COUNT(*) FROM tx_nrvault_audit_log WHERE secret_identifier = ? AND success = 0',
                [$identifier],
            );
    }
}
