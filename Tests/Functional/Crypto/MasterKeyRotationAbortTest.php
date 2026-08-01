<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Crypto;

use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Command\VaultRotateMasterKeyCommand;
use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Throwable;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Abort safety of `vault:rotate-master-key` when a secret cannot be re-wrapped.
 *
 * {@see MasterKeyRotationTest} covers the SUCCESS paths end-to-end plus an
 * atomicity property proven against a hand-rolled transaction loop that mirrors
 * the command. What it does not exercise is the REAL command's two abort points,
 * which is where a partial rotation would actually be produced:
 *
 *  1. the pre-transaction smoke test ({@see VaultRotateMasterKeyCommand::verifyOldKey()}),
 *     which re-wraps the FIRST secret to prove the old key before anything is
 *     written — a failure here must leave the vault completely untouched;
 *  2. the in-transaction batch loop, where a failure on a LATER secret must roll
 *     back the secrets already re-wrapped in the same transaction.
 *
 * Both are driven here through {@see CommandTester} with one envelope
 * deliberately made undecryptable in the database, and both assert the same
 * property from two directions: the stored `encrypted_dek`/`dek_nonce` columns of
 * every healthy secret are byte-identical to the pre-run snapshot (nothing was
 * committed), AND every healthy secret still decrypts to its original plaintext
 * under the unchanged master key (nothing was corrupted). Checking only
 * retrievability would pass even if the rotation had silently committed a
 * consistent-but-rotated state, so the column snapshot is what actually proves
 * the rollback.
 */
#[CoversClass(VaultRotateMasterKeyCommand::class)]
final class MasterKeyRotationAbortTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    protected ?string $backendUserFixture = __DIR__ . '/../Hook/Fixtures/be_users.csv';

    /**
     * The provider MUST be pinned to `file`. `AbstractVaultFunctionalTestCase`
     * writes a key file and wires `masterKeySource`/`autoKeyPath`, but the
     * `masterKeyProvider` setting defaults to `typo3` — so without this the
     * secrets would be sealed under the TYPO3 encryption key while
     * `--old-key <file>` supplied a completely different one, and every
     * assertion below would be testing a wrong-key abort instead of the
     * undecryptable-envelope abort it means to test.
     *
     * @var array<string, mixed>
     */
    protected array $extensionConfiguration = [
        'masterKeyProvider' => 'file',
    ];

    /**
     * Abort point 2 — failure inside the transaction.
     *
     * The first secret stays healthy so the smoke test passes and the command
     * commits to the transactional loop; a later secret is undecryptable, so the
     * batch must roll back the ones already re-wrapped.
     */
    #[Test]
    public function aFailureInsideTheTransactionRollsBackAlreadyRewrappedSecrets(): void
    {
        $seeded = $this->seedSecrets(5);
        $identifiers = $this->orderedIdentifiers();
        self::assertCount(5, $identifiers);

        // Corrupt a secret the batch reaches AFTER it has already re-wrapped
        // several others, so a missing rollback would leave a mixed state.
        $sabotaged = $identifiers[3];
        $this->corruptWrappedDek($sabotaged);

        $before = $this->snapshotDekColumns();

        $tester = $this->runRotation();

        self::assertSame(
            Command::FAILURE,
            $tester->getStatusCode(),
            'Rotation must fail when a secret cannot be re-wrapped. Output: ' . $tester->getDisplay(),
        );
        self::assertStringContainsString(
            'Transaction rolled back',
            $tester->getDisplay(),
            'The operator must be told the batch was rolled back',
        );
        self::assertStringContainsString(
            $sabotaged,
            $tester->getDisplay(),
            'The failing secret must be named in the failure report',
        );

        $this->assertDekColumnsUnchanged($before, 'a rolled-back rotation must not commit any DEK re-wrap');
        $this->assertHealthySecretsStillDecrypt($seeded, $sabotaged);

        self::assertTrue(
            $this->get(AuditLogServiceInterface::class)->verifyHashChain()->isValid(),
            'The audit hash chain must remain verifiable after a rolled-back rotation',
        );
    }

    /**
     * Abort point 1 — failure in the pre-transaction smoke test.
     *
     * Corrupting the FIRST secret makes `verifyOldKey()` fail, so the command
     * must bail out before opening a transaction at all: no secret, healthy or
     * not, may be modified.
     */
    #[Test]
    public function aFailedOldKeySmokeTestLeavesTheVaultUntouched(): void
    {
        $seeded = $this->seedSecrets(4);
        $identifiers = $this->orderedIdentifiers();

        // The command smoke-tests $identifiers[0] before writing anything.
        $sabotaged = $identifiers[0];
        $this->corruptWrappedDek($sabotaged);

        $before = $this->snapshotDekColumns();

        $tester = $this->runRotation();

        self::assertSame(
            Command::FAILURE,
            $tester->getStatusCode(),
            'A failed old-key smoke test must abort the rotation. Output: ' . $tester->getDisplay(),
        );
        self::assertStringContainsString(
            'Failed to decrypt with old master key',
            $tester->getDisplay(),
            'The smoke-test failure must be reported as a key problem',
        );
        self::assertStringNotContainsString(
            'Audit chain re-keyed',
            $tester->getDisplay(),
            'The audit chain must not be re-keyed when the rotation never started',
        );

        $this->assertDekColumnsUnchanged($before, 'an aborted smoke test must not modify any secret');
        $this->assertHealthySecretsStillDecrypt($seeded, $sabotaged);

        self::assertTrue(
            $this->get(AuditLogServiceInterface::class)->verifyHashChain()->isValid(),
            'The audit hash chain must remain verifiable after an aborted rotation',
        );
    }

    /**
     * Store $count secrets and return them as identifier => plaintext.
     *
     * @return array<string, string>
     */
    private function seedSecrets(int $count): array
    {
        $vaultService = $this->get(VaultServiceInterface::class);

        $seeded = [];
        for ($i = 0; $i < $count; ++$i) {
            $identifier = $this->generateUuidV7();
            $value = 'abort-safety-value-' . $i;
            $vaultService->store($identifier, $value);
            $seeded[$identifier] = $value;
        }

        return $seeded;
    }

    /**
     * Identifiers in the order the command will process them — read from the
     * repository rather than assumed, because `findIdentifiers()` applies no
     * explicit ORDER BY and the command smoke-tests whichever comes first.
     *
     * @return list<string>
     */
    private function orderedIdentifiers(): array
    {
        return $this->get(SecretRepositoryInterface::class)->findIdentifiers();
    }

    /**
     * Make one secret's wrapped DEK undecryptable by flipping a bit of the
     * sealed key material, leaving everything else (including valid base64)
     * intact. This is the "one envelope cannot be re-wrapped" condition the
     * rotation has to survive, and it is written straight to the column so the
     * damage predates the command run.
     */
    private function corruptWrappedDek(string $identifier): void
    {
        $connection = $this->get(ConnectionPool::class)->getConnectionForTable(self::SECRET_TABLE);

        $encodedDek = $connection->fetchOne(
            'SELECT encrypted_dek FROM ' . self::SECRET_TABLE . ' WHERE identifier = ?',
            [$identifier],
        );
        self::assertIsString($encodedDek);

        $raw = base64_decode($encodedDek, true);
        self::assertIsString($raw);
        self::assertNotSame('', $raw);

        $raw[0] = \chr(\ord($raw[0]) ^ 0xFF);

        $connection->update(
            self::SECRET_TABLE,
            ['encrypted_dek' => base64_encode($raw)],
            ['identifier' => $identifier],
        );
    }

    /**
     * Snapshot the DEK columns of every secret, keyed by identifier.
     *
     * @return array<string, array{encrypted_dek: string, dek_nonce: string}>
     */
    private function snapshotDekColumns(): array
    {
        $rows = $this->get(ConnectionPool::class)
            ->getConnectionForTable(self::SECRET_TABLE)
            ->fetchAllAssociative(
                'SELECT identifier, encrypted_dek, dek_nonce FROM ' . self::SECRET_TABLE . ' WHERE deleted = 0',
            );

        $snapshot = [];
        foreach ($rows as $row) {
            $snapshot[$this->asString($row['identifier'])] = [
                'encrypted_dek' => $this->asString($row['encrypted_dek']),
                'dek_nonce' => $this->asString($row['dek_nonce']),
            ];
        }

        return $snapshot;
    }

    /**
     * Narrow a DBAL column value to string. Asserting rather than casting keeps
     * the failure at the row that surprised us instead of silently stringifying
     * a null the schema says cannot happen.
     */
    private function asString(mixed $value): string
    {
        self::assertIsString($value);

        return $value;
    }

    /**
     * @param array<string, array{encrypted_dek: string, dek_nonce: string}> $before
     */
    private function assertDekColumnsUnchanged(array $before, string $why): void
    {
        self::assertSame($before, $this->snapshotDekColumns(), $why);
    }

    /**
     * Every seeded secret except the sabotaged one must still decrypt to its
     * original plaintext under the unchanged master key. The sabotaged one is
     * expected to stay broken — its damage was inflicted by the test, not by
     * the rotation, and the rotation must not have "fixed" or replaced it.
     *
     * @param array<string, string> $seeded
     */
    private function assertHealthySecretsStillDecrypt(array $seeded, string $sabotaged): void
    {
        FileMasterKeyProvider::clearCachedKey();
        $vaultService = $this->get(VaultServiceInterface::class);

        foreach ($seeded as $identifier => $expected) {
            if ($identifier === $sabotaged) {
                continue;
            }

            self::assertSame(
                $expected,
                $vaultService->retrieve($identifier),
                \sprintf(
                    'Secret "%s" MUST still decrypt with the original master key — '
                    . 'a partially rotated vault is the failure this test exists to catch',
                    $identifier,
                ),
            );
        }

        try {
            $vaultService->retrieve($sabotaged);
            self::fail('The sabotaged secret must remain undecryptable, not silently repaired');
        } catch (EncryptionException) {
            // Expected: the corrupted wrapped DEK still fails authentication.
        }
    }

    /**
     * Run the real command from the configured key file to a fresh new key.
     */
    private function runRotation(): CommandTester
    {
        self::assertIsString($this->masterKeyPath);

        $newKeyPath = $this->instancePath . '/master-abort-target.key';
        file_put_contents($newKeyPath, sodium_crypto_secretbox_keygen());

        $tester = new CommandTester($this->get(VaultRotateMasterKeyCommand::class));

        try {
            $tester->execute([
                '--old-key' => $this->masterKeyPath,
                '--new-key' => $newKeyPath,
                '--confirm' => true,
            ]);
        } catch (Throwable $exception) {
            self::fail(
                'The rotation command must handle an undecryptable envelope itself, '
                . 'not escape as ' . $exception::class . ': ' . $exception->getMessage(),
            );
        } finally {
            if (file_exists($newKeyPath)) {
                // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
                unlink($newKeyPath);
            }
        }

        return $tester;
    }
}
