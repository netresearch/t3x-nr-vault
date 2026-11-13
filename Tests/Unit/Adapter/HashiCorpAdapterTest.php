<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Adapter;

use Netresearch\NrVault\Adapter\HashiCorpAdapter;
use Netresearch\NrVault\Adapter\LocalEncryptionAdapter;
use Netresearch\NrVault\Configuration\Dto\VaultServerConfig;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Exception\HashiCorpException;
use Netresearch\NrVault\Storage\HashiCorp\KvStoreInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;

#[CoversClass(HashiCorpAdapter::class)]
#[AllowMockObjectsWithoutExpectations]
final class HashiCorpAdapterTest extends TestCase
{
    private const BINARY_VALUE = "cipher\x00\xff\x10text";

    /** @var array<string, Secret> */
    private array $rows = [];

    /** @var array<string, array<string, mixed>> */
    private array $vault = [];

    /** @var list<string> */
    private array $vaultCalls = [];

    private bool $failRowWrite = false;

    private bool $failRowDelete = false;

    private bool $rowAppearsBeforeFailure = false;

    protected function setUp(): void
    {
        parent::setUp();

        $this->rows                    = [];
        $this->vault                   = [];
        $this->vaultCalls              = [];
        $this->failRowWrite            = false;
        $this->failRowDelete           = false;
        $this->rowAppearsBeforeFailure = false;
    }

    #[Test]
    public function aNewSecretKeepsItsEnvelopeInVaultAndOnlyAPointerInTheRow(): void
    {
        $stored = $this->adapter()->store($this->envelopeSecret('api_key'));

        self::assertSame(1, $stored->getUid());
        $row = $this->rows['api_key'];
        self::assertSame('hashicorp', $row->getAdapter());
        self::assertSame('secret/data/typo3/api_key', $row->getExternalReference());
        self::assertNull($row->getEncryptedValue(), 'the row holds no ciphertext');
        self::assertSame('', $row->getEncryptedDek());
        self::assertSame('', $row->getValueChecksum());

        self::assertArrayHasKey('api_key', $this->vault);
        self::assertSame(base64_encode(self::BINARY_VALUE), $this->vault['api_key']['encrypted_value']);
    }

    #[Test]
    public function retrieveRebuildsTheExactEnvelopeFromVault(): void
    {
        $adapter  = $this->adapter();
        $original = $this->envelopeSecret('api_key');
        $adapter->store($original);

        $secret = $adapter->retrieve('api_key');

        self::assertInstanceOf(Secret::class, $secret);
        self::assertSame(self::BINARY_VALUE, $secret->getEncryptedValue());
        self::assertSame($original->getEncryptedDek(), $secret->getEncryptedDek());
        self::assertSame($original->getDekNonce(), $secret->getDekNonce());
        self::assertSame($original->getValueNonce(), $secret->getValueNonce());
        self::assertSame($original->getValueChecksum(), $secret->getValueChecksum());
        self::assertSame(2, $secret->getEncryptionVersion());
        self::assertSame('xchacha20poly1305', $secret->getEncryptionAlgorithm());
    }

    #[Test]
    public function retrieveIncludingDisabledRebuildsTheEnvelopeToo(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $secret = $adapter->retrieveIncludingDisabled('api_key');

        self::assertSame(self::BINARY_VALUE, $secret?->getEncryptedValue());
    }

    #[Test]
    public function retrieveOfAnUnknownSecretNeverCallsVault(): void
    {
        self::assertNull($this->adapter()->retrieve('missing'));
        self::assertSame([], $this->vaultCalls);
    }

    #[Test]
    public function aSecretStoredLocallyBeforeTheSwitchStaysLocal(): void
    {
        $this->rows['legacy'] = $this->envelopeSecret('legacy')->withUid(7);
        $adapter              = $this->adapter();

        $adapter->store($this->envelopeSecret('legacy')->withUid(7));

        self::assertSame('local', $this->rows['legacy']->getAdapter());
        self::assertNotNull($this->rows['legacy']->getEncryptedValue(), 'the envelope stays in the row');
        self::assertSame([], $this->vaultCalls, 'Vault is never touched for a local secret');
        self::assertSame('local', $adapter->retrieve('legacy')?->getAdapter());
        self::assertSame([], $this->vaultCalls);
    }

    #[Test]
    public function aRowThatExistsWithoutAValueMovesToVaultWhenTheValueArrives(): void
    {
        $this->rows['form_field'] = new Secret(identifier: 'form_field', uid: 5);

        $this->adapter()->store($this->envelopeSecret('form_field')->withUid(5));

        self::assertSame('hashicorp', $this->rows['form_field']->getAdapter());
        self::assertSame(5, $this->rows['form_field']->getUid());
        self::assertArrayHasKey('form_field', $this->vault);
    }

    #[Test]
    public function restoringAValuelessRowDoesNotMarkItAsVaultBacked(): void
    {
        $this->adapter()->store(new Secret(identifier: 'form_field', uid: 5));

        self::assertSame('local', $this->rows['form_field']->getAdapter());
        self::assertSame([], $this->vaultCalls);
    }

    #[Test]
    public function rotatingWritesANewVaultVersionAndKeepsTheRowPointer(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $first = $this->vault['api_key']['encrypted_value'];

        $rotated = $this->envelopeSecret('api_key', "rotated\x01value")->withUid(1);
        $adapter->store($rotated);

        self::assertNotSame($first, $this->vault['api_key']['encrypted_value']);
        self::assertSame("rotated\x01value", $adapter->retrieve('api_key')?->getEncryptedValue());
        self::assertSame('hashicorp', $this->rows['api_key']->getAdapter());
    }

    #[Test]
    public function aFailedFirstInsertRemovesTheValueItJustWroteToVault(): void
    {
        $this->failRowWrite = true;

        try {
            $this->adapter()->store($this->envelopeSecret('api_key'));
            self::fail('The row failure must propagate.');
        } catch (RuntimeException $e) {
            self::assertSame('row write failed', $e->getMessage());
        }

        self::assertArrayNotHasKey('api_key', $this->vault, 'no orphan value is left in Vault');
        self::assertContains('destroy:api_key', $this->vaultCalls);
    }

    #[Test]
    public function aFailedUpdateKeepsTheExistingVaultObject(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $this->failRowWrite = true;

        try {
            $adapter->store($this->envelopeSecret('api_key', 'newer')->withUid(1));
            self::fail('The row failure must propagate.');
        } catch (RuntimeException) {
        }

        self::assertArrayHasKey('api_key', $this->vault);
        self::assertNotContains('destroy:api_key', $this->vaultCalls);
    }

    #[Test]
    public function aFailedUpdateRestoresThePreviousEnvelopeInVault(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $before             = $this->vault['api_key'];
        $this->failRowWrite = true;

        try {
            $adapter->store($this->envelopeSecret('api_key', 'newer')->withUid(1));
            self::fail('The row failure must propagate.');
        } catch (RuntimeException) {
        }

        self::assertSame($before, $this->vault['api_key']);
    }

    #[Test]
    public function aFailedCreateDoesNotDestroyTheObjectOfAConcurrentCreate(): void
    {
        $this->failRowWrite            = true;
        $this->rowAppearsBeforeFailure = true;

        try {
            $this->adapter()->store($this->envelopeSecret('api_key'));
            self::fail('The row failure must propagate.');
        } catch (RuntimeException) {
        }

        self::assertArrayHasKey('api_key', $this->vault, 'a row refers to the object now');
    }

    #[Test]
    public function aFailedRowDeleteRestoresTheVaultValue(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $before              = $this->vault['api_key'];
        $this->failRowDelete = true;

        try {
            $adapter->delete('api_key');
            self::fail('The row failure must propagate.');
        } catch (RuntimeException) {
        }

        self::assertSame($before, $this->vault['api_key']);
        self::assertArrayHasKey('api_key', $this->rows);
    }

    #[Test]
    public function restoringADanglingExternalRowRemovesAValueWrittenSince(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $dangling = $adapter->retrieveIncludingDisabled('api_key');
        unset($this->vault['api_key']);
        self::assertInstanceOf(Secret::class, $dangling);
        $valueless = $dangling->withExternalStorage('hashicorp', 'secret/data/typo3/api_key');
        $adapter->store($this->envelopeSecret('api_key', 'written-since')->withUid(1));

        $adapter->store($valueless);

        self::assertArrayNotHasKey('api_key', $this->vault);
    }

    #[Test]
    public function restoringAValuelessLocalRowRemovesAValueWrittenSince(): void
    {
        $this->rows['form_field'] = new Secret(identifier: 'form_field', uid: 5);
        $adapter                  = $this->adapter();
        $adapter->store($this->envelopeSecret('form_field')->withUid(5));
        self::assertArrayHasKey('form_field', $this->vault);

        $adapter->store(new Secret(identifier: 'form_field', uid: 5));

        self::assertArrayNotHasKey('form_field', $this->vault);
        self::assertSame('local', $this->rows['form_field']->getAdapter());
    }

    #[Test]
    public function aFailedRestoreOfAValuelessRowPutsTheVaultValueBack(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $before             = $this->vault['api_key'];
        $this->failRowWrite = true;

        try {
            $adapter->store(new Secret(identifier: 'api_key', uid: 1));
            self::fail('The row failure must propagate.');
        } catch (RuntimeException) {
        }

        self::assertSame($before, $this->vault['api_key']);
    }

    #[Test]
    public function deleteRemovesTheVaultObjectBeforeTheRow(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $adapter->delete('api_key');

        self::assertArrayNotHasKey('api_key', $this->vault);
        self::assertArrayNotHasKey('api_key', $this->rows);
        self::assertSame('destroy:api_key', end($this->vaultCalls));
    }

    #[Test]
    public function deleteOfALocalSecretNeverCallsVault(): void
    {
        $this->rows['legacy'] = $this->envelopeSecret('legacy')->withUid(7);

        $this->adapter()->delete('legacy');

        self::assertArrayNotHasKey('legacy', $this->rows);
        self::assertSame([], $this->vaultCalls);
    }

    #[Test]
    public function aRowWhoseVaultObjectIsGoneIsReportedNotReturnedEmpty(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));
        unset($this->vault['api_key']);

        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400009);

        $adapter->retrieve('api_key');
    }

    #[Test]
    public function theAdministrativeLookupStillReturnsARowWhoseVaultObjectIsGone(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));
        unset($this->vault['api_key']);

        $row = $adapter->retrieveIncludingDisabled('api_key');

        self::assertInstanceOf(Secret::class, $row);
        self::assertNull($row->getEncryptedValue());
        self::assertSame('hashicorp', $row->getAdapter());
    }

    #[Test]
    public function aRowWhoseVaultObjectIsGoneCanStillBeDeleted(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));
        unset($this->vault['api_key']);

        $adapter->delete('api_key');

        self::assertArrayNotHasKey('api_key', $this->rows);
    }

    #[Test]
    public function aRowWhoseVaultObjectIsGoneIsRepairedByTheNextStore(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));
        unset($this->vault['api_key']);

        $adapter->store($this->envelopeSecret('api_key', 'replacement')->withUid(1));

        self::assertSame('replacement', $adapter->retrieve('api_key')?->getEncryptedValue());
    }

    #[Test]
    public function aVaultObjectThatBelongsToAnotherIdentifierIsRefused(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));
        $this->vault['api_key']['identifier'] = 'someone_else';

        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400010);

        $adapter->retrieve('api_key');
    }

    #[Test]
    public function aVaultObjectWithABrokenEnvelopeIsRefused(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));
        $this->vault['api_key']['encrypted_value'] = '!!not base64!!';

        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400010);

        $adapter->retrieve('api_key');
    }

    #[Test]
    public function aVaultObjectWithAnUnknownFormatIsRefused(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));
        $this->vault['api_key']['format'] = 99;

        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400010);

        $adapter->retrieve('api_key');
    }

    #[Test]
    public function dataOfSomebodyElseAtTheKvPathIsNeitherOverwrittenNorDestroyed(): void
    {
        $this->vault['api_key'] = ['unrelated' => 'value'];
        $adapter                = $this->adapter();

        try {
            $adapter->store($this->envelopeSecret('api_key'));
            self::fail('Foreign data at the path must refuse the store.');
        } catch (HashiCorpException $e) {
            self::assertSame(1794400012, $e->getCode());
        }

        self::assertSame(['unrelated' => 'value'], $this->vaultRead('api_key'));
        self::assertNotContains('write:api_key', $this->vaultCalls);
        self::assertNotContains('destroy:api_key', $this->vaultCalls);
        self::assertArrayNotHasKey('api_key', $this->rows);
    }

    #[Test]
    public function anObjectThatBelongsToAnotherIdentifierIsNotAdopted(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('other_key'));
        $this->vault['api_key'] = $this->vault['other_key'];
        unset($this->rows['other_key']);

        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400012);

        $adapter->store($this->envelopeSecret('api_key'));
    }

    #[Test]
    public function anUnreferencedEarlierWriteOfTheSameIdentifierIsAdoptedAndPutBackOnFailure(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $orphan = $this->vault['api_key'];
        unset($this->rows['api_key']);

        $adapter->store($this->envelopeSecret('api_key', 'adopted'));
        self::assertSame('adopted', $adapter->retrieve('api_key')?->getEncryptedValue());

        unset($this->rows['api_key']);
        $this->vault['api_key'] = $orphan;
        $this->failRowWrite     = true;

        try {
            $adapter->store($this->envelopeSecret('api_key', 'adopted-again'));
            self::fail('The row failure must propagate.');
        } catch (RuntimeException) {
        }

        self::assertSame($orphan, $this->vaultRead('api_key'), 'the adopted object is put back, not destroyed');
    }

    #[Test]
    public function registryOperationsNeverCallVault(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $this->vaultCalls = [];

        $adapter->exists('api_key');
        $adapter->list();
        $adapter->listSecrets();
        $adapter->getMetadata('api_key');
        $adapter->updateMetadata('api_key', ['a' => 'b']);
        $adapter->setHidden(1, true);
        $adapter->incrementReadCount(1);

        self::assertSame([], $this->vaultCalls);
    }

    #[Test]
    public function identifiesItselfAndReportsAvailabilityFromConfigurationAlone(): void
    {
        self::assertSame('hashicorp', $this->adapter()->getIdentifier());
        self::assertTrue($this->adapter()->isAvailable());
        self::assertFalse($this->adapter(address: 'http://vault.example.com')->isAvailable());
        self::assertSame([], $this->vaultCalls, 'availability makes no network call');
    }

    /**
     * @return array<string, mixed>|null
     */
    public function vaultRead(string $identifier): ?array
    {
        $this->vaultCalls[] = 'read:' . $identifier;

        return $this->vault[$identifier] ?? null;
    }

    /**
     * @param array<string, mixed> $data
     */
    public function vaultWrite(string $identifier, array $data): void
    {
        $this->vaultCalls[]       = 'write:' . $identifier;
        $this->vault[$identifier] = $data;
    }

    public function vaultDestroy(string $identifier): void
    {
        $this->vaultCalls[] = 'destroy:' . $identifier;
        unset($this->vault[$identifier]);
    }

    private function envelopeSecret(string $identifier, string $value = self::BINARY_VALUE): Secret
    {
        return new Secret(
            identifier: $identifier,
            encryptedValue: $value,
            encryptedDek: 'wrapped-dek',
            dekNonce: 'dek-nonce',
            valueNonce: 'value-nonce',
            encryptionVersion: 2,
            encryptionAlgorithm: 'xchacha20poly1305',
            valueChecksum: hash('sha256', $value),
        );
    }

    private function adapter(string $address = 'https://vault.example.com:8200'): HashiCorpAdapter
    {
        $repository = $this->createMock(SecretRepositoryInterface::class);
        $repository->method('findByIdentifier')->willReturnCallback(
            fn (string $identifier): ?Secret => $this->rows[$identifier] ?? null,
        );
        $repository->method('findByIdentifierIncludingDisabled')->willReturnCallback(
            fn (string $identifier): ?Secret => $this->rows[$identifier] ?? null,
        );
        $repository->method('exists')->willReturnCallback(
            fn (string $identifier): bool => isset($this->rows[$identifier]),
        );
        $repository->method('findIdentifiers')->willReturnCallback(
            fn (): array => array_keys($this->rows),
        );
        $repository->method('findAllWithFilters')->willReturnCallback(
            fn (): array => array_values($this->rows),
        );
        $repository->method('save')->willReturnCallback(function (Secret $secret): Secret {
            if ($this->failRowWrite) {
                if ($this->rowAppearsBeforeFailure) {
                    $this->rows[$secret->getIdentifier()] = $secret->withUid(99);
                }

                throw new RuntimeException('row write failed', 4778462882);
            }

            $saved                               = $secret->getUid() === null ? $secret->withUid(count($this->rows) + 1) : $secret;
            $this->rows[$saved->getIdentifier()] = $saved;

            return $saved;
        });
        $repository->method('delete')->willReturnCallback(function (Secret $secret): void {
            if ($this->failRowDelete) {
                throw new RuntimeException('row delete failed', 4778462883);
            }

            unset($this->rows[$secret->getIdentifier()]);
        });

        $configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $configuration->method('getHashiCorpConfig')->willReturn(new VaultServerConfig(
            address: $address,
            path: 'secret/data/typo3',
            authMethod: 'token',
            token: 'unit-token',
        ));

        $kv = new class ($this) implements KvStoreInterface {
            public function __construct(private readonly HashiCorpAdapterTest $test) {}

            public function read(string $identifier): ?array
            {
                return $this->test->vaultRead($identifier);
            }

            public function write(string $identifier, array $data): void
            {
                $this->test->vaultWrite($identifier, $data);
            }

            public function destroy(string $identifier): void
            {
                $this->test->vaultDestroy($identifier);
            }

            public function reference(string $identifier): string
            {
                return 'secret/data/typo3/' . $identifier;
            }
        };

        return new HashiCorpAdapter(new LocalEncryptionAdapter($repository), $kv, $configuration);
    }
}
