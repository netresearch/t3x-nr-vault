<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Adapter;

use Netresearch\NrVault\Adapter\AwsSecretsManagerAdapter;
use Netresearch\NrVault\Adapter\LocalEncryptionAdapter;
use Netresearch\NrVault\Configuration\Dto\AwsSecretsConfig;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Exception\AwsSecretsManagerException;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Storage\Aws\AwsSecretStoreInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;

#[CoversClass(AwsSecretsManagerAdapter::class)]
#[AllowMockObjectsWithoutExpectations]
final class AwsSecretsManagerAdapterTest extends TestCase
{
    private const BINARY_VALUE = "cipher\x00\xff\x10text";

    /** @var array<string, Secret> */
    private array $rows = [];

    /** @var array<string, array<string, mixed>> */
    private array $aws = [];

    /** @var list<string> */
    private array $awsCalls = [];

    private bool $failRowWrite = false;

    private bool $failRowDelete = false;

    private bool $rowAppearsBeforeFailure = false;

    /** @var array<string, int> */
    private array $versions = [];

    /** @var array<string, mixed>|null */
    private ?array $concurrentWriterReplacesSecret = null;

    private bool $readKeysSorted = false;

    protected function setUp(): void
    {
        parent::setUp();

        $this->rows                           = [];
        $this->aws                            = [];
        $this->awsCalls                       = [];
        $this->failRowWrite                   = false;
        $this->failRowDelete                  = false;
        $this->rowAppearsBeforeFailure        = false;
        $this->versions                       = [];
        $this->concurrentWriterReplacesSecret = null;
        $this->readKeysSorted                 = false;
    }

    #[Test]
    public function aNewSecretKeepsItsEnvelopeInAwsAndOnlyAPointerInTheRow(): void
    {
        $stored = $this->adapter()->store($this->envelopeSecret('api_key'));

        self::assertSame(1, $stored->getUid());
        $row = $this->rows['api_key'];
        self::assertSame('aws', $row->getAdapter());
        self::assertSame('eu-central-1:typo3/api_key', $row->getExternalReference());
        self::assertNull($row->getEncryptedValue(), 'the row holds no ciphertext');
        self::assertSame('', $row->getEncryptedDek());
        self::assertSame('', $row->getValueChecksum());

        self::assertArrayHasKey('api_key', $this->aws);
        self::assertSame(base64_encode(self::BINARY_VALUE), $this->aws['api_key']['encrypted_value']);
    }

    #[Test]
    public function retrieveRebuildsTheExactEnvelopeFromAws(): void
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
    public function retrieveOfAnUnknownSecretNeverCallsAws(): void
    {
        self::assertNull($this->adapter()->retrieve('missing'));
        self::assertSame([], $this->awsCalls);
    }

    #[Test]
    public function aSecretStoredLocallyBeforeTheSwitchStaysLocal(): void
    {
        $this->rows['legacy'] = $this->envelopeSecret('legacy')->withUid(7);
        $adapter              = $this->adapter();

        $adapter->store($this->envelopeSecret('legacy')->withUid(7));

        self::assertSame('local', $this->rows['legacy']->getAdapter());
        self::assertNotNull($this->rows['legacy']->getEncryptedValue(), 'the envelope stays in the row');
        self::assertSame([], $this->awsCalls, 'Aws is never touched for a local secret');
        self::assertSame('local', $adapter->retrieve('legacy')?->getAdapter());
        self::assertSame([], $this->awsCalls);
    }

    #[Test]
    public function aRowThatExistsWithoutAValueMovesToAwsWhenTheValueArrives(): void
    {
        $this->rows['form_field'] = new Secret(identifier: 'form_field', uid: 5);

        $this->adapter()->store($this->envelopeSecret('form_field')->withUid(5));

        self::assertSame('aws', $this->rows['form_field']->getAdapter());
        self::assertSame(5, $this->rows['form_field']->getUid());
        self::assertArrayHasKey('form_field', $this->aws);
    }

    #[Test]
    public function restoringAValuelessRowDoesNotMarkItAsAwsBacked(): void
    {
        $this->adapter()->store(new Secret(identifier: 'form_field', uid: 5));

        self::assertSame('local', $this->rows['form_field']->getAdapter());
        self::assertSame([], $this->awsCalls);
    }

    #[Test]
    public function rotatingWritesANewAwsVersionAndKeepsTheRowPointer(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $first = $this->aws['api_key']['encrypted_value'];

        $rotated = $this->envelopeSecret('api_key', "rotated\x01value")->withUid(1);
        $adapter->store($rotated);

        self::assertNotSame($first, $this->aws['api_key']['encrypted_value']);
        self::assertSame("rotated\x01value", $adapter->retrieve('api_key')?->getEncryptedValue());
        self::assertSame('aws', $this->rows['api_key']->getAdapter());
    }

    #[Test]
    public function aFailedFirstInsertRemovesTheValueItJustWroteToAws(): void
    {
        $this->failRowWrite = true;

        try {
            $this->adapter()->store($this->envelopeSecret('api_key'));
            self::fail('The row failure must propagate.');
        } catch (RuntimeException $e) {
            self::assertSame('row write failed', $e->getMessage());
        }

        self::assertArrayNotHasKey('api_key', $this->aws, 'no orphan value is left in Aws');
        self::assertContains('destroy:api_key', $this->awsCalls);
    }

    #[Test]
    public function aFailedUpdateKeepsTheExistingAwsObject(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $this->failRowWrite = true;

        try {
            $adapter->store($this->envelopeSecret('api_key', 'newer')->withUid(1));
            self::fail('The row failure must propagate.');
        } catch (RuntimeException) {
        }

        self::assertArrayHasKey('api_key', $this->aws);
        self::assertNotContains('destroy:api_key', $this->awsCalls);
    }

    #[Test]
    public function aFailedUpdateRestoresThePreviousEnvelopeInAws(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $before             = $this->aws['api_key'];
        $this->failRowWrite = true;

        try {
            $adapter->store($this->envelopeSecret('api_key', 'newer')->withUid(1));
            self::fail('The row failure must propagate.');
        } catch (RuntimeException) {
        }

        self::assertSame($before, $this->aws['api_key']);
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

        self::assertArrayHasKey('api_key', $this->aws, 'a row refers to the object now');
    }

    #[Test]
    public function aFailedRowDeleteRestoresTheAwsValue(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $before              = $this->aws['api_key'];
        $this->failRowDelete = true;

        try {
            $adapter->delete('api_key');
            self::fail('The row failure must propagate.');
        } catch (RuntimeException) {
        }

        self::assertSame($before, $this->aws['api_key']);
        self::assertArrayHasKey('api_key', $this->rows);
    }

    #[Test]
    public function restoringADanglingExternalRowRemovesAValueWrittenSince(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $dangling = $adapter->retrieveIncludingDisabled('api_key');
        unset($this->aws['api_key']);
        self::assertInstanceOf(Secret::class, $dangling);
        $valueless = $dangling->withExternalStorage('aws', 'eu-central-1:typo3/api_key');
        $adapter->store($this->envelopeSecret('api_key', 'written-since')->withUid(1));

        $adapter->store($valueless);

        self::assertArrayNotHasKey('api_key', $this->aws);
    }

    #[Test]
    public function restoringAValuelessLocalRowRemovesAValueWrittenSince(): void
    {
        $this->rows['form_field'] = new Secret(identifier: 'form_field', uid: 5);
        $adapter                  = $this->adapter();
        $adapter->store($this->envelopeSecret('form_field')->withUid(5));
        self::assertArrayHasKey('form_field', $this->aws);

        $adapter->store(new Secret(identifier: 'form_field', uid: 5));

        self::assertArrayNotHasKey('form_field', $this->aws);
        self::assertSame('local', $this->rows['form_field']->getAdapter());
    }

    #[Test]
    public function aFailedRestoreOfAValuelessRowPutsTheAwsValueBack(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $before             = $this->aws['api_key'];
        $this->failRowWrite = true;

        try {
            $adapter->store(new Secret(identifier: 'api_key', uid: 1));
            self::fail('The row failure must propagate.');
        } catch (RuntimeException) {
        }

        self::assertSame($before, $this->aws['api_key']);
    }

    #[Test]
    public function deleteRemovesTheAwsObjectBeforeTheRow(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $adapter->delete('api_key');

        self::assertArrayNotHasKey('api_key', $this->aws);
        self::assertArrayNotHasKey('api_key', $this->rows);
        self::assertSame('destroy:api_key', end($this->awsCalls));
    }

    #[Test]
    public function deleteOfALocalSecretNeverCallsAws(): void
    {
        $this->rows['legacy'] = $this->envelopeSecret('legacy')->withUid(7);

        $this->adapter()->delete('legacy');

        self::assertArrayNotHasKey('legacy', $this->rows);
        self::assertSame([], $this->awsCalls);
    }

    #[Test]
    public function aRowWhoseAwsObjectIsGoneIsReportedNotReturnedEmpty(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));
        unset($this->aws['api_key']);

        $this->expectException(AwsSecretsManagerException::class);
        $this->expectExceptionCode(1794500009);

        $adapter->retrieve('api_key');
    }

    #[Test]
    public function theAdministrativeLookupStillReturnsARowWhoseAwsObjectIsGone(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));
        unset($this->aws['api_key']);

        $row = $adapter->retrieveIncludingDisabled('api_key');

        self::assertInstanceOf(Secret::class, $row);
        self::assertNull($row->getEncryptedValue());
        self::assertSame('aws', $row->getAdapter());
    }

    #[Test]
    public function aRowWhoseAwsObjectIsGoneCanStillBeDeleted(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));
        unset($this->aws['api_key']);

        $adapter->delete('api_key');

        self::assertArrayNotHasKey('api_key', $this->rows);
    }

    #[Test]
    public function aRowWhoseAwsObjectIsGoneIsRepairedByTheNextStore(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));
        unset($this->aws['api_key']);

        $adapter->store($this->envelopeSecret('api_key', 'replacement')->withUid(1));

        self::assertSame('replacement', $adapter->retrieve('api_key')?->getEncryptedValue());
    }

    #[Test]
    public function anAwsObjectThatBelongsToAnotherIdentifierIsRefused(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));
        $this->aws['api_key']['identifier'] = 'someone_else';

        $this->expectException(AwsSecretsManagerException::class);
        $this->expectExceptionCode(1794500010);

        $adapter->retrieve('api_key');
    }

    #[Test]
    public function anAwsObjectWithABrokenEnvelopeIsRefused(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));
        $this->aws['api_key']['encrypted_value'] = '!!not base64!!';

        $this->expectException(AwsSecretsManagerException::class);
        $this->expectExceptionCode(1794500010);

        $adapter->retrieve('api_key');
    }

    #[Test]
    public function anAwsObjectWithAnUnknownFormatIsRefused(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));
        $this->aws['api_key']['format'] = 99;

        $this->expectException(AwsSecretsManagerException::class);
        $this->expectExceptionCode(1794500010);

        $adapter->retrieve('api_key');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function operationsOnARowOfAnotherAdapter(): iterable
    {
        yield 'store with a value' => ['store'];
        yield 'store without a value' => ['restore'];
        yield 'retrieve' => ['retrieve'];
        yield 'delete' => ['delete'];
    }

    #[Test]
    #[DataProvider('operationsOnARowOfAnotherAdapter')]
    public function aRowBoundToAnotherExternalAdapterIsNotRebuiltReboundOrDeletedHere(string $operation): void
    {
        $this->rows['api_key'] = $this->envelopeSecret('api_key')->withUid(3)->withExternalStorage('hashicorp', 'secret/data/typo3/api_key');
        $adapter               = $this->adapter();

        try {
            match ($operation) {
                'store'    => $adapter->store($this->envelopeSecret('api_key')->withUid(3)),
                'restore'  => $adapter->store(new Secret(identifier: 'api_key', uid: 3)),
                'retrieve' => $adapter->retrieve('api_key'),
                default    => $adapter->delete('api_key'),
            };
            self::fail('A row of another external adapter must be refused.');
        } catch (ConfigurationException $e) {
            self::assertSame(1794500020, $e->getCode());
            self::assertStringContainsString('"hashicorp"', $e->getMessage());
        }

        self::assertSame([], $this->awsCalls, 'AWS is never touched for it');
        self::assertSame('hashicorp', $this->rows['api_key']->getAdapter(), 'the row stays as it was');
        self::assertSame('hashicorp', $adapter->retrieveIncludingDisabled('api_key')?->getAdapter(), 'the administrative lookup still lists it');
    }

    #[Test]
    public function aSecretOfSomebodyElseUnderTheNameIsNeitherOverwrittenNorDestroyed(): void
    {
        $this->aws['api_key'] = ['unrelated' => 'value'];
        $adapter              = $this->adapter();

        try {
            $adapter->store($this->envelopeSecret('api_key'));
            self::fail('A foreign secret under the name must refuse the store.');
        } catch (AwsSecretsManagerException $e) {
            self::assertSame(1794500011, $e->getCode());
        }

        self::assertSame(['unrelated' => 'value'], $this->awsRead('api_key'));
        self::assertNotContains('write:api_key', $this->awsCalls);
        self::assertNotContains('destroy:api_key', $this->awsCalls);
        self::assertArrayNotHasKey('api_key', $this->rows);
    }

    #[Test]
    public function aSecretThatBelongsToAnotherIdentifierIsNotAdopted(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('other_key'));
        $this->aws['api_key'] = $this->aws['other_key'];
        unset($this->rows['other_key']);

        $this->expectException(AwsSecretsManagerException::class);
        $this->expectExceptionCode(1794500011);

        $adapter->store($this->envelopeSecret('api_key'));
    }

    #[Test]
    public function anUnreferencedEarlierWriteOfTheSameIdentifierIsAdoptedAndPutBackOnFailure(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $orphan = $this->aws['api_key'];
        unset($this->rows['api_key']);

        $adapter->store($this->envelopeSecret('api_key', 'adopted'));
        self::assertSame('adopted', $adapter->retrieve('api_key')?->getEncryptedValue());

        unset($this->rows['api_key']);
        $this->aws['api_key'] = $orphan;
        $this->failRowWrite   = true;

        try {
            $adapter->store($this->envelopeSecret('api_key', 'adopted-again'));
            self::fail('The row failure must propagate.');
        } catch (RuntimeException) {
        }

        self::assertSame($orphan, $this->aws['api_key'], 'the adopted secret is put back, not destroyed');
    }

    #[Test]
    public function aRollbackNeverOverwritesAConcurrentWritersVersion(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $this->failRowWrite                   = true;
        $this->concurrentWriterReplacesSecret = ['identifier' => 'api_key', 'format' => 1, 'winner' => true];

        try {
            $adapter->store($this->envelopeSecret('api_key', 'newer')->withUid(1));
            self::fail('The row failure must propagate.');
        } catch (RuntimeException) {
        }

        self::assertSame(['identifier' => 'api_key', 'format' => 1, 'winner' => true], $this->awsRead('api_key'));
    }

    #[Test]
    public function aRollbackOfACreateNeverDeletesASecretAConcurrentWriterHasWrittenSince(): void
    {
        $this->failRowWrite                   = true;
        $this->concurrentWriterReplacesSecret = ['identifier' => 'api_key', 'format' => 1, 'winner' => true];

        try {
            $this->adapter()->store($this->envelopeSecret('api_key'));
            self::fail('The row failure must propagate.');
        } catch (RuntimeException) {
        }

        self::assertSame(['identifier' => 'api_key', 'format' => 1, 'winner' => true], $this->awsRead('api_key'));
    }

    #[Test]
    public function aRollbackDoesNotDependOnTheOrderOfTheKeysTheServiceReturns(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $orphan = $this->aws['api_key'];
        unset($this->rows['api_key']);
        $this->readKeysSorted = true;
        $this->failRowWrite   = true;

        try {
            $adapter->store($this->envelopeSecret('api_key', 'adopted'));
            self::fail('The row failure must propagate.');
        } catch (RuntimeException) {
        }

        self::assertEquals($orphan, $this->aws['api_key'], 'the adopted secret is put back');
    }

    #[Test]
    public function aFailedCreateDestroysOnlyTheSecretItCreated(): void
    {
        $this->failRowWrite = true;

        try {
            $this->adapter()->store($this->envelopeSecret('api_key'));
            self::fail('The row failure must propagate.');
        } catch (RuntimeException) {
        }

        self::assertContains('create:api_key', $this->awsCalls);
        self::assertArrayNotHasKey('api_key', $this->aws);
    }

    #[Test]
    public function registryOperationsNeverCallAws(): void
    {
        $adapter = $this->adapter();
        $adapter->store($this->envelopeSecret('api_key'));

        $this->awsCalls = [];

        $adapter->exists('api_key');
        $adapter->list();
        $adapter->listSecrets();
        $adapter->getMetadata('api_key');
        $adapter->updateMetadata('api_key', ['a' => 'b']);
        $adapter->setHidden(1, true);
        $adapter->incrementReadCount(1);

        self::assertSame([], $this->awsCalls);
    }

    #[Test]
    public function identifiesItselfAndReportsAvailabilityFromConfigurationAlone(): void
    {
        self::assertSame('aws', $this->adapter()->getIdentifier());
        self::assertTrue($this->adapter()->isAvailable());
        self::assertFalse($this->adapter(endpoint: 'http://aws.example.com')->isAvailable(), 'plain http without the opt-in');
        self::assertFalse($this->adapter(region: '')->isAvailable(), 'no region');
        self::assertFalse($this->adapter(sdkInstalled: false)->isAvailable(), 'no SDK');
        self::assertSame([], $this->awsCalls, 'availability makes no network call');
    }

    /**
     * @return array<string, mixed>|null
     */
    public function awsRead(string $identifier): ?array
    {
        $this->awsCalls[] = 'read:' . $identifier;
        $data             = $this->aws[$identifier] ?? null;
        if ($data !== null && $this->readKeysSorted) {
            // The service does not promise to return keys in the order sent.
            ksort($data);
        }

        return $data;
    }

    /**
     * @param array<string, mixed> $data
     */
    public function awsWrite(string $identifier, array $data): string
    {
        $this->awsCalls[]            = 'write:' . $identifier;
        $this->aws[$identifier]      = $data;
        $this->versions[$identifier] = ($this->versions[$identifier] ?? 0) + 1;

        return $this->awsVersion($identifier);
    }

    public function awsVersion(string $identifier): string
    {
        return 'v' . ($this->versions[$identifier] ?? 0);
    }

    /**
     * @param array<string, mixed> $data
     */
    public function awsCreate(string $identifier, array $data): string
    {
        $this->awsCalls[] = 'create:' . $identifier;
        if (array_key_exists($identifier, $this->aws)) {
            throw AwsSecretsManagerException::nameExists($identifier);
        }

        $this->aws[$identifier]      = $data;
        $this->versions[$identifier] = 1;

        return 'v1';
    }

    public function awsDestroy(string $identifier): void
    {
        $this->awsCalls[] = 'destroy:' . $identifier;
        unset($this->aws[$identifier], $this->versions[$identifier]);
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

    private function adapter(string $endpoint = '', string $region = 'eu-central-1', bool $sdkInstalled = true): AwsSecretsManagerAdapter
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
                if ($this->concurrentWriterReplacesSecret !== null) {
                    $this->awsWrite($secret->getIdentifier(), $this->concurrentWriterReplacesSecret);
                }

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
        $configuration->method('getAwsConfig')->willReturn(new AwsSecretsConfig(
            region: $region,
            secretPrefix: 'typo3/',
            endpoint: $endpoint,
        ));

        $kv = new class ($this, $sdkInstalled) implements AwsSecretStoreInterface {
            public function __construct(private readonly AwsSecretsManagerAdapterTest $test, private readonly bool $sdkInstalled) {}

            public function isSdkInstalled(): bool
            {
                return $this->sdkInstalled;
            }

            public function read(string $identifier): ?array
            {
                return $this->test->awsRead($identifier);
            }

            public function create(string $identifier, array $data): string
            {
                return $this->test->awsCreate($identifier, $data);
            }

            public function write(string $identifier, array $data): string
            {
                return $this->test->awsWrite($identifier, $data);
            }

            public function restoreIfCurrent(string $identifier, array $data, string $versionId): bool
            {
                if ($this->test->awsVersion($identifier) !== $versionId) {
                    return false;
                }

                $this->test->awsWrite($identifier, $data);

                return true;
            }

            public function destroyIfCurrent(string $identifier, string $versionId): bool
            {
                if ($this->test->awsVersion($identifier) !== $versionId) {
                    return false;
                }

                $this->test->awsDestroy($identifier);

                return true;
            }

            public function destroy(string $identifier): void
            {
                $this->test->awsDestroy($identifier);
            }

            public function reference(string $identifier): string
            {
                return 'eu-central-1:typo3/' . $identifier;
            }
        };

        return new AwsSecretsManagerAdapter(new LocalEncryptionAdapter($repository), $kv, $configuration);
    }
}
