<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Storage\Aws;

use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Exception\AuditWriteException;
use Netresearch\NrVault\Exception\AwsSecretsManagerException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * The cases the adapter must pass against a real Secrets Manager emulation,
 * through the real VaultService and database. They mirror the HashiCorp set.
 */
final class AwsSecretsManagerAdapterTest extends AbstractAwsContainerTestCase
{
    #[Test]
    public function aSecretRoundTripsThroughAwsAndTheRowKeepsNoEnvelope(): void
    {
        $identifier = $this->newIdentifier();
        $plaintext  = 'correct-horse-' . bin2hex(random_bytes(8));

        $service = $this->get(VaultServiceInterface::class);
        $service->store($identifier, $plaintext);

        self::assertSame($plaintext, $service->retrieve($identifier));

        $row = $this->row($identifier);
        self::assertSame('aws', $row['adapter']);
        self::assertSame(MotoServer::REGION . ':typo3/' . $identifier, $row['external_reference']);
        self::assertContains($row['encrypted_value'], [null, ''], 'the database row holds no ciphertext');
        self::assertSame('', $row['encrypted_dek']);
        self::assertSame('', $row['value_checksum']);

        $stored = $this->server->storedData($identifier);
        self::assertNotNull($stored, 'AWS holds the secret');
        $raw = (string) json_encode($stored);
        self::assertStringNotContainsString($plaintext, $raw, 'AWS holds ciphertext, not the secret');
        self::assertStringNotContainsString(base64_encode($plaintext), $raw);
        self::assertArrayHasKey('encrypted_value', $stored);
    }

    #[Test]
    public function everyOperationIsAuditedAndTheChainStaysValid(): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);
        $audit      = $this->get(AuditLogServiceInterface::class);

        $service->store($identifier, 'first-value');
        $service->retrieve($identifier);
        $service->rotate($identifier, 'second-value');
        $service->delete($identifier);

        self::assertGreaterThanOrEqual(4, $audit->count());
        self::assertTrue($audit->verifyHashChain()->isValid());
    }

    #[Test]
    public function rotatingWritesANewAwsVersion(): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);

        $service->store($identifier, 'first-value');
        self::assertSame(1, $this->server->versionCount($identifier));

        $service->rotate($identifier, 'second-value');

        self::assertSame('second-value', $service->retrieve($identifier));
        self::assertSame(2, $this->server->versionCount($identifier));
    }

    #[Test]
    public function deletingRemovesTheAwsSecretWithItsVersionsAndTheRow(): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);

        $service->store($identifier, 'first-value');
        $service->rotate($identifier, 'second-value');
        $service->delete($identifier);

        self::assertFalse($service->exists($identifier));
        self::assertSame(0, $this->server->versionCount($identifier), 'no version survives in AWS');
        self::assertFalse($this->server->exists($identifier), 'DescribeSecret no longer finds it, so there is no recovery window');
    }

    #[Test]
    public function aDisabledSecretIsWithheldAndComesBackIntact(): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);
        $service->store($identifier, 'kept-value');

        $service->setEnabled($identifier, false);
        self::assertNull($service->retrieve($identifier));

        $service->setEnabled($identifier, true);
        self::assertSame('kept-value', $service->retrieve($identifier));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function auditFailureOperations(): iterable
    {
        yield 'create' => ['create'];
        yield 'rotate' => ['rotate'];
        yield 'delete' => ['delete'];
    }

    #[Test]
    #[DataProvider('auditFailureOperations')]
    public function anAuditFailureLeavesAwsAndTheRowAsTheyWere(string $operation): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);
        if ($operation !== 'create') {
            $service->store($identifier, 'original-value');
        }

        $valueBefore = $operation === 'create' ? null : $this->server->storedData($identifier);

        $connection = $this->get(ConnectionPool::class)->getConnectionForTable('tx_nrvault_secret');
        $schema     = $connection->createSchemaManager();
        $table      = $schema->introspectSchema()->getTable('tx_nrvault_audit_log');
        $schema->dropTable('tx_nrvault_audit_log');

        try {
            $failure = $this->thrownBy(static fn () => match ($operation) {
                'create' => $service->store($identifier, 'new-value'),
                'rotate' => $service->rotate($identifier, 'new-value'),
                default  => $service->delete($identifier),
            });
        } finally {
            $schema->createTable($table);
        }

        self::assertInstanceOf(AuditWriteException::class, $failure);

        if ($operation === 'create') {
            self::assertFalse($service->exists($identifier));
            self::assertNull($this->server->storedData($identifier), 'no AWS secret survives a failed create');

            return;
        }

        self::assertSame('aws', $this->row($identifier)['adapter']);
        self::assertSame('original-value', $service->retrieve($identifier), 'the value is back after the compensation');
        self::assertSame($valueBefore, $this->server->storedData($identifier));
    }

    #[Test]
    public function aRowWhoseSecretIsNotAJsonObjectCanStillBeDeleted(): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);
        $service->store($identifier, 'value');

        $this->server->overwriteBehindTheAdapter($identifier, 'not json at all');

        $service->delete($identifier);

        self::assertFalse($service->exists($identifier));
        self::assertNull($this->server->rawValue($identifier));
    }

    #[Test]
    public function aRowWhoseSecretHoldsAnotherIdentifiersPayloadIsNotDeletedByDeletingTheRow(): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);
        $service->store($identifier, 'value');

        $foreign = '{"identifier":"somebody_else","format":1,"theirs":"kept"}';
        $this->server->overwriteBehindTheAdapter($identifier, $foreign);

        $failure = $this->thrownBy(static fn () => $service->delete($identifier));

        self::assertInstanceOf(AwsSecretsManagerException::class, $failure);
        self::assertSame(1794500011, $failure->getCode());
        self::assertSame($foreign, $this->server->rawValue($identifier), 'the foreign secret is untouched');
        self::assertTrue($service->exists($identifier));
    }

    #[Test]
    public function anAuditFailureOfACreateThatAdoptedAnOrphanPutsTheOrphanBack(): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);
        $service->store($identifier, 'orphaned-value');

        $orphan = $this->server->storedData($identifier);

        // The row is gone, the AWS secret written by this installation stays.
        $connection = $this->get(ConnectionPool::class)->getConnectionForTable('tx_nrvault_secret');
        $connection->delete('tx_nrvault_secret', ['identifier' => $identifier]);

        $schema = $connection->createSchemaManager();
        $table  = $schema->introspectSchema()->getTable('tx_nrvault_audit_log');
        $schema->dropTable('tx_nrvault_audit_log');

        try {
            $failure = $this->thrownBy(static fn () => $service->store($identifier, 'new-value'));
        } finally {
            $schema->createTable($table);
        }

        self::assertInstanceOf(AuditWriteException::class, $failure);
        self::assertFalse($service->exists($identifier));
        self::assertSame($orphan, $this->server->storedData($identifier), 'the adopted secret is back, not destroyed');
    }

    #[Test]
    #[DataProvider('failureModes')]
    public function aSecretOfSomebodyElseUnderTheNameIsNeitherOverwrittenNorDestroyed(bool $auditFails): void
    {
        $identifier = $this->newIdentifier();
        $this->server->createForeign($identifier, 'somebody-elses-value');
        $service = $this->get(VaultServiceInterface::class);

        $connection = $this->get(ConnectionPool::class)->getConnectionForTable('tx_nrvault_secret');
        $schema     = $connection->createSchemaManager();
        $table      = $schema->introspectSchema()->getTable('tx_nrvault_audit_log');
        if ($auditFails) {
            $schema->dropTable('tx_nrvault_audit_log');
        }

        try {
            $failure = $this->thrownBy(static fn () => $service->store($identifier, 'new-value'));
        } finally {
            if ($auditFails) {
                $schema->createTable($table);
            }
        }

        self::assertInstanceOf(AwsSecretsManagerException::class, $failure);
        self::assertSame(1794500011, $failure->getCode());
        self::assertSame('somebody-elses-value', $this->server->rawValue($identifier), 'the foreign secret is untouched');
        self::assertSame(1, $this->server->versionCount($identifier), 'no version was added to it');
        self::assertSame(0, $this->countRows($identifier));
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function failureModes(): iterable
    {
        yield 'without an audit failure' => [false];
        yield 'with an audit failure' => [true];
    }

    #[Test]
    public function aRowWhoseAwsSecretWasRemovedIsReportedAndCanBeRepaired(): void
    {
        $identifier = $this->newIdentifier();
        $service    = $this->get(VaultServiceInterface::class);
        $service->store($identifier, 'lost-value');

        $this->server->removeBehindTheAdapter($identifier);

        $failure = $this->thrownBy(static fn () => $service->retrieve($identifier));
        self::assertInstanceOf(AwsSecretsManagerException::class, $failure, 'a row without its AWS secret must not read as an empty secret');
        self::assertSame(1794500009, $failure->getCode());

        $service->rotate($identifier, 'restored-value');

        self::assertSame('restored-value', $service->retrieve($identifier));
    }
}
