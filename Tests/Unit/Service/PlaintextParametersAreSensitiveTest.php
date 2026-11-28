<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service;

use Netresearch\NrVault\Command\VaultMigrateFieldCommand;
use Netresearch\NrVault\Controller\MigrationController;
use Netresearch\NrVault\Service\FieldValueMigrator;
use Netresearch\NrVault\Service\FieldValueMigratorInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Utility\IdentifierValidator;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ReflectionParameter;
use SensitiveParameter;

/**
 * Every parameter on the field-migration path that receives the plaintext is
 * a SensitiveParameter. With zend.exception_ignore_args off, the default of
 * the official php Docker image, a rendered stack trace shows the arguments
 * of every frame; such a trace reaches the log through the critical
 * record-link entry (#565). The trace tests cover the frames a probe can
 * reach; this list covers the rest.
 */
#[CoversNothing]
final class PlaintextParametersAreSensitiveTest extends TestCase
{
    /**
     * @return iterable<string, array{class-string, string, string}>
     */
    public static function plaintextParameterProvider(): iterable
    {
        yield 'interface migrate' => [FieldValueMigratorInterface::class, 'migrate', 'value'];
        yield 'migrate' => [FieldValueMigrator::class, 'migrate', 'value'];
        yield 'migrateValue' => [FieldValueMigrator::class, 'migrateValue', 'value'];
        yield 'restore value' => [FieldValueMigrator::class, 'restore', 'value'];
        yield 'restore read-back' => [FieldValueMigrator::class, 'restore', 'written'];
        yield 'afterFailedUpdate' => [FieldValueMigrator::class, 'afterFailedUpdate', 'value'];
        yield 'holdsIdentifier' => [FieldValueMigrator::class, 'holdsIdentifier', 'fieldValue'];
        yield 'writeField value' => [FieldValueMigrator::class, 'writeField', 'value'];
        yield 'writeField expected' => [FieldValueMigrator::class, 'writeField', 'expected'];
        yield 'command migrateRecords' => [VaultMigrateFieldCommand::class, 'migrateRecords', 'records'];
        yield 'command migrateRecord' => [VaultMigrateFieldCommand::class, 'migrateRecord', 'value'];
        yield 'command isExistingVaultIdentifier' => [VaultMigrateFieldCommand::class, 'isExistingVaultIdentifier', 'value'];
        yield 'command showDryRunResults' => [VaultMigrateFieldCommand::class, 'showDryRunResults', 'records'];
        yield 'command truncateValue' => [VaultMigrateFieldCommand::class, 'truncateValue', 'value'];
        yield 'module migrateRow' => [MigrationController::class, 'migrateRow', 'value'];
        yield 'isGeneratedIdentifier' => [IdentifierValidator::class, 'isGeneratedIdentifier', 'value'];
        yield 'looksLikeVaultIdentifier' => [IdentifierValidator::class, 'looksLikeVaultIdentifier', 'value'];
    }

    /**
     * @param class-string $class
     */
    #[Test]
    #[DataProvider('plaintextParameterProvider')]
    public function thePlaintextParameterIsSensitive(string $class, string $method, string $parameter): void
    {
        $reflection = new ReflectionParameter([$class, $method], $parameter);

        self::assertNotSame([], $reflection->getAttributes(SensitiveParameter::class), sprintf('%s::%s() $%s must be a SensitiveParameter', $class, $method, $parameter));
    }
}
