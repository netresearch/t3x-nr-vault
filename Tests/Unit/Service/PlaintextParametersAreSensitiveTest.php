<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service;

use Netresearch\NrVault\Command\VaultMigrateFieldCommand;
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
 * of every frame, and a logged exception carries that trace.
 */
#[CoversNothing]
final class PlaintextParametersAreSensitiveTest extends TestCase
{
    /**
     * @return iterable<string, array{class-string, string, string}>
     */
    public static function plaintextParameterProvider(): iterable
    {
        yield 'command migrateRecords' => [VaultMigrateFieldCommand::class, 'migrateRecords', 'records'];
        yield 'command showDryRunResults' => [VaultMigrateFieldCommand::class, 'showDryRunResults', 'records'];
        yield 'command truncateValue' => [VaultMigrateFieldCommand::class, 'truncateValue', 'value'];
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
