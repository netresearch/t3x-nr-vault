<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Traits;

use LogicException;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use TYPO3\CMS\Core\Schema\Field\FieldCollection;
use TYPO3\CMS\Core\Schema\Field\FieldTypeInterface;
use TYPO3\CMS\Core\Schema\TcaSchema;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;

/**
 * Shared helper for mocking TYPO3 TCA schema in unit tests.
 *
 * Extracted from ~4 duplicated copies:
 *  - `Tests/Unit/Hook/DataHandlerHookTest.php`
 *  - `Tests/Unit/Utility/VaultFieldResolverTest.php`
 *  - `Tests/Unit/Hook/FlexFormVaultHookTest.php`
 *  - `Tests/Unit/Command/VaultMigrateFieldCommandTest.php`
 *
 * Usage:
 *
 * ```php
 * use Netresearch\NrVault\Tests\Unit\Traits\TcaSchemaMockTrait;
 *
 * final class MyTest extends UnitTestCase
 * {
 *     use TcaSchemaMockTrait;
 *
 *     protected TcaSchemaFactory&Stub $tcaSchemaFactory;
 *
 *     protected function setUp(): void
 *     {
 *         parent::setUp();
 *         $this->tcaSchemaFactory = self::createStub(TcaSchemaFactory::class);
 *     }
 *
 *     public function testSomething(): void
 *     {
 *         $this->mockTcaSchemaForTable('tx_test', [
 *             'secret_field' => ['type' => 'text', 'renderType' => 'vaultSecret'],
 *         ]);
 *         // ...
 *     }
 * }
 * ```
 *
 * The trait requires the consuming test class to expose a protected
 * `TcaSchemaFactory&Stub` (or `&MockObject`) property named `$tcaSchemaFactory`;
 * a private one is invisible to the trait, which the project base class composes.
 *
 * The factory answers `has()` / `get()` from the tables registered in the
 * current test and fails the test on a lookup for any other table — the
 * argument check a `with($table)` constraint used to provide, without
 * pinning a call count the hook under test does not define (several tests
 * register a schema precisely to prove the hook returns before reading it).
 *
 * @phpstan-require-extends TestCase
 */
trait TcaSchemaMockTrait
{
    /** @var array<string, TcaSchema> table => schema registered in the current test */
    private array $mockedTcaSchemas = [];

    /**
     * Configure the `$tcaSchemaFactory` double to return a schema with the given fields.
     *
     * @param array<string, array<string, mixed>> $fields field name => TCA field config
     */
    protected function mockTcaSchemaForTable(string $table, array $fields = []): void
    {
        $schema = self::createStub(TcaSchema::class);

        $fieldStubs = [];
        foreach ($fields as $fieldName => $config) {
            $field = self::createStub(FieldTypeInterface::class);
            $field->method('getName')->willReturn($fieldName);
            $field->method('getConfiguration')->willReturn($config);
            $fieldStubs[$fieldName] = $field;
        }

        $schema->method('getFields')->willReturn(new FieldCollection($fieldStubs));
        $schema->method('hasField')->willReturnCallback(
            static fn (string $requested): bool => isset($fieldStubs[$requested]),
        );
        $schema->method('getField')->willReturnCallback(
            static function (string $requested) use ($fieldStubs): FieldTypeInterface {
                self::assertArrayHasKey(
                    $requested,
                    $fieldStubs,
                    \sprintf('Unexpected TCA field lookup for "%s".', $requested),
                );

                return $fieldStubs[$requested];
            },
        );

        $factory = $this->tcaSchemaFactory ?? null;
        if (!$factory instanceof TcaSchemaFactory || !$factory instanceof Stub) {
            throw new LogicException(
                \sprintf(
                    '%s requires the test to define a protected `$tcaSchemaFactory` property '
                    . 'of type `TcaSchemaFactory&Stub` before calling %s().',
                    self::class,
                    __FUNCTION__,
                ),
                3189279350,
            );
        }

        $firstRegistration = $this->mockedTcaSchemas === [];
        $this->mockedTcaSchemas[$table] = $schema;

        if (!$firstRegistration) {
            return;
        }

        $lookup = function (string $requested): TcaSchema {
            self::assertArrayHasKey(
                $requested,
                $this->mockedTcaSchemas,
                \sprintf('Unexpected TCA schema lookup for table "%s".', $requested),
            );

            return $this->mockedTcaSchemas[$requested];
        };

        $factory->method('has')->willReturnCallback(static function (string $requested) use ($lookup): bool {
            $lookup($requested);

            return true;
        });
        $factory->method('get')->willReturnCallback($lookup);
    }
}
