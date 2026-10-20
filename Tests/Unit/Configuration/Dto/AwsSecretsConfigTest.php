<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Configuration\Dto;

use Netresearch\NrVault\Configuration\Dto\AwsSecretsConfig;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(AwsSecretsConfig::class)]
final class AwsSecretsConfigTest extends TestCase
{
    #[Test]
    public function constructorDefaultsAllPropertiesToEmptyString(): void
    {
        $subject = new AwsSecretsConfig();

        self::assertSame('', $subject->region);
        self::assertSame('', $subject->secretPrefix);
    }

    #[Test]
    public function constructorSetsProvidedValues(): void
    {
        $subject = new AwsSecretsConfig(
            region: 'eu-west-1',
            secretPrefix: 'myapp',
        );

        self::assertSame('eu-west-1', $subject->region);
        self::assertSame('myapp', $subject->secretPrefix);
    }

    #[Test]
    public function fromArrayCreatesObjectWithAllFields(): void
    {
        $subject = AwsSecretsConfig::fromArray([
            'region'       => 'us-east-1',
            'secretPrefix' => 'prod',
        ]);

        self::assertSame('us-east-1', $subject->region);
        self::assertSame('prod', $subject->secretPrefix);
    }

    #[Test]
    public function fromArrayWithEmptyArrayUsesEmptyStringDefaults(): void
    {
        $subject = AwsSecretsConfig::fromArray([]);

        self::assertSame('', $subject->region);
        self::assertSame('', $subject->secretPrefix);
    }

    #[Test]
    public function fromArrayWithOnlyRegionSetSetsEmptyPrefix(): void
    {
        $subject = AwsSecretsConfig::fromArray(['region' => 'ap-southeast-1']);

        self::assertSame('ap-southeast-1', $subject->region);
        self::assertSame('', $subject->secretPrefix);
    }

    #[Test]
    public function isValidReturnsTrueWhenRegionIsSet(): void
    {
        $subject = new AwsSecretsConfig(region: 'eu-central-1');

        self::assertTrue($subject->isValid());
    }

    #[Test]
    public function isValidReturnsFalseWhenRegionIsEmpty(): void
    {
        $subject = new AwsSecretsConfig();

        self::assertFalse($subject->isValid());
    }

    #[Test]
    public function isValidIgnoresSecretPrefix(): void
    {
        $withPrefix    = new AwsSecretsConfig(region: 'us-east-1', secretPrefix: 'app');
        $withoutPrefix = new AwsSecretsConfig(region: 'us-east-1');

        self::assertTrue($withPrefix->isValid());
        self::assertTrue($withoutPrefix->isValid());
    }

    #[Test]
    #[DataProvider('getFullSecretNameProvider')]
    public function getFullSecretNameReturnsCorrectValue(
        string $prefix,
        string $secretName,
        string $expected,
    ): void {
        $subject = new AwsSecretsConfig(region: 'us-east-1', secretPrefix: $prefix);

        self::assertSame($expected, $subject->getFullSecretName($secretName));
    }

    public static function getFullSecretNameProvider(): iterable
    {
        yield 'no prefix returns secret name unchanged' => ['', 'my-secret', 'my-secret'];
        yield 'with prefix prepends prefix and slash' => ['myapp', 'my-secret', 'myapp/my-secret'];
        yield 'with nested prefix' => ['prod/myapp', 'db-password', 'prod/myapp/db-password'];
        yield 'prefix with trailing slash appends another slash' => ['app/', 'key', 'app//key'];
    }

    #[Test]
    public function getFullSecretNameWithEmptyPrefixReturnSecretNameDirectly(): void
    {
        $subject = new AwsSecretsConfig(region: 'us-east-1', secretPrefix: '');

        self::assertSame('api-key', $subject->getFullSecretName('api-key'));
    }

    #[Test]
    public function toArrayReturnsCorrectStructure(): void
    {
        $subject = new AwsSecretsConfig(region: 'eu-west-1', secretPrefix: 'staging');

        self::assertSame([
            'region'       => 'eu-west-1',
            'secretPrefix' => 'staging',
        ], $subject->toArray());
    }

    #[Test]
    public function toArrayWithDefaultsReturnsEmptyStrings(): void
    {
        $subject = new AwsSecretsConfig();

        self::assertSame([
            'region'       => '',
            'secretPrefix' => '',
        ], $subject->toArray());
    }

    #[Test]
    public function fromArrayRoundTripToArray(): void
    {
        $original = [
            'region'       => 'eu-north-1',
            'secretPrefix' => 'my-service',
        ];

        $subject = AwsSecretsConfig::fromArray($original);

        self::assertSame($original, $subject->toArray());
    }
}
