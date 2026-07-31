<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Configuration\Dto;

use Netresearch\NrVault\Configuration\Dto\TransitConfig;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(TransitConfig::class)]
final class TransitConfigTest extends TestCase
{
    private const ADDRESS = 'https://vault.example.com:8200';

    private const FALLBACK_PATH = '/var/www/var/secrets/vault-master.key.transit';

    #[Test]
    public function constructorAppliesTransitDefaults(): void
    {
        $subject = new TransitConfig();

        self::assertSame('', $subject->address);
        self::assertSame('transit', $subject->mount);
        self::assertSame('nr-vault-master', $subject->keyName);
        self::assertSame('', $subject->wrappedKeyPath);
        self::assertSame('token', $subject->authMethod);
        self::assertSame('VAULT_TOKEN', $subject->tokenEnvVar);
        self::assertSame('', $subject->token);
    }

    #[Test]
    public function fromArrayReadsTheHashicorpGroup(): void
    {
        $subject = TransitConfig::fromArray([
            'address' => self::ADDRESS,
            'authMethod' => 'token',
            'token' => 'unit-test-dev-token',
            'transitMount' => 'platform/transit',
            'transitKeyName' => 'master-key',
            'transitWrappedKeyPath' => '/secure/wrapped.key',
            'tokenEnvVar' => 'MY_VAULT_TOKEN',
        ]);

        self::assertSame(self::ADDRESS, $subject->address);
        self::assertSame('platform/transit', $subject->mount);
        self::assertSame('master-key', $subject->keyName);
        self::assertSame('/secure/wrapped.key', $subject->wrappedKeyPath);
        self::assertSame('MY_VAULT_TOKEN', $subject->tokenEnvVar);
        self::assertSame('unit-test-dev-token', $subject->token);
    }

    #[Test]
    public function fromArrayFallsBackToDefaultsForEmptyValues(): void
    {
        $subject = TransitConfig::fromArray([
            'address' => self::ADDRESS,
            'transitMount' => '',
            'transitKeyName' => '',
            'transitWrappedKeyPath' => '',
            'tokenEnvVar' => '',
            'authMethod' => '',
        ], self::FALLBACK_PATH);

        self::assertSame('transit', $subject->mount);
        self::assertSame('nr-vault-master', $subject->keyName);
        self::assertSame(self::FALLBACK_PATH, $subject->wrappedKeyPath);
        self::assertSame('VAULT_TOKEN', $subject->tokenEnvVar);
        self::assertSame('token', $subject->authMethod);
    }

    #[Test]
    public function fromArrayNormalisesAddressAndMountSeparators(): void
    {
        $subject = TransitConfig::fromArray([
            'address' => ' https://vault.example.com:8200/ ',
            'transitMount' => '/transit/',
        ]);

        self::assertSame(self::ADDRESS, $subject->address);
        self::assertSame('transit', $subject->mount);
    }

    #[Test]
    public function fromArrayOnEmptyConfigurationYieldsIncompleteConfig(): void
    {
        self::assertFalse(TransitConfig::fromArray([])->isComplete());
    }

    #[Test]
    public function isCompleteRequiresAddressAndWrappedKeyPath(): void
    {
        self::assertTrue($this->config(address: self::ADDRESS, wrappedKeyPath: '/tmp/w.key')->isComplete());
        self::assertFalse($this->config(address: '', wrappedKeyPath: '/tmp/w.key')->isComplete());
        self::assertFalse($this->config(address: self::ADDRESS, wrappedKeyPath: '')->isComplete());
    }

    #[Test]
    #[DataProvider('authMethodProvider')]
    public function usesTokenAuthOnlyAcceptsToken(string $authMethod, bool $expected): void
    {
        self::assertSame($expected, $this->config(authMethod: $authMethod)->usesTokenAuth());
    }

    /**
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function authMethodProvider(): iterable
    {
        yield 'token' => ['token', true];
        yield 'approle' => ['approle', false];
        yield 'kubernetes' => ['kubernetes', false];
        yield 'empty' => ['', false];
    }

    #[Test]
    public function endpointForBuildsTheVaultApiUrl(): void
    {
        $subject = $this->config(address: self::ADDRESS);

        self::assertSame(
            self::ADDRESS . '/v1/transit/encrypt/nr-vault-master',
            $subject->endpointFor('encrypt'),
        );
        self::assertSame(
            self::ADDRESS . '/v1/transit/decrypt/nr-vault-master',
            $subject->endpointFor('decrypt'),
        );
    }

    #[Test]
    public function toArrayOmitsTheToken(): void
    {
        $subject = $this->config(address: self::ADDRESS, token: 'unit-test-hidden-token');

        $array = $subject->toArray();

        self::assertArrayNotHasKey('token', $array);
        self::assertStringNotContainsString(
            'unit-test-hidden-token',
            json_encode($array, JSON_THROW_ON_ERROR),
        );
    }

    private function config(
        string $address = self::ADDRESS,
        string $wrappedKeyPath = '/tmp/wrapped.key',
        string $authMethod = 'token',
        string $token = '',
    ): TransitConfig {
        return new TransitConfig(
            address: $address,
            wrappedKeyPath: $wrappedKeyPath,
            authMethod: $authMethod,
            token: $token,
        );
    }
}
