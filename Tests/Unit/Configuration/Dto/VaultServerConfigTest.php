<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Configuration\Dto;

use Netresearch\NrVault\Configuration\Dto\VaultServerConfig;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(VaultServerConfig::class)]
final class VaultServerConfigTest extends TestCase
{
    private const ADDRESS_EXAMPLE = 'https://vault.example.com';

    private const ADDRESS_INTERNAL = 'https://vault.internal';

    private const ADDRESS_VAULT = 'https://vault.com';

    private const PATH_SECRET_DATA = 'secret/data';

    private const PATH_KV_MYAPP = 'kv/myapp';

    #[Test]
    public function constructorDefaultsAllPropertiesToEmptyString(): void
    {
        $subject = new VaultServerConfig();

        self::assertSame('', $subject->address);
        self::assertSame('', $subject->path);
        self::assertSame('', $subject->authMethod);
        self::assertSame('', $subject->token);
    }

    #[Test]
    public function constructorSetsProvidedValues(): void
    {
        $subject = new VaultServerConfig(
            address: self::ADDRESS_EXAMPLE,
            path: self::PATH_SECRET_DATA,
            authMethod: 'token',
            token: 's.mytoken123',
        );

        self::assertSame(self::ADDRESS_EXAMPLE, $subject->address);
        self::assertSame(self::PATH_SECRET_DATA, $subject->path);
        self::assertSame('token', $subject->authMethod);
        self::assertSame('s.mytoken123', $subject->token);
    }

    #[Test]
    public function fromArrayCreatesObjectWithAllFields(): void
    {
        $subject = VaultServerConfig::fromArray([
            'address'    => self::ADDRESS_INTERNAL,
            'path'       => self::PATH_KV_MYAPP,
            'authMethod' => 'token',
            'token'      => 's.abc123',
        ]);

        self::assertSame(self::ADDRESS_INTERNAL, $subject->address);
        self::assertSame(self::PATH_KV_MYAPP, $subject->path);
        self::assertSame('token', $subject->authMethod);
        self::assertSame('s.abc123', $subject->token);
    }

    #[Test]
    public function fromArrayWithEmptyArrayUsesEmptyStringDefaults(): void
    {
        $subject = VaultServerConfig::fromArray([]);

        self::assertSame('', $subject->address);
        self::assertSame('', $subject->path);
        self::assertSame('', $subject->authMethod);
        self::assertSame('', $subject->token);
    }

    #[Test]
    public function fromArrayIgnoresMissingOptionalFields(): void
    {
        $subject = VaultServerConfig::fromArray([
            'address' => self::ADDRESS_EXAMPLE,
            'path'    => 'secret',
        ]);

        self::assertSame(self::ADDRESS_EXAMPLE, $subject->address);
        self::assertSame('secret', $subject->path);
        self::assertSame('', $subject->authMethod);
        self::assertSame('', $subject->token);
    }

    #[Test]
    #[DataProvider('isValidProvider')]
    public function isValidReturnsCorrectResult(
        string $address,
        string $path,
        bool $expected,
    ): void {
        $subject = new VaultServerConfig(address: $address, path: $path);

        self::assertSame($expected, $subject->isValid());
    }

    public static function isValidProvider(): iterable
    {
        yield 'address and path set => valid' => [self::ADDRESS_EXAMPLE, 'kv/data', true];
        yield 'empty address => invalid' => ['', 'kv/data', false];
        yield 'empty path => invalid' => [self::ADDRESS_EXAMPLE, '', false];
        yield 'both empty => invalid' => ['', '', false];
    }

    #[Test]
    public function isValidIgnoresAuthMethodAndToken(): void
    {
        $withToken = new VaultServerConfig(
            address: self::ADDRESS_VAULT,
            path: 'kv',
            authMethod: 'token',
            token: 's.abc',
        );
        $withoutToken = new VaultServerConfig(
            address: self::ADDRESS_VAULT,
            path: 'kv',
        );

        self::assertTrue($withToken->isValid());
        self::assertTrue($withoutToken->isValid());
    }

    #[Test]
    #[DataProvider('hasTokenAuthProvider')]
    public function hasTokenAuthReturnsCorrectResult(
        string $token,
        string $authMethod,
        bool $expected,
    ): void {
        $subject = new VaultServerConfig(
            address: self::ADDRESS_VAULT,
            path: 'kv',
            authMethod: $authMethod,
            token: $token,
        );

        self::assertSame($expected, $subject->hasTokenAuth());
    }

    public static function hasTokenAuthProvider(): iterable
    {
        yield 'token and authMethod=token => true' => ['s.mytoken', 'token', true];
        yield 'token but wrong authMethod => false' => ['s.mytoken', 'approle', false];
        yield 'authMethod=token but no token => false' => ['', 'token', false];
        yield 'both empty => false' => ['', '', false];
        yield 'neither set => false' => ['', 'approle', false];
    }

    #[Test]
    public function toArrayReturnsCorrectStructure(): void
    {
        $subject = new VaultServerConfig(
            address: self::ADDRESS_EXAMPLE,
            path: self::PATH_KV_MYAPP,
            authMethod: 'token',
            token: 's.secret',
        );

        self::assertSame([
            'address'    => self::ADDRESS_EXAMPLE,
            'path'       => self::PATH_KV_MYAPP,
            'authMethod' => 'token',
            'token'      => 's.secret',
        ], $subject->toArray());
    }

    #[Test]
    public function toArrayWithDefaultsReturnsAllEmptyStrings(): void
    {
        $subject = new VaultServerConfig();

        self::assertSame([
            'address'    => '',
            'path'       => '',
            'authMethod' => '',
            'token'      => '',
        ], $subject->toArray());
    }

    #[Test]
    public function toArrayContainsExactlyFourKeys(): void
    {
        $subject = new VaultServerConfig();

        self::assertCount(4, $subject->toArray());
    }

    #[Test]
    public function fromArrayRoundTripToArray(): void
    {
        $original = [
            'address'    => self::ADDRESS_INTERNAL,
            'path'       => self::PATH_SECRET_DATA,
            'authMethod' => 'token',
            'token'      => 's.roundtrip',
        ];

        $subject = VaultServerConfig::fromArray($original);

        self::assertSame($original, $subject->toArray());
    }

    #[Test]
    public function newSettingsDefaultToTheDocumentedValues(): void
    {
        $subject = new VaultServerConfig();

        self::assertSame('VAULT_TOKEN', $subject->tokenEnvVar);
        self::assertSame('approle', $subject->approleMount);
        self::assertSame('VAULT_SECRET_ID', $subject->secretIdEnvVar);
        self::assertSame('kubernetes', $subject->kubernetesMount);
        self::assertSame('/var/run/secrets/kubernetes.io/serviceaccount/token', $subject->kubernetesJwtPath);
        self::assertFalse($subject->allowInsecureHttp);
    }

    #[Test]
    public function fromArrayReadsTheAuthSettingsAndKeepsDefaultsForBlankValues(): void
    {
        $subject = VaultServerConfig::fromArray([
            'authMethod'        => 'approle',
            'roleId'            => ' role-1 ',
            'approleMount'      => 'team/approle',
            'secretIdEnvVar'    => '',
            'kubernetesRole'    => 'typo3',
            'allowInsecureHttp' => '1',
        ]);

        self::assertSame('role-1', $subject->roleId);
        self::assertSame('team/approle', $subject->approleMount);
        self::assertSame('VAULT_SECRET_ID', $subject->secretIdEnvVar, 'a blank value keeps the default');
        self::assertSame('typo3', $subject->kubernetesRole);
        self::assertTrue($subject->allowInsecureHttp);
    }

    #[Test]
    public function allowInsecureHttpIsOffForEveryValueExceptAnExplicitYes(): void
    {
        foreach (['0', '', 'no', 'false', 0, false] as $value) {
            self::assertFalse(VaultServerConfig::fromArray(['allowInsecureHttp' => $value])->allowInsecureHttp);
        }

        foreach (['1', 'true', 1, true] as $value) {
            self::assertTrue(VaultServerConfig::fromArray(['allowInsecureHttp' => $value])->allowInsecureHttp);
        }
    }

    #[Test]
    public function theApproleSecretIdNeverAppearsInTheArrayForm(): void
    {
        $subject = VaultServerConfig::fromArray(['secretIdEnvVar' => 'MY_SECRET_ID', 'roleId' => 'r']);

        self::assertStringNotContainsString('MY_SECRET_ID', (string) json_encode($subject->toArray()));
    }
}
