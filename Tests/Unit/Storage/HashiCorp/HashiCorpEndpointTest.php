<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Storage\HashiCorp;

use Netresearch\NrVault\Configuration\Dto\VaultServerConfig;
use Netresearch\NrVault\Exception\HashiCorpException;
use Netresearch\NrVault\Storage\HashiCorp\HashiCorpEndpoint;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(HashiCorpEndpoint::class)]
final class HashiCorpEndpointTest extends TestCase
{
    #[Test]
    public function buildsKvV2UrlsFromMountPrefixAndIdentifier(): void
    {
        $endpoint = HashiCorpEndpoint::fromConfig($this->config());

        self::assertSame('https://vault.example.com:8200/v1/secret/data/typo3/api_key', $endpoint->dataUrl('api_key'));
        self::assertSame('https://vault.example.com:8200/v1/secret/metadata/typo3/api_key', $endpoint->metadataUrl('api_key'));
        self::assertSame('secret/data/typo3/api_key', $endpoint->reference('api_key'));
    }

    #[Test]
    public function supportsNestedMountsAndAnEmptyPrefix(): void
    {
        $nested = HashiCorpEndpoint::fromConfig($this->config(path: 'team/kv/data/typo3/prod'));
        $bare   = HashiCorpEndpoint::fromConfig($this->config(path: 'secret/data'));

        self::assertSame('https://vault.example.com:8200/v1/team/kv/data/typo3/prod/token', $nested->dataUrl('token'));
        self::assertSame('https://vault.example.com:8200/v1/secret/data/token', $bare->dataUrl('token'));
    }

    #[Test]
    public function encodesTheColonsOfASiteScopedIdentifier(): void
    {
        $endpoint = HashiCorpEndpoint::fromConfig($this->config());

        self::assertSame(
            'https://vault.example.com:8200/v1/secret/data/typo3/site%3Amain%3Aapi_key',
            $endpoint->dataUrl('site:main:api_key'),
        );
    }

    #[Test]
    public function refusesPlainHttpUnlessTheOperatorOptedIn(): void
    {
        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400002);

        HashiCorpEndpoint::fromConfig($this->config(address: 'http://vault.example.com:8200'));
    }

    #[Test]
    public function allowsPlainHttpWhenOptedIn(): void
    {
        $endpoint = HashiCorpEndpoint::fromConfig(
            $this->config(address: 'http://127.0.0.1:8200', allowInsecureHttp: true),
        );

        self::assertSame('http://127.0.0.1:8200/v1/secret/data/typo3/k', $endpoint->dataUrl('k'));
    }

    #[Test]
    public function refusesAnUnknownScheme(): void
    {
        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400002);

        HashiCorpEndpoint::fromConfig($this->config(address: 'ftp://vault.example.com', allowInsecureHttp: true));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unusableAddresses(): iterable
    {
        yield 'credentials in the address' => ['https://user:pass@vault.example.com'];
        yield 'a path' => ['https://vault.example.com/proxy'];
        yield 'a query' => ['https://vault.example.com?x=1'];
        yield 'a fragment' => ['https://vault.example.com#x'];
        yield 'no host' => ['https://'];
        yield 'not a url' => ['vault'];
    }

    #[Test]
    #[DataProvider('unusableAddresses')]
    public function refusesAnAddressThatIsNotABareOrigin(string $address): void
    {
        $this->expectException(HashiCorpException::class);

        HashiCorpEndpoint::fromConfig($this->config(address: $address));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unusablePaths(): iterable
    {
        yield 'no data segment' => ['secret/typo3'];
        yield 'data is the mount' => ['data/typo3'];
        yield 'traversal in the prefix' => ['secret/data/../sys'];
        yield 'dot segment' => ['secret/data/./x'];
        yield 'query character' => ['secret/data/a?b'];
        yield 'space' => ['secret/data/a b'];
        yield 'empty segment' => ['secret/data//x'];
        yield 'trailing newline' => ["secret/data/typo3\n"];
    }

    #[Test]
    #[DataProvider('unusablePaths')]
    public function refusesAPathThatCouldLeaveTheKvMount(string $path): void
    {
        $this->expectException(HashiCorpException::class);

        HashiCorpEndpoint::fromConfig($this->config(path: $path));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unusableIdentifiers(): iterable
    {
        yield 'traversal' => ['../x'];
        yield 'slash' => ['a/b'];
        yield 'dot' => ['a.b'];
        yield 'query' => ['a?b'];
        yield 'percent' => ['a%2fb'];
        yield 'empty' => [''];
        yield 'too long' => [str_repeat('a', 256)];
        yield 'trailing newline' => ["api_key\n"];
    }

    #[Test]
    #[DataProvider('unusableIdentifiers')]
    public function refusesAnIdentifierThatCouldChangeTheTargetPath(string $identifier): void
    {
        $endpoint = HashiCorpEndpoint::fromConfig($this->config());

        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400003);

        $endpoint->dataUrl($identifier);
    }

    #[Test]
    public function buildsTheLoginUrlOfAnAuthMount(): void
    {
        self::assertSame(
            'https://vault.example.com:8200/v1/auth/team/approle/login',
            HashiCorpEndpoint::loginUrl($this->config(), 'team/approle'),
        );
    }

    #[Test]
    public function refusesAnAuthMountWithATraversalSegment(): void
    {
        $this->expectException(HashiCorpException::class);

        HashiCorpEndpoint::loginUrl($this->config(), '../sys');
    }

    #[Test]
    public function refusesAnEmptyAddressAndAnEmptyPath(): void
    {
        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400001);

        HashiCorpEndpoint::fromConfig(new VaultServerConfig(address: '', path: ''));
    }

    private function config(
        string $address = 'https://vault.example.com:8200',
        string $path = 'secret/data/typo3',
        bool $allowInsecureHttp = false,
    ): VaultServerConfig {
        return new VaultServerConfig(
            address: $address,
            path: $path,
            authMethod: 'token',
            allowInsecureHttp: $allowInsecureHttp,
        );
    }
}
