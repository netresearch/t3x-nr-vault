<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Storage\Aws;

use Netresearch\NrVault\Configuration\Dto\AwsSecretsConfig;
use Netresearch\NrVault\Exception\AwsSecretsManagerException;
use Netresearch\NrVault\Storage\Aws\AwsSecretsEndpoint;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(AwsSecretsEndpoint::class)]
final class AwsSecretsEndpointTest extends TestCase
{
    #[Test]
    public function buildsTheNameFromThePrefixAndTheIdentifier(): void
    {
        $endpoint = AwsSecretsEndpoint::fromConfig($this->config());

        self::assertSame('typo3/api_key', $endpoint->name('api_key'));
        self::assertSame('eu-central-1:typo3/api_key', $endpoint->reference('api_key'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function prefixes(): iterable
    {
        yield 'trailing slash, the default' => ['typo3/', 'typo3/id'];
        yield 'both slashes' => ['/typo3/', 'typo3/id'];
        yield 'nested' => ['team/typo3', 'team/typo3/id'];
        yield 'none' => ['', 'id'];
    }

    #[Test]
    #[DataProvider('prefixes')]
    public function normalisesThePrefixSoTheNameNeverHasADoubleSlash(string $prefix, string $expected): void
    {
        $endpoint = AwsSecretsEndpoint::fromConfig($this->config(prefix: $prefix));

        self::assertSame($expected, $endpoint->name('id'));
    }

    #[Test]
    public function writesTheColonOfASiteIdentifierAsAPlusSoAwsAcceptsTheName(): void
    {
        $endpoint = AwsSecretsEndpoint::fromConfig($this->config());

        self::assertSame('typo3/site+main+api', $endpoint->name('site:main:api'));
    }

    #[Test]
    public function neverMapsTwoIdentifiersToOneName(): void
    {
        $endpoint = AwsSecretsEndpoint::fromConfig($this->config());
        $names    = [];
        // Every identifier of the alphabet's shape: with or without colons, at
        // the ends, adjacent, and next to the characters that look alike.
        foreach (['a:b', 'a-b', 'a_b', 'ab', ':a', 'a:', '::', ':-', '-:', 'a::b', 'a:b:c', 'a_b:c', 'a:b_c'] as $identifier) {
            $names[$endpoint->name($identifier)][] = $identifier;
        }

        foreach ($names as $name => $identifiers) {
            self::assertCount(1, $identifiers, sprintf('"%s" would serve %s', $name, implode(' and ', $identifiers)));
        }
    }

    #[Test]
    public function aNameContainsNoCharacterAwsRefuses(): void
    {
        $endpoint = AwsSecretsEndpoint::fromConfig($this->config());

        foreach (['a:b', 'site:ns:name', 'ABC-123_x', str_repeat('a', 255)] as $identifier) {
            self::assertMatchesRegularExpression('#^[A-Za-z0-9/_+=.@-]+$#D', $endpoint->name($identifier));
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unusableIdentifiers(): iterable
    {
        yield 'empty' => [''];
        yield 'a slash' => ['a/b'];
        yield 'a dot' => ['a.b'];
        yield 'a space' => ['a b'];
        yield 'a plus' => ['a+b'];
        yield 'a trailing newline' => ["a\n"];
        yield 'too long' => [str_repeat('a', 256)];
    }

    #[Test]
    #[DataProvider('unusableIdentifiers')]
    public function refusesAnIdentifierThatCouldReachAnotherSecretName(string $identifier): void
    {
        $endpoint = AwsSecretsEndpoint::fromConfig($this->config());

        $this->expectException(AwsSecretsManagerException::class);
        $this->expectExceptionCode(1794500004);

        $endpoint->name($identifier);
    }

    #[Test]
    public function refusesANameThatWouldOverflowTheRegistryColumn(): void
    {
        $endpoint = AwsSecretsEndpoint::fromConfig($this->config(prefix: str_repeat('p', 200) . '/' . str_repeat('q', 200)));

        $this->expectException(AwsSecretsManagerException::class);
        $this->expectExceptionCode(1794500004);

        $endpoint->name('a');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unusablePrefixes(): iterable
    {
        yield 'an empty segment' => ['a//b'];
        yield 'a space' => ['a b'];
        yield 'a colon' => ['a:b'];
        yield 'a trailing newline' => ["typo3\n"];
    }

    #[Test]
    #[DataProvider('unusablePrefixes')]
    public function refusesAPrefixAwsWouldRefuse(string $prefix): void
    {
        $this->expectException(AwsSecretsManagerException::class);
        $this->expectExceptionCode(1794500004);

        AwsSecretsEndpoint::fromConfig($this->config(prefix: $prefix));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unusableRegions(): iterable
    {
        yield 'empty' => [''];
        yield 'upper case' => ['EU-CENTRAL-1'];
        yield 'no dash' => ['eucentral1'];
        yield 'a host' => ['eu-central-1.evil.example'];
        yield 'too long' => ['eu-' . str_repeat('a', 40) . '-1'];
    }

    #[Test]
    #[DataProvider('unusableRegions')]
    public function refusesARegionThatIsNoRegionName(string $region): void
    {
        $this->expectException(AwsSecretsManagerException::class);
        $this->expectExceptionCode(1794500001);

        AwsSecretsEndpoint::fromConfig($this->config(region: $region));
    }

    #[Test]
    public function acceptsTheRegionNamesOfEveryPartition(): void
    {
        foreach (['eu-central-1', 'us-gov-west-1', 'cn-north-1', 'us-iso-east-1', 'eusc-de-east-1'] as $region) {
            self::assertSame($region, AwsSecretsEndpoint::fromConfig($this->config(region: $region))->region);
        }
    }

    #[Test]
    public function usesTheRegionalEndpointWhenNoneIsConfigured(): void
    {
        self::assertNull(AwsSecretsEndpoint::fromConfig($this->config())->endpoint);
    }

    #[Test]
    public function keepsACustomEndpointAsABareOrigin(): void
    {
        $endpoint = AwsSecretsEndpoint::fromConfig($this->config(endpoint: 'https://secretsmanager.vpce.example.com:8443/'));

        self::assertSame('https://secretsmanager.vpce.example.com:8443', $endpoint->endpoint);
    }

    #[Test]
    public function refusesPlainHttpUnlessTheOperatorOptedIn(): void
    {
        try {
            AwsSecretsEndpoint::fromConfig($this->config(endpoint: 'http://sm.example.com'));
            self::fail('Plain http must be refused.');
        } catch (AwsSecretsManagerException $e) {
            self::assertSame(1794500003, $e->getCode());
        }

        $endpoint = AwsSecretsEndpoint::fromConfig($this->config(endpoint: 'http://sm.example.com', allowInsecureHttp: true));
        self::assertSame('http://sm.example.com', $endpoint->endpoint);
    }

    #[Test]
    public function optingIntoPlainHttpDoesNotAllowOtherSchemes(): void
    {
        $this->expectException(AwsSecretsManagerException::class);
        $this->expectExceptionCode(1794500003);

        AwsSecretsEndpoint::fromConfig($this->config(endpoint: 'ftp://sm.example.com', allowInsecureHttp: true));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unusableEndpoints(): iterable
    {
        yield 'credentials' => ['https://user:pass@sm.example.com'];
        yield 'a path' => ['https://sm.example.com/v1'];
        yield 'a query' => ['https://sm.example.com?x=1'];
        yield 'a fragment' => ['https://sm.example.com#x'];
        yield 'no host' => ['https://'];
        yield 'not a url' => ['sm.example.com'];
    }

    #[Test]
    #[DataProvider('unusableEndpoints')]
    public function refusesAnEndpointThatIsNotABareOrigin(string $endpoint): void
    {
        $this->expectException(AwsSecretsManagerException::class);

        AwsSecretsEndpoint::fromConfig($this->config(endpoint: $endpoint));
    }

    private function config(
        string $region = 'eu-central-1',
        string $prefix = 'typo3/',
        string $endpoint = '',
        bool $allowInsecureHttp = false,
    ): AwsSecretsConfig {
        return new AwsSecretsConfig(
            region: $region,
            secretPrefix: $prefix,
            endpoint: $endpoint,
            allowInsecureHttp: $allowInsecureHttp,
        );
    }
}
