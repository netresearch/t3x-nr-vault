<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use Closure;
use InvalidArgumentException;
use Netresearch\NrVault\Http\AuthScheme;
use Netresearch\NrVault\Http\SecretPlacement;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(AuthScheme::class)]
final class AuthSchemeTest extends TestCase
{
    /**
     * @return iterable<string, array{Closure(): AuthScheme, array{SecretPlacement, ?string, ?string, ?string, ?string, ?string}}>
     */
    public static function schemeProvider(): iterable
    {
        yield 'bearer' => [AuthScheme::bearer(...), [SecretPlacement::Bearer, null, null, null, null, null]];
        yield 'basic, combined secret' => [static fn (): AuthScheme => AuthScheme::basicAuth(), [SecretPlacement::BasicAuth, null, null, null, null, null]];
        yield 'basic, username secret' => [static fn (): AuthScheme => AuthScheme::basicAuth('api_user'), [SecretPlacement::BasicAuth, null, null, null, null, 'api_user']];
        yield 'header, default name' => [static fn (): AuthScheme => AuthScheme::header(), [SecretPlacement::Header, 'X-API-Key', null, null, null, null]];
        yield 'header, name and prefix' => [static fn (): AuthScheme => AuthScheme::header('Authorization', 'DeepL-Auth-Key '), [SecretPlacement::Header, 'Authorization', 'DeepL-Auth-Key ', null, null, null]];
        yield 'api key' => [AuthScheme::apiKey(...), [SecretPlacement::ApiKey, null, null, null, null, null]];
        yield 'query, default name' => [static fn (): AuthScheme => AuthScheme::queryParam(), [SecretPlacement::QueryParam, null, null, 'api_key', null, null]];
        yield 'query, custom name' => [static fn (): AuthScheme => AuthScheme::queryParam('key'), [SecretPlacement::QueryParam, null, null, 'key', null, null]];
        yield 'body, default field' => [static fn (): AuthScheme => AuthScheme::bodyField(), [SecretPlacement::BodyField, null, null, null, 'api_key', null]];
        yield 'body, 64-character field' => [static fn (): AuthScheme => AuthScheme::bodyField(str_repeat('a', 64)), [SecretPlacement::BodyField, null, null, null, str_repeat('a', 64), null]];
    }

    /**
     * @param Closure(): AuthScheme                                               $build
     * @param array{SecretPlacement, ?string, ?string, ?string, ?string, ?string} $expected
     */
    #[Test]
    #[DataProvider('schemeProvider')]
    public function namedConstructorCarriesOnlyItsOwnOptions(Closure $build, array $expected): void
    {
        $scheme = $build();

        self::assertSame(
            $expected,
            [$scheme->placement, $scheme->headerName, $scheme->prefix, $scheme->queryParam, $scheme->bodyField, $scheme->usernameSecret],
        );
    }

    /**
     * @return iterable<string, array{Closure(): AuthScheme, int}>
     */
    public static function invalidSchemeProvider(): iterable
    {
        yield 'basic, username with a line break' => [static fn (): AuthScheme => AuthScheme::basicAuth("api\nuser"), 9410661933];
        yield 'basic, empty username' => [static fn (): AuthScheme => AuthScheme::basicAuth(''), 9410661933];
        yield 'header, empty name' => [static fn (): AuthScheme => AuthScheme::header(''), 7930377463];
        yield 'header, name with a space' => [static fn (): AuthScheme => AuthScheme::header('X Api Key'), 7930377463];
        yield 'header, name with a colon' => [static fn (): AuthScheme => AuthScheme::header('Authorization:'), 7930377463];
        yield 'header, empty prefix' => [static fn (): AuthScheme => AuthScheme::header('Authorization', ''), 9898564967];
        yield 'header, prefix with CRLF' => [static fn (): AuthScheme => AuthScheme::header('Authorization', "Key\r\nX-Injected: 1 "), 9898564967];
        yield 'query, empty name' => [static fn (): AuthScheme => AuthScheme::queryParam(''), 2722802580];
        yield 'query, name with a NUL byte' => [static fn (): AuthScheme => AuthScheme::queryParam("key\0"), 2722802580];
        yield 'body, leading digit' => [static fn (): AuthScheme => AuthScheme::bodyField('1key'), 4310510580];
        yield 'body, non-ASCII letter' => [static fn (): AuthScheme => AuthScheme::bodyField('schlüssel'), 4310510580];
        yield 'body, hyphen' => [static fn (): AuthScheme => AuthScheme::bodyField('api-key'), 4310510580];
        yield 'body, 65 characters' => [static fn (): AuthScheme => AuthScheme::bodyField(str_repeat('a', 65)), 4310510580];
    }

    /**
     * @param Closure(): AuthScheme $build
     */
    #[Test]
    #[DataProvider('invalidSchemeProvider')]
    public function invalidOptionIsRefusedWhenTheSchemeIsBuilt(Closure $build, int $code): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode($code);

        $build();
    }
}
