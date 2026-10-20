<?php

/* Copyright (c) 2026 Netresearch DTT GmbH; SPDX-License-Identifier: GPL-2.0-or-later */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Utility;

use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Utility\IdentifierValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(IdentifierValidator::class)]
final class StorageIdentifierTest extends TestCase
{
    /**
     * @return iterable<string,array{string,?string}>
     */
    public static function acceptedIdentifiers(): iterable
    {
        yield 'ordinary friendly identifier' => ['api_key', null];
        yield 'ordinary UUIDv7' => ['019bb129-5a00-7abc-9def-0123456789ab', null];
        yield 'minimum site and name' => ['site:a:key', 'a'];
        yield 'exact mixed-case site' => ['site:Main-01_A:Api_key', 'Main-01_A'];
        yield '80-byte site component' => ['site:' . str_repeat('a', 80) . ':key', str_repeat('a', 80)];
        yield '255-byte complete identifier' => [
            'site:' . str_repeat('a', 80) . ':k' . str_repeat('e', 168),
            str_repeat('a', 80),
        ];
    }

    #[Test]
    #[DataProvider('acceptedIdentifiers')]
    public function acceptsStorageGrammarAndReturnsExactSite(
        string $identifier,
        ?string $site,
    ): void {
        IdentifierValidator::validateForStorage($identifier);
        self::assertTrue(IdentifierValidator::isValidForStorage($identifier));
        self::assertSame(
            $site,
            IdentifierValidator::getSiteIdentifier($identifier),
        );
    }

    /**
     * @return iterable<string,array{string}>
     */
    public static function invalidNamespaces(): iterable
    {
        yield 'missing site' => ['site::api_key'];
        yield 'missing name' => ['site:main:'];
        yield 'short name' => ['site:main:ab'];
        yield 'numeric name' => ['site:main:123'];
        yield 'nested namespace' => ['site:main:site:other:key'];
        yield 'extra delimiter' => ['site:main:api_key:'];
        yield 'unsupported prefix case' => ['Site:main:api_key'];
        yield 'leading punctuation in site' => ['site:_main:api_key'];
        yield 'site dot' => ['site:main.example:api_key'];
        yield 'site slash' => ['site:main/other:api_key'];
        yield 'site Unicode' => ['site:máin:api_key'];
        yield 'name Unicode' => ['site:main:api_kéy'];
        yield 'name hyphen' => ['site:main:api-key'];
        yield '81-byte site component' => ['site:' . str_repeat('a', 81) . ':key'];
        yield '256-byte total' => ['site:' . str_repeat('a', 80) . ':k' . str_repeat('e', 169)];
        yield 'trailing LF' => ["site:main:api_key\n"];
        yield 'trailing CR' => ["site:main:api_key\r"];
        yield 'embedded NUL' => ["site:main:api\x00key"];
        yield 'leading space' => [' site:main:api_key'];
        yield 'trailing space' => ['site:main:api_key '];
    }

    #[Test]
    #[DataProvider('invalidNamespaces')]
    public function rejectsUnsupportedNamespaceBytes(
        string $identifier,
    ): void {
        self::assertFalse(IdentifierValidator::isValidForStorage($identifier));
        self::assertNull(IdentifierValidator::getSiteIdentifier($identifier));
    }

    #[Test]
    public function storageNamespaceDoesNotBroadenGenericReferenceDetection(): void
    {
        self::assertFalse(IdentifierValidator::isValid('site:main:api_key'));
        self::assertFalse(
            IdentifierValidator::looksLikeVaultIdentifier('site:main:api_key'),
        );
        self::assertTrue(
            IdentifierValidator::looksLikeVaultIdentifier(
                '%vault(site:main:api_key)%',
            ),
        );
    }
}
