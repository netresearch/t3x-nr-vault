<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service;

use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Http\VaultHttpClientFactoryInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Service\VaultService;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(VaultService::class)]
final class VaultListAdapterCompatibilityTest extends TestCase
{
    /**
     * @param list<string> $expected
     */
    #[Test]
    #[DataProvider('patterns')]
    public function serviceEnforcesThePatternWhenALegacyAdapterIgnoresIt(
        ?string $pattern,
        array $expected,
    ): void {
        $service = $this->serviceWithUnfilteredAdapter(true);
        self::assertSame(
            $expected,
            array_column($service->list($pattern), 'identifier'),
        );
    }

    /**
     * @return iterable<string, array{?string, list<string>}>
     */
    public static function patterns(): iterable
    {
        yield 'null leaves candidates unchanged' => [
            null,
            [
                'App_key',
                'app_key_extra',
                'billing_key',
                'app%key',
                'app\key',
                'app[abc]',
                'appékey',
            ],
        ];
        yield 'literal underscore' => ['APP_*', ['App_key', 'app_key_extra']];
        yield 'exact without star' => ['app_key', ['App_key']];
        yield 'middle star' => ['app*key', ['App_key', 'app%key', 'app\key', 'appékey']];
        yield 'multiple stars' => ['a**p_*key', ['App_key']];
        yield 'all stars' => [
            '***',
            [
                'App_key',
                'app_key_extra',
                'billing_key',
                'app%key',
                'app\key',
                'app[abc]',
                'appékey',
            ],
        ];
        yield 'empty matches no candidates' => ['', []];
        yield 'percent is literal' => ['app%key', ['app%key']];
        yield 'backslash is literal' => ['app\*', ['app\key']];
        yield 'regex bracket syntax is literal' => ['app[abc]', ['app[abc]']];
        yield 'multibyte bytes are literal' => ['appé*', ['appékey']];
        yield 'multibyte case is not folded' => ['appÉ*', []];
        yield 'long pattern does not compile a regex' => [str_repeat('*', 100000) . 'app_key', ['App_key']];
        yield 'long literal cannot match a short candidate' => [str_repeat('x', 100000), []];
    }

    #[Test]
    public function matchingLegacyCandidatesStillRequireReadAccess(): void
    {
        self::assertSame(
            [],
            $this->serviceWithUnfilteredAdapter(false)->list('*'),
        );
    }

    private function serviceWithUnfilteredAdapter(bool $canRead): VaultService
    {
        // This adapter models the published pre-pattern extension point: it
        // returns all visible records regardless of the new optional DTO field.
        $adapter = self::createStub(VaultAdapterInterface::class);
        $adapter
            ->method('listSecrets')
            ->willReturn(
                array_map(
                    static fn (
                        string $identifier,
                    ): Secret => new Secret(identifier: $identifier),
                    [
                        'App_key',
                        'app_key_extra',
                        'billing_key',
                        'app%key',
                        'app\key',
                        'app[abc]',
                        'appékey',
                    ],
                ),
            );
        $access = self::createStub(AccessControlServiceInterface::class);
        $access->method('canRead')->willReturn($canRead);
        $encryption = $this->createMock(EncryptionServiceInterface::class);
        $encryption->expects(self::never())->method('decrypt');

        return new VaultService(
            $adapter,
            $encryption,
            $access,
            self::createStub(AuditLogServiceInterface::class),
            self::createStub(ExtensionConfigurationInterface::class),
            self::createStub(VaultHttpClientFactoryInterface::class),
        );
    }
}
