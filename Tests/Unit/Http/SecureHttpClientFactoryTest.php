<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Client\ClientInterface;

#[CoversClass(SecureHttpClientFactory::class)]
final class SecureHttpClientFactoryTest extends TestCase
{
    use GuzzleClientConfigTrait;

    protected bool $resetSingletonInstances = true;

    private SecureHttpClientFactory $factory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->factory = new SecureHttpClientFactory();
        $GLOBALS['TYPO3_CONF_VARS'] = [];
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['TYPO3_CONF_VARS']);
        parent::tearDown();
    }

    #[Test]
    public function createReturnsClientInterface(): void
    {
        $client = $this->factory->create();

        self::assertInstanceOf(ClientInterface::class, $client);
    }

    #[Test]
    public function createWithTypo3HttpConfig(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [
            'timeout' => 60,
            'connect_timeout' => 5,
            'version' => '2.0',
        ];

        $client = $this->factory->create();

        self::assertInstanceOf(ClientInterface::class, $client);
    }

    #[Test]
    public function createWithProxyConfig(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [
            'proxy' => 'http://proxy.example.com:8080',
        ];

        $client = $this->factory->create();

        self::assertInstanceOf(ClientInterface::class, $client);
    }

    #[Test]
    public function createWithSslConfig(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [
            'verify' => false,
            'cert' => '/path/to/cert.pem',
            'ssl_key' => '/path/to/key.pem',
        ];

        $client = $this->factory->create();

        self::assertInstanceOf(ClientInterface::class, $client);
    }

    #[Test]
    public function createWithRedirectConfig(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [
            'allow_redirects' => ['max' => 5],
        ];

        $client = $this->factory->create();

        self::assertInstanceOf(ClientInterface::class, $client);
    }

    #[Test]
    public function isHostAllowedReturnsTrueWhenNoRestrictions(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [];

        self::assertTrue($this->factory->isHostAllowed('any.example.com'));
    }

    #[Test]
    public function isHostAllowedReturnsTrueForExactMatch(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [
            'allowed_hosts' => ['api.example.com', 'other.example.com'],
        ];

        self::assertTrue($this->factory->isHostAllowed('api.example.com'));
    }

    #[Test]
    public function isHostAllowedReturnsFalseWhenNotInList(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [
            'allowed_hosts' => ['api.example.com'],
        ];

        self::assertFalse($this->factory->isHostAllowed('other.example.com'));
    }

    #[Test]
    public function isHostAllowedSupportsWildcardPattern(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [
            'allowed_hosts' => ['*.example.com'],
        ];

        self::assertTrue($this->factory->isHostAllowed('api.example.com'));
        self::assertTrue($this->factory->isHostAllowed('sub.domain.example.com'));
        self::assertFalse($this->factory->isHostAllowed('api.other.com'));
    }

    #[Test]
    public function isHostAllowedIgnoresNonStringPatterns(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [
            'allowed_hosts' => ['api.example.com', 123, null],
        ];

        self::assertTrue($this->factory->isHostAllowed('api.example.com'));
        self::assertFalse($this->factory->isHostAllowed('other.example.com'));
    }

    #[Test]
    public function isHostAllowedReturnsEmptyArrayAsNoRestriction(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [
            'allowed_hosts' => [],
        ];

        self::assertTrue($this->factory->isHostAllowed('any.example.com'));
    }

    #[Test]
    public function createWithEmptyConfig(): void
    {
        $GLOBALS['TYPO3_CONF_VARS'] = [];

        $client = $this->factory->create();

        self::assertInstanceOf(ClientInterface::class, $client);
    }

    #[Test]
    public function createWithNonIntegerTimeoutUsesDefault(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [
            'timeout' => 'not-an-integer',
            'connect_timeout' => 'also-not-an-integer',
        ];

        $client = $this->factory->create();

        // Should not throw and use defaults
        self::assertInstanceOf(ClientInterface::class, $client);
    }

    #[Test]
    public function createAppliesPositiveTimeoutOverride(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [
            'timeout' => 60,
            'connect_timeout' => 5,
        ];

        $config = $this->getGuzzleConfig($this->factory->create(300));

        self::assertSame(300, $config['timeout']);
        // connect_timeout stays platform-managed: the override bounds the
        // whole transfer, not connection establishment.
        self::assertSame(5, $config['connect_timeout']);
    }

    #[Test]
    #[DataProvider('noTimeoutOverrideProvider')]
    public function createKeepsPlatformTimeoutWithoutPositiveOverride(?int $timeoutSeconds): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [
            'timeout' => 60,
        ];

        $config = $this->getGuzzleConfig($this->factory->create($timeoutSeconds));

        self::assertSame(60, $config['timeout']);
    }

    /**
     * @return iterable<string, array{int|null}>
     */
    public static function noTimeoutOverrideProvider(): iterable
    {
        yield 'null (no override requested)' => [null];
        yield 'zero' => [0];
        yield 'negative' => [-10];
    }

    #[Test]
    public function createWithNonStringVersionUsesDefault(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [
            'version' => 123, // Not a string
        ];

        $client = $this->factory->create();

        // Should not throw and use default '1.1'
        self::assertInstanceOf(ClientInterface::class, $client);
    }

    #[Test]
    public function createWithHttpsProxyFromEnvironment(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [];

        // Set environment variable
        $originalHttpsProxy = getenv('HTTPS_PROXY');
        putenv('HTTPS_PROXY=http://proxy.example.com:8080');

        try {
            $client = $this->factory->create();
            self::assertInstanceOf(ClientInterface::class, $client);
        } finally {
            // Restore original
            if ($originalHttpsProxy === false) {
                putenv('HTTPS_PROXY');
            } else {
                putenv('HTTPS_PROXY=' . $originalHttpsProxy);
            }
        }
    }

    #[Test]
    public function createWithNoProxyFromEnvironment(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [];

        // Set environment variables
        $originalNoProxy = getenv('NO_PROXY');
        putenv('NO_PROXY=localhost,127.0.0.1,.local');

        try {
            $client = $this->factory->create();
            self::assertInstanceOf(ClientInterface::class, $client);
        } finally {
            // Restore original
            if ($originalNoProxy === false) {
                putenv('NO_PROXY');
            } else {
                putenv('NO_PROXY=' . $originalNoProxy);
            }
        }
    }

    #[Test]
    public function isHostAllowedReturnsFalseWhenNoPatternMatches(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [
            'allowed_hosts' => ['specific.example.com', '*.other.com'],
        ];

        // Neither exact match nor wildcard match
        self::assertFalse($this->factory->isHostAllowed('different.domain.org'));
    }
}
