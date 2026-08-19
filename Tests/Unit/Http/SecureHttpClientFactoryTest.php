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
use TYPO3\CMS\Core\Log\LogLevel;
use TYPO3\CMS\Core\Log\LogRecord;
use TYPO3\CMS\Core\Log\Writer\AbstractWriter;

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
        CollectingLogWriter::reset();
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

    /**
     * The fallbacks that apply when TYPO3 configures no HTTP timeouts. They
     * bound how long a request carrying a vault secret may hang, and nothing
     * asserted them — `createWithNonIntegerTimeoutUsesDefault` below only
     * checks that a client came back, which is true for any default at all.
     */
    #[Test]
    public function createFallsBackToTheDocumentedTimeoutDefaults(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [];

        $config = $this->getGuzzleConfig($this->factory->create());

        self::assertSame(30, $config['timeout'] ?? null);
        self::assertSame(10, $config['connect_timeout'] ?? null);
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

    /**
     * @param array<string, mixed> $httpConfig
     */
    #[Test]
    #[DataProvider('tlsVerificationValues')]
    public function createWarnsExactlyWhenTlsVerificationIsTurnedOff(array $httpConfig, bool $expectWarning): void
    {
        // The condition moved out of the option-building block when it was
        // extracted into `buildOptions()`, from `array_key_exists('verify', …)`
        // plus `=== false` to `($typo3Config['verify'] ?? null) === false`.
        // Nothing covered it before, so this pins the whole value range rather
        // than the one case that motivated the warning.
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = $httpConfig;

        // The logger is reached through the real LogManager, configured from
        // $TYPO3_CONF_VARS['LOG'] — no @internal singleton injection needed.
        CollectingLogWriter::reset();
        $GLOBALS['TYPO3_CONF_VARS']['LOG']['Netresearch']['NrVault']['Http']['SecureHttpClientFactory']['writerConfiguration'] = [
            LogLevel::WARNING => [CollectingLogWriter::class => []],
        ];

        $this->factory->create();

        $tlsWarnings = array_values(array_filter(
            CollectingLogWriter::messages(),
            static fn (string $message): bool => str_starts_with($message, 'TLS verification is disabled'),
        ));

        self::assertCount($expectWarning ? 1 : 0, $tlsWarnings);
    }

    /**
     * @return iterable<string, array{0: array<string, mixed>, 1: bool}>
     */
    public static function tlsVerificationValues(): iterable
    {
        yield 'key absent' => [[], false];
        yield 'verify null' => [['verify' => null], false];
        yield 'verify false' => [['verify' => false], true];
        yield 'verify true' => [['verify' => true], false];
        yield 'verify zero' => [['verify' => 0], false];
        yield 'verify empty string' => [['verify' => ''], false];
        yield 'verify ca bundle path' => [['verify' => '/path/to/ca.pem'], false];
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

    /**
     * Environment proxy variables decide where outbound traffic — including
     * every request carrying a vault secret — is actually sent, so the built
     * client has to be inspected rather than merely constructed. The two tests
     * above assert only that a client came back, which holds just as well for
     * a client that silently dropped the proxy or read the wrong variable.
     *
     * `NO_PROXY` is a comma-separated list and Guzzle expects it split; the
     * uppercase spelling wins over the lowercase one; and an empty value is
     * not a proxy setting at all — an empty `proxy.https` would send requests
     * to nowhere.
     */
    #[Test]
    public function environmentProxyVariablesReachTheClientConfiguration(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [];

        $this->withProxyEnvironment(
            [
                'HTTPS_PROXY' => 'http://https-proxy.example.com:8080',
                'https_proxy' => 'http://lowercase-proxy.example.com:8080',
                'HTTP_PROXY' => 'http://http-proxy.example.com:3128',
                'NO_PROXY' => 'localhost,127.0.0.1,.local',
            ],
            function (): void {
                $config = $this->getGuzzleConfig($this->factory->create());

                self::assertSame(
                    [
                        'http' => 'http://http-proxy.example.com:3128',
                        'https' => 'http://https-proxy.example.com:8080',
                        'no' => ['localhost', '127.0.0.1', '.local'],
                    ],
                    $config['proxy'] ?? null,
                );
            },
        );
    }

    #[Test]
    public function emptyProxyEnvironmentVariablesAreNotTreatedAsAProxy(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [];

        $this->withProxyEnvironment(
            [
                'HTTPS_PROXY' => '',
                'https_proxy' => '',
                'HTTP_PROXY' => '',
                'http_proxy' => '',
                'NO_PROXY' => '',
                'no_proxy' => '',
            ],
            function (): void {
                $config = $this->getGuzzleConfig($this->factory->create());

                self::assertNull(
                    $config['proxy'] ?? null,
                    'An empty proxy variable must leave the client without a proxy, not with an empty one.',
                );
            },
        );
    }

    #[Test]
    public function lowercaseProxyVariablesAreUsedWhenTheUppercaseOnesAreUnset(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [];

        $this->withProxyEnvironment(
            [
                'HTTPS_PROXY' => null,
                'https_proxy' => 'http://lowercase-proxy.example.com:8080',
                'HTTP_PROXY' => null,
                'http_proxy' => null,
                'NO_PROXY' => null,
                'no_proxy' => 'example.org',
            ],
            function (): void {
                $config = $this->getGuzzleConfig($this->factory->create());

                self::assertSame(
                    [
                        'https' => 'http://lowercase-proxy.example.com:8080',
                        'no' => ['example.org'],
                    ],
                    $config['proxy'] ?? null,
                );
            },
        );
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

    /**
     * Apply proxy environment variables for the duration of one callable and
     * restore whatever the environment held before, including variables the
     * caller set to `null` (meaning: must be unset while the callable runs).
     *
     * @param array<string, string|null> $variables
     * @param callable(): void $assertions
     */
    private function withProxyEnvironment(array $variables, callable $assertions): void
    {
        $originals = [];
        foreach (array_keys($variables) as $name) {
            $originals[$name] = getenv($name);
        }

        foreach ($variables as $name => $value) {
            if ($value === null) {
                putenv($name);

                continue;
            }

            putenv($name . '=' . $value);
        }

        try {
            $assertions();
        } finally {
            foreach ($originals as $name => $value) {
                if ($value === false) {
                    putenv($name);

                    continue;
                }

                putenv($name . '=' . $value);
            }
        }
    }
}

/**
 * Collects the messages written to a logger, so a test can assert on what the
 * factory logged without touching `@internal` singleton injection: the real
 * LogManager builds its writers from `$TYPO3_CONF_VARS['LOG']`.
 */
final class CollectingLogWriter extends AbstractWriter
{
    /** @var list<string> */
    private static array $messages = [];

    public function writeLog(LogRecord $record): self
    {
        self::$messages[] = $record->getMessage();

        return $this;
    }

    /**
     * @return list<string>
     */
    public static function messages(): array
    {
        return self::$messages;
    }

    public static function reset(): void
    {
        self::$messages = [];
    }
}
