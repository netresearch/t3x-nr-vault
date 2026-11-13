<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Storage\Aws;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Netresearch\NrVault\Configuration\Dto\AwsSecretsConfig;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\AwsSecretsManagerException;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Storage\Aws\AwsClientFactory;
use Netresearch\NrVault\Storage\Aws\AwsSecretsEndpoint;
use Netresearch\NrVault\Storage\Aws\AwsSecretsManagerStore;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\RequestInterface;

#[CoversClass(AwsClientFactory::class)]
#[AllowMockObjectsWithoutExpectations]
final class AwsClientFactoryTest extends TestCase
{
    private const VARIABLES = [
        'NR_VAULT_AWS_ACCESS_KEY_ID',
        'NR_VAULT_AWS_SECRET_ACCESS_KEY',
        'NR_VAULT_AWS_SESSION_TOKEN',
        'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
        'AWS_SESSION_TOKEN',
        'AWS_PROFILE',
        'AWS_ENDPOINT_URL',
        'AWS_ENDPOINT_URL_SECRETS_MANAGER',
        'AWS_EC2_METADATA_DISABLED',
        'AWS_CONFIG_FILE',
    ];

    /** @var list<RequestInterface> */
    private array $requests = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->requests = [];
        foreach (self::VARIABLES as $name) {
            putenv($name);
        }
    }

    protected function tearDown(): void
    {
        foreach (self::VARIABLES as $name) {
            putenv($name);
        }

        parent::tearDown();
    }

    #[Test]
    public function withoutTheSdkTheErrorIsAConfigurationErrorAndNeverALocalFallback(): void
    {
        $factory = new AwsClientFactory($this->configuration(), $this->client(), 'Not\\An\\Installed\\Client');

        self::assertFalse($factory->isInstalled());

        try {
            $factory->create($this->endpoint());
            self::fail('Creating a client without the SDK must fail.');
        } catch (ConfigurationException $e) {
            self::assertSame(1794500002, $e->getCode());
            self::assertStringContainsString('composer require aws/aws-sdk-php', $e->getMessage());
            self::assertStringContainsString('does not fall back to local storage', $e->getMessage());
        }
    }

    #[Test]
    public function aStoreWithoutTheSdkFailsOnFirstUseAndReportsItself(): void
    {
        $configuration = $this->configuration();
        $store         = new AwsSecretsManagerStore($configuration, new AwsClientFactory($configuration, $this->client(), 'Not\\An\\Installed\\Client'));

        self::assertFalse($store->isSdkInstalled());

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1794500002);

        $store->write('api_key', ['k' => 'v']);
    }

    #[Test]
    public function readsTheCredentialsFromTheNamedEnvironmentVariablesAndSignsWithThem(): void
    {
        putenv('NR_VAULT_AWS_ACCESS_KEY_ID=AKIAENVIRONMENTKEY001');
        putenv('NR_VAULT_AWS_SECRET_ACCESS_KEY=environment-secret-value');

        $this->send($this->factory());

        self::assertStringContainsString('Credential=AKIAENVIRONMENTKEY001/', $this->requests[0]->getHeaderLine('Authorization'));
        self::assertSame('', $this->requests[0]->getHeaderLine('X-Amz-Security-Token'));
    }

    #[Test]
    public function theEnvironmentWinsOverTheStoredAccessKeyId(): void
    {
        putenv('NR_VAULT_AWS_ACCESS_KEY_ID=AKIAENVIRONMENTKEY001');
        putenv('NR_VAULT_AWS_SECRET_ACCESS_KEY=environment-secret-value');

        $this->send($this->factory(new AwsSecretsConfig(region: 'eu-central-1', accessKeyId: 'AKIASTOREDKEY0000001')));

        self::assertStringContainsString('Credential=AKIAENVIRONMENTKEY001/', $this->requests[0]->getHeaderLine('Authorization'));
    }

    #[Test]
    public function fallsBackToTheStoredAccessKeyIdButNeverForTheSecret(): void
    {
        $config = new AwsSecretsConfig(region: 'eu-central-1', accessKeyId: 'AKIASTOREDKEY0000001');

        putenv('NR_VAULT_AWS_SECRET_ACCESS_KEY=environment-secret-value');
        $this->send($this->factory($config));
        self::assertStringContainsString('Credential=AKIASTOREDKEY0000001/', $this->requests[0]->getHeaderLine('Authorization'));

        putenv('NR_VAULT_AWS_SECRET_ACCESS_KEY');

        try {
            $this->factory($config)->create($this->endpoint());
            self::fail('The secret access key has no stored fallback.');
        } catch (AwsSecretsManagerException $e) {
            self::assertSame(1794500005, $e->getCode());
            self::assertStringContainsString('NR_VAULT_AWS_SECRET_ACCESS_KEY', $e->getMessage());
        }
    }

    #[Test]
    public function reportsAMissingAccessKeyIdByTheNameOfTheVariable(): void
    {
        putenv('NR_VAULT_AWS_SECRET_ACCESS_KEY=environment-secret-value');

        try {
            $this->factory()->create($this->endpoint());
            self::fail('A missing access key id must be reported.');
        } catch (AwsSecretsManagerException $e) {
            self::assertSame(1794500005, $e->getCode());
            self::assertStringContainsString('NR_VAULT_AWS_ACCESS_KEY_ID', $e->getMessage());
        }
    }

    #[Test]
    public function sendsTheSessionTokenOfTemporaryCredentials(): void
    {
        putenv('NR_VAULT_AWS_ACCESS_KEY_ID=ASIATEMPORARYKEY0001');
        putenv('NR_VAULT_AWS_SECRET_ACCESS_KEY=environment-secret-value');
        putenv('NR_VAULT_AWS_SESSION_TOKEN=session-token-value');

        $this->send($this->factory());

        self::assertSame('session-token-value', $this->requests[0]->getHeaderLine('X-Amz-Security-Token'));
    }

    #[Test]
    public function honoursTheConfiguredVariableNames(): void
    {
        putenv('MY_KEY_ID=AKIACUSTOMNAMEKEY0001');
        putenv('MY_SECRET=custom-secret');

        try {
            $this->send($this->factory(new AwsSecretsConfig(region: 'eu-central-1', accessKeyIdEnvVar: 'MY_KEY_ID', secretAccessKeyEnvVar: 'MY_SECRET')));
        } finally {
            putenv('MY_KEY_ID');
            putenv('MY_SECRET');
        }

        self::assertStringContainsString('Credential=AKIACUSTOMNAMEKEY0001/', $this->requests[0]->getHeaderLine('Authorization'));
    }

    #[Test]
    public function ignoresTheAmbientAwsEnvironmentAndTheSharedFilesAndMakesNoMetadataCall(): void
    {
        putenv('NR_VAULT_AWS_ACCESS_KEY_ID=AKIAEXPLICITKEY000001');
        putenv('NR_VAULT_AWS_SECRET_ACCESS_KEY=explicit-secret');
        // What the default provider chain would have used instead.
        putenv('AWS_ACCESS_KEY_ID=AKIAAMBIENTKEY0000001');
        putenv('AWS_SECRET_ACCESS_KEY=ambient-secret');
        putenv('AWS_SESSION_TOKEN=ambient-token');
        putenv('AWS_PROFILE=no-such-profile');

        $this->send($this->factory());

        self::assertCount(1, $this->requests, 'exactly the one request: no 169.254.169.254 call, no credential lookup');
        $request = $this->requests[0];
        self::assertStringContainsString('Credential=AKIAEXPLICITKEY000001/', $request->getHeaderLine('Authorization'));
        self::assertSame('', $request->getHeaderLine('X-Amz-Security-Token'));
        self::assertSame('secretsmanager.eu-central-1.amazonaws.com', $request->getUri()->getHost());
    }

    #[Test]
    public function anEndpointFromTheEnvironmentDoesNotRedirectTheSdk(): void
    {
        $this->explicitCredentials();
        putenv('AWS_ENDPOINT_URL=http://127.0.0.1:1');
        putenv('AWS_ENDPOINT_URL_SECRETS_MANAGER=http://127.0.0.1:1');

        $client = $this->factory()->create($this->endpoint());

        self::assertSame('secretsmanager.eu-central-1.amazonaws.com', $client->getEndpoint()->getHost());
        self::assertSame('https', $client->getEndpoint()->getScheme());
    }

    #[Test]
    public function aSharedConfigFileHasNoSayOverTheEndpoint(): void
    {
        $this->explicitCredentials();
        $file = tempnam(sys_get_temp_dir(), 'awsconfig');
        self::assertIsString($file);
        file_put_contents($file, "[default]\nuse_fips_endpoint = true\n");
        putenv('AWS_CONFIG_FILE=' . $file);

        try {
            $client = $this->factory()->create($this->endpoint());
        } finally {
            putenv('AWS_CONFIG_FILE');
            unlink($file);
        }

        self::assertSame('secretsmanager.eu-central-1.amazonaws.com', $client->getEndpoint()->getHost());
    }

    #[Test]
    public function usesTheConfiguredEndpointInsteadOfTheRegionalOne(): void
    {
        $this->explicitCredentials();
        $config = new AwsSecretsConfig(region: 'eu-central-1', endpoint: 'https://sm.vpce.example.com:8443');

        $client = $this->factory($config)->create(AwsSecretsEndpoint::fromConfig($config));

        self::assertSame('sm.vpce.example.com', $client->getEndpoint()->getHost());
        self::assertSame(8443, $client->getEndpoint()->getPort());
    }

    #[Test]
    public function sendsEveryRequestThroughTheInjectedClient(): void
    {
        $this->explicitCredentials();

        $this->send($this->factory());

        self::assertCount(1, $this->requests, 'the injected client saw the request');
    }

    private function explicitCredentials(): void
    {
        putenv('NR_VAULT_AWS_ACCESS_KEY_ID=AKIAEXPLICITKEY000001');
        putenv('NR_VAULT_AWS_SECRET_ACCESS_KEY=explicit-secret');
    }

    private function send(AwsClientFactory $factory): void
    {
        $factory->create($this->endpoint())->getSecretValue(['SecretId' => 'typo3/x']);
    }

    private function endpoint(?AwsSecretsConfig $config = null): AwsSecretsEndpoint
    {
        return AwsSecretsEndpoint::fromConfig($config ?? new AwsSecretsConfig(region: 'eu-central-1', secretPrefix: 'typo3/'));
    }

    private function configuration(?AwsSecretsConfig $config = null): ExtensionConfigurationInterface
    {
        $configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $configuration->method('getAwsConfig')->willReturn($config ?? new AwsSecretsConfig(region: 'eu-central-1', secretPrefix: 'typo3/'));

        return $configuration;
    }

    private function factory(?AwsSecretsConfig $config = null): AwsClientFactory
    {
        return new AwsClientFactory($this->configuration($config), $this->client());
    }

    private function client(): Client
    {
        $stack = HandlerStack::create(new MockHandler([
            new Response(200, ['Content-Type' => 'application/x-amz-json-1.1'], '{"SecretString":"{}"}'),
        ]));
        $stack->push(Middleware::mapRequest(function (RequestInterface $request): RequestInterface {
            $this->requests[] = $request;

            return $request;
        }));

        return new Client(['handler' => $stack, 'http_errors' => false]);
    }
}
