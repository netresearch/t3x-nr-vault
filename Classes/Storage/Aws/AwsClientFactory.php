<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage\Aws;

use Aws\Credentials\Credentials;
use Aws\Handler\Guzzle\GuzzleHandler;
use Aws\SecretsManager\SecretsManagerClient;
use GuzzleHttp\ClientInterface;
use Netresearch\NrVault\Configuration\Dto\AwsSecretsConfig;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\AwsSecretsManagerException;
use Netresearch\NrVault\Exception\ConfigurationException;
use SensitiveParameter;

use function is_string;

/**
 * Builds the SDK client, and is the only class that names SDK types.
 *
 * The SDK is a `suggest` of the extension, not a requirement: nothing outside
 * this class and {@see AwsSecretsManagerStore} may reference it, and this class
 * only does so after {@see isInstalled()} said yes, so a TYPO3 installation
 * that never selects `aws` boots without the package.
 *
 * Everything that could send the SDK somewhere else is pinned:
 *
 *  - Credentials are one explicit object. Passing it means the SDK never builds
 *    its default provider chain, which asks the instance metadata service at
 *    169.254.169.254; the extension's SSRF defence refuses that address, and the
 *    chain would otherwise pick up whatever ambient credentials the host has.
 *  - Shared config and credentials files are not read, so `AWS_PROFILE` and
 *    `~/.aws` have no say.
 *  - Endpoint URLs configured through the environment (`AWS_ENDPOINT_URL`,
 *    `AWS_ENDPOINT_URL_SECRETS_MANAGER`) are ignored; only `aws.endpoint` counts.
 *  - Requests leave through the client {@see SecureHttpClientFactory} builds
 *    (SSRF range check, DNS pin, no redirects, no logging, a ten second bound),
 *    handed to the SDK as its HTTP handler instead of the SDK's own transport.
 *  - At most one retry, so an unreachable endpoint cannot hold a request for
 *    minutes.
 *  - HTTP error statuses are errors. The hardened client reports them as plain
 *    responses (so the vault HTTP client can audit them); the SDK has to see
 *    them as failures, or a rejected request looks like an empty success.
 */
final readonly class AwsClientFactory
{
    private const SDK_CLIENT_CLASS = SecretsManagerClient::class;

    public function __construct(
        private ExtensionConfigurationInterface $configuration,
        private ClientInterface $httpClient,
        private string $clientClass = self::SDK_CLIENT_CLASS,
    ) {}

    public function isInstalled(): bool
    {
        return class_exists($this->clientClass);
    }

    /**
     * @throws AwsSecretsManagerException
     * @throws ConfigurationException     When the SDK is not installed
     */
    public function create(AwsSecretsEndpoint $endpoint): SecretsManagerClient
    {
        if (!$this->isInstalled()) {
            throw ConfigurationException::awsSdkMissing();
        }

        $config  = $this->configuration->getAwsConfig();
        $options = [
            'version'                     => '2017-10-17',
            'region'                      => $endpoint->region,
            'credentials'                 => $this->credentials($config),
            'http_handler'                => new GuzzleHandler($this->httpClient),
            'use_aws_shared_config_files' => false,
            'retries'                     => 1,
            // The secure client is built with `http_errors => false`, so a 4xx or
            // 5xx would come back to the SDK as a successful response and be
            // parsed as an empty result: a rejected write would read as stored.
            'http' => ['http_errors' => true],
        ];

        if ($endpoint->endpoint !== null) {
            $options['endpoint'] = $endpoint->endpoint;
        } else {
            $options['ignore_configured_endpoint_urls'] = true;
        }

        return new SecretsManagerClient($options);
    }

    /**
     * @throws AwsSecretsManagerException
     */
    private function credentials(AwsSecretsConfig $config): Credentials
    {
        $keyId = getenv($config->accessKeyIdEnvVar);
        if (!is_string($keyId) || $keyId === '') {
            $keyId = $config->accessKeyId;
        }

        if ($keyId === '') {
            throw AwsSecretsManagerException::credentialMissing('environment variable ' . $config->accessKeyIdEnvVar);
        }

        $secret = getenv($config->secretAccessKeyEnvVar);
        if (!is_string($secret) || $secret === '') {
            throw AwsSecretsManagerException::credentialMissing('environment variable ' . $config->secretAccessKeyEnvVar);
        }

        $token = getenv($config->sessionTokenEnvVar);

        return $this->build($keyId, $secret, is_string($token) && $token !== '' ? $token : null);
    }

    private function build(
        string $keyId,
        #[SensitiveParameter]
        string $secret,
        #[SensitiveParameter]
        ?string $token,
    ): Credentials {
        return new Credentials($keyId, $secret, $token);
    }
}
