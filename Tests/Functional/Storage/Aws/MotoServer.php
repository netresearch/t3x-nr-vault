<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Storage\Aws;

use Aws\Credentials\Credentials;
use Aws\Exception\AwsException;
use Aws\Iam\IamClient;
use Aws\SecretsManager\SecretsManagerClient;
use GuzzleHttp\Client;
use Netresearch\NrVault\Tests\Functional\Storage\HashiCorp\FreePortGenerator;
use RuntimeException;
use Testcontainers\Container\GenericContainer;
use Testcontainers\Container\StartedGenericContainer;
use Throwable;

use function count;
use function is_array;
use function is_string;
use function sprintf;

/**
 * A real AWS Secrets Manager emulation (Moto), started with Testcontainers.
 *
 * One server serves the whole test run: it starts on first use and stops with
 * the PHP process. Moto is used instead of LocalStack, whose current releases
 * need a licence token. It emulates the five Secrets Manager calls the adapter
 * makes (create, put, get, describe, delete without recovery) and, with its IAM
 * enforcement switched on, rejects a request signed with a key it does not know
 * or with the wrong secret. That makes "wrong credentials" a real rejection and
 * lets the least-privilege policy of the operations page be tested as written.
 *
 * Moto switches enforcement on after the first {@see self::BOOTSTRAP_ACTIONS}
 * calls it sees, so provisioning must make exactly that many, and every later
 * call needs a valid signature and an allowing policy.
 *
 * Docker is a precondition. {@see AbstractAwsContainerTestCase} skips the class
 * on a developer machine without it and lets the failure through in CI.
 */
final class MotoServer
{
    public const REGION = 'eu-central-1';

    public const PREFIX = 'typo3';

    /** Two users, each with an access key and an inline policy. */
    private const BOOTSTRAP_ACTIONS = 6;

    private const IMAGE = 'motoserver/moto:5.2.5';

    private static ?self $shared = null;

    private ?SecretsManagerClient $admin = null;

    private function __construct(
        private readonly StartedGenericContainer $container,
        public readonly string $host,
        public readonly string $address,
        /** The extension's credentials: the least-privilege policy of the operations page. */
        public readonly string $keyId,
        public readonly string $secretKey,
        private readonly string $adminKeyId,
        private readonly string $adminSecretKey,
    ) {}

    public static function shared(): self
    {
        if (self::$shared instanceof self) {
            return self::$shared;
        }

        self::$shared = self::boot();

        register_shutdown_function(static function (): void {
            self::$shared?->stop();
        });

        return self::$shared;
    }

    /**
     * The fields of the secret as AWS stores them, or null when it does not exist.
     *
     * @return array<array-key, mixed>|null
     */
    public function storedData(string $identifier): ?array
    {
        try {
            $result = $this->admin()->getSecretValue(['SecretId' => $this->name($identifier)]);
        } catch (AwsException $e) {
            if ($e->getAwsErrorCode() === 'ResourceNotFoundException') {
                return null;
            }

            throw $e;
        }

        $decoded = json_decode(is_string($result['SecretString'] ?? null) ? $result['SecretString'] : '', true);

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * How many versions of the secret AWS still holds, deprecated ones
     * included; 0 when the secret does not exist.
     */
    public function versionCount(string $identifier): int
    {
        // Moto answers ListSecretVersionIds for a deleted secret with HTTP 500
        // instead of ResourceNotFoundException; DescribeSecret answers correctly.
        if (!$this->exists($identifier)) {
            return 0;
        }

        $result   = $this->admin()->listSecretVersionIds(['SecretId' => $this->name($identifier), 'IncludeDeprecated' => true]);
        $versions = $result['Versions'] ?? [];

        return is_array($versions) ? count($versions) : 0;
    }

    /**
     * Whether DescribeSecret still finds the secret.
     */
    public function exists(string $identifier): bool
    {
        try {
            $this->admin()->describeSecret(['SecretId' => $this->name($identifier)]);
        } catch (AwsException $e) {
            if ($e->getAwsErrorCode() === 'ResourceNotFoundException') {
                return false;
            }

            throw $e;
        }

        return true;
    }

    /**
     * A secret of somebody else under the name nr-vault would use.
     */
    public function createForeign(string $identifier, string $value): void
    {
        $this->admin()->createSecret(['Name' => $this->name($identifier), 'SecretString' => $value]);
    }

    public function rawValue(string $identifier): ?string
    {
        try {
            $result = $this->admin()->getSecretValue(['SecretId' => $this->name($identifier)]);
        } catch (AwsException $e) {
            if ($e->getAwsErrorCode() === 'ResourceNotFoundException') {
                return null;
            }

            throw $e;
        }

        $value = $result['SecretString'] ?? null;

        return is_string($value) ? $value : null;
    }

    /**
     * Put a new current version behind the adapter's back.
     */
    public function overwriteBehindTheAdapter(string $identifier, string $value): void
    {
        $this->admin()->putSecretValue(['SecretId' => $this->name($identifier), 'SecretString' => $value]);
    }

    /**
     * Remove the secret behind the adapter's back, with every version.
     */
    public function removeBehindTheAdapter(string $identifier): void
    {
        $this->admin()->deleteSecret(['SecretId' => $this->name($identifier), 'ForceDeleteWithoutRecovery' => true]);
    }

    public function name(string $identifier): string
    {
        return self::PREFIX . '/' . str_replace(':', '+', $identifier);
    }

    public function stop(): void
    {
        try {
            $this->container->stop();
        } catch (Throwable) {
            // The container may already be gone; the run is over either way.
        }
    }

    private function admin(): SecretsManagerClient
    {
        return $this->admin ??= new SecretsManagerClient(self::options($this->address, $this->adminKeyId, $this->adminSecretKey));
    }

    /**
     * @return array<string, mixed>
     */
    private static function options(string $address, string $keyId, string $secretKey): array
    {
        return [
            'version'                     => 'latest',
            'region'                      => self::REGION,
            'endpoint'                    => $address,
            'credentials'                 => new Credentials($keyId, $secretKey),
            'use_aws_shared_config_files' => false,
            'retries'                     => 0,
        ];
    }

    private static function boot(): self
    {
        $container = (new GenericContainer(self::IMAGE))
            ->withEnvironment(['INITIAL_NO_AUTH_ACTION_COUNT' => (string) self::BOOTSTRAP_ACTIONS])
            ->withExposedPorts(5000)
            ->withPortGenerator(new FreePortGenerator())
            ->start();

        self::waitUntilAnswering($container);

        $host    = $container->getHost();
        $address = sprintf('http://%s:%d', $host, $container->getMappedPort(5000)); // NOSONAR: test fixture without TLS by design

        $iam = new IamClient(self::options($address, 'AKIABOOTSTRAP', 'bootstrap'));

        // Exactly the four actions the adapter calls, so the whole suite passing
        // under this policy is the evidence that no other action is needed. The
        // resource is "*": Moto evaluates a policy's Resource against "*" for
        // Secrets Manager calls instead of against the secret's ARN (an ARN
        // scoped to the prefix denied every call, measured on 5.2.5), so the
        // prefix scoping documented for real AWS is not exercised here.
        $extension = self::createUser($iam, 'typo3', [[
            'Effect'   => 'Allow',
            'Action'   => ['secretsmanager:CreateSecret', 'secretsmanager:PutSecretValue', 'secretsmanager:GetSecretValue', 'secretsmanager:DeleteSecret'],
            'Resource' => '*',
        ]]);
        $admin = self::createUser($iam, 'admin', [[
            'Effect'   => 'Allow',
            'Action'   => 'secretsmanager:*',
            'Resource' => '*',
        ]]);

        return new self($container, $host, $address, $extension[0], $extension[1], $admin[0], $admin[1]);
    }

    /**
     * Three IAM calls, so two users cost the six bootstrap actions.
     *
     * @param list<array<string, mixed>> $statements
     *
     * @return array{string, string} Access key id and secret access key
     */
    private static function createUser(IamClient $iam, string $name, array $statements): array
    {
        $iam->createUser(['UserName' => $name]);
        $key = $iam->createAccessKey(['UserName' => $name])->get('AccessKey');
        $iam->putUserPolicy([
            'UserName'       => $name,
            'PolicyName'     => 'secrets',
            'PolicyDocument' => json_encode(['Version' => '2012-10-17', 'Statement' => $statements], JSON_THROW_ON_ERROR),
        ]);

        $keyId  = is_array($key) ? ($key['AccessKeyId'] ?? null) : null;
        $secret = is_array($key) ? ($key['SecretAccessKey'] ?? null) : null;
        if (!is_string($keyId) || !is_string($secret)) {
            throw new RuntimeException('Moto answered without an access key', 1794500101);
        }

        return [$keyId, $secret];
    }

    /**
     * Poll the container until it answers. Written out instead of using the
     * library's wait strategy so that a slow or broken start reports the
     * container's own log and the last thing the poll saw. The probe is a plain
     * GET that is not an AWS action, so it does not use up a bootstrap action.
     */
    private static function waitUntilAnswering(StartedGenericContainer $container): void
    {
        $deadline = microtime(true) + 120;
        $client   = new Client(['http_errors' => false, 'timeout' => 3, 'connect_timeout' => 3]);
        $seen     = 'no attempt';

        while (microtime(true) < $deadline) {
            foreach ([$container->getHost(), '127.0.0.1'] as $host) {
                try {
                    $url      = sprintf('http://%s:%d/moto-api/', $host, $container->getMappedPort(5000)); // NOSONAR: test fixture without TLS by design
                    $response = $client->request('GET', $url);
                    $seen     = sprintf('%s answered HTTP %d', $url, $response->getStatusCode());
                    if ($response->getStatusCode() === 200) {
                        return;
                    }
                } catch (Throwable $e) {
                    $seen = $host . ': ' . $e->getMessage();
                }
            }

            usleep(500_000);
        }

        throw new RuntimeException(
            sprintf("Moto did not answer within 120 seconds. Last attempt: %s\nIts log:\n%s", $seen, substr($container->logs(), -2000)),
            1794500100,
        );
    }
}
