<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage\Aws;

use Aws\Exception\AwsException;
use Aws\SecretsManager\SecretsManagerClient;
use JsonException;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\AwsSecretsManagerException;
use SensitiveParameter;
use Throwable;

use function is_array;
use function is_string;
use function sprintf;

/**
 * AWS Secrets Manager as a key-value store for the adapter.
 *
 * One nr-vault secret is one AWS secret holding one JSON document. A write adds
 * a version (`PutSecretValue`) and creates the secret when AWS says it does not
 * exist yet. A delete uses `ForceDeleteWithoutRecovery`, because the recovery
 * window would keep the last value alive for up to thirty days and block the
 * name; with it no version survives.
 *
 * Nothing the service says is surfaced: the exception carries the operation, the
 * HTTP status and the AWS error code, not the SDK exception that holds the
 * signed request and the command parameters.
 */
final class AwsSecretsManagerStore implements AwsSecretStoreInterface
{
    private ?SecretsManagerClient $client = null;

    public function __construct(
        private readonly ExtensionConfigurationInterface $configuration,
        private readonly AwsClientFactory $clients,
    ) {}

    public function isSdkInstalled(): bool
    {
        return $this->clients->isInstalled();
    }

    public function read(string $identifier): ?array
    {
        $name   = $this->endpoint()->name($identifier);
        $client = $this->client();

        try {
            $result = $client->getSecretValue(['SecretId' => $name]);
        } catch (Throwable $e) {
            if ($this->isNotFound($e)) {
                return null;
            }

            throw $this->translate($e, 'read');
        }

        $raw = $result['SecretString'] ?? null;
        if (!is_string($raw) || $raw === '') {
            throw AwsSecretsManagerException::malformedResponse('read', 'secret holds no string value');
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw AwsSecretsManagerException::malformedResponse('read', 'secret value is not valid JSON');
        }

        if (!is_array($decoded)) {
            throw AwsSecretsManagerException::malformedResponse('read', 'secret value is not a JSON object');
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    public function createIfAbsent(string $identifier, #[SensitiveParameter] array $data): ?array
    {
        $name   = $this->endpoint()->name($identifier);
        $client = $this->client();

        try {
            $encoded = json_encode($data, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw AwsSecretsManagerException::malformedResponse('create', 'payload is not encodable');
        }

        try {
            $client->createSecret(['Name' => $name, 'SecretString' => $encoded]);

            return null;
        } catch (Throwable $e) {
            if (!$e instanceof AwsException || $e->getAwsErrorCode() !== 'ResourceExistsException') {
                throw $this->translate($e, 'create');
            }
        }

        try {
            return $this->read($identifier) ?? throw AwsSecretsManagerException::requestRejected('create', 400, 'ResourceExistsException');
        } catch (AwsSecretsManagerException $e) {
            // Present, but not a JSON object: not ours either.
            if ($e->getCode() === 1794500008) {
                return [];
            }

            throw $e;
        }
    }

    public function write(string $identifier, #[SensitiveParameter] array $data): void
    {
        $name   = $this->endpoint()->name($identifier);
        $client = $this->client();

        try {
            $encoded = json_encode($data, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw AwsSecretsManagerException::malformedResponse('write', 'payload is not encodable');
        }

        try {
            $this->put($client, $name, $encoded);
        } catch (Throwable $e) {
            if (!$this->isNotFound($e)) {
                throw $this->translate($e, 'write');
            }

            $this->createOrPut($client, $name, $encoded);
        }
    }

    public function destroy(string $identifier): void
    {
        $name   = $this->endpoint()->name($identifier);
        $client = $this->client();

        try {
            $client->deleteSecret(['SecretId' => $name, 'ForceDeleteWithoutRecovery' => true]);
        } catch (Throwable $e) {
            // A repeated delete after a half-finished one must succeed.
            if (!$this->isNotFound($e)) {
                throw $this->translate($e, 'delete');
            }
        }
    }

    public function reference(string $identifier): string
    {
        return $this->endpoint()->reference($identifier);
    }

    /**
     * Strip anything credential-shaped from a transport error message.
     * Delimiter-anchored character classes only, so every pattern is linear.
     */
    public static function redact(string $message): string
    {
        return (string) preg_replace(
            [
                '/\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{12,}/',
                '/((?:Authorization|X-Amz-Security-Token):\s*)[^\r\n]+/i',
                '/(X-Amz-(?:Credential|Signature|Security-Token)=)[^&\s"\']+/i',
                '/(Signature=)[0-9a-f]{16,}/i',
            ],
            ['[REDACTED]', '$1[REDACTED]', '$1[REDACTED]', '$1[REDACTED]'],
            $message,
        );
    }

    /**
     * The secret did not exist for the put. Create it; when a concurrent create
     * won in between, add the version to that secret instead.
     */
    private function createOrPut(SecretsManagerClient $client, string $name, #[SensitiveParameter] string $encoded): void
    {
        try {
            $client->createSecret(['Name' => $name, 'SecretString' => $encoded]);
        } catch (Throwable $e) {
            if (!$e instanceof AwsException || $e->getAwsErrorCode() !== 'ResourceExistsException') {
                throw $this->translate($e, 'write');
            }

            try {
                $this->put($client, $name, $encoded);
            } catch (Throwable $second) {
                throw $this->translate($second, 'write');
            }
        }
    }

    private function put(SecretsManagerClient $client, string $name, #[SensitiveParameter] string $encoded): void
    {
        $client->putSecretValue(['SecretId' => $name, 'SecretString' => $encoded]);
    }

    private function isNotFound(Throwable $e): bool
    {
        return $e instanceof AwsException && $e->getAwsErrorCode() === 'ResourceNotFoundException';
    }

    private function endpoint(): AwsSecretsEndpoint
    {
        return AwsSecretsEndpoint::fromConfig($this->configuration->getAwsConfig());
    }

    private function client(): SecretsManagerClient
    {
        return $this->client ??= $this->clients->create($this->endpoint());
    }

    /**
     * Reduce whatever failed to an exception that holds no credential, no
     * response body and no request. The SDK exception is not chained: it keeps
     * the command, whose parameters include the encrypted envelope.
     */
    private function translate(Throwable $e, string $operation): AwsSecretsManagerException
    {
        if ($e instanceof AwsSecretsManagerException) {
            return $e;
        }

        if ($e instanceof AwsException && $e->getStatusCode() !== null) {
            return AwsSecretsManagerException::requestRejected($operation, $e->getStatusCode(), $this->safeCode($e->getAwsErrorCode()));
        }

        $previous = $e->getPrevious();
        $cause    = $previous ?? $e;

        return AwsSecretsManagerException::transportFailure(
            $operation,
            self::redact($cause->getMessage()) . sprintf(' (caused by %s)', $cause::class),
        );
    }

    /**
     * An AWS error code is a short identifier; anything else is dropped.
     */
    private function safeCode(?string $code): string
    {
        return $code !== null && preg_match('/^[A-Za-z0-9.]{1,64}$/D', $code) === 1 ? $code : '';
    }
}
