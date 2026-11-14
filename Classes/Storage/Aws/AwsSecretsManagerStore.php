<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage\Aws;

use Aws\Exception\AwsException;
use Aws\Result;
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
    private const VERSION_READ_ATTEMPTS = 3;

    private const VERSION_READ_DELAY_MICROSECONDS = 150_000;

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

    public function create(string $identifier, #[SensitiveParameter] array $data): string
    {
        $name    = $this->endpoint()->name($identifier);
        $client  = $this->client();
        $encoded = $this->encode($data, 'create');

        try {
            $result = $client->createSecret(['Name' => $name, 'SecretString' => $encoded]);
        } catch (Throwable $e) {
            if ($e instanceof AwsException && $e->getAwsErrorCode() === 'ResourceExistsException') {
                throw AwsSecretsManagerException::nameExists($identifier);
            }

            throw $this->translate($e, 'create');
        }

        return $this->versionOf($result, 'create');
    }

    public function write(string $identifier, #[SensitiveParameter] array $data): string
    {
        $name    = $this->endpoint()->name($identifier);
        $client  = $this->client();
        $encoded = $this->encode($data, 'write');

        try {
            return $this->put($client, $name, $encoded);
        } catch (Throwable $e) {
            if (!$this->isNotFound($e)) {
                throw $this->translate($e, 'write');
            }
        }

        return $this->createOrPut($client, $identifier, $name, $encoded);
    }

    public function restoreIfCurrent(string $identifier, #[SensitiveParameter] array $data, string $versionId): bool
    {
        if (!$this->isCurrent($identifier, $versionId)) {
            return false;
        }

        $this->write($identifier, $data);

        return true;
    }

    public function destroyIfCurrent(string $identifier, string $versionId): bool
    {
        if (!$this->isCurrent($identifier, $versionId)) {
            return false;
        }

        $this->destroy($identifier);

        return true;
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
     * The secret did not exist for the put. Create it. When a concurrent create
     * won in between, the secret belongs to that writer: the conflict is raised,
     * nothing is written into it.
     */
    private function createOrPut(SecretsManagerClient $client, string $identifier, string $name, #[SensitiveParameter] string $encoded): string
    {
        try {
            return $this->versionOf($client->createSecret(['Name' => $name, 'SecretString' => $encoded]), 'write');
        } catch (Throwable $e) {
            if ($e instanceof AwsException && $e->getAwsErrorCode() === 'ResourceExistsException') {
                throw AwsSecretsManagerException::nameExists($identifier);
            }

            throw $this->translate($e, 'write');
        }
    }

    private function put(SecretsManagerClient $client, string $name, #[SensitiveParameter] string $encoded): string
    {
        return $this->versionOf($client->putSecretValue(['SecretId' => $name, 'SecretString' => $encoded]), 'write');
    }

    /**
     * Whether AWSCURRENT is the given version. A read that has not caught up
     * with our own write shows an older version for a moment; a few short
     * retries tell that apart from a real concurrent write, which keeps showing
     * another version.
     */
    private function isCurrent(string $identifier, string $versionId): bool
    {
        for ($attempt = 1; $attempt <= self::VERSION_READ_ATTEMPTS; ++$attempt) {
            // Not found is retried too: a read that has not caught up with the
            // create looks like a missing secret for a moment.
            $current = $this->currentVersion($identifier);
            if ($current === $versionId) {
                return true;
            }

            if ($attempt < self::VERSION_READ_ATTEMPTS) {
                usleep(self::VERSION_READ_DELAY_MICROSECONDS);
            }
        }

        return false;
    }

    /**
     * The version id of AWSCURRENT, or null when the secret does not exist.
     * GetSecretValue is read so the policy needs no further action. Only the id
     * is used: nothing about the stored document is compared.
     */
    private function currentVersion(string $identifier): ?string
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

        return $this->versionOf($result, 'read');
    }

    /**
     * @param array<string, mixed> $data
     */
    private function encode(#[SensitiveParameter] array $data, string $operation): string
    {
        try {
            return json_encode($data, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw AwsSecretsManagerException::malformedResponse($operation, 'payload is not encodable');
        }
    }

    /**
     * @param Result<string, mixed> $result
     */
    private function versionOf(Result $result, string $operation): string
    {
        $version = $result['VersionId'] ?? null;
        if (!is_string($version) || $version === '') {
            throw AwsSecretsManagerException::malformedResponse($operation, 'response has no VersionId');
        }

        return $version;
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
