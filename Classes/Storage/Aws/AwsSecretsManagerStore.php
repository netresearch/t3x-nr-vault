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
use Closure;
use JsonException;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\AwsSecretsManagerException;
use Psr\Log\LoggerInterface;
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
 * name; with it no version survives. AWS removes a force-deleted name
 * asynchronously, so a create that meets it still being deleted
 * (`InvalidRequestException`, assumed) is retried with a short back-off, at
 * most 3.75 s.
 *
 * Nothing the service says is surfaced: the exception carries the operation, the
 * HTTP status and the AWS error code, not the SDK exception that holds the
 * signed request and the command parameters.
 */
final class AwsSecretsManagerStore implements AwsSecretStoreInterface, AwsVersionedSecretStoreInterface
{
    private const VERSION_READ_ATTEMPTS = 3;

    private const VERSION_READ_DELAY_MICROSECONDS = 150_000;

    /**
     * Back-off between CreateSecret attempts while a force-deleted name is
     * still being deleted (≤ 3.75 s over five attempts).
     */
    private const CREATE_RETRY_DELAYS_MICROSECONDS = [250_000, 500_000, 1_000_000, 2_000_000];

    private ?SecretsManagerClient $client = null;

    /** @var Closure(int): void */
    private readonly Closure $sleep;

    /**
     * @param (Closure(int): void)|null $sleep Waits the given microseconds; injectable for tests
     */
    public function __construct(
        private readonly ExtensionConfigurationInterface $configuration,
        private readonly AwsClientFactory $clients,
        ?Closure $sleep = null,
        private readonly ?LoggerInterface $logger = null,
    ) {
        $this->sleep = $sleep ?? static function (int $microseconds): void {
            usleep($microseconds);
        };
    }

    public function isSdkInstalled(): bool
    {
        return $this->clients->isInstalled();
    }

    public function read(string $identifier): ?array
    {
        return $this->fetch($identifier)[0] ?? null;
    }

    public function readWithVersion(string $identifier): ?array
    {
        $fetched = $this->fetch($identifier);

        if ($fetched === null) {
            return null;
        }

        // Without a version id the caller takes a write back by
        // read-then-write, as before #567; the read itself is fine.
        $version = $fetched[1]['VersionId'] ?? null;

        return ['data' => $fetched[0], 'versionId' => is_string($version) && $version !== '' ? $version : null];
    }

    public function create(string $identifier, #[SensitiveParameter] array $data): string
    {
        $name    = $this->endpoint()->name($identifier);
        $client  = $this->client();
        $encoded = $this->encode($data, 'create');

        // AWS deletes a force-deleted secret asynchronously and asks callers
        // that create the same name right after to "use appropriate back off
        // and retry logic" (API_DeleteSecret). Which error a create returns
        // inside that window is not documented; InvalidRequestException ("The
        // secret is scheduled for deletion") is assumed. Only the create is
        // retried: a put is never re-sent, so a secret another writer creates
        // in the meantime is never written into.
        $delays  = self::CREATE_RETRY_DELAYS_MICROSECONDS;
        $retries = 0;
        while (true) {
            try {
                $result = $client->createSecret(['Name' => $name, 'SecretString' => $encoded]);

                if ($retries > 0) {
                    // The production signal for the assumption above (#539).
                    $this->logger?->notice(
                        'nr-vault: AWS Secrets Manager CreateSecret succeeded after {retries} InvalidRequestException answer(s); AWS was still deleting the name.',
                        ['retries' => $retries],
                    );
                }

                break;
            } catch (Throwable $e) {
                if ($e instanceof AwsException && $e->getAwsErrorCode() === 'ResourceExistsException') {
                    throw AwsSecretsManagerException::nameExists($identifier);
                }

                if ($delays === [] || !$e instanceof AwsException || $e->getAwsErrorCode() !== 'InvalidRequestException') {
                    throw $this->translate($e, 'create');
                }

                ($this->sleep)(array_shift($delays));
                ++$retries;
            }
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

    public function restoreToVersionIfCurrent(string $identifier, #[SensitiveParameter] array $data, string $versionId, string $previousVersionId): AwsRestoreOutcome
    {
        // The stage move is conditional (API_UpdateSecretVersionStage): it
        // fails when AWSCURRENT is attached to any version but ours, so a
        // writer that landed since keeps its value. No new version is written:
        // the previous one becomes current again and ours becomes AWSPREVIOUS.
        // The SDK already retries a throttled or failed request once.
        try {
            $this->moveBack($identifier, $versionId, $previousVersionId);

            return AwsRestoreOutcome::Applied;
        } catch (Throwable $e) {
            if ($this->isAccessDenied($e)) {
                // Without the permission, the read-then-write of
                // restoreIfCurrent() is the rollback, as before #567.
                $this->warnDenied($identifier, $e);

                return $this->restoreIfCurrent($identifier, $data, $versionId) ? AwsRestoreOutcome::Applied : AwsRestoreOutcome::OtherWriter;
            }

            return $this->outcomeAfterFailedMove($identifier, $versionId, $previousVersionId);
        }
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
     * The decoded document of AWSCURRENT and the response it came from, or
     * null when the secret does not exist.
     *
     * @return array{0: array<string, mixed>, 1: Result<string, mixed>}|null
     */
    private function fetch(string $identifier): ?array
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
        return [$decoded, $result];
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

    private function moveBack(string $identifier, string $versionId, string $previousVersionId): void
    {
        $this->client()->updateSecretVersionStage([
            'SecretId'            => $this->endpoint()->name($identifier),
            'VersionStage'        => 'AWSCURRENT',
            'MoveToVersionId'     => $previousVersionId,
            'RemoveFromVersionId' => $versionId,
        ]);
    }

    /**
     * What a failed move leaves, read from AWSCURRENT rather than from the
     * error code, which AWS does not document for a mismatch. Nothing is
     * written. AWSCURRENT is read until it shows our version or the version
     * moved back to, at most VERSION_READ_ATTEMPTS times.
     *
     * - Our version: the move is called once more; it is conditional, so that
     *   is safe. Only a move call that succeeds counts as applied.
     * - The version moved back to: unconfirmed. An applied move whose answer
     *   was lost shows it, and so does a read that lags behind our own write.
     * - Anything else: another writer won, or the secret is gone.
     */
    private function outcomeAfterFailedMove(string $identifier, string $versionId, string $previousVersionId): AwsRestoreOutcome
    {
        $current = null;
        for ($attempt = 1; $attempt <= self::VERSION_READ_ATTEMPTS && $current !== $versionId && $current !== $previousVersionId; ++$attempt) {
            if ($attempt > 1) {
                ($this->sleep)(self::VERSION_READ_DELAY_MICROSECONDS);
            }

            $current = $this->currentVersion($identifier);
        }

        return match ($current) {
            $versionId         => $this->moveAgain($identifier, $versionId, $previousVersionId),
            $previousVersionId => AwsRestoreOutcome::Unconfirmed,
            default            => AwsRestoreOutcome::OtherWriter,
        };
    }

    private function moveAgain(string $identifier, string $versionId, string $previousVersionId): AwsRestoreOutcome
    {
        try {
            $this->moveBack($identifier, $versionId, $previousVersionId);

            return AwsRestoreOutcome::Applied;
        } catch (Throwable) {
            return AwsRestoreOutcome::NotApplied;
        }
    }

    /**
     * AccessDeniedException, or a 403 without a readable error code (Moto
     * answers a denied call with an XML 403).
     */
    private function isAccessDenied(Throwable $e): bool
    {
        if (!$e instanceof AwsException) {
            return false;
        }

        $code = $this->safeCode($e->getAwsErrorCode());

        return $code === 'AccessDeniedException' || ($code === '' && $e->getStatusCode() === 403);
    }

    /**
     * Only AccessDeniedException names the missing permission; a bare 403 is
     * reported with its status, since nothing says what was refused.
     */
    private function warnDenied(string $identifier, Throwable $failure): void
    {
        $code    = $this->failureCode($failure);
        $message = $code === 'AccessDeniedException'
            ? 'nr-vault: AWS Secrets Manager refused UpdateSecretVersionStage ({code}); grant secretsmanager:UpdateSecretVersionStage. The rollback fell back to read-then-write, which overwrites a write that lands in between.'
            : 'nr-vault: AWS Secrets Manager answered UpdateSecretVersionStage with {code} and no error code. The rollback fell back to read-then-write, which overwrites a write that lands in between.';

        $this->logger?->warning($message, ['secret' => $identifier, 'code' => $code]);
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
            if ($this->currentVersion($identifier) === $versionId) {
                return true;
            }

            if ($attempt < self::VERSION_READ_ATTEMPTS) {
                ($this->sleep)(self::VERSION_READ_DELAY_MICROSECONDS);
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
     * The AWS error code of a failure for a log line, or the HTTP status when
     * the response carried no code that can be read.
     */
    private function failureCode(Throwable $e): string
    {
        if (!$e instanceof AwsException) {
            return 'transport failure';
        }

        $code = $this->safeCode($e->getAwsErrorCode());
        if ($code !== '') {
            return $code;
        }

        return $e->getStatusCode() !== null ? 'HTTP ' . $e->getStatusCode() : 'no error code';
    }

    /**
     * An AWS error code is a short identifier; anything else is dropped.
     */
    private function safeCode(?string $code): string
    {
        return $code !== null && preg_match('/^[A-Za-z0-9.]{1,64}$/D', $code) === 1 ? $code : '';
    }
}
