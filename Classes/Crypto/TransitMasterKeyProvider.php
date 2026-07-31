<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use JsonException;
use Netresearch\NrVault\Configuration\Dto\TransitConfig;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\MasterKeyException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use SensitiveParameter;

/**
 * HashiCorp Vault Transit master-key provider.
 *
 * Key custody model — the master key is generated once, wrapped by Vault's
 * transit secrets engine, and only the WRAPPED ciphertext (`vault:v1:…`) is
 * stored on the local filesystem. Unwrapping requires a live Vault call, so the
 * key material never sits at rest next to the database:
 *
 *   generateMasterKey() → random_bytes(32)
 *   storeMasterKey()    → POST /v1/{mount}/encrypt/{key}  → local wrapped blob
 *   getMasterKey()      → local wrapped blob → POST /v1/{mount}/decrypt/{key}
 *
 * What this buys, honestly:
 *  - key custody and rotation move into Vault (`vault write -f
 *    transit/keys/{key}/rotate` re-wraps future ciphertexts without touching
 *    any secret in the TYPO3 database);
 *  - every unwrap is centrally audited and revocable — pulling the token or the
 *    policy locks the vault out immediately, with no key file to recover;
 *  - a stolen database plus a stolen webroot is useless without Vault access.
 *
 * What it does NOT buy: a fully compromised PHP process can still call
 * `decrypt` with the token it legitimately holds and obtain the master key.
 * Transit protects custody, rotation and auditability — not a live attacker
 * already inside the request.
 *
 * Auth: token only (`hashicorp.authMethod = token`), read from the configured
 * environment variable in preference to the stored setting. `approle` and
 * `kubernetes` are rejected rather than silently downgraded; see the class-level
 * note in Documentation/Configuration/Index.rst for the follow-up.
 *
 * Allowed in the hardened security profile: it is exactly the kind of external
 * KMS custody that profile asks for.
 *
 * Request-lifetime caching (one decrypt per request) is inherited from
 * {@see AbstractMasterKeyProvider}; see ADR-020.
 */
final class TransitMasterKeyProvider extends AbstractMasterKeyProvider
{
    private const KEY_LENGTH = 32; // 256 bits

    private const OPERATION_ENCRYPT = 'encrypt';

    private const OPERATION_DECRYPT = 'decrypt';

    /**
     * Characters permitted in a transit mount segment or key name before they
     * are interpolated into a Vault API path. Validated by explode + preg over
     * single segments (no nested quantifiers) so a mount like
     * `platform/transit` stays usable while `../` and control characters cannot
     * reach the URL.
     */
    private const PATH_SEGMENT_PATTERN = '/^[A-Za-z0-9._-]+$/';

    public function __construct(
        private readonly ExtensionConfigurationInterface $configuration,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {}

    public function __destruct()
    {
        // Wipe this provider's request-lifetime cache slot; the inherited cache
        // is keyed by class so no other provider is affected. See ADR-020.
        self::clearCachedKey();
    }

    public function getIdentifier(): string
    {
        return 'transit';
    }

    /**
     * Configuration completeness + local wrapped blob presence.
     *
     * Deliberately performs NO network call: availability is consulted on hot
     * paths, and a Vault outage must not turn into a per-request HTTP timeout.
     * A live probe is `getMasterKey()` itself (that is what
     * VaultHealthService does).
     */
    public function isAvailable(): bool
    {
        $config = $this->configuration->getTransitConfig();

        if (!$config->isComplete() || !$config->usesTokenAuth()) {
            return false;
        }

        try {
            $this->assertKeyReferencesAreSafe($config);
        } catch (MasterKeyException) {
            return false;
        }

        $vaultToken = $this->findToken($config);
        if ($vaultToken === null) {
            return false;
        }
        $this->wipeTokenCopy($vaultToken, $config);

        return file_exists($config->wrappedKeyPath) && is_readable($config->wrappedKeyPath);
    }

    /**
     * Wrap the key with Vault Transit and persist ONLY the ciphertext.
     *
     * Used by `vault:init` and `vault:rotate-master-key`. The plaintext never
     * touches the filesystem: it is base64-encoded for the API call, sent, and
     * both copies are zeroed before this method returns.
     */
    public function storeMasterKey(#[SensitiveParameter] string $key): void
    {
        if (\strlen($key) !== self::KEY_LENGTH) {
            throw MasterKeyException::invalidLength(self::KEY_LENGTH, \strlen($key));
        }

        $config = $this->requireUsableConfig();

        $encoded = base64_encode($key);

        try {
            $data = $this->callTransit($config, self::OPERATION_ENCRYPT, ['plaintext' => $encoded]);
        } finally {
            sodium_memzero($encoded);
        }

        $ciphertext = $data['ciphertext'] ?? null;
        if (!\is_string($ciphertext) || !str_starts_with($ciphertext, 'vault:')) {
            throw MasterKeyException::transitMalformedResponse(
                self::OPERATION_ENCRYPT,
                'missing or malformed data.ciphertext',
            );
        }

        $this->writeWrappedKey($config->wrappedKeyPath, $ciphertext);
    }

    public function generateMasterKey(): string
    {
        return random_bytes(self::KEY_LENGTH);
    }

    protected function loadRawKey(): string
    {
        $config = $this->requireUsableConfig();
        $wrapped = $this->readWrappedKey($config->wrappedKeyPath);

        $data = $this->callTransit($config, self::OPERATION_DECRYPT, ['ciphertext' => $wrapped]);

        $encoded = $data['plaintext'] ?? null;
        if (!\is_string($encoded) || $encoded === '') {
            throw MasterKeyException::transitMalformedResponse(
                self::OPERATION_DECRYPT,
                'missing or empty data.plaintext',
            );
        }

        $rawKey = base64_decode($encoded, true);
        sodium_memzero($encoded);

        if ($rawKey === false) {
            throw MasterKeyException::transitMalformedResponse(
                self::OPERATION_DECRYPT,
                'data.plaintext is not valid base64',
            );
        }

        if (\strlen($rawKey) !== self::KEY_LENGTH) {
            $length = \strlen($rawKey);
            sodium_memzero($rawKey);

            throw MasterKeyException::invalidLength(self::KEY_LENGTH, $length);
        }

        return $rawKey;
    }

    /**
     * Resolve the configuration and refuse to proceed on anything that would
     * make the request ambiguous or unauthenticated (fail closed).
     *
     * @throws MasterKeyException
     */
    private function requireUsableConfig(): TransitConfig
    {
        $config = $this->configuration->getTransitConfig();

        if ($config->address === '') {
            throw MasterKeyException::transitNotConfigured('hashicorp.address is empty');
        }
        if ($config->wrappedKeyPath === '') {
            throw MasterKeyException::transitNotConfigured('hashicorp.transitWrappedKeyPath is empty');
        }
        if (!$config->usesTokenAuth()) {
            throw MasterKeyException::transitUnsupportedAuthMethod($config->authMethod);
        }

        $this->assertKeyReferencesAreSafe($config);

        return $config;
    }

    /**
     * @throws MasterKeyException
     */
    private function assertKeyReferencesAreSafe(TransitConfig $config): void
    {
        foreach (explode('/', $config->mount) as $segment) {
            if (!$this->isSafePathSegment($segment)) {
                throw MasterKeyException::transitInvalidKeyReference('mount path');
            }
        }

        if (!$this->isSafePathSegment($config->keyName)) {
            throw MasterKeyException::transitInvalidKeyReference('key name');
        }
    }

    /**
     * A segment must consist of the allowed characters AND carry at least one
     * character that is not a dot: the dot itself is legal inside a Vault mount
     * or key name, but `.` and `..` are traversal segments and must never reach
     * the API path.
     */
    private function isSafePathSegment(string $segment): bool
    {
        return preg_match(self::PATH_SEGMENT_PATTERN, $segment) === 1
            && trim($segment, '.') !== '';
    }

    /**
     * Perform a transit operation and return the response `data` array.
     *
     * @param array<string, string> $payload
     *
     * @throws MasterKeyException
     *
     * @return array<array-key, mixed>
     */
    private function callTransit(TransitConfig $config, string $operation, array $payload): array
    {
        $vaultToken = $this->findToken($config);
        if ($vaultToken === null) {
            throw MasterKeyException::transitTokenMissing($config->tokenEnvVar);
        }

        try {
            $body = json_encode($payload, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            $this->wipeTokenCopy($vaultToken, $config);

            throw MasterKeyException::transitMalformedResponse($operation, 'request payload not encodable: ' . $e->getMessage());
        }

        $request = $this->requestFactory
            ->createRequest('POST', $config->endpointFor($operation))
            ->withHeader('X-Vault-Token', $vaultToken)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream($body));

        // Best effort: our copy is zeroed immediately. The PSR-7 request keeps
        // its own immutable copy of the header value until it is collected —
        // there is no PSR-7 API to scrub that.
        $this->wipeTokenCopy($vaultToken, $config);

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw MasterKeyException::transitTransportFailure(
                $operation,
                $this->redactTokens($e->getMessage()) . \sprintf(' (caused by %s)', $e::class),
            );
        }

        return $this->decodeTransitData($response, $operation);
    }

    /**
     * @throws MasterKeyException
     *
     * @return array<array-key, mixed> the Vault response `data` object; callers
     *                                 read individual fields and type-check them
     */
    private function decodeTransitData(ResponseInterface $response, string $operation): array
    {
        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            // The body is NOT surfaced: Vault echoes the submitted ciphertext on
            // some error paths, and error text may carry cluster internals.
            throw MasterKeyException::transitRequestRejected($operation, $status);
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode((string) $response->getBody(), true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw MasterKeyException::transitMalformedResponse($operation, 'response body is not valid JSON');
        }

        if (!\is_array($decoded)) {
            throw MasterKeyException::transitMalformedResponse($operation, 'response body is not a JSON object');
        }

        $data = $decoded['data'] ?? null;
        if (!\is_array($data)) {
            throw MasterKeyException::transitMalformedResponse($operation, 'response has no "data" object');
        }

        return $data;
    }

    /**
     * Vault token, environment variable first.
     *
     * The env var is preferred over `hashicorp.token` so production deployments
     * keep the credential out of the extension configuration (which is readable
     * in the Install Tool and dumped into configuration exports).
     *
     * Returns null instead of throwing so `isAvailable()` can probe without
     * producing an exception. Callers own the returned copy and should
     * `sodium_memzero()` it.
     */
    private function findToken(TransitConfig $config): ?string
    {
        $fromEnv = getenv($config->tokenEnvVar);
        if (\is_string($fromEnv) && $fromEnv !== '') {
            return $fromEnv;
        }

        return $config->token !== '' ? $config->token : null;
    }

    /**
     * Zero a token copy — but only one we actually own.
     *
     * A token that came from `hashicorp.token` shares its string buffer with the
     * ExtensionConfiguration singleton (PHP copy-on-write), and
     * `sodium_memzero()` wipes the buffer in place: zeroing it would NUL out the
     * stored configuration, so every later lookup in the same request would send
     * a token of NUL bytes and Vault would answer 403. Env-derived tokens are
     * freshly allocated by `getenv()` and are safe to wipe.
     *
     * hash_equals() keeps the comparison constant-time, per the repo-wide rule
     * for touching secret values.
     *
     * The parameter is nullable because `sodium_memzero()` nulls the variable it
     * wipes; callers must not read $vaultToken afterwards.
     */
    private function wipeTokenCopy(?string &$vaultToken, TransitConfig $config): void
    {
        if ($vaultToken === null) {
            return;
        }

        if (!hash_equals($config->token, $vaultToken)) {
            sodium_memzero($vaultToken);
        }
    }

    /**
     * @throws MasterKeyException
     */
    private function readWrappedKey(string $path): string
    {
        if (!file_exists($path)) {
            throw MasterKeyException::notFound($path);
        }
        if (!is_readable($path)) {
            throw MasterKeyException::notFound($path . ' (not readable)');
        }

        $raw = file_get_contents($path);
        if ($raw === false) {
            throw MasterKeyException::notFound($path);
        }

        $wrapped = trim($raw);
        if (!str_starts_with($wrapped, 'vault:')) {
            throw MasterKeyException::transitNotConfigured(\sprintf(
                'the file at %s does not contain a Vault Transit ciphertext (expected a "vault:v…" prefix)',
                $path,
            ));
        }

        return $wrapped;
    }

    /**
     * Persist the wrapped key atomically with 0600 permissions.
     *
     * Same umask-race defence as FileMasterKeyProvider::storeMasterKey (tighten
     * umask so the file is never briefly world-readable), plus a
     * write-to-temp + rename so a crash mid-write cannot leave a truncated
     * blob — a truncated wrapped key is an unrecoverable vault, not just a
     * failed write. 0600 rather than 0400 because rotation must be able to
     * overwrite it.
     *
     * @throws MasterKeyException
     */
    private function writeWrappedKey(string $path, string $ciphertext): void
    {
        $dir = \dirname($path);
        if (!is_dir($dir) && (!mkdir($dir, 0o700, true) && !is_dir($dir))) {
            throw MasterKeyException::cannotStore("Cannot create directory: {$dir}");
        }

        $temporaryPath = $path . '.' . bin2hex(random_bytes(6)) . '.tmp';
        $previousUmask = umask(0o077);

        try {
            if (file_put_contents($temporaryPath, $ciphertext) === false) {
                throw MasterKeyException::cannotStore("Cannot write to: {$temporaryPath}");
            }

            chmod($temporaryPath, 0o600);

            if (!rename($temporaryPath, $path)) {
                throw MasterKeyException::cannotStore("Cannot move wrapped key into place: {$path}");
            }
        } catch (MasterKeyException $e) {
            if (file_exists($temporaryPath)) {
                // nosemgrep: php.lang.security.unlink-use.unlink-use - $temporaryPath is a code-generated temp path for the atomic wrapped-key write, never user input; this only cleans up our own leftover on failure.
                unlink($temporaryPath);
            }

            throw $e;
        } finally {
            umask($previousUmask);
        }

        chmod($path, 0o600);
    }

    /**
     * Strip anything token-shaped from a transport error message before it
     * reaches an exception or log line.
     *
     * Guzzle's `RequestException::getMessage()` normally carries method, URL and
     * response excerpt — not request headers — but verbose formatting and
     * middleware can surface the `X-Vault-Token` header, so redact defensively.
     * All patterns are delimiter-anchored character classes (no `.*?`, no
     * nested quantifiers) and therefore linear.
     */
    private function redactTokens(string $message): string
    {
        return (string) preg_replace(
            [
                '/(X-Vault-Token:\s*)\S+/i',
                // Vault service/batch/recovery tokens and the legacy `s.` form.
                '/\bhv[sbr]\.[A-Za-z0-9._-]+/',
                '/\bs\.[A-Za-z0-9]{20,}/',
            ],
            ['$1[REDACTED]', '[REDACTED]', '[REDACTED]'],
            $message,
        );
    }
}
