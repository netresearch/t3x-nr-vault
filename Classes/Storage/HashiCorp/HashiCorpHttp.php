<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage\HashiCorp;

use JsonException;
use Netresearch\NrVault\Exception\HashiCorpException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use SensitiveParameter;

use function is_array;
use function sprintf;

/**
 * The one place the HashiCorp adapter talks to Vault.
 *
 * The injected client is the one `SecureHttpClientFactory` builds, so every
 * request passes the SSRF range check and the DNS pin, never follows a
 * redirect and never logs. A private or loopback Vault address is therefore
 * refused unless the operator lists it literally in
 * `$GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts']`.
 *
 * Nothing the response body says is surfaced: Vault echoes submitted data on
 * some error paths, and its error text can name cluster internals.
 */
final readonly class HashiCorpHttp
{
    public function __construct(
        private ClientInterface $httpClient,
        private RequestFactoryInterface $requestFactory,
        private StreamFactoryInterface $streamFactory,
    ) {}

    /**
     * @param array<string, mixed>|null $body
     *
     * @return array{status: int, json: array<array-key, mixed>}
     *
     * @throws HashiCorpException On a transport failure or an undecodable 2xx body
     */
    public function request(
        string $method,
        string $url,
        #[SensitiveParameter]
        ?string $token,
        #[SensitiveParameter]
        ?array $body,
        string $operation,
    ): array {
        $request = $this->requestFactory
            ->createRequest($method, $url)
            ->withHeader('Accept', 'application/json');

        if ($token !== null) {
            $request = $request->withHeader('X-Vault-Token', $token);
        }

        if ($body !== null) {
            try {
                $encoded = json_encode($body, JSON_THROW_ON_ERROR);
            } catch (JsonException) {
                throw HashiCorpException::malformedResponse($operation, 'request payload is not encodable');
            }

            $request = $request
                ->withHeader('Content-Type', 'application/json')
                ->withBody($this->streamFactory->createStream($encoded));
        }

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw HashiCorpException::transportFailure(
                $operation,
                self::redact($e->getMessage()) . sprintf(' (caused by %s)', $e::class),
            );
        }

        $status = $response->getStatusCode();
        $raw    = (string) $response->getBody();
        if ($status < 200 || $status >= 300 || $raw === '') {
            return ['status' => $status, 'json' => []];
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw HashiCorpException::malformedResponse($operation, 'response body is not valid JSON');
        }

        if (!is_array($decoded)) {
            throw HashiCorpException::malformedResponse($operation, 'response body is not a JSON object');
        }

        return ['status' => $status, 'json' => $decoded];
    }

    /**
     * Strip anything token-shaped from a transport error message.
     *
     * Delimiter-anchored character classes only, so every pattern is linear.
     */
    public static function redact(string $message): string
    {
        return (string) preg_replace(
            [
                '/(X-Vault-Token:\s*)\S+/i',
                '/\bhv[sbr]\.[A-Za-z0-9._-]+/',
                '/\bs\.[A-Za-z0-9]{20,}/',
                '/("(?:secret_id|jwt|client_token|token)"\s*:\s*")[^"]*/i',
            ],
            ['$1[REDACTED]', '[REDACTED]', '[REDACTED]', '$1[REDACTED]'],
            $message,
        );
    }
}
