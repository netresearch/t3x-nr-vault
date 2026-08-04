<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Http;

use JsonException;
use Netresearch\NrVault\Exception\VaultException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/**
 * Wrapper around PSR-7 ResponseInterface with convenience methods.
 *
 * Provides a developer-friendly API for handling HTTP responses
 * while maintaining full PSR-7 compatibility.
 */
final readonly class VaultHttpResponse
{
    public function __construct(
        private ResponseInterface $response,
    ) {}

    /**
     * Get the underlying PSR-7 response.
     */
    public function getPsrResponse(): ResponseInterface
    {
        return $this->response;
    }

    /**
     * Get the HTTP status code.
     */
    public function getStatusCode(): int
    {
        return $this->response->getStatusCode();
    }

    /**
     * Get the reason phrase (e.g., "OK", "Not Found").
     */
    public function getReasonPhrase(): string
    {
        return $this->response->getReasonPhrase();
    }

    /**
     * Check if the response indicates success (2xx status code).
     */
    public function isSuccessful(): bool
    {
        $code = $this->getStatusCode();

        return $code >= 200 && $code < 300;
    }

    /**
     * Check if the response indicates a client error (4xx status code).
     */
    public function isClientError(): bool
    {
        $code = $this->getStatusCode();

        return $code >= 400 && $code < 500;
    }

    /**
     * Check if the response indicates a server error (5xx status code).
     */
    public function isServerError(): bool
    {
        $code = $this->getStatusCode();

        return $code >= 500 && $code < 600;
    }

    /**
     * Check if the response indicates any error (4xx or 5xx).
     */
    public function isError(): bool
    {
        if ($this->isClientError()) {
            return true;
        }

        return $this->isServerError();
    }

    /**
     * Check if the response is a redirect (3xx status code).
     */
    public function isRedirect(): bool
    {
        $code = $this->getStatusCode();

        return $code >= 300 && $code < 400;
    }

    /**
     * Get the response body as a string.
     */
    public function getBody(): string
    {
        return (string) $this->response->getBody();
    }

    /**
     * Get the response body stream.
     */
    public function getBodyStream(): StreamInterface
    {
        return $this->response->getBody();
    }

    /**
     * Decode JSON response body.
     *
     * @param bool $associative When true, returns associative arrays instead of objects
     *
     * @throws JsonException If JSON is invalid
     *
     * @return array<string, mixed>|object|null
     */
    public function json(bool $associative = true): array|object|null
    {
        $body = $this->getBody();

        if ($body === '') {
            return $associative ? [] : null;
        }

        $decoded = json_decode($body, $associative, 512, JSON_THROW_ON_ERROR);

        if ($associative) {
            if (!\is_array($decoded)) {
                return [];
            }

            /** @var array<string, mixed> $decoded */
            return $decoded;
        }

        return \is_object($decoded) ? $decoded : null;
    }

    /**
     * Get a specific value from JSON response using dot notation.
     *
     * @param string $key Key in dot notation (e.g., "data.user.name")
     * @param mixed $default Default value if key not found
     */
    public function jsonGet(string $key, mixed $default = null): mixed
    {
        try {
            $data = $this->json(true);
        } catch (JsonException) {
            return $default;
        }

        if (!\is_array($data)) {
            return $default;
        }

        $keys = explode('.', $key);
        $value = $data;

        foreach ($keys as $segment) {
            if (!\is_array($value) || !\array_key_exists($segment, $value)) {
                return $default;
            }

            $value = $value[$segment];
        }

        return $value;
    }

    /**
     * Get a response header value.
     *
     * @param string $name Header name (case-insensitive)
     *
     * @return string|null First header value or null if not present
     */
    public function getHeader(string $name): ?string
    {
        $values = $this->response->getHeader($name);

        return $values[0] ?? null;
    }

    /**
     * Get all values for a response header.
     *
     * @param string $name Header name (case-insensitive)
     *
     * @return array<string> Header values
     */
    public function getHeaderValues(string $name): array
    {
        return $this->response->getHeader($name);
    }

    /**
     * Get all response headers.
     *
     * @return array<string, array<string>> Headers indexed by name
     */
    public function getHeaders(): array
    {
        /** @phpstan-ignore return.type */
        return $this->response->getHeaders();
    }

    /**
     * Check if a header exists.
     */
    public function hasHeader(string $name): bool
    {
        return $this->response->hasHeader($name);
    }

    /**
     * Get the Content-Type header value.
     */
    public function getContentType(): ?string
    {
        $contentType = $this->getHeader('Content-Type');

        if ($contentType === null) {
            return null;
        }

        // Strip parameters like charset
        $parts = explode(';', $contentType);

        return trim($parts[0]);
    }

    /**
     * Check if response is JSON content type.
     */
    public function isJson(): bool
    {
        $contentType = $this->getContentType();

        return $contentType !== null && (
            $contentType === 'application/json'
            || str_ends_with($contentType, '+json')
        );
    }

    /**
     * Get the Content-Length header value.
     */
    public function getContentLength(): ?int
    {
        $length = $this->getHeader('Content-Length');

        return $length !== null ? (int) $length : null;
    }

    /**
     * Throw an exception if the response indicates an error.
     *
     * @throws VaultException
     */
    public function throwIfError(): self
    {
        if ($this->isError()) {
            throw new VaultException(
                \sprintf(
                    'HTTP request failed with status %d: %s',
                    $this->getStatusCode(),
                    $this->getReasonPhrase(),
                ),
                9782525747,
            );
        }

        return $this;
    }

    /**
     * Create from a PSR-7 response.
     */
    public static function fromPsrResponse(ResponseInterface $response): self
    {
        return new self($response);
    }
}
