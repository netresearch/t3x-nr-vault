<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Http;

use InvalidArgumentException;
use Netresearch\NrVault\Utility\IdentifierValidator;

/**
 * How a client injects its primary secret, together with exactly the options
 * that placement reads (ADR-056).
 *
 * Each named constructor accepts only its own placement's options, so an option
 * that the placement would ignore, or a misspelled option key, cannot be
 * expressed. Values are validated here, when the client is configured, instead
 * of surfacing as a rejected request after the secret was already read.
 *
 * OAuth 2.0 has no scheme: it authenticates with an `OAuthConfig` instead of a
 * single secret identifier, through `VaultHttpClientInterface::withOAuth()`.
 */
final readonly class AuthScheme
{
    private const CONTROL_CHARACTERS = '/[\x00-\x1F\x7F]/';

    private function __construct(
        public SecretPlacement $placement,
        public ?string $headerName = null,
        public ?string $prefix = null,
        public ?string $queryParam = null,
        public ?string $bodyField = null,
        public ?string $usernameSecret = null,
    ) {}

    /**
     * `Authorization: Bearer <secret>`.
     */
    public static function bearer(): self
    {
        return new self(SecretPlacement::Bearer);
    }

    /**
     * `Authorization: Basic <base64>`.
     *
     * Without `$usernameSecret` the secret must hold `username:password`;
     * with it, the secret is the password and `$usernameSecret` names the
     * Vault identifier of the username.
     *
     * @throws InvalidArgumentException when `$usernameSecret` is not a Vault identifier
     */
    public static function basicAuth(?string $usernameSecret = null): self
    {
        if ($usernameSecret !== null && (!IdentifierValidator::isValidForStorage($usernameSecret) || preg_match(self::CONTROL_CHARACTERS, $usernameSecret) === 1)) {
            throw new InvalidArgumentException('The Basic username secret must be a Vault identifier.', 9410661933);
        }

        return new self(SecretPlacement::BasicAuth, usernameSecret: $usernameSecret);
    }

    /**
     * `<name>: <prefix><secret>`, e.g. `header('Authorization', 'DeepL-Auth-Key ')`.
     *
     * @throws InvalidArgumentException when `$name` is not an HTTP header name or `$prefix` is empty or holds control characters
     */
    public static function header(string $name = 'X-API-Key', ?string $prefix = null): self
    {
        if (preg_match("/\\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\\z/", $name) !== 1) {
            throw new InvalidArgumentException('The header name must be an HTTP token.', 7930377463);
        }

        if ($prefix !== null && ($prefix === '' || preg_match(self::CONTROL_CHARACTERS, $prefix) === 1)) {
            throw new InvalidArgumentException('The header prefix must be non-empty and free of control characters.', 9898564967);
        }

        return new self(SecretPlacement::Header, headerName: $name, prefix: $prefix);
    }

    /**
     * `X-API-Key: <secret>`.
     */
    public static function apiKey(): self
    {
        return new self(SecretPlacement::ApiKey);
    }

    /**
     * `?<name>=<secret>`, appended to the existing query.
     *
     * @throws InvalidArgumentException when `$name` is empty or holds control characters
     */
    public static function queryParam(string $name = 'api_key'): self
    {
        if ($name === '' || preg_match(self::CONTROL_CHARACTERS, $name) === 1) {
            throw new InvalidArgumentException('The query parameter name must be non-empty and free of control characters.', 2722802580);
        }

        return new self(SecretPlacement::QueryParam, queryParam: $name);
    }

    /**
     * `<field>=<secret>` in a form-encoded body or a JSON object body.
     *
     * @throws InvalidArgumentException when `$field` does not match `[A-Za-z_][A-Za-z0-9_]{0,63}`
     */
    public static function bodyField(string $field = 'api_key'): self
    {
        if (preg_match('/\A[A-Za-z_]\w{0,63}\z/', $field) !== 1) {
            throw new InvalidArgumentException('The body field must be a simple field name.', 4310510580);
        }

        return new self(SecretPlacement::BodyField, bodyField: $field);
    }
}
