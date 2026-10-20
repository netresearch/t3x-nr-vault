<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Http;

/**
 * Defines how a secret should be placed in an HTTP request.
 *
 * This enum provides type-safe options for secret injection.
 */
enum SecretPlacement: string
{
    /**
     * Bearer token in Authorization header.
     * Format: Authorization: Bearer {secret}.
     */
    case Bearer = 'bearer';

    /**
     * HTTP Basic Authentication.
     * For single secret: expects "username:password" format
     * For dual secrets: use with auth_username_secret option
     * Format: Authorization: Basic {base64(username:password)}.
     */
    case BasicAuth = 'basic';

    /**
     * Custom header with secret value.
     * Use auth_header option to specify header name (default: X-API-Key)
     * Format: {header_name}: {secret}.
     */
    case Header = 'header';

    /**
     * Query parameter with secret value.
     * Use auth_query_param option to specify param name (default: api_key)
     * Format: ?{param_name}={secret}.
     */
    case QueryParam = 'query';

    /**
     * Secret placed in request body as a field.
     * Use auth_body_field option to specify field name
     * Works with JSON and form-encoded bodies.
     */
    case BodyField = 'body_field';

    /**
     * OAuth 2.0 Bearer token with automatic refresh.
     * Requires oauth_config option with token endpoint and credentials.
     */
    case OAuth2 = 'oauth2';

    /**
     * API key in a custom header (common pattern).
     * Shorthand for Header placement with X-API-Key header.
     */
    case ApiKey = 'api_key';

    /**
     * Get a human-readable description of this placement type.
     */
    public function description(): string
    {
        return match ($this) {
            self::Bearer     => 'Bearer token in Authorization header',
            self::BasicAuth  => 'HTTP Basic Authentication',
            self::Header     => 'Custom header value',
            self::QueryParam => 'URL query parameter',
            self::BodyField  => 'Request body field',
            self::OAuth2     => 'OAuth 2.0 with automatic token refresh',
            self::ApiKey     => 'X-API-Key header',
        };
    }

    /**
     * Check if this placement type requires additional configuration.
     */
    public function requiresConfig(): bool
    {
        return match ($this) {
            self::Header, self::QueryParam, self::BodyField, self::OAuth2 => true,
            default                                                       => false,
        };
    }

    /**
     * Get the default config key for this placement type.
     */
    public function defaultConfigKey(): ?string
    {
        return match ($this) {
            self::Header     => 'X-API-Key',
            self::QueryParam => 'api_key',
            self::BodyField  => 'api_key',
            self::ApiKey     => 'X-API-Key',
            default          => null,
        };
    }
}
