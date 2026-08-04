<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Http\OAuth;

use SensitiveParameter;

/**
 * Token-request parameters for an OAuth POST to the token endpoint.
 *
 * Composes:
 *  - grant_type + client_id + client_secret (always required)
 *  - scope (optional)
 *  - refresh_token (refresh_token grant only)
 *  - additionalParams (per-deployment escape hatch)
 *
 * Holds credential plaintext between vault retrieval and the HTTP send.
 * `wipeCredentials()` runs `sodium_memzero()` on each sensitive field so a
 * stack trace / dump in the failure path cannot leak the secret material.
 *
 * Not `readonly` because `sodium_memzero()` mutates the property in place —
 * the trade-off is intentional: we want zeroized memory more than we want
 * compile-time immutability for what is, in practice, a one-shot
 * request-scoped value.
 */
final class OAuthTokenRequestParams
{
    private bool $wiped = false;

    public function __construct(
        public string $grantType,
        #[SensitiveParameter]
        public string $clientId,
        #[SensitiveParameter]
        public string $clientSecret,
        public ?string $scope = null,
        #[SensitiveParameter]
        public ?string $refreshToken = null,
        /** @var array<string, string> */
        public array $additionalParams = [],
    ) {}

    /**
     * Build the `application/x-www-form-urlencoded` body for the POST.
     */
    public function toHttpQuery(): string
    {
        $params = [
            'grant_type' => $this->grantType,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];
        if ($this->scope !== null) {
            $params['scope'] = $this->scope;
        }

        if ($this->refreshToken !== null) {
            $params['refresh_token'] = $this->refreshToken;
        }

        return http_build_query(array_merge($params, $this->additionalParams));
    }

    /**
     * Zeroize every credential field. Idempotent and safe to call multiple
     * times — the guard flag makes repeat calls no-ops, which matters on
     * failure paths: `sodium_memzero()` sets the zval to null after zeroing,
     * so an unguarded second wipe would raise a SodiumException and replace
     * the real error.
     *
     * PHPStan's stub marks the by-ref param as nullable so we ignore the
     * spurious "does not accept null" diagnostics on the lines below.
     */
    public function wipeCredentials(): void
    {
        if ($this->wiped) {
            return;
        }

        $this->wiped = true;

        /** @phpstan-ignore assign.propertyType */
        sodium_memzero($this->clientId);
        /** @phpstan-ignore assign.propertyType */
        sodium_memzero($this->clientSecret);
        if ($this->refreshToken !== null) {
            sodium_memzero($this->refreshToken);
            $this->refreshToken = null;
        }
    }
}
