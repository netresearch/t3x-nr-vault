<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

/*
 * Router script for PHP's built-in web server, started by OAuthIntegrationTest.
 *
 * Implements exactly the endpoints the test talks to, mirroring the
 * mock-oauth2-server behaviour it relies on (see .ddev/mock-oauth/config.json):
 *
 *  - GET  /.well-known/openid-configuration and /default/.well-known/openid-configuration
 *         discovery document carrying `token_endpoint`
 *  - POST /default/token      client_credentials grant; issues a fresh token per
 *                             call, rejects unknown clients with RFC 6749 errors
 *  - GET  /default/userinfo   200 only for a bearer token this server issued
 *  - GET  /echo/authorization echoes the Authorization header the client sent
 *
 * The built-in server runs this script afresh for every request, so issued tokens
 * are self-verifying: `<random>.<hmac>` keyed with a per-run secret the test
 * passes in NR_VAULT_MOCK_OAUTH_SECRET.
 */

const MOCK_OAUTH_CLIENT_ID = 'test-client-id';
const MOCK_OAUTH_CLIENT_SECRET = 'test-client-secret';

/**
 * @param array<string, mixed> $body
 */
function mockOAuthRespond(int $status, array $body): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    echo json_encode($body, JSON_THROW_ON_ERROR);
}

function mockOAuthSign(string $payload, string $secret): string
{
    return hash_hmac('sha256', $payload, $secret);
}

function mockOAuthAuthorizationHeader(): string
{
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

    return is_string($header) ? $header : '';
}

function mockOAuthPostString(string $name): string
{
    $value = $_POST[$name] ?? '';

    return is_string($value) ? $value : '';
}

$secret = getenv('NR_VAULT_MOCK_OAUTH_SECRET');
if (!is_string($secret) || $secret === '') {
    mockOAuthRespond(500, ['error' => 'server_error', 'error_description' => 'NR_VAULT_MOCK_OAUTH_SECRET not set']);

    return;
}

$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url(is_string($requestUri) ? $requestUri : '/', PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$host = $_SERVER['HTTP_HOST'] ?? '127.0.0.1';
// Plain HTTP: PHP's built-in server on loopback cannot terminate TLS. NOSONAR — test-only.
$issuer = 'http://' . (is_string($host) ? $host : '127.0.0.1') . '/default'; // NOSONAR

switch (true) {
    case $method === 'GET' && in_array($path, ['/.well-known/openid-configuration', '/default/.well-known/openid-configuration'], true):
        mockOAuthRespond(200, [
            'issuer' => $issuer,
            'token_endpoint' => $issuer . '/token',
            'userinfo_endpoint' => $issuer . '/userinfo',
            'grant_types_supported' => ['client_credentials'],
        ]);
        break;
    case $method === 'POST' && $path === '/default/token':
        if (mockOAuthPostString('grant_type') !== 'client_credentials') {
            mockOAuthRespond(400, ['error' => 'unsupported_grant_type']);
            break;
        }

        if (
            !hash_equals(MOCK_OAUTH_CLIENT_ID, mockOAuthPostString('client_id'))
            || !hash_equals(MOCK_OAUTH_CLIENT_SECRET, mockOAuthPostString('client_secret'))
        ) {
            mockOAuthRespond(401, ['error' => 'invalid_client']);
            break;
        }

        $nonce = bin2hex(random_bytes(16));
        mockOAuthRespond(200, [
            'access_token' => $nonce . '.' . mockOAuthSign($nonce, $secret),
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => mockOAuthPostString('scope'),
        ]);
        break;
    case $method === 'GET' && $path === '/default/userinfo':
        $token = str_starts_with(mockOAuthAuthorizationHeader(), 'Bearer ')
            ? substr(mockOAuthAuthorizationHeader(), 7)
            : '';
        $parts = explode('.', $token, 2);
        if (count($parts) !== 2 || !hash_equals(mockOAuthSign($parts[0], $secret), $parts[1])) {
            mockOAuthRespond(401, ['error' => 'invalid_token']);
            break;
        }

        mockOAuthRespond(200, ['sub' => 'test-client']);
        break;
    case $method === 'GET' && $path === '/echo/authorization':
        mockOAuthRespond(200, ['authorization' => mockOAuthAuthorizationHeader()]);
        break;
    default:
        mockOAuthRespond(404, ['error' => 'not_found']);
}
