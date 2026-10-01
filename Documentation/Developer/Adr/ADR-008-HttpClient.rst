.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-008-http-client:

=========================
ADR-008: HTTP client
=========================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-01-03

Context
=======

Applications often need to make authenticated HTTP requests to external APIs
using secrets stored in the vault. The typical pattern exposes secrets to
application code:

.. code-block:: php
   :caption: Typical insecure pattern

   $apiKey = $vault->retrieve('stripe_api_key');
   $client->request('POST', '/charges', [
       'headers' => ['Authorization' => 'Bearer ' . $apiKey],
   ]);
   // $apiKey remains in memory, possibly logged

This approach:

-  Exposes secrets to application code
-  Risks logging secrets in debug output
-  Requires manual memory cleanup
-  Duplicates authentication logic across services

Problem statement
=================

How can applications make authenticated HTTP requests using vault secrets
without exposing the secret values to application code?

Decision drivers
================

-  **Secret isolation**: Application code should never see raw secrets
-  **Memory safety**: Secrets cleared from memory immediately after use
-  **Standards compliance**: Use PSR-18 for HTTP client interoperability
-  **Flexibility**: Support various authentication methods
-  **Auditability**: Log API calls without exposing credentials
-  **Simplicity**: Fluent API for common use cases

Considered options
==================

Option 1: Helper methods returning configured clients
-----------------------------------------------------

Factory methods that return pre-configured HTTP clients.

**Pros:**

-  Simple API

**Cons:**

-  Secrets exposed during client creation
-  Limited flexibility
-  Hard to audit

Option 2: Request middleware/interceptor
----------------------------------------

Middleware that injects credentials into requests.

**Pros:**

-  Transparent injection

**Cons:**

-  Framework-specific (Guzzle middleware vs PSR-18)
-  Complex configuration

Option 3: PSR-18 wrapper with fluent authentication API
-------------------------------------------------------

Immutable wrapper implementing PSR-18 with authentication configuration.

**Pros:**

-  Standards-compliant (PSR-18)
-  Immutable (thread-safe, predictable)
-  Fluent API for configuration
-  Secret injection at request time

**Cons:**

-  Wrapper overhead
-  Must implement all PSR-18 methods

Decision
========

We chose **PSR-18 wrapper with fluent authentication API** because:

1. **Standards compliance**: Works with any PSR-18 compatible code
2. **Immutability**: Each ``with*`` call returns new instance, preventing state issues
3. **Late binding**: Secrets retrieved only when request is sent
4. **Memory safety**: ``sodium_memzero()`` clears secrets after injection
5. **Audit integration**: Logs API calls with secret identifiers (not values)

Implementation
==============

Interface design
----------------

.. code-block:: php
   :caption: Classes/Http/VaultHttpClientInterface.php

   interface VaultHttpClientInterface extends ClientInterface
   {
       public function withAuthentication(
           string $secretIdentifier,
           SecretPlacement $placement = SecretPlacement::Bearer,
           array $options = [],
       ): static;

       public function withOAuth(OAuthConfig $config, string $reason = ''): static;

       public function withReason(string $reason): static;
   }

SecretPlacement enum
--------------------

Type-safe authentication placement options:

.. code-block:: php
   :caption: Classes/Http/SecretPlacement.php

   enum SecretPlacement: string
   {
       case Bearer = 'bearer';         // Authorization: Bearer {secret}
       case BasicAuth = 'basic';       // Authorization: Basic {base64}
       case Header = 'header';         // Custom header
       case QueryParam = 'query';      // URL query parameter
       case BodyField = 'body_field';  // Request body field
       case OAuth2 = 'oauth2';         // OAuth 2.0 with token refresh
       case ApiKey = 'api_key';        // X-API-Key header
   }

Fluent API usage
----------------

.. code-block:: php
   :caption: Using VaultHttpClient

   use GuzzleHttp\Psr7\Request;
   use Netresearch\NrVault\Http\SecretPlacement;

   // Bearer authentication
   $response = $this->httpClient
       ->withAuthentication('stripe_api_key', SecretPlacement::Bearer)
       ->sendRequest(new Request('POST', 'https://api.stripe.com/v1/charges'));

   // Custom header
   $response = $this->httpClient
       ->withAuthentication('api_token', SecretPlacement::Header, [
           'headerName' => 'X-API-Key',
       ])
       ->sendRequest(new Request('GET', 'https://api.example.com/data'));

   // Basic authentication with two secrets
   $response = $this->httpClient
       ->withAuthentication('service_password', SecretPlacement::BasicAuth, [
           'usernameSecret' => 'service_username',
           'reason' => 'Fetching secure data',
       ])
       ->sendRequest(new Request('GET', 'https://api.example.com/secure'));

Immutable implementation
------------------------

.. code-block:: php
   :caption: Classes/Http/VaultHttpClient.php

   final readonly class VaultHttpClient implements VaultHttpClientInterface
   {
       public function __construct(
           private VaultServiceInterface $vaultService,
           private AuditLogServiceInterface $auditLogService,
           private ?ClientInterface $innerClient = null,
           private ?string $secretIdentifier = null,
           private ?SecretPlacement $placement = null,
           // ... other configuration
       ) {}

       public function withAuthentication(
           string $secretIdentifier,
           SecretPlacement $placement = SecretPlacement::Bearer,
           array $options = [],
       ): static {
           // Return NEW instance with updated configuration
           return new self(
               $this->vaultService,
               $this->auditLogService,
               $this->innerClient,
               $secretIdentifier,
               $placement,
               // ... merge options
           );
       }

       public function sendRequest(RequestInterface $request): ResponseInterface
       {
           // Inject authentication into request
           $request = $this->injectAuthentication($request);

           // Send request
           $response = $this->getInnerClient()->sendRequest($request);

           // Audit log (secret identifier, not value)
           $this->logHttpCall($request, $response);

           return $response;
       }
   }

Memory-safe secret injection
----------------------------

.. code-block:: php
   :caption: Secure injection with immediate cleanup

   private function injectBearer(RequestInterface $request): RequestInterface
   {
       $secret = $this->vaultService->retrieve($this->secretIdentifier);

       try {
           return $request->withHeader('Authorization', 'Bearer ' . $secret);
       } finally {
           sodium_memzero($secret);  // Clear from memory immediately
       }
   }

   private function injectBasicAuth(RequestInterface $request): RequestInterface
   {
       $password = $this->vaultService->retrieve($this->secretIdentifier);
       $username = $this->usernameSecretIdentifier
           ? $this->vaultService->retrieve($this->usernameSecretIdentifier)
           : '';

       try {
           $credentials = base64_encode($username . ':' . $password);
           return $request->withHeader('Authorization', 'Basic ' . $credentials);
       } finally {
           sodium_memzero($password);
           if ($username !== '') {
               sodium_memzero($username);
           }
       }
   }

OAuth 2.0 support
-----------------

.. code-block:: php
   :caption: OAuth configuration

   $config = OAuthConfig::clientCredentials(
       tokenUrl: 'https://oauth.example.com/token',
       clientIdSecret: 'oauth_client_id',
       clientSecretSecret: 'oauth_client_secret',
       scopes: ['read', 'write'],
   );

   $response = $this->httpClient
       ->withOAuth($config, 'API access')
       ->sendRequest($request);

The :php:`OAuthTokenManager` handles:

-  Token caching (in-memory)
-  Automatic refresh before expiry
-  Secure credential handling

Secure client factory
---------------------

.. code-block:: php
   :caption: Classes/Http/SecureHttpClientFactory.php

   final class SecureHttpClientFactory
   {
       public function create(): ClientInterface
       {
           return new Client([
               'debug' => false,  // Never log request/response bodies
               'http_errors' => false,  // Handle errors in vault client
               // Respect TYPO3 HTTP settings
               'proxy' => $GLOBALS['TYPO3_CONF_VARS']['HTTP']['proxy'] ?? null,
               'verify' => $GLOBALS['TYPO3_CONF_VARS']['HTTP']['verify'] ?? true,
               'timeout' => $GLOBALS['TYPO3_CONF_VARS']['HTTP']['timeout'] ?? 30,
           ]);
       }
   }

Audit logging
-------------

.. code-block:: php
   :caption: Logging without exposing secrets

   private function logHttpCall(RequestInterface $request, ResponseInterface $response): void
   {
       $this->auditLogService->log(
           $this->secretIdentifier,          // Which secret was used
           'http_call',
           $response->getStatusCode() < 400,  // Success flag
           null,
           $this->reason,
           context: HttpCallContext::fromRequest(
               $request->getMethod(),
               (string) $request->getUri(),
               $response->getStatusCode(),
           ),
       );
   }

Consequences
============

Positive
--------

-  **Secret isolation**: Application code never sees raw secret values
-  **Memory safety**: ``sodium_memzero()`` clears secrets immediately
-  **Standards compliance**: PSR-18 compatible, works with any framework
-  **Immutable design**: Thread-safe, predictable behavior
-  **Audit trail**: API calls logged with context, not credentials
-  **TYPO3 integration**: Respects proxy, SSL, timeout settings
-  **No debug leaks**: ``debug: false`` prevents request/response logging

Negative
--------

-  **Wrapper overhead**: Additional object creation per request
-  **PSR-18 limitation**: Async requests not supported by PSR-18
-  **Memory pressure**: Brief window where secret exists in memory

Risks
-----

-  Exception handlers might capture request objects with injected secrets
-  Memory dumps could expose secrets during injection window

Mitigation
----------

-  Use ``try/finally`` to ensure cleanup even on exceptions
-  Avoid storing configured requests in variables
-  Document memory safety requirements

Related decisions
=================

-  :ref:`adr-006-audit-logging` - HTTP calls are logged

References
==========

-  `PSR-18 HTTP Client <https://www.php-fig.org/psr/psr-18/>`_
-  `libsodium Memory Management <https://doc.libsodium.org/memory_management>`_
