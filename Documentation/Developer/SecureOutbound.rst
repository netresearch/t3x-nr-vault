.. include:: /Includes.rst.txt

.. _developer-secure-outbound:

===============
Secure Outbound
===============

.. note::
   Secure Outbound is a planned feature for nr-vault. This documentation
   describes the planned architecture and API. Implementation is in progress —
   no class named on this page exists in ``Classes/`` yet.

   **If you need a vault-aware HTTP client today, you already have one:**
   :php:`VaultHttpClientInterface` (:ref:`api-http-client`) injects secrets
   into outbound requests without exposing them to calling code.

   Do not mistake the shipped :php:`Classes/Http/SecureHttpClientFactory` for
   this feature. Despite the similar name it is an internal factory that
   configures Guzzle from TYPO3's HTTP settings, used by
   :php:`VaultHttpClient`, :php:`OAuthTokenManager` and
   :php:`WebhookAuditSink`.

Secure Outbound extends nr-vault into a governed outbound integration platform
for TYPO3. It provides centralized credential management, policy enforcement,
and audit logging for all external API calls.

.. contents:: Table of contents
   :local:
   :depth: 2

Overview
========

TYPO3 projects increasingly depend on external APIs (LLMs, shipping, payments,
CRM, marketing, internal platforms). Today, most integrations are implemented
per extension:

-  endpoints are configured in multiple places
-  credentials get passed around in PHP memory
-  every integration re-implements auth/retry/timeouts/logging
-  no centralized policy enforcement (SSRF hardening, allowed hosts/paths)
-  no consistent audit trail per outbound API call

Secure Outbound addresses these issues with three core components:

Service Registry
   Central definition of service endpoints with security policies.

Credential Sets
   Typed bundles of secrets (OAuth2, API key, Basic auth) managed as one unit.

SecureHttpClient
   Stable PHP API for extensions to call services by ``serviceId``.

Core concepts
=============

Service Registry
----------------

Services are centrally configured with:

-  **serviceId**: stable identifier used by consuming code
-  **base URLs**: allowed endpoint URLs
-  **security policy**: allowed hosts, methods, path patterns, timeout caps
-  **credential binding**: link to a Credential Set

Extensions never hardcode endpoints. They reference services by ``serviceId``.

Credential Sets
---------------

Credential Sets are typed wrappers over nr-vault secrets. They store encrypted
JSON payloads containing all fields for a credential type:

**Bearer Token:**

.. code-block:: json
   :caption: Bearer token payload

   {"token": "sk-abc123..."}

**OAuth2 Client Credentials:**

.. code-block:: json
   :caption: OAuth2 client credentials payload

   {
     "client_id": "my-client",
     "client_secret": "secret123",
     "token_url": "https://oauth.example.com/token",
     "scopes": ["read", "write"]
   }

Supported credential types (MVP):

-  Bearer Token
-  API Key Header
-  Basic Authentication
-  OAuth2 Client Credentials

SecureHttpClient API
--------------------

Extensions call external services using a simple PHP API:

.. code-block:: php
   :caption: SecureHttpClientInterface

   interface SecureHttpClientInterface
   {
       public function request(
           string $serviceId,
           string $method,
           string $path,
           array $options = []
       ): SecureHttpResponse;
   }

**Request options:**

-  ``query``: Query parameters
-  ``headers``: Additional headers (non-secret)
-  ``json``: JSON body
-  ``body``: Raw body
-  ``timeout``: Timeout override (clamped by policy)
-  ``idempotencyKey``: Optional idempotency key

**Response:**

.. code-block:: php
   :caption: SecureHttpResponse methods

   $response->statusCode();  // int
   $response->headers();     // array
   $response->body();        // string
   $response->json();        // array (throws on invalid JSON)

Security features
=================

Policy enforcement
------------------

All requests are validated against the service's security policy:

-  **Allowed hosts/base URLs**: Requests can only go to configured endpoints
-  **Allowed methods**: Restrict to GET, POST, etc.
-  **Allowed path patterns**: Limit which paths can be called
-  **Private range blocking**: Block access to private IPs, link-local, metadata endpoints
-  **Timeout caps**: Maximum request duration
-  **Max body sizes**: Prevent resource exhaustion

Audit logging
-------------

Every outbound call is logged with metadata:

-  serviceId, caller identity, timestamp
-  method, path template, status code
-  duration, bytes in/out
-  error classification, correlation ID

Request/response bodies and secrets are **never** logged.

Secret protection
-----------------

Credentials are:

-  stored encrypted at rest
-  never exposed in PHP variables when using Rust transport
-  redacted from all logs and debug output
-  rotated centrally without code changes

Transport backends
==================

Secure Outbound supports multiple transport backends:

PhpTransport (default)
----------------------

Uses PSR-18 or Symfony HttpClient. Works everywhere, no special requirements.

RustFfiTransport (optional)
---------------------------

Rust-based transport that:

-  decrypts credentials inside the Rust runtime
-  makes HTTP requests without exposing secrets to PHP
-  supports HTTP/2 and optional HTTP/3

Requires:

-  Rust library installed separately
-  PHP ``ffi.enable=preload`` configuration

See :ref:`adr-013-rust-ffi-preload` for security considerations.

SidecarTransport (future)
-------------------------

For highest security requirements, a separate daemon process can provide
stronger isolation. See :ref:`adr-016-sidecar-option`.

Usage example
=============

.. code-block:: php
   :caption: Calling an external API

   use Netresearch\NrVault\Service\SecureHttpClientInterface;

   final class MyApiService
   {
       public function __construct(
           private readonly SecureHttpClientInterface $httpClient,
       ) {}

       public function fetchData(string $resourceId): array
       {
           $response = $this->httpClient->request(
               serviceId: 'my-api',
               method: 'GET',
               path: '/resources/' . $resourceId,
               options: [
                   'query' => ['include' => 'metadata'],
               ]
           );

           return $response->json();
       }
   }

The ``my-api`` service and its credentials are configured in the backend
module. The extension code never handles credentials directly.

Related ADRs
============

Architecture decisions for Secure Outbound:

-  :ref:`adr-010-secure-outbound` - Feature scope decision
-  :ref:`adr-011-credential-sets` - Credential Sets data model
-  :ref:`adr-012-secure-http-transports` - Transport abstraction
-  :ref:`adr-013-rust-ffi-preload` - Rust FFI security
-  :ref:`adr-014-packaging-native` - Native artifact distribution
-  :ref:`adr-015-http3-feature-flag` - HTTP/3 support
-  :ref:`adr-016-sidecar-option` - Sidecar daemon option
-  :ref:`adr-017-audit-metadata-retention` - Audit log design

