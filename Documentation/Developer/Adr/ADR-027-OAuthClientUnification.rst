.. include:: /Includes.rst.txt

.. _adr-027-oauth-client-unification:

========================================================
ADR-027: OAuth token requests use the secure HTTP client
========================================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-05-22

Context
=======

``Classes/Http/OAuth/OAuthTokenManager`` issues token-endpoint
requests for adapters that need OAuth client-credentials /
refresh-token flows. Until PR #145 the token request path used a
``ClientInterface`` injected via constructor and *did not* go
through ``SecureHttpClientFactory``. Two real consequences:

1.  **SSRF protections were missing on the token endpoint.** The
    ``isHostAllowed`` / ``isDangerousIpLiteral`` checks documented
    in :ref:`adr-010-secure-outbound` ran on the adapter's
    secret-fetch URL but *not* on its OAuth token URL — an attacker
    who could write the `oauth.tokenEndpoint` config could pivot
    to internal infrastructure even though the secret URL itself
    was hardened.
2.  **Cache-key collision risk.** The token cache key originally
    hashed ``tokenEndpoint + clientIdSecret + grantType + scopes``.
    Two adapters that shared a tokenEndpoint + clientId + scope but
    used different *client secrets* (e.g., a rotation in progress)
    would collide and serve the wrong cached token.

A separate finding (multi-axis review) was that error-path log
messages and audit-log payloads could quote
``$exception->getMessage()`` which — for token failures — frequently
echoes back the request body, leaking ``client_secret=``,
``refresh_token=``, and ``Authorization: Bearer`` values into
warm storage.

Decision
========

Three converging changes packaged as PRs #145 and #146:

1.  **Single client surface.** ``OAuthTokenManager`` accepts a
    ``SecureHttpClientFactory`` and builds its own per-request
    client via ``factory->create(...)``. The pre-existing
    ``ClientInterface`` constructor parameter remains for explicit
    test-double injection and adapter-supplied stubs, but the
    production path goes through the factory so the SSRF
    middleware (see :ref:`adr-026-dns-rebinding-defence`) protects
    the token endpoint too.

2.  **tokenEndpoint isHostAllowed gate.** Before any token request
    fires, ``dispatchTokenRequest`` calls
    ``isHostAllowed(tokenEndpoint)``. Adapter misconfiguration
    pointing at ``http://169.254.169.254`` fails fast with an
    audit-logged ``OAUTH_TOKEN_REJECTED`` row, not as a stack
    trace exposing internal infra.

3.  **Cache key fragmentation by secret.** The OAuth token-cache
    key now includes ``$config->clientSecretSecret`` (the vault
    *handle*, not the secret value) so a credential rotation
    invalidates the cache cleanly:

    .. code-block:: php

        hash('xxh128', implode(':', [
            $config->tokenEndpoint,
            $config->clientIdSecret,
            $config->clientSecretSecret,  // new
            $config->grantType,
            $config->getScopesString(),
        ]));

4.  **Credential redaction in error paths.** A ``redactCredentials``
    helper replaces ``client_secret=...``, ``refresh_token=...``,
    and ``Authorization: Bearer ...`` / ``Basic ...`` patterns
    before the original exception message reaches the logger or
    the audit log. Four call-sites cover both the synchronous
    Guzzle exception path and the async retry path.

Consequences
============

Positive
--------

-  Token endpoints get the full DNS-rebinding + isHostAllowed
   defence that secret URLs already had.
-  Credential rotation no longer needs a manual cache-bust.
-  Token-endpoint failures leave no credential material in logs or
   audit rows — replayable secrets stay in the vault.
-  Tested via fuzz suite (regression added: malformed token
   responses no longer leak secrets via the exception chain).

Negative
--------

-  Constructor signature grew: ``OAuthTokenManager`` now takes
   ``VaultServiceInterface, ClientInterface, SecureHttpClientFactory,
   ?LoggerInterface, ?RequestFactoryInterface, ?StreamFactoryInterface,
   ?AuditLogServiceInterface``. Optional params are trailing-only to
   avoid positional BC breaks for the existing fuzz tests.
-  Adapter authors must invalidate their own caches if they cache
   ``OAuthTokenManager`` instances across config changes. (Most
   adapters fetch the manager from DI per request, so this is a
   non-issue in practice.)

Verified
========

-  Unit tests: cache-key fragmentation regression, isHostAllowed
   gate, credential-redaction across all four call-sites.
-  Architecture test (:ref:`adr-028-phpat-http-client-lock`)
   enforces that only ``SecureHttpClientFactory`` constructs
   Guzzle clients.

References
==========

-  Pull requests: `#145 <https://github.com/netresearch/t3x-nr-vault/pull/145>`__,
   `#146 <https://github.com/netresearch/t3x-nr-vault/pull/146>`__
-  Related: :ref:`adr-010-secure-outbound`,
   :ref:`adr-026-dns-rebinding-defence`,
   :ref:`adr-028-phpat-http-client-lock`
