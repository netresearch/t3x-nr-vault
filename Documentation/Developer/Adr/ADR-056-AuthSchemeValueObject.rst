.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-056-auth-scheme-value-object:

=====================================================
ADR-056: Authentication schemes as a value object
=====================================================

Status
======

Accepted. Builds on :ref:`adr-008-http-client` and follows the capability
pattern of :ref:`adr-041-additional-body-credentials`.

Date
====

2026-11-17

Context
=======

``VaultHttpClientInterface::withAuthentication()`` takes a
``SecretPlacement`` and an options array. Each placement reads only some
options: ``Header`` reads ``headerName`` and ``prefix``, ``QueryParam``
reads ``queryParam``, ``BodyField`` reads ``bodyField`` and ``BasicAuth``
reads ``usernameSecret``. The array cannot express that coupling.

Two mistakes therefore pass without an error:

*   An option of another placement, e.g. ``headerName`` with ``Bearer``, is
    accepted and ignored.
*   A misspelled key, e.g. ``preffix``, is ignored. For a caller that does not
    pass a literal array, static analysis cannot see it. The secret is then sent
    without its prefix, and the mistake shows only as a rejected request from
    the remote service.

Invalid values, such as a header name with a space, surface even later: the
secret is read and audited first, and the request fails when it is built.

Decision
========

Add an ``AuthScheme`` value object with one named constructor per placement:
``bearer()``, ``basicAuth(?string $usernameSecret)``,
``header(string $name, ?string $prefix)``, ``apiKey()``,
``queryParam(string $name)`` and ``bodyField(string $field)``. Each
constructor accepts only the options of its placement and validates them when
the scheme is built.

Add a feature-detectable calling capability,
``AuthSchemeHttpClientInterface`` extending ``VaultHttpClientInterface``, with
``withAuthScheme(string $secretIdentifier, AuthScheme $scheme)``. The concrete
client implements it by setting the same internal fields as
``withAuthentication()``, so both send the same request for the same
placement and options. The audit reason, timeout, pinned addresses and
additional body credentials carry over, as they do for
``withAuthentication()``.

Mark ``withAuthentication()`` as deprecated on the interface and on the
client. It keeps its behaviour and is removed in the next major release.

Three points deviate from the proposal in issue #171:

*   A new method replaces the proposed ``array|AuthScheme`` union on
    ``withAuthentication()``. A union parameter would change the signature
    of a method that callers use today, and two meanings in one parameter
    keep the old shape alive.
*   There is no ``oauth2()`` scheme. OAuth 2.0 authenticates with an
    ``OAuthConfig`` and has no single secret identifier;
    ``withOAuth()`` already covers it.
*   The ``$authPrefix`` constructor parameter of ``VaultHttpClient`` stays.
    Removing it changes the constructor signature, which waits for a major
    release.

Consequences
============

``VaultHttpClientInterface`` is unchanged, so its existing implementations
keep loading. ``VaultServiceInterface::http()`` still declares
``VaultHttpClientInterface``; a caller narrows with
``instanceof AuthSchemeHttpClientInterface`` before it calls
``withAuthScheme()``. In the next major release, ``http()`` can declare the
narrower type, and ``withAuthentication()`` and the options array go.

Static analysis with deprecation rules reports each remaining
``withAuthentication()`` call. This package's own tests keep calling it on
purpose, because they keep the deprecated method working until it is removed;
``phpstan.neon`` ignores the deprecation for ``Tests/`` only.

Unit tests send the same request through both methods for each placement and
each option. A functional test sends a header scheme with a prefix to a
local server on the blocking and the streaming path. The executed
documentation examples use ``withAuthScheme()``.
