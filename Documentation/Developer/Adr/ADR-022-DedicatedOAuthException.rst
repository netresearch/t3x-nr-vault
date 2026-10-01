.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-022-dedicated-oauth-exception:

=============================================
ADR-022: Dedicated OAuth exception
=============================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-03-28

Context
=======

OAuth-related errors (token refresh failures, invalid grants, expired
tokens, provider errors) used the generic ``VaultException`` class. This
prevented callers from distinguishing OAuth failures from other vault
errors, making targeted error handling impossible.

For example, a caller wanting to retry on token expiry but fail fast on
a missing secret had to inspect exception messages rather than catching
a specific exception type. This is fragile and violates the principle of
using the type system for error classification.

Decision
========

Create an ``OAuthException`` class that extends ``VaultException`` with
OAuth-specific factory methods:

-  ``OAuthException::tokenRefreshFailed(string $provider, string $reason)``
-  ``OAuthException::invalidGrant(string $provider)``
-  ``OAuthException::providerUnavailable(string $provider)``
-  ``OAuthException::tokenExpired(string $provider)``

Each factory method sets an appropriate error code and message, providing
structured error information without exposing sensitive token data.

Consequences
============

Positive
--------

-  **Targeted error handling**: Callers can ``catch (OAuthException $e)``
   to handle OAuth failures distinctly from other vault errors.
-  **Backward compatible**: ``OAuthException`` extends ``VaultException``,
   so existing ``catch (VaultException $e)`` blocks continue to work.
-  **Structured errors**: Factory methods ensure consistent error messages
   and codes across all OAuth failure paths.
-  **Type safety**: Error classification moves from string inspection to
   the type system.

Negative
--------

-  **Exception hierarchy growth**: Adding more exception subclasses
   increases the API surface that callers must be aware of.

Related decisions
=================

-  :ref:`adr-008-http-client` - HTTP client integration
-  :ref:`adr-012-secure-http-transports` - Secure HTTP client transports
