.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-041-additional-body-credentials:

=========================================================
ADR-041: Additional body credentials keep one transport
=========================================================

Status
======

Accepted

Date
====

2026-10-09

Context
=======

An RFC-8693 exchange can require confidential client authentication and a
separately stored subject token in the same request. ``withAuthentication()``
replaces the primary authentication. Nesting credential-bearing HTTP clients
complicates cancellation, timeout rebuilding and the audit boundary.

Decision
========

Add a feature-detectable calling capability,
``AdditionalSecretHttpClientInterface`` extending ``VaultHttpClientInterface``,
with ``withAdditionalBodyField(string $secretIdentifier, string $bodyField)``.
Do not change the existing calling interface. The concrete immutable
client implements the capability and returns a new client with an additional
Vault identifier bound to a simple body-field name.

Bindings survive authentication, OAuth, reason and timeout clones. They are
injected inside the existing audited injection
boundary, on blocking, cancellable and streaming sends. Secrets are retrieved
only inside Vault and are zeroed through existing BodyField injection. Existing
host/SSRF, cancellation-before-read, DNS pin and redirect guards remain in force.
Additional resource credentials are read before OAuth can contact a token
endpoint; they remain on the resource request and never enter the token request.

Reject duplicate additional fields, collisions with the primary BodyField,
invalid field names or identifiers and more than eight additional bindings.
Identifiers use the existing canonical Vault validator. Validate the final
primary/additional combination in either builder order. A refused read prevents
all transport contact. A caller receives no secret, transport or promise.

Consequences
============

The old interface and default single-secret behavior remain unchanged. Consumers
requiring this capability fail closed when the installed Vault version lacks it.
Each underlying secret read retains its access audit; the request retains one
HTTP outcome audit and never logs body values. Tests prove real request contents,
clone behavior, refused reads and cancellation before credentials are read.
