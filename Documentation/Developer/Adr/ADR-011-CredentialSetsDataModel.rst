.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-011-credential-sets:

==============================================
ADR-011: Credential Sets data model
==============================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-01-12

Context
=======

nr-vault currently stores atomic secrets (single values). Real integrations often
require a set of related fields (e.g. OAuth2 client credentials: client_id,
client_secret, token_url, scopes). Managing these as separate secrets is
error-prone and lacks semantic validation.

We need a "Credential Set" concept while preserving the existing ``tx_nrvault_secret``
primitive and its encryption/audit semantics.

Decision
========

We will introduce a new table/concept ``tx_nrvault_credential_set`` and define:

-  ``tx_nrvault_secret`` remains the **primitive encrypted storage unit** (atomic, type-agnostic)
-  ``tx_nrvault_credential_set`` becomes a **typed wrapper** that references exactly
   **one** secret row via ``secret_uid``
-  The referenced secret contains an **encrypted JSON payload** holding all
   credential fields for the set

Credential sets do **not** replace ``tx_nrvault_secret``. They build on top of it.

Example decrypted payloads
--------------------------

Bearer token:

.. code-block:: json
   :caption: Bearer token payload

   {"token": "sk-abc123..."}

OAuth2 Client Credentials:

.. code-block:: json
   :caption: OAuth2 client credentials payload

   {
     "client_id": "my-client",
     "client_secret": "secret123",
     "token_url": "https://oauth.example.com/token",
     "scopes": ["read", "write"]
   }

Consequences
============

Positive
--------

-  Reuses nr-vault's encryption, ACL, and audit model without duplication
-  A credential set becomes the stable reference target for the Service Registry
-  Rotation becomes straightforward: update one credential set = update one encrypted payload
-  Simplifies Rust transport integration: pass one ciphertext payload instead of N

Negative
--------

-  Fine-grained per-field ACL inside one credential set is not supported
   (acceptable: if you can use the credential set, you can use its fields)
-  Requires a migration/import story for existing scattered secrets

Alternatives considered
=======================

Parent-child secrets model
--------------------------

Credential set as parent, multiple child secrets.

**Rejected** for MVP: more joins and complexity; awkward for FFI integration
(multiple blobs); unclear audit semantics.

Store encrypted blob directly in credential_set
-----------------------------------------------

No secret FK, store encryption directly in ``tx_nrvault_credential_set``.

**Rejected**: duplicates encryption/audit logic and creates two competing secret stores.

Metadata-only linking (tags)
----------------------------

Link secrets via tags or metadata.

**Rejected**: weak referential integrity; too easy to break.

Related decisions
=================

-  :ref:`adr-002-envelope-encryption` - Encryption model used by credential sets
-  :ref:`adr-010-secure-outbound` - Parent decision for Secure Outbound feature
