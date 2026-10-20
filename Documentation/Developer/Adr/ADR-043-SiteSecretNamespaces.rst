.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-043-site-secret-namespaces:

====================================
ADR-043: Creation of site namespaces
====================================

Status
======

Accepted

Date
====

2026-10-10

Context
=======

:ref:`ADR-030 <adr-030-site-config-vault-read-time-resolution>` advertises a
``site:<siteIdentifier>:<secretName>`` lookup before a global secret.
Its unit tests construct that name in a mock.
The public storage API, CLI and backend previously rejected the colon, so the
documented namespace could not be created through a supported path.
The existing processor also treated denied, disabled or broken site secrets as
absent and silently tried a global credential.

Decision
========

Existing storage paths accept the exact canonical namespace through a dedicated
storage validator.
Friendly names and UUIDv7 identifiers retain their existing grammar.
The site component is 1--80 ASCII characters matching
``[a-zA-Z0-9][a-zA-Z0-9_-]*``.
The secret component retains the friendly-name grammar
``[a-zA-Z][a-zA-Z0-9_]*`` and its minimum of three characters.
The complete identifier is at most 255 bytes.
Nested namespaces, additional colons and empty components are refused.

A new namespace must name an exactly configured TYPO3 site before encryption
or insertion.
The specific ``tx_nrvault_secret.identifier`` creation guard accepts the same
storage grammar and checks the site before DataHandler creates a blank row.
Whitespace and control bytes in a submitted namespace are refused before TCA
can trim the value into a different authenticated name.
Manual construction without the optional site-validator dependency keeps
ordinary identifiers usable, but new namespace creation fails closed.
Automatic reference detection on other TCA fields keeps its existing rules.
The public interfaces gain no new abstract method.

An existing encrypted namespace remains updateable, rotatable, retrievable
through the existing CLI file-output path and deletable after its site is
renamed or deleted. This does not introduce a separate import/export API.
Such changes do not rename or delete secrets automatically.
The authenticated identifier remains unchanged throughout storage and custody.
Database lookup follows the installation's configured collation; this decision
does not promise that all databases distinguish identifier case.
A lookup that finds a differently spelled canonical namespace must not silently
rename it or encrypt under a different authenticated identifier.

Read-time site resolution permits global fallback only when the namespaced
record is actually missing.
The disabled-visible metadata API distinguishes that outcome from denial,
expiry, disabled state or another failure.
A present namespace whose value cannot be used keeps the unresolved placeholder
and emits a bounded warning.
Presence and plaintext retrieval errors are handled separately.
An inaccessible site credential never substitutes a global credential.
Resolution remains an explicit operation at the point of use; core site
configuration is never cached with resolved plaintext.

Acceptance specification
========================

* Creating ``site:main:payment_key`` through the real public API, CLI and backend
  stores an encrypted record that resolves for ``main`` and emits a read audit.
* Two configured sites may use the same friendly secret name and resolve their
  own values; a call without a site resolves the ordinary global identifier.
* Secret ACL applies independently of the site name.
  A denied site value remains unresolved even when its global counterpart is
  readable.
* A missing site value permits fallback; a denied, expired, disabled, malformed
  or undecryptable site value does not.
* Invalid components, unknown sites and overlong identifiers fail before a
  successful storage audit or persisted record.
* Site rename/delete leaves existing credential administration usable.
  Rotation and CLI file retrieval use the complete original authenticated
  identifier; the exported plaintext does not carry identifier metadata.
* SQLite and MariaDB execute collision cases against their actual schema and
  collation rather than accepting a repository mock as evidence.
* Removing the namespace selection, ACL, grammar or fail-closed behavior must
  fail a behavioral assertion in the associated regression tests.

Consequences
============

The accepted namespace becomes usable through existing creation paths.
Ordinary identifiers remain suitable for site identifiers outside the supported
ASCII subset and require no migration.
Existing colon-prefixed records created outside supported APIs are not rewritten
or merged automatically.
Renaming an authenticated identifier requires a separately designed
decrypt-and-reseal migration with audit evidence.

Alternatives
============

An additional site-aware public method would leave the established CLI and
backend creation paths unable to implement ADR-030 and enlarge the public API.
Broadly accepting colons in every TCA field would alter reference detection for
unrelated application values.
Treating every retrieval failure as absence would silently substitute a
different credential after an access denial or operational failure.
