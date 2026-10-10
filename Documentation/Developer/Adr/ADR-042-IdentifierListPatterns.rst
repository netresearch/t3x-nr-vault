.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-042-identifier-list-patterns:

========================================
ADR-042: Identifier patterns in listings
========================================

Status
======

Accepted

Date
====

2026-10-10

Context
=======

The public PHP interface and CLI manual promise ``*`` patterns in listings.
The previous service passed that pattern into a literal repository prefix
filter, so the documented ``payment_*`` example returned no valid identifiers.
The existing unit test returned mocked adapter results and checked the argument
rather than the promised database result.
Repository prefix filters deliberately escape SQL wildcards to protect callers
that need a literal prefix.

Decision
========

The public pattern matches the entire identifier.
Each ``*`` matches zero or more characters, including at the start or middle.
All other characters are literal, including SQL ``%``, ``_`` and backslashes.
``null`` means no identifier filter, while an empty pattern matches none.
The repository retains the database's existing LIKE case rules.
The service additionally filters the returned candidates with ASCII case
folding, so a case-insensitive database match is not accidentally discarded.
A backend with stricter case rules may already have selected fewer candidates.
This is not a promise that every external storage system shares a collation.

An optional ``pattern`` field is appended to :php:`SecretFilters`.
The existing ``prefix`` field and positional constructor arguments keep their
meaning.
When both fields are set, both restrictions apply.
The array transport preserves an explicitly empty pattern.

The repository escapes LIKE metacharacters before converting stars to percent
wildcards, and binds the resulting expression as a query parameter.
Both repository listing methods use this same conversion.
The public service enforces the pattern on returned identifiers as well.
Existing extension-point adapters may ignore the new optional filter field;
they still cannot cause the service to return identifiers outside the pattern.
The comparison treats only ``*`` as special and does not compile input as a
regular expression, including for long or multibyte patterns.
Access control remains in the public service, and database restrictions still
exclude disabled records by default and soft-deleted records always.
No schema migration is needed.

Acceptance specification
========================

Given ``app_key``, ``app_key_extra``, ``appXkey``, ``billing_key`` and
``app_second_token``:

.. list-table:: Identifier pattern results
   :header-rows: 1

   * - Pattern
     - Selected identifiers
   * - ``app_*``
     - ``app_key``, ``app_key_extra``, ``app_second_token``
   * - ``app_key``
     - ``app_key``
   * - ``*key``
     - ``app_key``, ``appXkey``, ``billing_key``
   * - ``app*key``
     - ``app_key``, ``appXkey``
   * - ``a**p_*key``
     - ``app_key``
   * - ``*``
     - All five identifiers, subject to visibility and access checks
   * - ``app%``, ``app_key_``, ``app\*``, or an empty string
     - None

The same cases run against the public service and both repository query paths.
A real CLI invocation must return the expected JSON records for ``app_*``.
An actor without read access must receive no metadata, even for ``*``.
Disabling and deleting matching records must preserve the default restrictions;
``includeDisabled`` may expose the disabled record's metadata but never a deleted
record.
The literal prefix ``app_`` remains a prefix, and combining it with ``*key``
selects only ``app_key``.
SQLite and MariaDB must retain the mixed-case ``App_Key`` match selected by
their configured LIKE rules for ``app_*``.
An older adapter that ignores ``pattern`` must still produce the correct
service results for exact names, multiple stars, literal SQL metacharacters,
backslashes, multibyte input and long input.
Listing returns metadata without decrypting values and still enforces read ACL.

Consequences
============

The advertised wildcard feature now works through the actual database.
Callers that relied on the previous erroneous implicit prefix behavior in
:php:`VaultService::list()` must append ``*`` to request a prefix match.
The repository's ``SecretFilters::prefix`` API retains its existing behavior.
The tests assert actual results instead of treating an adapter mock as proof of
pattern matching.
