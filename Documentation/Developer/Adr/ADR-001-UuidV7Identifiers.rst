.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-001-uuid-v7:

=======================================
ADR-001: UUID v7 for secret identifiers
=======================================

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

The nr-vault extension needs a reliable, collision-free identifier format for
secrets stored in the vault. These identifiers are:

-  Stored in the database column of the TCA/FlexForm field
-  Used to look up the actual secret value from the vault
-  Part of audit logs and metadata
-  Potentially used in B-tree indexed database columns

Initially, a human-readable format was considered
(``{table}__{field}__{uid}``), but this approach has drawbacks:

-  Exposes internal database structure in identifiers
-  Requires parsing logic to extract components
-  Not suitable for secrets without direct TCA record association
-  Long identifiers for FlexForm fields

Problem statement
=================

What identifier format should be used for vault secrets that:

1. Is guaranteed unique across all installations
2. Performs well in database indexes
3. Does not leak internal structure information
4. Supports both TCA-managed and manually created secrets

Decision drivers
================

-  **Uniqueness**: Must be collision-free without central coordination
-  **Performance**: Should be efficient for B-tree database indexes
-  **Security**: Should not expose internal database structure
-  **Simplicity**: Easy to generate and validate
-  **Debuggability**: Helpful for troubleshooting when possible

Considered options
==================

Option 1: Human-readable format
-------------------------------

Format: ``{table}__{field}__{uid}`` (e.g., ``tx_myext__api_key__42``)

**Pros:**

-  Human-readable, easy to understand
-  Contains context about the secret's source

**Cons:**

-  Exposes internal database structure
-  Complex format for FlexForm fields
-  Requires parsing logic
-  Not suitable for non-TCA secrets

Option 2: UUID v4 (random)
--------------------------

Format: ``xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx``

**Pros:**

-  Simple to generate
-  Widely supported
-  No information leakage

**Cons:**

-  Random distribution causes poor B-tree index performance
-  No time-ordering (debugging harder)
-  Index fragmentation over time

Option 3: UUID v7 (time-ordered)
--------------------------------

Format: ``xxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx``

**Pros:**

-  Time-ordered (48-bit millisecond timestamp)
-  Excellent B-tree index performance
-  Timestamp aids debugging
-  Collision-free with randomness
-  RFC 9562 standardized

**Cons:**

-  Slightly more complex generation
-  Timestamp visible in identifier (minor information leak)

Option 4: GUID (Microsoft format)
---------------------------------

Similar to UUID v4 but with different byte ordering.

**Pros:**

-  Familiar to Windows developers

**Cons:**

-  Non-standard in Unix/Linux environments
-  Same performance issues as UUID v4

Decision
========

We chose **UUID v7** because:

1. **Index performance**: Time-ordering ensures new secrets append to B-tree
   indexes rather than causing random inserts and page splits.
2. **Debuggability**: The embedded timestamp helps identify when secrets were
   created, useful for audit and troubleshooting.
3. **Simplicity**: Standard format, easy to validate with regex.
4. **Future-proof**: RFC 9562 standardized, replacing deprecated UUID versions.

Implementation
==============

UUID v7 generation
------------------

.. code-block:: php
   :caption: UUID v7 generation in DataHandlerHook

   private function generateUuid(): string
   {
       // 48-bit timestamp in milliseconds
       $time = (int) (microtime(true) * 1000);
       $random = random_bytes(10);

       return sprintf(
           '%08x-%04x-7%03x-%04x-%012x',
           ($time >> 16) & 0xFFFFFFFF,
           $time & 0xFFFF,
           ord($random[0]) << 4 | ord($random[1]) >> 4 & 0x0FFF,
           (ord($random[1]) & 0x0F) << 8 | ord($random[2]) & 0x3FFF | 0x8000,
           (ord($random[3]) << 40) | (ord($random[4]) << 32)
               | (ord($random[5]) << 24) | (ord($random[6]) << 16)
               | (ord($random[7]) << 8) | ord($random[8]),
       );
   }

UUID v7 validation
------------------

Pattern used to validate UUID v7 identifiers:

.. code-block:: php
   :caption: UUID v7 validation pattern

   private const string UUID_PATTERN =
       '/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';

   public static function isVaultIdentifier(mixed $value): bool
   {
       if (!is_string($value) || $value === '') {
           return false;
       }

       return preg_match(self::UUID_PATTERN, $value) === 1;
   }

Example identifiers
-------------------

Valid UUID v7 examples::

   01937b6e-4b6c-7abc-8def-0123456789ab
   01937b6f-0000-7000-8000-000000000000
   01937b6f-ffff-7fff-bfff-ffffffffffff

The format components:

-  Positions 1-8: Timestamp (high bits)
-  Positions 10-13: Timestamp (low bits)
-  Position 15: Version (always ``7``)
-  Positions 16-18: Random data
-  Position 20: Variant (``8``, ``9``, ``a``, or ``b``)
-  Positions 21-23: Random data
-  Positions 25-36: Random data

Consequences
============

Positive
--------

-  **Excellent index performance**: Time-ordered UUIDs append to indexes,
   avoiding random inserts and page splits.
-  **No structure leakage**: Identifiers don't reveal table/field names.
-  **Unified format**: Same identifier format for TCA fields, FlexForm fields,
   and manually managed secrets.
-  **Debuggable timestamps**: Creation time can be extracted for diagnostics.
-  **RFC standardized**: Future-proof, widely supported format.

Negative
--------

-  **No context in identifier**: Cannot determine source table/field from
   identifier alone (use metadata instead).
-  **Timestamp visible**: Minor information leak about creation time.

Risks
-----

-  Clock skew on distributed systems could affect ordering (mitigated by
   random component).
-  Migration from old format required for existing installations.

Related decisions
=================

-  Human-readable identifiers remain available for manually managed secrets
   via the :php:`VaultService` API (e.g., ``my_extension_api_key``).
-  TCA-managed secrets always use UUID v7 format.

References
==========

-  `RFC 9562 - UUID Version 7 <https://www.rfc-editor.org/rfc/rfc9562>`_
-  `UUID v7 vs v4 Performance <https://www.percona.com/blog/uuids-are-popular-but-bad-for-performance-lets-discuss/>`_
