.. include:: /Includes.rst.txt

.. _adr-023-audit-hash-chain-hmac:

=============================================
ADR-023: Audit hash chain HMAC consideration
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

The current audit hash chain (see :ref:`adr-006-audit-logging`) uses plain
SHA-256 hashing without a secret key. While this provides tamper detection
against accidental corruption or naive modification, an attacker with
database-level access can recompute valid hashes after altering audit log
entries, rendering the chain ineffective against adversarial tampering.

The original hash chain was designed for tamper *detection* (corruption,
accidental modification), not for tamper *resistance* against
database-privileged attackers. This threat model gap was identified during
a subsequent security review.

Decision
========

Migrate the audit hash chain from plain SHA-256 to HMAC-SHA256,
keyed with an HMAC key derived from the master key:

-  The HMAC key is derived from the master key using HKDF with a
   dedicated context string, ensuring cryptographic separation from the
   encryption key.
-  New audit entries are signed with HMAC-SHA256 instead of plain
   SHA-256.
-  An epoch-based migration separates legacy SHA-256 entries (epoch 0)
   from new HMAC-SHA256 entries (epoch 1+).

Implementation details
----------------------

HMAC key derivation
~~~~~~~~~~~~~~~~~~~

The HMAC key is derived from the master key using HKDF:

.. code-block:: php
   :caption: HMAC key derivation

   $hmacKey = hash_hkdf('sha256', $masterKey, 32, 'nr-vault-audit-hmac-v1');

The ``info`` parameter ``"nr-vault-audit-hmac-v1"`` provides cryptographic
domain separation, ensuring the HMAC key is independent of any encryption
key material derived from the same master key.

Epoch-based migration
~~~~~~~~~~~~~~~~~~~~~

Rather than rehashing all existing entries, a "chain epoch" marker separates
legacy entries from HMAC-authenticated entries:

-  **Epoch 0**: Legacy SHA-256 entries (pre-migration). These entries remain
   as-is and are verified using plain ``hash('sha256', ...)``.
-  **Epoch 1+**: HMAC-SHA256 entries (post-migration). These entries are
   created and verified using ``hash_hmac('sha256', ..., $hmacKey)``.

The verifier handles both epochs transparently, selecting the appropriate
algorithm based on the epoch marker stored with each entry.

Migration command
~~~~~~~~~~~~~~~~~

The CLI command ``vault:audit-migrate-hmac`` migrates existing audit log
entries from epoch 0 to epoch 1. See :ref:`command-audit-migrate-hmac` for
usage details.

Trade-offs
==========

Benefits
--------

-  **Adversarial resistance**: An attacker with database access but without
   the master key cannot forge valid HMAC values.
-  **Cryptographic separation**: HKDF-derived HMAC key is independent of
   the encryption key material.
-  **Standards alignment**: HMAC-SHA256 is the standard construction for
   keyed message authentication.

Risks
-----

-  **Data migration**: Existing hash chain entries are left as a legacy
   epoch (epoch 0) until migrated via the ``vault:audit-migrate-hmac``
   command.
-  **HMAC key lifecycle**: The epoch value is an algorithm/version marker,
   not a key diversifier — the HMAC key is always derived identically from
   the current master key regardless of the epoch number. Master key
   rotation requires re-deriving the HMAC key. After master key rotation,
   a new epoch should be started so the verifier knows which key was used.
   If the old master key is discarded, verification of historical entries
   derived from it becomes impossible unless the old HMAC key is retained
   separately.
-  **Operational complexity**: Introduces a dependency between the audit
   subsystem and the master key provider, coupling two previously
   independent components.

Scope of the tamper-evidence claim
----------------------------------

The HMAC chain authenticates the rows that are present. It says nothing about
rows that were removed: deleting the tail (or the whole table) leaves a
self-consistent chain. That gap is closed separately by the tip anchor in
:ref:`adr-034-audit-chain-tip-anchor`, which pins "row ``uid = A`` still exists
with ``entry_hash = H``" in ``sys_registry`` under an HKDF-separated MAC key.

With the anchor armed, tail truncation and a full wipe are detectable against a
database-write attacker without the master key. An attacker who also deletes the
anchor row degrades the installation to the pre-anchor behaviour, but does so
*with a warning* rather than silently — and with ``auditAnchorRequired`` enabled,
with an error.

Why not implemented initially
=============================

The hash chain was designed for tamper *detection* -- catching corruption,
accidental modification, or naive tampering. The threat model did not
originally include database-privileged attackers who could recompute hashes.

This was a deliberate scoping decision: the initial implementation
prioritized self-contained integrity checking without external key
dependencies. The HMAC enhancement represents a threat model upgrade
identified during security review.

Related decisions
=================

-  :ref:`adr-006-audit-logging` - Core audit logging model with hash chain
-  :ref:`adr-003-master-key-management` - Master key from which HMAC key
   would be derived
