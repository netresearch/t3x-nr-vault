.. include:: /Includes.rst.txt

.. _adr-024-audit-hash-forensic-fields:

==================================================
ADR-024: Audit hash payload covers forensic fields
==================================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-05-21

Context
=======

The HMAC audit hash chain introduced in :ref:`adr-023-audit-hash-chain-hmac`
(epoch 1) binds only **identity fields** into each entry's hash:

-  ``uid``
-  ``secret_identifier``
-  ``action``
-  ``actor_uid``
-  ``crdate``
-  ``previous_hash``

A subsequent security review (the "multi-axis review" — H-4) showed this
leaves the forensic fields **unauthenticated**. A database-privileged
attacker can rewrite any of:

-  ``success`` (flip a denied access from ``0 → 1`` to make a rejection
   look like an approval),
-  ``error_message`` (rewrite the audit narrative — "Decryption failed:
   wrong master key" becomes ""),
-  ``reason`` (alter the human-readable justification),
-  ``ip_address`` / ``user_agent`` (misattribute the action to a
   different client),
-  ``hash_before`` / ``hash_after`` (change the secret-state checksum
   without breaking the chain),
-  ``context`` (rewrite the JSON-encoded contextual payload),

...without breaking the chain. Each row's HMAC is still valid because
the HMAC only covers identity fields — the forensic fields the audit
log *exists to preserve* are not actually tamper-evident.

Decision
========

Introduce **epoch 2**: extend the HMAC payload to cover identity AND
forensic fields. The new payload is a canonical JSON object containing
all of:

-  ``uid``, ``secret_identifier``, ``action``, ``actor_uid``, ``crdate``,
   ``previous_hash`` (from epoch 1)
-  ``success``, ``error_message``, ``reason``, ``ip_address``,
   ``user_agent``, ``hash_before``, ``hash_after``, ``context`` (NEW)

Encoded with ``JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE |
JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE`` so the byte sequence
that feeds into the HMAC is canonical (no escape drift across PHP
versions, no crash on invalid UTF-8 in attacker-controlled
``user_agent`` / ``error_message`` fields).

Existing epoch-0 (SHA-256) and epoch-1 (HMAC v1) entries continue to
verify under their stored ``hmac_key_epoch`` column. ``DEFAULT_AUDIT_HMAC_EPOCH``
moves to 2 so fresh installs write epoch-2 from day one; existing
installs migrate via the existing ``AuditHmacMigrationWizard`` /
``vault:audit-migrate-hmac`` CLI.

Migration tooling generalised: the wizard's gate condition changes from
"any epoch-0 row exists" to "any row below the configured target
epoch", so a 1 → 2 upgrade also surfaces in the Install Tool.

Consequences
============

Positive
--------

-  ``success`` flip from ``false → true`` now breaks the chain.
-  Rewriting ``error_message`` / ``reason`` / IP / UA / context now
   breaks the chain.
-  Attribution forensic value is preserved across the entire log
   surface, not just the identity columns.
-  Forward compatibility: the epoch column lets us add epoch 3 later
   without breaking any existing entries.

Negative
--------

-  Slightly larger HMAC payload (~10× the byte count of v1) — negligible
   on modern hardware; HMAC-SHA256 is constant-time per byte.
-  Existing installs need a one-time migration run before any
   verification of pre-upgrade rows reports the new payload.

Verified
========

-  Unit tests cover identity-field-only verification of epoch 0/1 rows,
   forensic-field-only verification of epoch 2 rows, and a mixed-epoch
   chain that walks both algorithms across a single ``verifyHashChain()``
   call.
-  Regression guards:
   ``verifyHashChainEpoch2DetectsForensicTampering`` flips a ``success``
   value in storage and asserts the verifier returns
   ``isValid() === false``.

References
==========

-  Pull request: `#138 <https://github.com/netresearch/t3x-nr-vault/pull/138>`__
-  Previous: :ref:`adr-023-audit-hash-chain-hmac`
-  Related: :ref:`adr-006-audit-logging`
