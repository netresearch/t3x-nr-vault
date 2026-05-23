.. include:: /Includes.rst.txt

.. _adr-025-secret-entity-readonly:

=================================================
ADR-025: Secret entity is a readonly value object
=================================================

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

The original ``Domain\Model\Secret`` was a classic "anaemic + mutable"
entity: 28 fields, 28 ``set*()`` mutators, a ``Secret::create()``
named factory, and a ``setUid()`` mutator that the repository called
after ``INSERT`` to write back the auto-assigned UID into the
caller's reference.

The multi-axis review (H-5) flagged this for three reasons:

1.  **Aliased mutation is hard to reason about.** A controller hands
    a ``Secret`` to a service, the service mutates it, the
    repository mutates it again, an event listener mutates it once
    more — anyone holding the reference observes silent state
    changes.
2.  **The pattern leaks into wider TYPO3 code.** Downstream
    extensions consuming the entity inherit the mutable contract:
    they need to defensively clone or risk shared-state bugs.
3.  **Reviewer-found bugs were direct consequences.** A subsequent
    PR (#142 review) surfaced that ``SecretCreatedEvent`` would
    receive ``uid = null`` because the event dispatch happened
    against the pre-save instance — a regression that would have
    been impossible if the repository's write-back returned a new
    instance instead of mutating the input.

Decision
========

Convert ``Secret`` to a fully readonly value object:

-  Constructor promotion with ``readonly`` on all 28 fields.
-  All ``set*()`` mutators removed.
-  All ``$secret->getX()`` accessor methods retained as a
   compatibility shim; new code should use direct property access
   (``$secret->encryptedValue``).
-  Validation moves into the constructor (envelope-encryption triple
   must be all-set-or-all-empty); ``Secret::create()`` named factory
   removed.

Four named lifecycle transitions remain as ``with*()`` withers, each
returning a new instance:

-  ``withUid(?int)`` — repository attaches the post-INSERT UID
-  ``withValueRotation(EncryptedData, int $rotatedAt)`` — bundles
   the seven fields that change during a value rotation
-  ``withReEncryptedDek(string, string)`` — master-key rotation
   updates only the DEK envelope
-  ``withMetadata(array)`` — adapter merge

Each wither delegates to a private ``cloneWith(array $changes)``
helper that uses ``get_object_vars($this)`` spread to avoid the
N×28-arg duplication that would otherwise dominate the file.

Repository contract change
--------------------------

``SecretRepositoryInterface::save(Secret $secret): Secret`` (was ``void``).
On INSERT the returned instance carries the freshly-assigned UID;
on UPDATE the original is returned. Callers MUST capture the
return value if they need the UID — the input is readonly.

Same shape applied to ``VaultAdapterInterface::store(Secret $secret): Secret``
so events fired after ``adapter->store()`` see the populated UID.

Consequences
============

Positive
--------

-  Aliased mutation no longer possible. Defensive cloning becomes
   unnecessary throughout the codebase.
-  Two real bugs uncovered + fixed during the conversion:

   -  ``SecretCreatedEvent`` UID-null regression that this design
      makes structurally impossible.
   -  Pre-existing missing ``cruser_id`` column from
      ``toDatabaseRow()`` (silently ``cruser_id = 0`` since the
      entity was first written, surfaced via PR #142 review).

-  Tests significantly smaller and clearer: ~30 tautological
   "setX/getX round-trip" tests removed; constructor coverage
   subsumes them.

Negative
--------

-  Breaking API change for downstream extensions constructing
   ``Secret`` directly or calling ``set*()`` mutators. Migration is
   mechanical (named-args ctor + ``with*()``).
-  ``$repo->save($secret); $secret->getUid()`` no longer works —
   must capture the return value. CHANGELOG entry mandatory.

Verified
========

-  1711 unit tests pass after conversion (down from 1745 because
   tautological tests deleted; ``+369`` assertions net because
   surviving tests cover more behaviour per case).
-  Functional master-key rotation test exercises the full
   ``withReEncryptedDek → save`` round-trip end-to-end.

References
==========

-  Pull request: `#142 <https://github.com/netresearch/t3x-nr-vault/pull/142>`__
-  Follow-up: `#143 <https://github.com/netresearch/t3x-nr-vault/pull/143>`__
   (related table-routing audit triggered by this PR's review cycle)
