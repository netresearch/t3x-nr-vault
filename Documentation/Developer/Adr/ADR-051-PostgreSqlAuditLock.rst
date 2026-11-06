.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-051-postgresql-audit-lock:

==========================================
ADR-051: PostgreSQL audit-chain lock
==========================================

Status
======

Accepted. Supersedes the platform restriction in
:ref:`adr-050-local-mutation-transactions`.

Date
====

2026-11-05

Context
=======

TYPO3 supports MySQL, MariaDB, PostgreSQL and SQLite. nr-vault wrote audit
entries only on SQLite and MySQL/MariaDB. Every non-SQLite connection took the
MySQL branch of ``AuditChainLockTrait`` and sent ``GET_LOCK("nr_vault_audit",
5)``. PostgreSQL has no ``GET_LOCK()`` and reads the double-quoted name as a
column, so every audited operation failed with SQLSTATE 42703: reads, HTTP
calls through the vault client, mutations and scheduler tasks
(`issue #494 <https://github.com/netresearch/t3x-nr-vault/issues/494>`__).
ADR-050 rejected PostgreSQL on the mutation path with code ``1793180003``; the
plain audit path had no such check.

Decision
========

Support PostgreSQL with a session-level advisory lock on one fixed bigint key.
``pg_try_advisory_lock()`` is polled every 50 ms for up to 5 seconds, the
bound ``GET_LOCK`` uses. ``pg_advisory_unlock()`` releases it at the point
where the MySQL branch calls ``RELEASE_LOCK()``.

The session-level lock matches the protocol the MySQL branch already follows:

- It is counted per session. Master-key rotation and a coordinated mutation
  acquire it again for the audit writes inside them, and the inner acquire
  returns at once.
- It survives a commit. A coordinated mutation (``VaultMutationTransaction``)
  keeps it until its own commit and releases it before publishing to sinks,
  as on MySQL. Master-key rotation releases it at the end of
  ``rekeyAuditChain()``, before the outer commit; that window exists on MySQL
  as well and is tracked in
  `issue #496 <https://github.com/netresearch/t3x-nr-vault/issues/496>`__.

The non-blocking function is chosen over ``pg_advisory_lock()`` with a
``lock_timeout``. A lock wait that ends in an error aborts the whole
PostgreSQL transaction, including a caller's outer transaction during
master-key rotation. ``pg_try_advisory_lock()`` answers false and leaves the
transaction usable.

The transaction-level ``pg_advisory_xact_lock()`` and
``pg_try_advisory_xact_lock()`` are not used either. They are released by the
commit, before the coordinator publishes.

PostgreSQL sequences do not roll back, like MySQL ``AUTO_INCREMENT``. The
explicit-UID allocation from ADR-050 therefore applies to PostgreSQL too: when
a verified enabled anchor matches the current tip, the next entry takes the
following UID. An explicit UID does not advance a PostgreSQL sequence, so the
writer sets the sequence to that UID with ``setval()`` under the same lock.
Without it, the next entry that takes the sequence (anchoring disabled or not
matching) would collide with an existing row.

Three more PostgreSQL defects surfaced once the lock worked, and are fixed
alongside it:

- ``value_checksum``, ``hash_before`` and ``hash_after`` were ``char(64)``.
  PostgreSQL returns ``char`` values padded with spaces, which broke the
  cryptographic-field check and hash verification. They are ``varchar(64)``.
- ``encrypted_value`` is ``bytea`` on PostgreSQL, which PDO returns as a
  stream. ``Secret::fromDatabaseRow()`` reads the stream.
- ``AuditLogService::query()`` ordered by ``crdate`` alone. Entries from the
  same second came back in arbitrary order; ``uid`` now breaks the tie.

Consequences
============

``VaultMutationTransaction`` accepts PostgreSQL. Any platform other than
SQLite, MySQL/MariaDB and PostgreSQL is still rejected with ``1793180003``.

``setval()`` is not transactional. When the transaction that set it rolls
back, the sequence stays one ahead of the table. The next anchored write takes
an explicit UID again, so nothing changes there. A write without a matching
anchor then leaves a one-UID gap, which is the same gap MySQL leaves after a
rollback in that mode.

The advisory-lock key is shared by every database user of the same database.
Another application that picks the same bigint would serialise with the audit
writer. The key is the ASCII value of ``nrvaudit``, which a small-integer key
cannot reach.

Verification
============

Unit tests pin the lock protocol per platform. The functional suite runs
against PostgreSQL with ``Build/Scripts/runTests.sh -s functional -d
postgres``.
