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
  as on MySQL. Master-key rotation takes it for the chain re-key and releases
  it after its outer commit or rollback
  (`issue #496 <https://github.com/netresearch/t3x-nr-vault/issues/496>`__).

The non-blocking function is chosen over ``pg_advisory_lock()`` with a
``lock_timeout``. A lock wait that ends in an error aborts the whole
PostgreSQL transaction, including a caller's outer transaction during
master-key rotation. ``pg_try_advisory_lock()`` answers false and leaves the
transaction usable.

The transaction-level ``pg_try_advisory_xact_lock()`` is not used either.
Its release at commit would fit the coordinator, which already releases the
MySQL lock after the commit and before publishing. But it has to be taken
inside the transaction, so the first lock poll starts the transaction's
snapshot. Under ``REPEATABLE READ`` the writer would then read the chain tip
as it was before the lock was granted. The session lock is taken before
the writer's own ``BEGIN``, so a standalone writer and a coordinated mutation
read the tip after the lock is granted at any isolation level. Master-key
rotation is the exception: its outer transaction is already open when the
audit writes take the lock, so under ``REPEATABLE READ`` its snapshot could
predate the lock, on MySQL with the InnoDB default as well. The rotation
therefore runs its transaction in ``READ COMMITTED``
(`issue #496 <https://github.com/netresearch/t3x-nr-vault/issues/496>`__).

PostgreSQL sequences do not roll back, like MySQL ``AUTO_INCREMENT``. The
explicit-UID allocation from ADR-050 therefore applies to PostgreSQL too: when
a verified enabled anchor matches the current tip, the next entry takes the
following UID. An explicit UID does not advance a PostgreSQL sequence, so the
writer sets the sequence to that UID with ``setval()`` under the same lock.
Without it, the next entry that takes the sequence (anchoring disabled or not
matching) would collide with an existing row.

Two more PostgreSQL defects surfaced once the lock worked, and are fixed
alongside it:

- ``value_checksum``, ``hash_before`` and ``hash_after`` were ``char(64)``.
  PostgreSQL returns ``char`` values padded with spaces, which broke the
  cryptographic-field check and hash verification. They are ``varchar(64)``.
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

``setval()`` needs the ``UPDATE`` privilege on the sequence behind
``tx_nrvault_audit_log.uid``. The table owner holds it. A database user that
was granted only table privileges fails the first anchored audit write, and
the mutation it belongs to is rolled back.

The advisory-lock key is shared by every database user of the same database.
Another application that picks the same bigint would serialise with the audit
writer. The key is the ASCII value of ``nrvaudit``, which a small-integer key
cannot reach.

A session-level advisory lock needs one server connection per database
session. PgBouncer in transaction pooling mode does not provide that: its
feature table lists session-level advisory locks as not supported in that mode.
The lock would then not serialise the audit writes, and its release could miss.
TYPO3 has the same requirement independently of nr-vault, because the
database driver reads a new row's ID with a separate ``SELECT LASTVAL()``.
Run PostgreSQL behind PgBouncer in session pooling mode, or connect directly.

Verification
============

Unit tests pin the lock protocol per platform. The functional suite runs
against PostgreSQL with ``Build/Scripts/runTests.sh -s functional -d
postgres``.
