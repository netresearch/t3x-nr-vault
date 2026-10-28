.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-050-local-mutation-transactions:

==========================================
ADR-050: Local mutation transactions
==========================================

Status
======

Accepted. Supersedes the programmatic local-adapter compensation design in
:ref:`adr-036-mutation-audit-atomicity`.

Date
====

2026-10-28

Context and failure modes
=========================

Writing a secret and then compensating a failed audit write does not provide
crash atomicity. A process can disappear between the two writes. A failure
while writing the second ACL tier can leave the secret and first tier behind
before the audit call is even reached. A compensating write can also restore
a stale snapshot over another request's successful change.

The audit lock already supports nested Doctrine savepoints. Its previous
description as incompatible with outer transactions was outdated. However,
simply adding an outer transaction still releases the audit lock and publishes
external evidence too early: a savepoint release is not a durable commit.

Decision
========

Coordinate ``VaultService::store()``, ``rotate()``, ``delete()`` and
``setEnabled()`` when using the stock local adapter, repository and audit
service. One shared ``VaultMutationTransaction`` owns the transaction before
the initial lookup and through the outer commit. No compensating secret write
runs on this path. Database errors roll back the whole pending change.

Require identical actual connections for the secret, both ACL MM tables,
audit table and ``sys_registry`` before writing. Reject an already active
caller transaction: without a callback for its final commit, this service
cannot correctly publish events or release its lock at the durable boundary.
Manually constructed services must share the coordinator and actual database
connection; an unsupported construction must not be described as atomic.

Hold MySQL/MariaDB's counted audit advisory lock through the outer commit.
SQLite uses a Doctrine-managed transaction, so the audit writer nests through
a savepoint. An overlapping stale SQLite reader may fail with ``SQLITE_BUSY``;
the guarantee is rollback of that attempt, not automatic eventual completion.

MySQL auto-increment reservations survive rollback. When a verified enabled
anchor matches the current tip, allocate the next UID from that tip under the
same lock. This prevents an aborted audit insert from creating a false gap
alarm. Without a healthy matching anchor, retain the previous auto-increment
behavior so a missing tail is not silently replaced with reused numbers.

Queue external sink publication and successful mutation events until commit
and lock release. A listener or external sink cannot roll back a completed
database commit. Failed access-denied audit entries are replayed after a
rollback, outside the aborted transaction. No successful mutation entry is
replayed after rollback.

Consequences and limits
=======================

The stock local service paths atomically commit their applicable secret/ACL
changes, successful audit entry and healthy enabled audit-tip update. This
assumes transactional tables, database atomic commit and no dirty reads.
It does not verify storage durability settings or the database engine.

Custom adapters and audit implementations retain their existing integration
contract. Direct repository writes, DataHandler/TCA metadata and deferred MM
writes, master-key rotation and read counters have separate boundaries. This
decision supplies no extension-wide or arbitrary adapter atomicity guarantee.
Disabled anchoring and deliberately preserved corrupt/missing anchors remain
separate integrity states. External delivery is best effort; a process can die
after commit before publication. Reliable eventual delivery needs a separately
specified durable outbox and retry protocol.

Verification
============

``Tests/Formal`` contains a finite two-request TLA+ model. Its successful
configuration checks mutation/audit correspondence, chain ordering and rollback
isolation. Known-bad controls must exhibit the crash gap and stale compensation.
Additional reachability checks prevent an unreachable-success model from
passing vacuously. ``Build/Scripts/check-formal.sh`` pins TLC and rejects parse
errors, timeouts and unexpected negative-control failures. The separate
``Formal Model`` workflow runs these checks on pull requests and merge groups.

Functional tests execute database failures, process termination and overlapping
requests against the actual service. Unit tests cover transaction ownership and
post-commit effects. The mapping and assumptions are maintained in
``Tests/Formal/README.md``. These checks connect the model to the code; they are
not a formal refinement proof of PHP, TYPO3, the database or cryptography.
