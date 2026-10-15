.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-045-flexform-delete-refusal:

==================================================
ADR-045: Preflight and contain FlexForm deletion
==================================================

Status
======

Accepted; implement through the dependent deletion repair.

Date
====

2026-10-10

Context
=======

ADR-018 requires a refused vault deletion to cancel the owning record deletion.
The FlexForm hook instead caught a failed secret deletion and left Core's
cancellation flag unchanged. A real Core DataHandler test with the actual vault
ACL denied the secret deletion, wrote an ``access_denied`` audit and then
removed the owning record while its secret survived.

ADR-036 L1 separately states the preflight and best-effort boundary for
multi-field records. It does not promise that a later independent secret
deletion can restore earlier deletions.

Decision
========

For a hard-deleting record, collect unique, existing, non-shared references
from all its FlexForm columns and preflight every selected identifier through
``VaultServiceInterface::assertDeletable()`` before the first secret deletion.
Use the same service for the actual deletions.

On discovery, authorization or deletion failure, stop the cascade and set
Core's existing cancellation flag before invoking diagnostics. Report the
existing correlation reference to the editor without including the raw cause. On success, leave Core to
remove its record normally. A duplicate reference is processed once.

Sharing is an exclusion for the complete identity: if any discovered column
is shared, another occurrence in an unshared column cannot select that secret
for deletion. This holds regardless of the order of the FlexForm columns.

Keep FlexForm soft-delete/recycle behavior: its secrets remain available for
record restoration. Translation-shared secrets remain outside this record's
cascade. No public interface is extended and no second ACL path is introduced.

Consequences
============

A denied preflight leaves all selected secrets and the owning record intact.
A deletion failure retains the record and stops the remaining cascade,
but already-applied secret deletions cannot be undone automatically. The
failing current operation may itself have persisted its deletion before a
``SecretDeletedEvent`` observer throws. The editor diagnostic must say that
secrets may already have been deleted; it must not imply rollback or promise
that the failing target is intact. Cancellation is set before reporting so a
diagnostic failure cannot defer that protection.

This is a preflight within the FlexForm hook. A record mixing plain TCA vault
fields and FlexForm fields still needs a separate cross-hook coordination
repair; this decision does not claim that guarantee. Copy compensation is
also outside this deletion repair.

Related decisions
=================

- :ref:`adr-018-flexform-secret-lifecycle`
- :ref:`adr-036-mutation-audit-atomicity`
