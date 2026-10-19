.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-046-flexform-copy-link-compensation:

=========================================================
ADR-046: Compensate failed final FlexForm copy links
=========================================================

Status
======

Accepted

Date
====

2026-10-10

Context
=======

ADR018 requires a failed copy to abandon its new secrets and clear references.
FlexForm cloning already handles a failed secret read/store. The final Core
XML serialization and record-link write run outside that boundary, however.
An actual eight-case native Unit counterexample stores a clone before either
final operation throws and proves that its compensation is skipped. A database
write can also take effect before its caller receives an exception.

Decision
========

Include final serialization and link persistence in the per-column clone
compensation boundary. On failure, abandon successfully stored clones and clear
all recognized source vault positions in that column while preserving other
FlexForm data. Keep plaintext zeroing and normal successful writes unchanged.

Always attempt the clearing update after a failed final link. Equality with
the initially read XML is insufficient: the failing write may already have
changed the record. Treat a failure to serialize or persist the cleared column
as uncertain record state. The existing correlation diagnostic states either
that the column was cleared or that the duplicate may still reference source
or abandoned cloned secrets and needs manual review. It never exposes the raw
failure cause to the editor.

Consequences
============

Cleanup remains best-effort and uses existing authorized/audited Vault deletes.
Successful clearing with failed cleanup can leave an orphan. Failed clearing
can retain a reference to a clone whose deletion already took effect; therefore
neither record rollback nor an always-unreferenced orphan is promised.

This decision closes the final-link boundary of one FlexForm column. Coordination
across columns or plain TCA fields, a store that persists before throwing, and
failing diagnostic providers remain separate audit work. No public interface,
database schema or global availability rule changes.

Related decisions
=================

- :ref:`adr-018-flexform-secret-lifecycle`
- :ref:`adr-036-mutation-audit-atomicity`
