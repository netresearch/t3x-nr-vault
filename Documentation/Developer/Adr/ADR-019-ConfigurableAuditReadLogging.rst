.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-019-configurable-audit-read-logging:

=============================================
ADR-019: Configurable audit read logging
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

Every call to ``VaultService::retrieve()`` wrote audit log entries,
resulting in three database operations per read (fetch secret, write audit
entry, update hash chain). In frontend rendering scenarios where multiple
vault references are resolved per page request, this caused significant
performance overhead.

For a typical page with 5 vault-backed content elements, this meant 15
additional database operations per page render solely for audit logging of
read operations. Write operations (create, update, delete, rotate) are
infrequent and their audit overhead is acceptable, but read operations
dominate in frontend contexts.

Decision
========

Add an ``auditReads`` configuration option that controls whether read
(retrieve) operations are written to the audit log:

-  **When enabled** (default for backend): Every ``retrieve()`` call is
   audit-logged, preserving full read traceability.
-  **When disabled**: Read operations skip the audit log write, eliminating
   2 of the 3 database operations per retrieve call.

Write operations (create, update, delete, rotate) are always audit-logged
regardless of this setting. The option is designed for use in
performance-sensitive contexts such as frontend rendering, where read audit
is less critical than in backend administrative contexts.

Consequences
============

Positive
--------

-  **~60% fewer DB operations** for frontend vault reference resolution
   (from 3 to 1 per retrieve call).
-  **Configurable per context**: Backend can retain full read auditing while
   frontend skips it.
-  **No impact on write auditing**: All mutating operations remain fully
   logged.

Negative
--------

-  **Reduced read traceability**: When disabled, there is no audit record of
   which secrets were read in frontend contexts.
-  **Configuration complexity**: Operators must understand the security
   trade-off when disabling read auditing.

Related decisions
=================

-  :ref:`adr-006-audit-logging` - Core audit logging model
-  :ref:`adr-017-audit-metadata-retention` - Audit metadata retention policy
