.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-047-hook-diagnostic-containment:

=======================================================
ADR-047: Contain failed hook diagnostic writes
=======================================================

Status
======

Proposed

Date
====

2026-10-10

Context
========

The cause-independent hook reporter sends a server-side diagnostic before
returning a correlated message to the editor.
A failing PSR-3 writer instead propagates its own exception.
An actual public FlexForm copy counterexample proves this can interrupt clone
compensation before the column's references are cleared.
This is the diagnostic-provider boundary left open by ADR046.

Decision
========

Attempt the existing PSR-3 error write once and contain its Throwable failures.
Return the same sanitized, cause-independent user diagnostic so callers can
continue their existing refusal or compensation.
Keep accepted server records unchanged and avoid recursive fallback logging.

This boundary concerns secondary diagnostics.
Required Vault mutation auditing, storage and permission failures keep their
existing propagation and compensation contracts.
A failed clone deletion remains a failed deletion; containing its diagnostic
writer allows reference clearing to continue, not a claim of atomic rollback.

Consequences
============

A correlation reference still identifies the attempted diagnostic, but a failed
writer may leave no corresponding server record.
Neither an attempt nor a returned user message proves diagnostic delivery.
Core record logs and language-service failures remain distinct boundaries.
There is no new public signature, database schema or fallback writer.

Related decisions
=================

- :ref:`adr-046-flexform-copy-link-compensation`
- :ref:`adr-036-mutation-audit-atomicity`
