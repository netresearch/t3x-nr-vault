.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-021-batch-secret-loading:

=============================================
ADR-021: Batch secret loading
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

``VaultService::list()`` suffered from an N+1 query problem. For N secrets,
the implementation executed:

-  1 query to fetch the secret records
-  N queries to resolve each secret's MM group relations (allowed_groups)
-  N queries for additional per-secret metadata

This resulted in 1+2N database queries, meaning a vault with 50 secrets
required 101 queries for a single list operation. This scaled poorly and
caused noticeable latency in the backend module.

Decision
========

Add a ``findAllWithFilters()`` repository method that uses batch loading
to resolve all data in a constant number of queries:

-  **Query 1**: Fetch all matching secret records with filters applied.
-  **Query 2**: Batch-load all MM group relations for the fetched secrets
   in a single query using ``WHERE uid_local IN (...)``.

Group assignments are then mapped to their respective secrets in PHP,
avoiding per-secret queries entirely.

Consequences
============

Positive
--------

-  **Constant query count**: Exactly 2 queries regardless of the number of
   secrets, eliminating the N+1 problem.
-  **Predictable performance**: List operations scale with result set size
   in PHP, not in database round-trips.
-  **Backward compatible**: The existing ``list()`` API is preserved;
   the optimization is internal to the repository layer.

Negative
--------

-  **Memory usage**: All matching secrets and their group relations are
   loaded into memory at once. For very large vaults, pagination should
   be used.
-  **Complexity**: The batch MM resolution logic is more complex than the
   straightforward per-record approach.

Related decisions
=================

-  :ref:`adr-005-access-control` - Group-based access control requiring MM resolution
-  :ref:`adr-007-secret-metadata` - Secret metadata model
