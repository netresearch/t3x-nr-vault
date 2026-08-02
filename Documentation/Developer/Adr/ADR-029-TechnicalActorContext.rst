.. include:: /Includes.rst.txt

.. _adr-029-technical-actor-context:

=========================================================
ADR-029: Scoped technical-actor identity for headless use
=========================================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-07-17

Context
=======

Headless consumers — Symfony Messenger workers, scheduler runs, CLI jobs —
need vault-gated secrets under a **named** technical backend user:
per-consumer audit attribution, group-scoped vault ACL, per-user budget
windows in downstream extensions.
The global CLI access configuration (``allowCliAccess`` +
``cliAccessGroups``) is an all-or-nothing trusted-operator switch; it
cannot express "this worker acts as technical user X".

Because ``AccessControlService`` read only ``$GLOBALS['BE_USER']``,
consumers worked around this by mutating the global themselves for the
duration of a call (nr_ai_search ``BackendUserContext::runAs()``; nr_llm
ADR-052 documents the same pattern as a workaround).
That mutation is a footgun:

-  a temporarily privileged identity is visible to **all** code sharing
   the PHP process while the scope is open — from a shared frontend
   request that is exploitable;
-  every consumer re-implements hydration via ``@internal`` core APIs
   (``setBeUserByUid()``, raw ``->user`` reads);
-  restoration discipline (``finally``) is copied per consumer instead of
   guaranteed centrally.

Decision
========

Vault owns the impersonation seam:
``Netresearch\NrVault\Security\TechnicalActorContext::runAs(int $beUserUid, callable $fn): mixed``.

-  ``runAs()`` loads the ``be_users`` record itself (Doctrine
   QueryBuilder), refuses ``uid <= 0`` and deleted, disabled, or
   start/endtime-restricted users with typed
   ``TechnicalActorException`` codes, resolves groups through core's
   ``GroupResolver`` (the same resolution a real login gets, including
   subgroup expansion), and snapshots the result into an immutable
   ``TechnicalActor`` value object.
-  The actor lives on a per-service-instance **stack**; nested ``runAs()``
   calls stack cleanly with the innermost actor winning, and every scope
   is popped in ``finally`` — the identity cannot leak past the scope,
   including on exceptions.
-  ``AccessControlService`` consults the active technical actor **before**
   its BE_USER/CLI branches and evaluates it with the same user-based
   semantics an authenticated backend user gets: admin override — itself
   removable under the hardened profile, since it routes through the same
   ``adminBypassActive()`` seam — owner check, ADR-005 group tiers with
   stale-group filtering. ``$GLOBALS['BE_USER']`` is never touched.
-  Operation permissions resolve separately, because a technical actor has
   no session whose ``groupData`` could be consulted: ``secret.use`` is
   granted implicitly, and every other permission only if one of the
   actor's subgroup-expanded ``be_groups`` rows carries the matching
   ``tx_nrvault:<permission>`` custom option. Fail-closed on a missing
   group, a missing ``ConnectionPool`` or any database error.
-  Without an active scope every check falls through unchanged — ambient
   web/CLI behaviour is bit-identical (guarded by characterization
   tests).
-  The audit log records the technical actor as such:
   ``actor_type = 'technical'`` plus the actor's uid and username, sealed
   into the HMAC chain like every other attribution field (epoch 3,
   ADR-024).

Consequences
============

-  Consumers replace their ``$GLOBALS['BE_USER']`` mutation with a single
   ``TechnicalActorContextInterface::runAs()`` call; the ``@internal``
   core API reads live in one reviewed place inside vault.
-  ``runAs()`` is **not** authentication: any PHP code with DI access can
   act as any enabled backend user — the same power global mutation
   already grants every extension.
   The API adds validation, scoping, and honest audit attribution, not a
   new privilege boundary.
-  The audit ``actor_type`` vocabulary grows by ``'technical'``;
   analytics count it as an automated actor.
-  The technical actor's group snapshot is taken at scope entry; group
   changes during a long-running scope are not observed (same as a real
   BE session).
