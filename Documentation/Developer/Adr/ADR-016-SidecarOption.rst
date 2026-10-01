.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-016-sidecar-option:

=============================================
ADR-016: Sidecar daemon option
=============================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-01-12

Context
=======

FFI does not provide true isolation. If the threat model includes "PHP process
compromise", a separate process (sidecar/daemon) running under different OS
permissions can provide stronger separation:

-  Master key not readable by PHP process user
-  Narrower filesystem and network capabilities
-  Independent hardening and observability

We don't want to block MVP with sidecar complexity, but we must not paint
ourselves into a corner.

Decision
========

-  The transport abstraction (:ref:`adr-012-secure-http-transports`) remains
   compatible with a future ``SidecarTransport``
-  Request/response specs are designed to be serializable (e.g., JSON or binary
   framing) so that FFI and sidecar can share the same protocol shape
-  Sidecar mode is explicitly a Phase 3 candidate, not MVP scope

Consequences
============

Positive
--------

-  Preserves an upgrade path to stronger isolation without breaking consumers
-  Allows security-conscious customers to adopt a more robust deployment model
   later

Negative
--------

-  Some design choices (spec framing, error taxonomy) must be slightly more
   disciplined early on

Alternatives considered
=======================

Commit only to FFI and ignore sidecar
-------------------------------------

Do not support a sidecar mode at all.

**Rejected**: too limiting for serious security requirements.

Start with sidecar immediately
------------------------------

Build sidecar mode from the start.

**Rejected**: slows down MVP and increases operational burden prematurely.

Related decisions
=================

-  :ref:`adr-012-secure-http-transports` - Transport abstraction (enables sidecar)
-  :ref:`adr-013-rust-ffi-preload` - FFI mode (alternative to sidecar)

