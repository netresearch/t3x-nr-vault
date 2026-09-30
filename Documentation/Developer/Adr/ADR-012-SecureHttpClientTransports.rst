.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-012-secure-http-transports:

=================================================
ADR-012: SecureHttpClient API and transports
=================================================

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

Multiple extensions need to call external HTTP services with centralized credentials,
policies, and audit. We need:

-  a stable, minimal public PHP API,
-  a clean boundary between "product logic" (registry/policy/audit) and "transport engine".

We also want optional Rust (FFI or later sidecar) without forcing it on everyone.

Decision
========

We define a public ``SecureHttpClientInterface`` and a transport abstraction:

SecureHttpClient (product logic)
--------------------------------

-  Resolves service by ``serviceId``
-  Loads credential set
-  Enforces policy (deny-by-default)
-  Executes request via a configured transport backend
-  Records audit metadata
-  Returns a response wrapper

TransportInterface (engine)
---------------------------

.. code-block:: php
   :caption: TransportInterface

   interface TransportInterface
   {
       public function send(RequestSpec $request): ResponseSpec;
   }

Backends:

-  ``PhpTransport`` (default; PSR-18 or Symfony HttpClient)
-  ``RustFfiTransport`` (optional)
-  (future) ``SidecarTransport``

Consumers never talk to transports directly; they only use ``SecureHttpClientInterface``.

Consequences
============

Positive
--------

-  Decouples governance logic from transport implementation
-  Allows fallback and progressive rollout of Rust
-  Keeps API surface small and stable for consumers
-  Avoids "typed DTO in Rust" trap: response is raw/json in PHP

Negative
--------

-  Slight abstraction overhead
-  Requires careful policy enforcement placement (must not be bypassable)

Alternatives considered
=======================

Let consumers pick HTTP client directly
---------------------------------------

Allow consumers to use PSR-18 clients directly.

**Rejected**: loses central policy enforcement and audit guarantees.

Make Rust mandatory
-------------------

Require Rust transport for all installations.

**Rejected**: adoption killer; too many environments can't/won't run native code.

Related decisions
=================

-  :ref:`adr-008-http-client` - Current HTTP client (extended by this decision)
-  :ref:`adr-010-secure-outbound` - Parent decision for Secure Outbound feature
-  :ref:`adr-013-rust-ffi-preload` - Rust FFI production configuration
