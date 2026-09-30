.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-013-rust-ffi-preload:

=============================================
ADR-013: Rust FFI preload-only mode
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

PHP FFI is powerful but increases attack surface if enabled broadly. Dynamic
``FFI::cdef()`` at runtime allows binding arbitrary native symbols, which is
risky in web contexts.

We need a production-safe operational model that reduces risk and keeps behavior
predictable.

Decision
========

If we ship/use a Rust FFI transport, we require:

-  Production deployments run with ``ffi.enable=preload`` (or an equivalent
   hardened configuration)
-  FFI bindings are created in preload (e.g. ``opcache.preload``) and not
   dynamically in request handling
-  The PHP layer exposes only a limited wrapper API (no arbitrary symbol access)
-  We provide a non-FFI fallback transport and keep it as the default

Consequences
============

Positive
--------

-  Smaller attack surface vs full runtime FFI
-  More predictable behavior and better operability
-  Easier to audit what native code is actually callable

Negative
--------

-  Requires ops work (preload configuration)
-  Some hosting environments will still refuse FFI entirely → fallback must work

Alternatives considered
=======================

Enable full FFI at runtime
--------------------------

Use ``ffi.enable=true`` to allow dynamic FFI calls.

**Rejected**: unacceptable risk in typical web hosting setups.

Use ext-php-rs or custom PHP extension
--------------------------------------

Build a native PHP extension in Rust.

**Deferred**: could be considered later, but increases maintenance and build
complexity.

Related decisions
=================

-  :ref:`adr-012-secure-http-transports` - Transport abstraction that uses FFI
-  :ref:`adr-014-packaging-native` - How Rust artifacts are distributed
