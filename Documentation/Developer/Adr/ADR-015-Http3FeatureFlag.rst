.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-015-http3-feature-flag:

=============================================
ADR-015: HTTP/3 feature flag
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

HTTP/3 support is uneven across ecosystems and can be experimental in client
libraries. For our target installations, correctness and operability matter
more than "having HTTP/3".

We want to benefit from HTTP/3 where it works, without destabilizing the
platform.

Decision
========

-  MVP requires stable HTTP/1.1 and HTTP/2 support
-  HTTP/3 is optional and controlled by:

   -  feature flag per service or global
   -  runtime capability detection
   -  mandatory fallback to HTTP/2/1.1

-  No business-critical functionality depends on HTTP/3 availability

Consequences
============

Positive
--------

-  Avoids shipping unstable transport as a dependency
-  Keeps rollout safe; reduces support burden

Negative
--------

-  Some expected performance gains will not be guaranteed everywhere

Alternatives considered
=======================

Make HTTP/3 the default transport
---------------------------------

Use HTTP/3 as the default transport mode.

**Rejected**: too risky, too unstable, too environment-dependent.

Related decisions
=================

-  :ref:`adr-012-secure-http-transports` - Transport abstraction
-  :ref:`adr-013-rust-ffi-preload` - Rust transport using reqwest with HTTP/3 support

