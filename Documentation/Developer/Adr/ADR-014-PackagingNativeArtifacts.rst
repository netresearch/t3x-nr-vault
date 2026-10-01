.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-014-packaging-native:

=============================================
ADR-014: Packaging native artifacts
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

Shipping native binaries inside extension packages:

-  complicates security review and supply-chain trust,
-  complicates updates (CVE patching),
-  complicates platform support (x86_64, aarch64, glibc vs musl),
-  and often triggers "no executables in extensions" policies in
   security-conscious environments.

We still want Rust as an optional performance/security feature where it makes
sense.

Decision
========

-  The default nr-vault distribution remains **PHP-only**
-  Rust transport artifacts are distributed as **separate platform-specific
   artifacts**, e.g.:

   -  OS packages (deb/rpm)
   -  Container images / sidecar
   -  A dedicated "engine package" download with checksums/signing

-  "Bundled binary inside extension" is allowed only for controlled managed
   environments and is not the default path

Consequences
============

Positive
--------

-  Better adoption in security-conscious TYPO3 environments
-  Clear update and patching model for native components
-  Cleaner separation of responsibilities and reduced TER friction

Negative
--------

-  Additional installation steps for Rust mode
-  Requires CI/CD pipeline for multi-arch artifacts and release management

Alternatives considered
=======================

Bundle libvault.so directly in the extension
--------------------------------------------

Ship the native library inside the TYPO3 extension package.

**Rejected** as default; allowed only in managed/special cases.

Related decisions
=================

-  :ref:`adr-013-rust-ffi-preload` - FFI security configuration
-  :ref:`adr-012-secure-http-transports` - Transport abstraction that uses FFI

