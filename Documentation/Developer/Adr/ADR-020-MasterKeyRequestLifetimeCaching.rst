.. include:: /Includes.rst.txt

.. _adr-020-master-key-request-lifetime-caching:

=============================================
ADR-020: Master key request-lifetime caching
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

Master key providers re-read the key material from disk, environment
variables, or re-derived it via HKDF on every decrypt operation. In
requests that decrypt multiple secrets (e.g., frontend rendering with
several vault-backed content elements), this caused repeated filesystem
reads or HKDF computations for the same key material.

The master key does not change within a single HTTP request, so repeated
derivation is pure overhead.

Decision
========

Cache the derived master key in memory for the lifetime of the current
request:

-  On first access, the master key provider reads/derives the key and
   stores it in a request-lifetime cache slot.
-  Subsequent decrypt operations within the same request reuse the cached
   key without additional I/O or derivation.
-  The cache lives in the shared ``AbstractMasterKeyProvider`` base class,
   keyed by concrete provider class, so each provider keeps an isolated
   slot and ``clearCachedKey()`` on one provider never wipes another's.
-  All providers expose a static ``clearCachedKey()`` (declared on
   ``MasterKeyProviderInterface``) that wipes the cached key material via
   ``sodium_memzero()``.

This follows the principle of minimizing key material exposure: the key
exists in memory only for the duration of the request and is actively
cleared rather than left for garbage collection.

Wipe lifecycle differs by provider
----------------------------------

The cache is wiped by two distinct mechanisms depending on the provider:

-  **FileMasterKeyProvider / EnvironmentMasterKeyProvider** define a
   ``__destruct()`` that calls ``clearCachedKey()``. When the provider
   instance is garbage-collected (typically at end of request), the cached
   key is zeroed.
-  **Typo3MasterKeyProvider** (the default) deliberately has **no**
   ``__destruct()``. Its cache slot is shared across instances, so wiping
   on the first instance's destruction would break the rest of the request.
   For this provider the cache is zeroed only by an explicit
   ``clearCachedKey()`` call or implicitly when PHP frees statics at script
   shutdown. Long-running processes (scheduler tasks, daemons) that must
   observe a rotated TYPO3 ``encryptionKey`` should call
   ``clearCachedKey()`` explicitly.

Consequences
============

Positive
--------

-  **One key derivation per request** instead of per-decrypt, eliminating
   redundant I/O and HKDF computations.
-  **Secure cleanup**: ``sodium_memzero()`` wipes key material — via
   ``__destruct()`` for the File/Env providers and via an explicit
   ``clearCachedKey()`` for the default Typo3 provider — so it does not
   persist in memory beyond the request (at the latest, until PHP frees
   statics at shutdown for the Typo3 provider).
-  **Transparent**: Read-path callers are unaware of the caching; the
   cache-wipe seam is now uniform via ``clearCachedKey()`` on the interface.

Negative
--------

-  **Memory residency**: The master key remains in process memory for the
   full request duration rather than being immediately discarded after each
   use. For the default Typo3 provider, residency is "until an explicit
   ``clearCachedKey()`` call or PHP shutdown" because it has no destructor.
-  **Lifecycle dependency**: File/Env providers rely on PHP object lifecycle
   (``__destruct``) for cleanup; the default Typo3 provider relies on an
   explicit ``clearCachedKey()``. Long-running processes (e.g., workers,
   scheduler tasks) must call ``clearCachedKey()`` to bound residency and to
   observe a rotated source key.

Related decisions
=================

-  :ref:`adr-003-master-key-management` - Master key management architecture
-  :ref:`adr-002-envelope-encryption` - Envelope encryption model
