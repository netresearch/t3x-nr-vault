.. include:: /Includes.rst.txt

.. _adr-030-site-config-vault-read-time-resolution:

====================================================================
ADR-030: Read-time resolution of site-configuration vault references
====================================================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-07-23

Context
=======

Site configuration may reference secrets with the
:yaml:`%vault(identifier)%` syntax (see
:ref:`Site configuration <configuration-site>`). The extension originally
shipped an auto-registered event listener,
``SiteConfigurationVaultListener``, that resolved those references on
``SiteConfigurationLoadedEvent`` and wrote the resolved array back onto the
event.

That eager path is unsafe because of how TYPO3 core loads site
configuration. ``SiteConfiguration::getAllSiteConfigurationFromFiles()``
dispatches ``SiteConfigurationLoadedEvent`` **only on a cache miss** and then
``var_export()``\s the post-event array — the array the listener has just
filled with decrypted plaintext — into the ``core`` cache, which defaults to a
file-backed backend on disk. Every later load is a cache hit that returns the
pre-resolved array without re-dispatching the event. Two guarantees break:

-  **Encryption at rest.** The decrypted secret is written verbatim into
   ``var/cache/code/cache_core`` in cleartext, so a filesystem read (backup,
   misconfigured permissions, a second tenant) recovers it without the master
   key, the database, or any vault access.
-  **Per-reader access control.** ``VaultService::retrieve()`` runs its
   ``canRead()`` / expiry / audit checks exactly once — in whichever context
   warms the cache (an authenticated admin request, or a CLI run). A secret
   that is not ``frontend_accessible`` is then served from the cache to
   anonymous frontend requests and to lower-privileged backend users, because
   the gate never runs again.

The listener also called the processor without the ``Site`` object, so it
always took the global-identifier branch and never distinguished
site-scoped secrets.

Decision
========

Remove ``SiteConfigurationVaultListener``. Resolution of site-configuration
vault references is **caller-driven and happens at read time**, through
``SiteConfigurationVaultProcessor`` (the entry point already documented in the
class and exposed as a public service):

.. code-block:: php

   $site = $request->getAttribute('site');
   $processor = GeneralUtility::makeInstance(SiteConfigurationVaultProcessor::class);
   $config = $processor->processConfiguration($site->getConfiguration(), $site);
   $apiKey = $config['settings']['payment']['apiKey'];

The cached site-configuration array keeps the literal ``%vault(...)%``
placeholders; the plaintext exists only within the request that resolves it,
and ``canRead()`` runs for the actual reader on every resolution. Passing the
``$site`` object enables site-scoped identifiers
(``site:<siteIdentifier>:<secret>``).

Consequences
============

-  Plaintext secrets are never persisted to the on-disk ``core`` cache, and
   the access decision is enforced per reader rather than once per cache
   generation.
-  **Behaviour change.** Consumers that relied on transparent resolution —
   reading ``$site->getConfiguration()[...]`` and receiving a decrypted value —
   must now call ``processConfiguration()`` at the point of use. That
   transparent behaviour was the unsafe path; the explicit call is the
   supported one.
-  The processor, its interface, and its public service registration are
   unchanged; only the eager listener and its tests are removed.
-  TypoScript resolution (``TypoScriptVaultListener``) is unaffected: it is
   gated on ``frontend_accessible`` and documented as making a secret
   frontend-readable by design.
