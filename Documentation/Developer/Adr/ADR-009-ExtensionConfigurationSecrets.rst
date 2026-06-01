.. include:: /Includes.rst.txt

.. _adr-009-extension-configuration-secrets:

==========================================
ADR-009: Extension configuration secrets
==========================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-01-04

Context
=======

TYPO3 extensions commonly store API keys and credentials in extension settings
(defined in :file:`ext_conf_template.txt`, managed via
:guilabel:`Admin Tools > Settings > Extension Configuration`).

These settings are stored in the database (:sql:`sys_registry` table in v12+)
and loaded into :php:`$GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']` at runtime.

Challenges
----------

1. **No PSR-14 events**: TYPO3 provides no events for extension configuration
   save/load operations. The old ``afterExtensionConfigurationWrite`` signal
   was removed in v9.

2. **Memory persistence**: Values loaded into ``$GLOBALS`` persist for the
   entire request lifecycle. Storing actual secrets there defeats vault's
   security model (immediate memory cleanup via ``sodium_memzero``).

3. **No custom field types**: While ``type=user[...]`` allows custom rendering,
   there's no hook into the save/load lifecycle to intercept values.

Decision
========

Store **vault identifiers** (not secrets) in extension settings. The identifier
is resolved to the actual secret only at use time via :php:`VaultHttpClient`.

Two patterns are supported depending on use case:

Pattern A: Direct identifier (recommended)
------------------------------------------

For settings that are always vault references:

.. code-block:: text
   :caption: Extension setting value

   my_translation_api_key

Used directly with :php:`withAuthentication()`:

.. literalinclude:: _DirectUsage.php
   :language: php
   :caption: Direct usage
   :lines: 5-8

**Advantages:**

- Simple, no parsing needed
- Safe failure mode (vault lookup fails if wrong value)
- Works directly with VaultHttpClient

Pattern B: Prefixed reference (optional)
----------------------------------------

For mixed settings, explicit documentation, or **migration from plaintext to vault**:

.. code-block:: text
   :caption: Extension setting value

   vault:my_translation_api_key

Parsed with :php:`VaultReference` helper:

.. literalinclude:: _PrefixedUsage.php
   :language: php
   :caption: Prefixed usage
   :lines: 5-11

**Advantages:**

- Self-documenting in settings UI
- Distinguishes vault refs from plain values
- Explicit validation

Implementation
==============

Example: Translation service integration
----------------------------------------

**Extension settings template:**

.. literalinclude:: _ext_conf_template.txt
   :language: text
   :caption: EXT:acme_translate/ext_conf_template.txt

**Service implementation:**

.. literalinclude:: _TranslationService.php
   :language: php
   :caption: EXT:acme_translate/Classes/Service/TranslationService.php

**Setup via backend:**

1. Create secret in vault:

   a. Go to :guilabel:`Admin Tools > Vault > Secrets`
   b. Click :guilabel:`+ Create new`
   c. Enter identifier: ``acme_translate_api_key``
   d. Paste your API key
   e. Click :guilabel:`Save`

2. Configure extension:

   a. Go to :guilabel:`Admin Tools > Settings > Extension Configuration`
   b. Find :guilabel:`acme_translate`
   c. Enter API Key: ``acme_translate_api_key``
   d. Click :guilabel:`Save`

**Via CLI (alternative):**

.. code-block:: bash
   :caption: Store secret via CLI

   ./vendor/bin/typo3 vault:store acme_translate_api_key --value="your-actual-api-key"

Why this is safe
----------------

The extension setting stores only the **identifier**, never the secret:

.. code-block:: text
   :caption: What gets stored where

   sys_registry (extension config):
     apiKey = "acme_translate_api_key"    ← Just the identifier

   tx_nrvault_secret (vault):
     identifier = "acme_translate_api_key"
     encrypted_value = [AES-256-GCM encrypted actual key]

Even if someone accidentally enters the actual API key in extension settings:

1. :php:`withAuthentication('sk_live_abc123...')` tries vault lookup
2. Vault returns "secret not found"
3. Request fails safely (secret never sent)

Alternatives considered
=======================

Store actual secrets in extension config
----------------------------------------

**Rejected because:**

- Secrets persist in ``$GLOBALS`` for entire request
- No ``sodium_memzero()`` cleanup possible
- Secrets visible in database (sys_registry)
- May leak to logs, backups, version control

Custom user field type with vault UI
------------------------------------

.. code-block:: text
   :caption: Hypothetical

   # type=user[Netresearch\NrVault\Configuration\VaultSecretField->render]
   apiKey =

**Rejected because:**

- No save/load lifecycle hooks in TYPO3
- Would need to store secret in config (defeats purpose)
- Complex JavaScript for vault API interaction

Consequences
============

Positive
--------

- **Memory safety preserved**: Secrets resolved only at use time
- **Simple pattern**: Direct identifier works with VaultHttpClient
- **Safe failure**: Wrong values cause "not found", not exposure
- **No core changes**: Works with standard extension configuration
- **Backend-friendly**: Admins manage via TYPO3 backend, no CLI needed

Negative
--------

- **Two-step setup**: Create secret in vault, then reference in settings
- **No UI validation**: Extension settings show plain text field
- **Convention-based**: Developers must document which fields are vault refs

References
==========

- :ref:`usage-extension-settings` - Usage documentation
- `ext_conf_template.txt <https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/ExtensionArchitecture/FileStructure/ExtConfTemplate.html>`__ - TYPO3 documentation
