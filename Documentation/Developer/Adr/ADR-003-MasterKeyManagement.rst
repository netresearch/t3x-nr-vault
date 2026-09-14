.. include:: /Includes.rst.txt

.. _adr-003-master-key-management:

================================
ADR-003: Master key management
================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-01-03

Context
=======

The envelope encryption system (see :ref:`adr-002-envelope-encryption`) requires
a master key to encrypt Data Encryption Keys (DEKs). The master key management
approach must:

-  Work in various deployment environments (development, production, cloud)
-  Support key rotation without service interruption
-  Integrate with existing TYPO3 security infrastructure
-  Allow external secret management systems for enterprise deployments

Problem statement
=================

How should the master key be stored, retrieved, and rotated across different
deployment scenarios?

Decision drivers
================

-  **Flexibility**: Support multiple key sources (file, environment, external)
-  **Zero-config default**: Work out-of-the-box using TYPO3's encryption key
-  **Security**: Keys should never be logged or exposed
-  **Rotation**: Support key rotation with atomic switchover
-  **Extensibility**: Allow custom providers for enterprise needs

Considered options
==================

Option 1: Single hardcoded source
---------------------------------

Always derive from TYPO3's encryption key.

**Pros:**

-  Zero configuration
-  Always available

**Cons:**

-  No separation between TYPO3 and vault security
-  Cannot use external key management

Option 2: Pluggable provider system
-----------------------------------

Interface-based providers with factory pattern for selection.

**Pros:**

-  Flexible deployment options
-  Enterprise integration (HashiCorp Vault, AWS KMS)
-  Testable with mock providers

**Cons:**

-  More complex configuration
-  Multiple code paths to maintain

Decision
========

We chose a **pluggable provider system** with four built-in providers:

1. **typo3** (default): Derives key from TYPO3's encryption key using HKDF
2. **file**: Reads key from filesystem with strict permissions
3. **env**: Reads key from environment variable
4. **transit**: Unwraps the key through HashiCorp Vault's transit engine

This provides zero-config operation while enabling enterprise deployments.
Providers are resolved through a registry keyed by identifier, so a consuming
extension can supply a fifth — see `Provider registry`_ below.

Implementation
==============

Provider interface
------------------

.. code-block:: php
   :caption: Classes/Crypto/MasterKeyProviderInterface.php

   interface MasterKeyProviderInterface
   {
       public function getIdentifier(): string;
       public function isAvailable(): bool;
       public function getMasterKey(): string;
       public function storeMasterKey(string $key): void;
       public function generateMasterKey(): string;
   }

TYPO3 provider (default)
------------------------

Uses HKDF-SHA256 to derive a vault-specific key from TYPO3's encryption key:

.. code-block:: php
   :caption: Classes/Crypto/Typo3MasterKeyProvider.php

   final class Typo3MasterKeyProvider implements MasterKeyProviderInterface
   {
       private const int KEY_LENGTH = 32;
       private const string HKDF_INFO = 'nr-vault-master-key';

       public function getMasterKey(): string
       {
           $encryptionKey = $GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey'];

           return hash_hkdf(
               'sha256',
               $encryptionKey,
               self::KEY_LENGTH,
               self::HKDF_INFO,
           );
       }
   }

The HKDF context string ``nr-vault-master-key`` ensures the derived key is
unique to nr-vault even if other extensions use the same derivation pattern.

File provider
-------------

Reads a 32-byte key from a file with strict permission requirements:

.. code-block:: php
   :caption: Classes/Crypto/FileMasterKeyProvider.php

   public function getMasterKey(): string
   {
       $key = file_get_contents($this->keyPath);
       $key = trim($key);  // Remove trailing newlines

       // Handle base64-encoded keys
       if (strlen($key) !== self::KEY_LENGTH) {
           $decoded = base64_decode($key, true);
           if ($decoded !== false && strlen($decoded) === self::KEY_LENGTH) {
               return $decoded;
           }
       }

       return $key;
   }

   public function storeMasterKey(string $key): void
   {
       file_put_contents($this->keyPath, base64_encode($key));
       chmod($this->keyPath, 0o400);  // Read-only for owner
   }

Environment provider
--------------------

Reads key from environment variable (default: ``NR_VAULT_MASTER_KEY``):

.. code-block:: php
   :caption: Classes/Crypto/EnvironmentMasterKeyProvider.php

   public function getMasterKey(): string
   {
       $key = getenv($this->envVarName);

       if ($key === false || $key === '') {
           throw MasterKeyException::environmentVariableNotSet($this->envVarName);
       }

       // Handle base64-encoded keys
       $decoded = base64_decode($key, true);
       if ($decoded !== false && strlen($decoded) === self::KEY_LENGTH) {
           return $decoded;
       }

       return $key;
   }

Factory with auto-detection
---------------------------

.. code-block:: php
   :caption: Classes/Crypto/MasterKeyProviderFactory.php

   public function getAvailableProvider(): MasterKeyProviderInterface
   {
       // 1. Try explicitly configured provider
       $configured = $this->configuration->getMasterKeyProvider();
       if ($configured && $this->providers[$configured]->isAvailable()) {
           return $this->providers[$configured];
       }

       // 2. Fallback chain: typo3 -> env -> file
       foreach (['typo3', 'env', 'file'] as $id) {
           if ($this->providers[$id]->isAvailable()) {
               return $this->providers[$id];
           }
       }

       // 3. Return TYPO3 provider (will fail with clear error)
       return $this->providers['typo3'];
   }

Provider registry
-----------------

The set of providers is not a closed list inside the factory. Every service
tagged ``nr_vault.master_key_provider`` is collected by
:php:`MasterKeyProviderRegistry` and indexed under the identifier it returns
from :php:`getIdentifier()`; ``masterKeyProvider`` names one of those
identifiers. The four built-in providers are tagged the same way and hold no
privilege the registry can see, so an extension supplying a cloud-KMS or HSM
provider registers it exactly as nr-vault registers its own
(:ref:`developer-custom-key-providers`).

Three rules make the indirection safe, because an identifier decides which key
source protects the vault:

*   **A duplicate identifier is refused, not resolved** (``1789430001``).
    Last-one-wins would let an installed extension take over the master key by
    choosing the name ``file``; first-one-wins would let load order decide the
    same thing. While a collision exists the registry refuses *every* lookup,
    not only the colliding name: in that state "which key source is in use?"
    has no answer, and serving the other names would hide the ambiguity from
    the operator.
*   **A blank identifier is refused** (``1789430002``), because ``''`` is what
    ``masterKeyProvider`` holds before anybody configures it.
*   **The ambiguity check runs before the standard-profile fallback**, which
    swallows :php:`ConfigurationException` to survive an unconfigured install.
    Without that ordering, auto-detection would answer the custody question by
    load order after all.

The hardened profile's deny list names ``typo3`` and nothing else. Its demand
is that the key lives outside :file:`config/system/settings.php`, which is
what an extension-supplied provider delivers; refusing unknown identifiers by
default would forbid exactly the deployments the profile exists to serve. What
it cannot police is what installed code does — a custom provider may derive
its key from the TYPO3 encryption key under another name. The profile
constrains configuration, not the trustworthiness of an installed extension.

Auto-detection still probes the three built-in local sources only. Falling
back to a custom provider would mean adopting a key custody nobody configured.

Configuration
-------------

.. code-block:: php
   :caption: Extension configuration options

   $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault'] = [
       'masterKeyProvider' => 'typo3',  // typo3, file, or env
       'masterKeySource' => 'NR_VAULT_MASTER_KEY',  // env var or file path
       'autoKeyPath' => 'var/secrets/vault-master.key',  // auto-generated key
   ];

Key rotation command
--------------------

.. code-block:: bash
   :caption: Rotate master key

   # Dry run first
   vendor/bin/typo3 vault:rotate-master-key --dry-run

   # Execute rotation
   vendor/bin/typo3 vault:rotate-master-key \
       --old-key=/path/to/old.key \
       --new-key=/path/to/new.key \
       --confirm

The rotation process:

1. Inventory this extension's secrets and every registered consumer's sealed
   envelopes (:ref:`ADR-033 <adr-033-foreign-envelope-rotation>`)
2. Verify old key can decrypt existing secrets
3. Re-encrypt all DEKs with new master key (transactional)
4. Re-wrap every registered consumer's envelopes, in the same transaction
5. Re-key the audit chain, then commit
6. Dispatch :php:`MasterKeyRotatedEvent`
7. Update configuration to use new key

.. note::

   Steps 1, 4 and 6 landed with
   :ref:`ADR-033 <adr-033-foreign-envelope-rotation>`. Before that, rotation
   covered ``tx_nrvault_secret`` only and step 6 was never actually reached —
   :php:`MasterKeyRotatedEvent` existed and was documented but was not dispatched
   from anywhere, so consumer-owned envelopes were left wrapped under the retired
   key.

Consequences
============

Positive
--------

-  **Zero-config default**: Works immediately with TYPO3 installation
-  **Deployment flexibility**: File/env for containers, external for enterprise
-  **Key separation**: HKDF ensures vault key is distinct from TYPO3 key
-  **Atomic rotation**: Database transaction ensures consistency
-  **Extensibility**: Custom providers via interface implementation

Negative
--------

-  **Configuration complexity**: Multiple options to understand
-  **Key synchronization**: Multi-server deployments need key distribution

Risks
-----

-  TYPO3 provider: Changing ``encryptionKey`` breaks vault access
-  File provider: Key file backup and distribution challenges
-  All providers: Master key loss = permanent data loss

Mitigation
----------

-  Document backup procedures prominently
-  Provide key export command for disaster recovery
-  Log warnings when using derived keys in production

Related decisions
=================

-  :ref:`adr-002-envelope-encryption` - Uses master key for DEK encryption

References
==========

-  `HKDF RFC 5869 <https://tools.ietf.org/html/rfc5869>`_
-  `HashiCorp Vault Transit Engine <https://developer.hashicorp.com/vault/docs/secrets/transit>`_
