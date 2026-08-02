.. include:: /Includes.rst.txt

.. _installation:

============
Installation
============

.. _installation-requirements:

Requirements
============

Before installing nr-vault, ensure your system meets these requirements:

-  TYPO3 v\ |typo3_version|.
-  PHP |php_version| or higher.
-  PHP sodium extension (usually included in PHP 8.2+).
-  Composer-based TYPO3 installation.

.. _installation-composer:

Installation via Composer
=========================

Install the extension using Composer:

.. code-block:: bash
   :caption: Install via Composer

   composer require netresearch/nr-vault

.. _installation-activate:

Activate the extension
======================

After installation, activate the extension in the TYPO3 backend:

1. Go to :guilabel:`Admin Tools > Extensions`.
2. Find "nr-vault" in the list.
3. Click the activation icon.

Or use the command line:

.. code-block:: bash
   :caption: Activate extension via CLI

   vendor/bin/typo3 extension:activate nr_vault

.. _installation-database:

Database schema
===============

Update the database schema to create the required tables:

.. code-block:: bash
   :caption: Update database schema

   vendor/bin/typo3 database:updateschema

This creates the following tables:

-  :sql:`tx_nrvault_secret` - Stores encrypted secrets with metadata.
-  :sql:`tx_nrvault_audit_log` - Stores audit log entries with hash chain.

.. _installation-master-key:

Master key setup
================

nr-vault requires a master encryption key to protect your secrets. There are
three options, from simplest to most configurable:

.. _installation-master-key-typo3:

Option 1: TYPO3 encryption key (default, zero configuration)
------------------------------------------------------------

**This is the recommended default.** nr-vault automatically derives a master key
from TYPO3's built-in encryption key (:php:`$GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey']`).

**No configuration required** - nr-vault works immediately after installation.

Benefits:

-  Zero setup - works out of the box
-  Unique per TYPO3 installation
-  Already secured by TYPO3's configuration protection

.. note::

   If you later rotate TYPO3's encryption key, use the
   :ref:`vault:rotate-master-key <command-rotate-master-key>` command first
   to re-encrypt all secrets with the new key.

.. _installation-master-key-env:

Option 2: Environment variable
------------------------------

For containerized deployments or when you need explicit control:

1. Generate a master key:

   .. code-block:: bash
      :caption: Generate master key

      openssl rand -base64 32

2. Set the environment variable:

   .. code-block:: bash
      :caption: Set environment variable

      export NR_VAULT_MASTER_KEY="your-generated-key"

3. Configure the extension in :guilabel:`Admin Tools > Settings > Extension Configuration`:

   -  :confval:`masterKeyProvider <ext-nrvault-masterKeyProvider>`: ``env``
   -  :confval:`masterKeySource <ext-nrvault-masterKeySource>`: ``NR_VAULT_MASTER_KEY``

.. _installation-master-key-file:

Option 3: Key file
------------------

For maximum security, store the key in a file outside the web root:

.. code-block:: bash
   :caption: Create secure key file

   openssl rand -base64 32 > /secure/path/vault.key
   chmod 0400 /secure/path/vault.key

Configure the extension:

-  :confval:`masterKeyProvider <ext-nrvault-masterKeyProvider>`: ``file``
-  :confval:`masterKeySource <ext-nrvault-masterKeySource>`: ``/secure/path/vault.key``

.. warning::

   For file and environment providers: never commit master keys to version
   control. Store them securely outside the web root.

.. _installation-master-key-transit:

Option 4: HashiCorp Vault Transit
---------------------------------

Where a Vault deployment already exists, the master key can be kept wrapped by
Vault's transit engine so only ciphertext is stored locally, and custody,
rotation and audit move into Vault. Setup (transit engine, policy, token) is
described in :ref:`configuration-master-key-transit`.

See :ref:`configuration-master-key-providers` for detailed information on each provider.

.. _installation-verify:

Verify installation
===================

Verify the installation by listing secrets (should return empty if newly installed):

.. code-block:: bash
   :caption: List vault secrets

   vendor/bin/typo3 vault:list

If the command executes without errors, the extension is properly configured.

You can also test by storing and retrieving a test secret:

.. code-block:: bash
   :caption: Test vault functionality

   # Store a test secret
   vendor/bin/typo3 vault:store test_secret --value="test-value"

   # Retrieve it
   vendor/bin/typo3 vault:retrieve test_secret

   # Clean up
   vendor/bin/typo3 vault:delete test_secret --force
