.. include:: /Includes.rst.txt

.. _troubleshooting:

===============
Troubleshooting
===============

Common issues and frequently asked questions about nr-vault.

.. _troubleshooting-faq:

FAQ
===

.. _troubleshooting-lost-master-key:

I lost the master key. Can I recover my secrets?
-------------------------------------------------

No. This is by design. The master key is the root of trust for all
encrypted secrets. Without it, decryption is impossible.

**What to do:**

1. Restore the master key from a backup if available.
2. If no backup exists, all secrets encrypted with that key are
   permanently lost.
3. Generate a new master key and re-encrypt all secrets from their
   original plaintext sources.

.. tip::

   Always keep a secure, offline backup of your master key. See
   :ref:`security-file-storage` for storage recommendations.

.. _troubleshooting-access-denied:

Users get "Access denied" when reading secrets
----------------------------------------------

Check the following:

1. **Backend user group**: The user must belong to a group that has
   access to the secret. Verify group membership in
   :guilabel:`Backend Users` module.

2. **TSconfig restrictions**: Check if Page TSconfig or User TSconfig
   restricts access to vault features. Look for
   ``tx_vault.`` prefixed settings.

3. **Ownership**: Only the secret creator and members of allowed groups
   can access a secret. Administrators can access all secrets.

4. **CLI access**: CLI commands require explicit configuration. See
   :ref:`configuration` for details.

.. _troubleshooting-non-composer:

Can I use nr-vault without Composer?
------------------------------------

No. nr-vault requires a Composer-based TYPO3 installation. Classic
(non-Composer) installations are not supported. This is because nr-vault
depends on packages (such as ``sodium``) that must be managed through
Composer's autoloader.

If you are using a classic installation, migrate to Composer first. See
the `TYPO3 documentation on Composer migration
<https://docs.typo3.org/m/typo3/guide-installation/main/en-us/MigrateToComposer/Index.html>`__.

.. _troubleshooting-decryption-failed:

"Decryption failed" error
-------------------------

This error occurs when the encrypted data cannot be decrypted. Common
causes:

**Key mismatch**
   The master key currently configured does not match the key used to
   encrypt the secret. This happens when:

   -  The master key file was replaced or regenerated.
   -  The environment variable points to a different key.
   -  You restored a database backup but not the corresponding master key.

**Corrupted data**
   The encrypted value in the database has been modified or truncated.
   This can happen due to:

   -  Incomplete database migrations.
   -  Manual edits to the database.
   -  Character encoding issues during database import/export.

**Resolution:**

1. Verify that the active master key matches the one used during
   encryption.
2. Check database integrity for the ``tx_nrvault_secret`` table.
3. If the data is corrupt, restore from a database backup and ensure
   the matching master key is in place.

.. _troubleshooting-master-key-not-found:

"Master key not found" error
----------------------------

This means nr-vault cannot locate or read the master key from the
configured provider.

**File provider:**

-  Verify the key file exists at the configured path.
-  Check file permissions: the web server user must be able to read the
   file (recommended: ``0400``).
-  Ensure the path is absolute, not relative.

**Environment provider:**

-  Verify the environment variable is set:
   ``echo $NR_VAULT_MASTER_KEY``.
-  Check that the variable is available to the PHP process (not just
   the shell). For Apache, use ``SetEnv``; for PHP-FPM, use
   ``env[NR_VAULT_MASTER_KEY]`` in the pool configuration.
-  In containerized environments, ensure the variable is passed through
   ``docker-compose.yml`` or the orchestrator's secret injection.

**TYPO3 provider (default):**

-  Ensure ``$GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey']`` is
   set in :file:`settings.php`.

.. _troubleshooting-performance:

Performance with many secrets
-----------------------------

If you manage a large number of secrets, consider these optimizations:

**Batch loading**
   Use the :php:`VaultService::list()` method with context filters
   rather than loading all secrets at once. The service optimizes
   queries when a context is specified.

**Caching**
   nr-vault caches decrypted values during a single request. For
   repeated access across requests, consider caching the decrypted
   values in your application layer (be mindful of security
   implications).

**Database indexing**
   The ``tx_nrvault_secret`` table includes indexes on commonly queried
   columns. Ensure these indexes exist after migrations.

.. _troubleshooting-rotate-master-key:

How to rotate the master key
----------------------------

Master key rotation re-encrypts all Data Encryption Keys (DEKs) with a
new master key without changing the actual secret values.

1. **Create a backup** of the current master key and database.

2. **Generate a new master key.** The file master-key provider accepts either
   32 raw bytes or a base64-encoded 32-byte key. A base64 key file is easy to
   create with:

   .. code-block:: bash

      openssl rand -base64 32 > /secure/path/new-master-key

   (``vault:init`` itself writes a raw 32-byte key file by default, or a
   base64 value with ``--env``; the file provider reads both.)

3. **Run the rotation command** with ``--confirm`` (without it the command
   prints an opt-in warning and exits without rotating):

   .. code-block:: bash

      vendor/bin/typo3 vault:rotate-master-key \
          --new-key=/secure/path/new-master-key \
          --confirm

   Use ``--dry-run`` first to simulate, and ``--old-key`` if the current key
   cannot be auto-detected from your provider configuration.

4. **Update your configuration** to point to the new master key.

5. **Verify** that secrets are still readable.

6. **Securely delete** the old master key after confirming success.

.. warning::

   Do not delete the old master key until you have verified that all
   secrets decrypt correctly with the new key.

.. _troubleshooting-migrate-plaintext:

How to migrate from plaintext to vault
--------------------------------------

To migrate existing plaintext credentials stored in TYPO3 records to
vault-managed secrets:

1. **Identify fields** that contain plaintext secrets (API keys,
   passwords, tokens).

2. **Add TCA configuration** for those fields using the
   ``vaultSecret`` renderType. See :ref:`developer` for TCA
   integration details.

3. **Run the migration command:**

   .. code-block:: bash

      vendor/bin/typo3 vault:migrate-field \
          tx_myext_domain_model_connection \
          api_key

   This reads the current plaintext value, encrypts it into the vault,
   and replaces the field value with a vault reference identifier.

4. **Verify** that the application still reads the credentials
   correctly through the vault API.

5. **Clear caches** after migration:

   .. code-block:: bash

      vendor/bin/typo3 cache:flush
