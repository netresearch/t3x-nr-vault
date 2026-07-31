.. include:: /Includes.rst.txt

.. _configuration:

=============
Configuration
=============

.. _configuration-extension:

Extension configuration
=======================

Configure nr-vault in :guilabel:`Admin Tools > Settings > Extension Configuration`.

.. confval:: storageAdapter
   :name: ext-nrvault-storageAdapter
   :type: string
   :Default: local
   :Options: local

   Where secrets are stored.

   local
      Store secrets in the TYPO3 database (default). Secrets are encrypted
      with envelope encryption before storage.

   .. note::
      **External vault adapters (HashiCorp Vault, AWS Secrets Manager) are
      planned for future releases.** The adapter architecture is designed to
      support external backends, but currently only the local database adapter
      is implemented. See :ref:`developer-custom-adapters` for information on
      implementing custom adapters.

.. confval:: securityProfile
   :name: ext-nrvault-securityProfile
   :type: string
   :Default: standard
   :Options: standard, hardened

   The vault's operating profile — a single, internally consistent policy
   rather than a bag of independent toggles. Enforcement happens in code
   (provider selection, access control, audit anchoring), never only in
   documentation.

   standard
      Secure defaults with zero-configuration TYPO3 integration.

   hardened
      Fail-closed and audit-ready. Requires an explicit external
      master-key provider (``file`` or ``env``), disables provider
      auto-detection and any fallback to the TYPO3 encryption key, and
      makes vault operations refuse to run on a misconfigured or
      unavailable provider. It is also the prerequisite for
      :ref:`disableAdminOverride <ext-nrvault-disableAdminOverride>`.

   An unrecognised value throws rather than degrading to ``standard`` — a
   typo in a hardened deployment must never weaken the effective policy.

.. confval:: masterKeyProvider
   :name: ext-nrvault-masterKeyProvider
   :type: string
   :Default: typo3
   :Options: typo3, file, env

   How to retrieve the master encryption key.

   typo3
      Derive from TYPO3's encryption key. This is the recommended default
      as it requires no additional configuration and works out of the box.

   file
      Read from a file on the filesystem.

   env
      Read from an environment variable.

.. confval:: masterKeySource
   :name: ext-nrvault-masterKeySource
   :type: string
   :Default: NR_VAULT_MASTER_KEY

   Source location for the master key. Interpretation depends on the provider:

   -  **file**: Path to the key file (e.g., :file:`/secure/path/vault.key`).
   -  **env**: Environment variable name (e.g., :samp:`NR_VAULT_MASTER_KEY`).
   -  **typo3**: Not used (key derived from TYPO3's encryption key).

.. confval:: allowCliAccess
   :name: ext-nrvault-allowCliAccess
   :type: boolean
   :Default: false

   Allow CLI commands to access secrets without a backend user session.

.. confval:: cliAccessGroups
   :name: ext-nrvault-cliAccessGroups
   :type: string
   :Default: empty

   Comma-separated list of backend user group UIDs that CLI can access.
   Empty means all secrets are accessible when CLI access is enabled.

.. confval:: auditLogRetention
   :name: ext-nrvault-auditLogRetention
   :type: integer
   :Default: 365

   Number of days to retain audit log entries. Set to 0 for unlimited retention.

.. confval:: auditReads
   :name: ext-nrvault-auditReads
   :type: boolean
   :Default: true

   Log every secret *read* to the audit log. Disable only for
   high-throughput scenarios where read logging is not required.

   .. warning::

      Disabling read logging means secret retrievals leave no audit
      trail. The toggle is configurable by design
      (see :ref:`adr-019-configurable-audit-read-logging`), but flipping
      it does not itself emit a sentinel entry. For tamper-resistant
      deployments, pin the value filesystem-only via
      :file:`config/system/additional.php` so it cannot be changed from
      the backend Settings module:

      .. code-block:: php

         $GLOBALS['TYPO3_CONF_VARS']['SYS']['nrVault']['auditReads'] = true;

.. confval:: disableAdminOverride
   :name: ext-nrvault-disableAdminOverride
   :type: boolean
   :Default: false

   Remove the unconditional "administrators and system maintainers may do
   anything" bypass — both the operation permissions and the per-secret
   read/write/delete tiers. Administrators then hold exactly what their
   groups were granted and reach only the secrets they own or share a
   group with.

   **Only effective when** :ref:`securityProfile
   <ext-nrvault-securityProfile>` **is** ``hardened``. In the standard
   profile the flag is inert — a lockout guard, since setting it without
   the rest of the hardened policy is more likely a misunderstanding than
   a decision. ``vault:break-glass --status`` reports
   ``adminOverrideDisabledEffective`` so the mismatch is visible.

   .. warning::

      Removing the override without an escape hatch turns the first
      genuine incident into an outage. The hatch is
      :ref:`break-glass mode <security-break-glass>`
      (:ref:`vault:break-glass <command-break-glass>`) — a justified,
      audited, time-boxed window that restores full admin power.

      Pin the value out of admin reach in
      :file:`config/system/additional.php`, or a compromised admin can
      simply untick it in the backend Settings module:

      .. code-block:: php

         $GLOBALS['TYPO3_CONF_VARS']['SYS']['nrVault']['disableAdminOverride'] = true;

   See :ref:`security-disable-admin-override` for what exactly is removed.

.. confval:: auditHmacEpoch
   :name: ext-nrvault-auditHmacEpoch
   :type: integer
   :Default: 2

   Hash-algorithm version marker for the audit log hash chain:

   0
      Legacy SHA-256 without HMAC.

   1
      HMAC-SHA256 over identity fields only.

   2
      HMAC-SHA256 over identity **and** forensic fields (``success``,
      ``error_message``, ``reason``, ``ip_address``, ``user_agent``,
      ``context``).

   The default (``2``) binds the forensic surface into the chain so a
   DB-write attacker cannot flip ``success`` or rewrite
   ``error_message`` without breaking the chain. After raising this
   value, run the Install Tool wizard *Migrate audit hash chain* (or
   the :ref:`vault:audit-migrate-hmac <command-audit-migrate-hmac>`
   command) to re-hash existing rows. See
   :ref:`adr-023-audit-hash-chain-hmac`.

.. confval:: preferXChaCha20
   :name: ext-nrvault-preferXChaCha20
   :type: boolean
   :Default: false

   Prefer XChaCha20-Poly1305 over AES-256-GCM. XChaCha20 is recommended
   when hardware AES acceleration is not available.

.. confval:: cacheEnabled
   :name: ext-nrvault-cacheEnabled
   :type: boolean
   :Default: true

   Enable request-scoped caching of decrypted secrets. When enabled,
   repeated retrievals of the same secret within a single request
   return the cached value instead of decrypting again.

.. _configuration-master-key-providers:

Master key providers
====================

.. _configuration-master-key-typo3:

TYPO3 provider (default)
------------------------

Uses TYPO3's built-in encryption key to derive the master key. This is the
recommended default because:

-  **Zero configuration**: Works immediately after installation.
-  **No server access required**: Ideal for users without shell access.
-  **Unique per installation**: Each TYPO3 instance has its own key.
-  **Already secured**: TYPO3's encryption key is already protected.

The master key is derived from the encryption key using HKDF-SHA256 with a
nr-vault-specific context, ensuring it cannot be used to compromise other
TYPO3 functionality.

.. code-block:: php
   :caption: Master key derivation (internal)

   // How it works internally
   $masterKey = hash_hkdf(
       'sha256',
       $GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey'],
       32,
       'nr-vault-master-key'
   );

.. note::

   If you rotate TYPO3's encryption key, all secrets will need to be
   re-encrypted. Use the key rotation command before changing the
   encryption key.

.. _configuration-master-key-file:

File provider
-------------

Store the master key in a file with restrictive permissions:

.. code-block:: bash
   :caption: Create master key file

   # Generate a new key
   openssl rand -base64 32 > /secure/path/vault-master.key
   chmod 0400 /secure/path/vault-master.key

Configure in extension settings:

-  :confval:`masterKeyProvider <ext-nrvault-masterKeyProvider>`: file
-  :confval:`masterKeySource <ext-nrvault-masterKeySource>`: /secure/path/vault-master.key

.. warning::

   The key file must be:

   -  Outside the web root.
   -  Readable only by the web server user.
   -  Not in version control.
   -  Backed up separately from the database.

.. _configuration-master-key-env:

Environment provider
--------------------

Store the master key in an environment variable:

.. code-block:: bash
   :caption: Set master key via environment

   export NR_VAULT_MASTER_KEY="base64-encoded-key"

Configure in extension settings:

-  :confval:`masterKeyProvider <ext-nrvault-masterKeyProvider>`: env
-  :confval:`masterKeySource <ext-nrvault-masterKeySource>`: NR_VAULT_MASTER_KEY

This is ideal for containerized deployments where secrets are injected
via environment variables.

.. _configuration-access-control:

Access control
==============

Access to secrets is controlled by:

1. **Ownership**: The user who created the secret has full access.
2. **Group membership**: Secrets can be shared with backend user groups.
3. **Admin access**: Backend administrators have access to all secrets.
4. **CLI access**: Configurable via :confval:`allowCliAccess <ext-nrvault-allowCliAccess>`.

.. _configuration-context:

Context-based scoping
=====================

Organize secrets by context for easier management:

-  :samp:`payment` - Payment gateway credentials.
-  :samp:`email` - Email service API keys.
-  :samp:`api` - Third-party API tokens.
-  :samp:`database` - External database credentials.

Contexts are user-defined strings that help organize and filter secrets.

.. _configuration-site:

Site configuration integration
==============================

Use the :yaml:`%vault(identifier)%` syntax in site configuration files:

.. code-block:: yaml
   :caption: config/sites/main/config.yaml

   settings:
     payment:
       stripeSecretKey: '%vault(stripe_api_key)%'
     email:
       mailchimpKey: '%vault(mailchimp_key)%'

References are resolved on demand, in the reading context, via
:php:`SiteConfigurationVaultProcessor` — not automatically when the site
configuration is loaded:

.. code-block:: php
   :caption: Resolve at read time

   use Netresearch\NrVault\Configuration\SiteConfigurationVaultProcessor;
   use TYPO3\CMS\Core\Utility\GeneralUtility;

   $site = $request->getAttribute('site');
   $processor = GeneralUtility::makeInstance(SiteConfigurationVaultProcessor::class);
   $config = $processor->processConfiguration($site->getConfiguration(), $site);
   $stripeKey = $config['settings']['payment']['stripeSecretKey'];

This keeps sensitive values out of version control while allowing configuration
through the standard TYPO3 site settings.

.. note::

   Resolution is deliberately caller-driven. TYPO3 caches the loaded site
   configuration to an on-disk file; resolving :yaml:`%vault()%` references
   eagerly at load time would persist the decrypted secrets there in cleartext
   and would enforce access control only once, at cache-warm time. Read-time
   resolution avoids both. See :ref:`Site configuration <usage-site-configuration>`
   in the Usage chapter for the full example.

.. _configuration-frontend:

Frontend-accessible secrets
===========================

By default, secrets cannot be resolved in frontend context (TypoScript).
To allow a secret to be used in TypoScript:

1. Create the secret with :php:`frontend_accessible` metadata.
2. Use the :typoscript:`%vault(identifier)%` syntax in TypoScript.

.. code-block:: php
   :caption: Store frontend-accessible secret

   $this->vaultService->store(
       'google_maps_key',
       $apiKey,
       [
           'metadata' => [
               'frontend_accessible' => true,
           ],
       ],
   );

.. warning::

   Frontend-accessible secrets may be exposed in rendered HTML output.
   Only use this for secrets that are intended to be public (like
   client-side API keys).
