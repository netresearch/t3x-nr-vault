.. include:: /Includes.rst.txt

.. _usage-extension-settings:

=============================================
Example: SaaS API keys in extension settings
=============================================

Many TYPO3 extensions integrate with SaaS services (DeepL, Personio, Stepstone,
Stripe, etc.) and store API keys in extension settings. This page shows how to
secure these credentials with nr-vault.

.. contents:: Table of contents
   :local:
   :depth: 2

.. _extension-settings-challenge:

The challenge
=============

Extension settings defined in :file:`ext_conf_template.txt` are stored in
:file:`LocalConfiguration.php` - not in TCA tables. This means:

-  The ``renderType: 'vaultSecret'`` approach doesn't work directly
-  API keys are stored as plaintext in the filesystem
-  Keys may end up in version control or backups

.. _extension-settings-approaches:

Approaches
==========

There are three approaches to secure extension settings with vault:

.. _extension-settings-approach-1:

Approach 1: Store vault identifier in settings (recommended)
------------------------------------------------------------

Store a vault reference in extension settings, resolve at runtime.

**Advantages:**

-  Works with existing extension settings UI
-  No schema changes required
-  Secrets properly encrypted in vault
-  Self-documenting ``vault:`` prefix

**Extension settings template:**

.. code-block:: text
   :caption: EXT:my_deepl_extension/ext_conf_template.txt

   # cat=api; type=string; label=DeepL API Key (Vault Reference): Enter vault:your-secret-id
   deeplApiKey = vault:

The admin enters a vault reference like ``vault:deepl_api_key`` (not the actual key).

The ``vault:`` prefix makes it clear this is a vault reference and enables
validation. See :ref:`adr-009-extension-configuration-secrets` for the design rationale.

**Service implementation:**

.. literalinclude:: _DeepLServiceVault.php
   :language: php
   :caption: EXT:my_deepl_extension/Classes/Service/DeepLService.php

**Setup steps:**

1. Store the actual DeepL API key in vault:

   **Via backend (recommended):**

   a. Go to :guilabel:`Admin Tools > Vault > Secrets`
   b. Click :guilabel:`+ Create new`
   c. Enter identifier: ``deepl_api_key``
   d. Paste your DeepL API key into the secret field
   e. Optionally set owner and allowed groups
   f. Click :guilabel:`Save`

   **Via CLI (alternative):**

   .. code-block:: bash
      :caption: Store API key via command line

      ./vendor/bin/typo3 vault:store deepl_api_key --value="your-deepl-api-key-here"

2. Configure extension setting with vault reference:

   **Via backend:**

   a. Go to :guilabel:`Admin Tools > Settings > Extension Configuration`
   b. Find your extension and expand it
   c. Enter the vault reference: ``vault:deepl_api_key``
   d. Click :guilabel:`Save`

3. The service parses the ``vault:`` prefix and resolves the secret at use time.

.. tip::

   No CLI or file access required. Admins can manage everything through the
   TYPO3 backend:

   - Create secrets in :guilabel:`Admin Tools > Vault`
   - Reference them in :guilabel:`Extension Configuration` with ``vault:identifier``

.. _extension-settings-approach-2:

Approach 2: Environment variable reference
------------------------------------------

For containerized deployments, reference environment variables.

**Extension settings template:**

.. code-block:: text
   :caption: EXT:my_deepl_extension/ext_conf_template.txt

   # cat=api; type=string; label=DeepL API Key (env var): Environment variable name containing the API key
   deeplApiKeyEnvVar = DEEPL_API_KEY

**Service implementation:**

.. literalinclude:: _DeepLServiceEnv.php
   :language: php
   :caption: EXT:my_deepl_extension/Classes/Service/DeepLService.php

.. warning::

   This approach stores the API key in memory for the request lifetime.
   No automatic memory cleanup. Consider Approach 1 for sensitive keys.

.. _extension-settings-approach-3:

Approach 3: Configuration record with TCA vault field
------------------------------------------------------

For maximum security and a proper backend UI, create a configuration record.

**TCA definition:**

.. literalinclude:: _tca-deepl-config.php
   :language: php
   :caption: EXT:my_deepl_extension/Configuration/TCA/tx_mydeeplext_config.php
   :lines: 3-

**Repository to load configuration:**

.. literalinclude:: _ConfigRepository.php
   :language: php
   :caption: EXT:my_deepl_extension/Classes/Domain/Repository/ConfigRepository.php

**DTO:**

.. literalinclude:: _DeepLConfig.php
   :language: php
   :caption: EXT:my_deepl_extension/Classes/Domain/Dto/DeepLConfig.php

**Service using config record:**

.. literalinclude:: _DeepLServiceTca.php
   :language: php
   :caption: EXT:my_deepl_extension/Classes/Service/DeepLService.php

**Advantages of Approach 3:**

-  Full vault UI with masked input, reveal, copy buttons
-  Proper access control (owner, groups)
-  Audit logging of configuration access
-  Multiple configurations possible (e.g., per site)

.. _extension-settings-comparison:

Comparison
==========

.. list-table::
   :header-rows: 1
   :widths: 25 25 25 25

   * - Aspect
     - Approach 1 (Vault ID)
     - Approach 2 (Env var)
     - Approach 3 (TCA record)
   * - Setup complexity
     - Low
     - Low
     - Medium
   * - Security
     - High
     - Medium
     - High
   * - Memory safety
     - Yes (sodium_memzero)
     - No
     - Yes (sodium_memzero)
   * - Audit trail
     - Yes
     - No
     - Yes
   * - Backend UI
     - Text field
     - Text field
     - Vault secret field
   * - Multi-config
     - Manual
     - Manual
     - Native

**Recommendation:** Use Approach 1 for simple single-key integrations, Approach 3
for complex integrations requiring multiple configurations or strict access control.
