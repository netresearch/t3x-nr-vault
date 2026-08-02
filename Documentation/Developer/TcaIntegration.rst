.. include:: /Includes.rst.txt

.. _tca-integration:

===============
TCA integration
===============

nr-vault provides a custom TCA field type that allows any TYPO3 extension
to store sensitive data (API keys, credentials, tokens) securely in the vault
instead of plaintext in the database.

.. contents:: Table of contents
   :local:
   :depth: 2

.. _tca-quick-start:

Quick start
===========

.. _tca-step1-dependency:

Step 1: Add dependency
----------------------

Add nr-vault as a dependency in your extension's :file:`composer.json`:

.. code-block:: json
   :caption: EXT:my_extension/composer.json

   {
       "require": {
           "netresearch/nr-vault": "^0.4"
       }
   }

.. _tca-step2-configure:

Step 2: Configure TCA field
---------------------------

Use the ``vaultSecret`` renderType in your TCA configuration:

.. code-block:: php
   :caption: Configuration/TCA/tx_myext_settings.php

   <?php
   return [
       'ctrl' => [
           'title' => 'My Extension Settings',
           // ... other ctrl settings
       ],
       'columns' => [
           'api_key' => [
               'label' => 'API Key',
               'config' => [
                   'type' => 'input',
                   'renderType' => 'vaultSecret',
                   'size' => 30,
               ],
           ],
       ],
   ];

.. _tca-step3-database:

Step 3: Add database column
---------------------------

Add the column to your extension's :file:`ext_tables.sql`:

.. code-block:: sql
   :caption: EXT:my_extension/ext_tables.sql

   CREATE TABLE tx_myext_settings (
       api_key varchar(255) DEFAULT '' NOT NULL
   );

The column stores the vault identifier, not the actual secret.

.. _tca-step4-retrieve:

Step 4: Retrieve secrets in code
--------------------------------

Use the :php:`VaultFieldResolver` utility to retrieve actual secret values:

.. code-block:: php
   :caption: Resolve vault fields in code

   use Netresearch\NrVault\Utility\VaultFieldResolver;

   class MyService
   {
       public function callExternalApi(array $settings): void
       {
           // Resolve vault identifiers to actual values
           $resolved = VaultFieldResolver::resolveFields(
               $settings,
               ['api_key', 'api_secret']
           );

           // Now $resolved['api_key'] contains the actual secret
           $client->authenticate($resolved['api_key']);
       }
   }


.. _tca-helper:

Using the TCA helper
====================

For cleaner TCA configuration, use the :php:`VaultFieldHelper`:

.. code-block:: php
   :caption: Configuration/TCA/tx_myext_settings.php

   <?php
   use Netresearch\NrVault\TCA\VaultFieldHelper;

   return [
       'columns' => [
           'api_key' => VaultFieldHelper::getFieldConfig([
               'label' => 'API Key',
               'description' => 'Your API authentication key',
               'size' => 30,
           ]),

           // Secure field with common defaults (exclude: true, l10n_mode: exclude)
           'api_secret' => VaultFieldHelper::getSecureFieldConfig(
               'API Secret',
               ['required' => true]
           ),
       ],
   ];

.. _tca-helper-options:

Available options
-----------------

==================  ======  ===================================================
Option              Type    Description
==================  ======  ===================================================
``label``           string  Field label.
``description``     string  Field description/help text.
``size``            int     Input field size (default: 30).
``required``        bool    Whether field is required (default: false).
``placeholder``     string  Placeholder text.
``displayCond``     string  TCA display condition.
``l10n_mode``       string  Localization mode.
``exclude``         bool    Exclude from non-admin access.
==================  ======  ===================================================


.. _tca-flexform:

FlexForm integration
====================

Vault secrets also work in FlexForm fields:

.. code-block:: xml
   :caption: Configuration/FlexForms/Settings.xml

   <T3DataStructure>
       <sheets>
           <settings>
               <ROOT>
                   <el>
                       <apiKey>
                           <label>API Key</label>
                           <config>
                               <type>input</type>
                               <renderType>vaultSecret</renderType>
                               <size>30</size>
                           </config>
                       </apiKey>
                   </el>
               </ROOT>
           </settings>
       </sheets>
   </T3DataStructure>

Resolve FlexForm secrets using :php:`FlexFormVaultResolver`:

.. code-block:: php
   :caption: Resolve FlexForm vault fields

   use Netresearch\NrVault\Utility\FlexFormVaultResolver;
   use TYPO3\CMS\Core\Service\FlexFormService;

   class MyPlugin
   {
       public function __construct(
           private readonly FlexFormService $flexFormService,
       ) {}

       public function processSettings(array $contentElement): array
       {
           $settings = $this->flexFormService->convertFlexFormContentToArray(
               $contentElement['pi_flexform']
           );

           // Resolve specific fields
           return FlexFormVaultResolver::resolveSettings(
               $settings,
               ['apiKey', 'apiSecret']
           );

           // Or resolve all vault identifiers automatically
           return FlexFormVaultResolver::resolveAll($settings);
       }
   }


.. _tca-resolver-api:

VaultFieldResolver API
======================

The :php:`VaultFieldResolver` class provides utilities for working with
vault-backed TCA fields.

.. _tca-resolver-resolve-fields:

resolveFields()
---------------

Resolve specific fields in a data array:

.. code-block:: php
   :caption: VaultFieldResolver::resolveFields()

   $resolved = VaultFieldResolver::resolveFields(
       $data,           // Array with potential vault identifiers
       ['field1'],      // Fields to resolve
       false            // Throw on error (default: false)
   );

.. _tca-resolver-resolve:

resolve()
---------

Resolve a single vault identifier (UUID v7 format):

.. code-block:: php
   :caption: VaultFieldResolver::resolve()

   // TCA field identifiers use UUID v7 format
   $secret = VaultFieldResolver::resolve('01937b6e-4b6c-7abc-8def-0123456789ab');

.. _tca-resolver-resolve-record:

resolveRecord()
---------------

Automatically resolve all vault fields in a record based on TCA:

.. code-block:: php
   :caption: VaultFieldResolver::resolveRecord()

   $resolved = VaultFieldResolver::resolveRecord('tx_myext_settings', $record);

.. _tca-resolver-is-identifier:

isVaultIdentifier()
-------------------

Check if a value is a vault identifier:

.. code-block:: php
   :caption: VaultFieldResolver::isVaultIdentifier()

   if (VaultFieldResolver::isVaultIdentifier($value)) {
       // This is a vault identifier
   }

.. _tca-resolver-get-fields:

getVaultFieldsForTable()
------------------------

Get list of vault field names for a table:

.. code-block:: php
   :caption: VaultFieldResolver::getVaultFieldsForTable()

   $fields = VaultFieldResolver::getVaultFieldsForTable('tx_myext_settings');
   // Returns: ['api_key', 'api_secret']


.. _tca-how-it-works:

How it works
============

.. _tca-data-flow:

Data flow
---------

1. **Form display**: The :php:`VaultSecretElement` renders an obfuscated
   password field with reveal/copy buttons.

2. **Form submit**: The :php:`DataHandlerHook` intercepts the form data:

   - Extracts the secret value from the form.
   - Generates a UUID v7 identifier (time-ordered, unique).
   - Stores the secret in the vault with metadata (table, field, uid).
   - Saves only the UUID identifier to the database.

3. **Runtime retrieval**: Your code uses :php:`VaultFieldResolver` to
   look up the actual secret from the vault using the UUID.

.. _tca-identifier-format:

Identifier format
-----------------

TCA and FlexForm fields use **UUID v7** identifiers::

   01937b6e-4b6c-7abc-8def-0123456789ab

UUID v7 provides:

-  **Time-ordering**: Better B-tree index performance in databases.
-  **Uniqueness**: Collision-free without central coordination.
-  **Security**: Does not expose table/field names in the identifier.

The source context (table, field, uid) is stored as metadata in the vault,
not in the identifier itself.

.. tip::

   See :ref:`adr-001-uuid-v7` for the full rationale behind this design
   decision.

.. _tca-record-operations:

Record operations
-----------------

-  **Create**: New vault secret is stored automatically.
-  **Update**: Secret is rotated (maintains audit trail).
-  **Delete**: Vault secrets are removed when the record is deleted.
-  **Copy**: Vault secrets are cloned to the new record under fresh
   identifiers.

Records with several vault fields are handled all-or-nothing.

A **copy** clones every field or none: if one secret cannot be cloned, the
secrets already cloned for that copy are deleted again and *all* vault fields
of the new record are cleared. They are never left holding the source record's
identifiers — the copy would otherwise share the original's secrets, and
rotating or deleting one record would silently change the other. The editor
gets an error message and re-enters the values.

A **delete** checks the delete permission of every vault field *before*
removing the first secret, because a vault delete cannot be undone. If any
field is denied, no secret is removed and the record delete is cancelled. A
field pointing at a secret that no longer exists does not block the delete.


.. _tca-security:

Security considerations
=======================

.. _tca-security-access-control:

Access control
--------------

Vault secrets inherit the access control of the record they belong to.
If a backend user can edit the record, they can update the vault secret.

The reveal button requires explicit user action and is logged.

.. _tca-security-audit:

Audit trail
-----------

All vault operations are logged:

-  Secret creation.
-  Secret reads (via reveal button).
-  Secret updates.
-  Secret deletion.

Review the audit log in the backend module under
:guilabel:`Admin Tools > Vault > Audit Log`.

.. _tca-security-no-plaintext:

No plaintext in database
------------------------

Only vault identifiers are stored in your extension's database tables.
The actual secrets are encrypted with AES-256-GCM in the vault.


.. _tca-migration:

Migration
=========

To migrate existing plaintext credentials to vault storage:

1. Add the ``renderType`` to your existing TCA field configuration.
2. Run the migration command:

   .. code-block:: bash
      :caption: Migrate existing field to vault

      vendor/bin/typo3 vault:migrate-field tx_myext_settings api_key

This will:

-  Read existing plaintext values.
-  Store them securely in the vault.
-  Update records with vault identifiers.

.. attention::

   Always backup your database before running migrations.
