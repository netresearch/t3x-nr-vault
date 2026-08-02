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
           "netresearch/nr-vault": "^0.13"
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
       // VaultFieldResolver is a DI service — inject it, never call it
       // statically.
       public function __construct(
           private readonly VaultFieldResolver $vaultFieldResolver,
       ) {}

       public function callExternalApi(array $settings): void
       {
           // Resolve vault identifiers to actual values
           $resolved = $this->vaultFieldResolver->resolveFields(
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
           private readonly FlexFormVaultResolver $flexFormVaultResolver,
       ) {}

       public function processSettings(array $contentElement): array
       {
           $settings = $this->flexFormService->convertFlexFormContentToArray(
               $contentElement['pi_flexform']
           );

           // Resolve specific fields
           return $this->flexFormVaultResolver->resolveSettings(
               $settings,
               ['apiKey', 'apiSecret']
           );

           // Or resolve all vault identifiers automatically
           return $this->flexFormVaultResolver->resolveAll($settings);
       }
   }


.. _tca-resolver-api:

VaultFieldResolver API
======================

The :php:`VaultFieldResolver` class provides utilities for working with
vault-backed TCA fields.

..  important::

    :php:`VaultFieldResolver` and :php:`FlexFormVaultResolver` are
    ``final readonly`` DI services with **instance** methods. Inject them via
    the constructor; calling any of the methods below statically is a fatal
    error. The examples show the call on an injected
    ``$this->vaultFieldResolver``.

.. _tca-resolver-resolve-fields:

resolveFields()
---------------

Resolve specific fields in a data array:

.. code-block:: php
   :caption: VaultFieldResolver::resolveFields()

   $resolved = $this->vaultFieldResolver->resolveFields(
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
   $secret = $this->vaultFieldResolver->resolve('01937b6e-4b6c-7abc-8def-0123456789ab');

.. _tca-resolver-resolve-record:

resolveRecord()
---------------

Automatically resolve all vault fields in a record based on TCA:

.. code-block:: php
   :caption: VaultFieldResolver::resolveRecord()

   $resolved = $this->vaultFieldResolver->resolveRecord('tx_myext_settings', $record);

.. _tca-resolver-is-identifier:

isVaultIdentifier()
-------------------

Check if a value is a vault identifier:

.. code-block:: php
   :caption: VaultFieldResolver::isVaultIdentifier()

   if ($this->vaultFieldResolver->isVaultIdentifier($value)) {
       // This is a vault identifier
   }

.. _tca-resolver-get-fields:

getVaultFieldsForTable()
------------------------

Get list of vault field names for a table:

.. code-block:: php
   :caption: VaultFieldResolver::getVaultFieldsForTable()

   $fields = $this->vaultFieldResolver->getVaultFieldsForTable('tx_myext_settings');
   // Returns: ['api_key', 'api_secret']

.. _tca-resolver-has-fields:

hasVaultFields()
----------------

Cheap check for whether a table has any vault-backed field at all — use it to
skip resolution work entirely rather than resolving an empty field list:

.. code-block:: php
   :caption: VaultFieldResolver::hasVaultFields()

   if ($this->vaultFieldResolver->hasVaultFields('tx_myext_settings')) {
       // ... resolve
   }

.. _tca-resolver-flex-fields:

getFlexFieldsForTable()
-----------------------

The FlexForm counterpart, on :php:`FlexFormVaultResolver`: the FlexForm
columns of a table whose data structure declares ``vaultSecret`` fields.

.. code-block:: php
   :caption: FlexFormVaultResolver::getFlexFieldsForTable()

   $flexFields = $this->flexFormVaultResolver->getFlexFieldsForTable('tt_content');


.. _tca-how-it-works:

How it works
============

.. _tca-data-flow:

Data flow
---------

1. **Form display**: The :php:`VaultSecretElement` renders an obfuscated
   password field with a reveal button, plus a copy button outside the
   hardened profile.

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

Records with several vault fields are handled as one unit, with the residual
cases named below.

A **create** whose secret value is refused is compensated rather than left
half-applied: the just-inserted ``tx_nrvault_secret`` row is removed, the
record's field value is rolled back, and no success audit entry survives — a
refused create leaves nothing behind that would later read as a successful
one. Only a genuinely value-less record is audited as created. The mutation
and its audit entry commit together throughout, including the MM rows behind
``allowed_groups`` and ``write_groups``: DataHandler writes those *before* the
completion hook runs, so a snapshot taken beforehand is what restores them if
the audit write fails.

A **copy** clones every field or none: if one secret cannot be cloned, the
secrets already cloned for that copy are deleted again and *all* vault fields
of the new record are cleared, so the copy does not end up holding the source
record's identifiers — it would otherwise share the original's secrets, and
rotating or deleting one record would silently change the other. The editor
gets an error message and re-enters the values.

Both halves of that rollback are best effort. If a rollback delete fails, the
clone it should have removed survives as an orphan that nothing references any
more; the failure is logged for the administrator rather than shown to the
editor. If the blanking write fails, the copy keeps the source record's
identifiers and does share its secrets — the editor's error message says so
explicitly, and the record needs manual review.

A **delete** checks the delete permission of every vault field *before*
removing the first secret, because a vault delete cannot be undone. If any
field is denied, no secret is removed and the record delete is cancelled. A
field pointing at a secret that no longer exists does not block the delete.

The preflight cannot cover a failure it is unable to predict — an audit write
that fails, a vault outage, a permission revoked between the check and the
delete. If one of those hits partway through, the loop stops rather than
enlarging the damage, the record is preserved, and the error names how many
secrets of preceding fields were already deleted and cannot be restored. That
count is the signal to re-enter those values; the record still exists, so
nothing else is lost.


.. _tca-security:

Security considerations
=======================

.. _tca-security-access-control:

Access control
--------------

Editing the record is necessary but **not** sufficient. Every vault field
mutation goes through the same two gates as any other vault operation: the
operation permission (``secret.create`` when the field is first filled,
``secret.rotate`` on a change, ``secret.delete`` when the record goes) and the
per-secret owner/group tiers. A backend user who may edit the record but holds
neither will have the mutation refused, and the refusal is audited — see
:ref:`security-operation-permissions` and :ref:`security-access-control`.

The reveal button requires explicit user action and is logged. Revealing also
asserts ``secret.reveal``, which ``secret.use`` does not imply.

On top of both gates, page TSconfig can narrow what the *widget* offers, per
table and per field:

.. code-block:: typoscript
   :caption: Page TSconfig

   vault.permissions {
       default {
           reveal = 1
           copy = 1
           edit = 1
       }

       tx_myext_settings {
           default {
               reveal = 0
           }

           api_key {
               reveal = 1
               copy = 0
               edit = 1
               readOnly = 0
           }
       }
   }

This layer only ever removes affordances from the form; it cannot grant an
operation the permission gates withheld. Administrators are exempt from it,
except for ``readOnly``.

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
The actual secrets are encrypted with XChaCha20-Poly1305 — or AES-256-GCM when
:confval:`ext-nrvault-encryptionAlgorithm` selects it — under a per-secret DEK
that is itself wrapped by the master key.


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
