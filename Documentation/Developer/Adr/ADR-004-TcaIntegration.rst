.. include:: /Includes.rst.txt

.. _adr-004-tca-integration:

=============================
ADR-004: TCA integration
=============================

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

TYPO3 extensions commonly store sensitive data (API keys, credentials, tokens)
in database fields configured via TCA. The nr-vault extension needs to provide
a seamless way to store these values securely without requiring extensions to
rewrite their data handling.

The integration must:

-  Work with existing TCA field configurations
-  Handle record operations (create, update, delete, copy)
-  Support both regular TCA fields and FlexForm fields
-  Maintain the TYPO3 backend user experience

Problem statement
=================

How should nr-vault integrate with TYPO3's TCA system to transparently
encrypt sensitive fields while maintaining standard TYPO3 workflows?

Decision drivers
================

-  **Transparency**: Extensions should need minimal code changes
-  **Compatibility**: Must work with standard TYPO3 record operations
-  **User experience**: Backend users should see familiar interfaces
-  **Flexibility**: Support various field types and configurations
-  **Auditability**: All operations must be trackable

Considered options
==================

Option 1: Custom field type
---------------------------

Create a completely new TCA field type.

**Pros:**

-  Full control over behavior

**Cons:**

-  Requires TCA rewrite for existing extensions
-  Different behavior from standard fields

Option 2: FormEngine override
-----------------------------

Override the default input field rendering globally.

**Pros:**

-  No TCA changes needed

**Cons:**

-  Affects all input fields
-  Difficult to target specific fields
-  Potential conflicts

Option 3: Custom renderType with DataHandler hooks
--------------------------------------------------

Provide a ``renderType`` for FormEngine and intercept saves via hooks.

**Pros:**

-  Opt-in per field (add ``renderType: 'vaultSecret'``)
-  Uses standard TYPO3 hook system
-  Familiar pattern for TYPO3 developers

**Cons:**

-  Requires TCA modification (but minimal)
-  Two components to maintain (element + hook)

Decision
========

We chose **custom renderType with DataHandler hooks** because:

1. **Explicit opt-in**: Only fields marked with ``renderType: 'vaultSecret'``
   are encrypted
2. **Standard patterns**: Uses FormEngine elements and DataHandler hooks
3. **Minimal changes**: One line added to existing TCA configurations
4. **Full lifecycle**: Hooks handle create, update, delete, and copy operations

Implementation
==============

FormEngine element
------------------

.. code-block:: php
   :caption: Classes/Form/Element/VaultSecretElement.php

   final class VaultSecretElement extends AbstractFormElement
   {
       public function render(): array
       {
           // Render password field with:
           // - Masked display (dots)
           // - Reveal button (permission-based)
           // - Copy button (permission-based)
           // - Hidden field for vault identifier
       }
   }

Registration in :file:`ext_localconf.php`:

.. code-block:: php
   :caption: ext_localconf.php

   $GLOBALS['TYPO3_CONF_VARS']['SYS']['formEngine']['nodeRegistry'][1735400000] = [
       'nodeName' => 'vaultSecret',
       'priority' => 40,
       'class' => VaultSecretElement::class,
   ];

DataHandler hook
----------------

.. code-block:: php
   :caption: Classes/Hook/DataHandlerHook.php

   final class DataHandlerHook
   {
       // Before save: Extract secret, generate UUID, queue for storage
       public function processDatamap_preProcessFieldArray(...): void
       {
           foreach ($this->getVaultFields($table) as $field) {
               if ($this->hasSecretValue($fieldArray, $field)) {
                   $uuid = $this->generateUuid();
                   $this->pendingSecrets[$table][$id][$field] = [
                       'uuid' => $uuid,
                       'value' => $fieldArray[$field]['value'],
                   ];
                   $fieldArray[$field] = $uuid;  // Store UUID in database
               }
           }
       }

       // After save: Store secrets with correct UID. The shipped hook
       // delegates this to PendingSecretPersister, which rolls the field
       // value back and reports to the editor when the store is refused.
       public function processDatamap_afterDatabaseOperations(...): void
       {
           foreach ($this->pendingSecrets[$table][$id] as $field => $data) {
               $this->vaultService->store($data['uuid'], $data['value'], [
                   'metadata' => [
                       'table' => $table,
                       'field' => $field,
                       'uid' => $recordUid,
                       'source' => 'tca_field',
                   ],
               ]);
           }
       }

       // Before delete: Remove associated secrets
       public function processCmdmap_preProcess(...): void;

       // After copy: Create new secrets for copied record
       public function processCmdmap_postProcess(...): void;
   }

FlexForm hook
-------------

Separate hook for FlexForm fields due to different data structure:

.. code-block:: php
   :caption: Classes/Hook/FlexFormVaultHook.php

   final class FlexFormVaultHook
   {
       public function processDatamap_preProcessFieldArray(...): void
       {
           // Recursively scan FlexForm XML for vaultSecret fields
           // Same UUID-based approach as TCA fields
           // Store metadata: flexField, sheet, fieldPath
       }

       // Store the pending secrets once the record has its final UID
       public function processDatamap_afterDatabaseOperations(...): void;

       // Before delete: remove the secrets the FlexForm references
       public function processCmdmap_deleteAction(...): void;

       // After copy: re-key the copied FlexForm onto fresh identifiers
       public function processCmdmap_postProcess(...): void;
   }

TCA configuration
-----------------

Extensions add vault support with one line:

.. code-block:: php
   :caption: Configuration/TCA/tx_myext_settings.php

   'api_key' => [
       'label' => 'API Key',
       'config' => [
           'type' => 'input',
           'renderType' => 'vaultSecret',  // This one line
           'size' => 30,
       ],
   ],

Helper for common patterns:

.. code-block:: php
   :caption: Using VaultFieldHelper

   use Netresearch\NrVault\TCA\VaultFieldHelper;

   'api_key' => VaultFieldHelper::getSecureFieldConfig('API Key'),

Data flow
---------

.. code-block:: text
   :caption: TCA vault field data flow

   Form Display:
   1. VaultSecretElement renders password field
   2. If UUID exists, shows masked value with reveal option
   3. JavaScript handles reveal/copy interactions

   Form Submit:
   1. DataHandlerHook.preProcess extracts secret value
   2. Generates UUID v7 identifier (see ADR-001)
   3. Sets field value to UUID (for database)
   4. DataHandlerHook.afterDatabaseOperations delegates to
      PendingSecretPersister, which stores the secret in the vault
   5. On refusal: the field value is rolled back, VaultFailureReporter tells
      the editor, and no success audit entry survives

   Record Delete:
   1. DataHandlerHook.processCmdmap_preProcess finds vault fields
   2. Retrieves UUIDs from record
   3. Asserts every field's delete gate BEFORE removing the first secret
   4. Deletes corresponding vault secrets
   5. On failure: processCmdmap cancels the record delete, so the record and
      its surviving secret stay together rather than orphaning either

   Record Copy:
   1. DataHandlerHook.processCmdmap_postProcess detects copy
   2. Retrieves source secrets by UUID
   3. Creates new secrets with new UUIDs for copied record
   4. On failure: the secrets already cloned are deleted again and every
      vault field of the new record is blanked; both steps are best-effort,
      so a failed rollback delete leaves an orphaned clone and a failed
      blanking leaves the copy referencing the source record's secrets

Runtime resolution
------------------

.. code-block:: php
   :caption: Resolving secrets in application code

   use Netresearch\NrVault\Utility\VaultFieldResolver;

   // VaultFieldResolver is a DI service, not a static utility — inject it.
   public function __construct(
       private readonly VaultFieldResolver $vaultFieldResolver,
   ) {}

   // Resolve specific fields
   $resolved = $this->vaultFieldResolver->resolveFields($record, ['api_key']);

   // Auto-detect vault fields from TCA
   $resolved = $this->vaultFieldResolver->resolveRecord('tx_myext_settings', $record);

Consequences
============

Positive
--------

-  **Minimal migration**: Add ``renderType`` to existing fields
-  **Familiar patterns**: Standard FormEngine and DataHandler usage
-  **Full lifecycle**: Handles all record operations automatically
-  **Audit trail**: All operations logged with context metadata
-  **UUID portability**: Secrets not tied to table structure

Negative
--------

-  **Two hooks required**: Separate handling for TCA and FlexForm
-  **Runtime resolution**: Application code must resolve UUIDs to values
-  **Learning curve**: Developers must understand vault resolution

Risks
-----

-  Hook execution order conflicts with other extensions
-  FlexForm structure changes could break field detection

Mitigation
----------

-  Use high priority for hooks
-  Comprehensive test coverage for FlexForm parsing
-  Clear documentation for resolution patterns

Related decisions
=================

-  :ref:`adr-001-uuid-v7` - Identifier format for stored secrets

References
==========

-  `TYPO3 FormEngine Documentation <https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/ApiOverview/FormEngine/Index.html>`_
-  `TYPO3 DataHandler Hooks <https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/ApiOverview/Typo3CoreEngine/Database/Index.html>`_
