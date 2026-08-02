.. include:: /Includes.rst.txt

.. _adr-018-flexform-secret-lifecycle:

=============================================
ADR-018: FlexForm secret lifecycle management
=============================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-03-28

Context
=======

FlexForm vault secrets were not managed across record lifecycle operations.
When a TYPO3 record containing FlexForm vault references was deleted, the
referenced secrets remained in the vault as orphans, consuming storage and
polluting audit trails. When a record was copied, the new record shared the
same secret UUIDs as the original, meaning changes to the secret in one
record would silently affect the other.

This created two distinct problems:

-  **Orphaned secrets**: Deleted records left behind unreferenced vault
   entries with no owner, violating the principle that every secret should
   be traceable to a consuming record.
-  **Shared secrets on copy**: Copied records pointed to the same vault
   secrets as the original, breaking data isolation between records and
   causing unintended side-effects on secret updates.

Decision
========

Implement ``processCmdmap`` hooks in the TYPO3 DataHandler to intercept
record lifecycle operations:

-  **Delete hook**: When a record containing FlexForm vault references is
   deleted, automatically clean up (delete) the associated vault secrets.
-  **Copy hook**: When a record is copied, generate fresh UUIDs for all
   vault secret references in the new record and duplicate the secret
   values under the new identifiers. If any one duplication fails, the
   secrets already cloned for that copy are deleted again and *every* vault
   field of the new record is blanked, so a copy never silently shares the
   source record's secrets. If the blanking itself fails, the editor is told
   the new record may still reference them.

This ensures vault secrets follow the same lifecycle as the records that
own them.

..  note::

    The decision is written from the FlexForm case, but the shipped
    lifecycle hooks are not FlexForm-specific: :php:`DataHandlerHook` applies
    the same fail-closed copy and delete semantics to plain TCA vault fields,
    while :php:`FlexFormVaultHook` handles the FlexForm shape. Read the
    consequences below as covering both.

Consequences
============

Positive
--------

-  **No orphaned secrets**: Vault entries are cleaned up when their owning
   record is deleted, keeping the vault tidy.
-  **Data isolation**: Copied records receive independent secret copies,
   preventing unintended cross-record side-effects.
-  **Consistent lifecycle**: Vault secrets and TYPO3 records share the same
   create/copy/delete semantics.

Negative
--------

-  **Hook complexity**: The DataHandler hooks must correctly parse FlexForm
   XML to discover vault references, adding parsing logic to the lifecycle
   layer.
-  **Copy overhead**: Copying a record with many vault secrets requires
   additional vault write operations for each secret duplication.
-  **Fail-closed cascade**: a vault delete that fails — including one that is
   *denied* — cancels the record delete rather than leaving partial state, and
   the failure surfaces to the editor. Deleting the record while its secret
   survived would orphan the secret and hide the failed delete behind an
   apparently successful record removal. The cost is that a record cannot be
   removed while its secret delete is refused.

Related decisions
=================

-  :ref:`adr-004-tca-integration` - TCA integration for vault fields
-  :ref:`adr-006-audit-logging` - Lifecycle operations are audit-logged
