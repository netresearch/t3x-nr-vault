.. include:: /Includes.rst.txt

.. _adr-005-access-control:

===========================
ADR-005: Access control
===========================

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

Secrets in the vault may contain highly sensitive data (API keys, passwords,
certificates). Access to these secrets must be controlled to:

-  Prevent unauthorized access to sensitive data
-  Support collaborative workflows (teams, departments)
-  Integrate with TYPO3's existing permission system
-  Enable audit trails for compliance

Problem statement
=================

How should access to vault secrets be controlled in a way that integrates
naturally with TYPO3's backend user system?

Decision drivers
================

-  **TYPO3 integration**: Use existing backend users and groups
-  **Granularity**: Per-secret permissions, not just global
-  **Simplicity**: Familiar model for TYPO3 administrators
-  **Flexibility**: Support owner, group, and admin access patterns
-  **Auditability**: All access attempts must be logged

Considered options
==================

Option 1: TYPO3 page-based permissions
--------------------------------------

Inherit permissions from the page tree where secrets are stored.

**Pros:**

-  Familiar TYPO3 pattern
-  Works with existing mount points

**Cons:**

-  Secrets aren't naturally page-based
-  Complex for cross-page secrets
-  Inflexible for API-created secrets

Option 2: Custom ACL system
---------------------------

Build a separate permission system specific to vault.

**Pros:**

-  Maximum flexibility
-  Could model complex scenarios

**Cons:**

-  Learning curve for administrators
-  Doesn't leverage existing TYPO3 knowledge
-  More code to maintain

Option 3: Owner/Group model with TYPO3 integration
--------------------------------------------------

Each secret has an owner (backend user) and allowed groups (backend groups).

**Pros:**

-  Maps to TYPO3 concepts (users, groups)
-  Simple mental model: "who owns it, who can access it"
-  Familiar to Unix-style permissions

**Cons:**

-  Less granular than full ACL
-  No per-operation permissions (read vs write)

Decision
========

We chose **Owner/Group model with TYPO3 integration** because:

1. **Familiarity**: TYPO3 administrators understand users and groups
2. **Simplicity**: Easy to reason about access decisions
3. **Sufficient granularity**: Owner + groups covers most use cases
4. **Admin override**: TYPO3 admins can access all secrets (expected behavior)

Implementation
==============

Permission model
----------------

.. code-block:: text
   :caption: Access decision tree

   Access Decision Tree:

   0. Does the actor hold the operation permission for what it is about to do
      (secret.use / secret.reveal / secret.create / secret.rotate /
      secret.delete / secret.manage_policy)?
      → NO: DENY. This gate is independent of everything below it; the
        per-secret tiers can never grant an operation the actor may not perform.

   1. Is user a TYPO3 admin or system maintainer?
      → YES: ALLOW (full access) — UNLESS the hardened profile withdrew the
        bypass (disableAdminOverride) and no break-glass window is open.

   2. Is user the secret's owner (owner_uid)?
      → YES: ALLOW (full access)

   3. Is user a member of the secret's group tiers?
      → READ:   member of allowed_groups OR write_groups → ALLOW
      → WRITE:  member of write_groups → ALLOW
      → DELETE: no group tier applies — owner or admin only

   4. Is this a CLI/scheduler context with CLI access enabled?
      → YES: Check CLI access groups
      → Group matches: ALLOW

   5. Is this frontend context with frontend_accessible=true?
      → YES: ALLOW (read only). A frontend request holds NO operation
        permission at all, whatever backend session the visitor carries —
        TYPO3 populates $GLOBALS['BE_USER'] for any visitor with a valid
        backend session, and frontend output is page-cached.

   6. Default: DENY

Database schema
---------------

.. code-block:: sql
   :caption: Access control columns

   -- Single owner
   owner_uid int(11) unsigned DEFAULT 0 NOT NULL,

   -- Two group tiers (many-to-many). allowed_groups grants READ;
   -- write_groups grants read AND write. Neither grants delete.
   allowed_groups text,
   write_groups text,

   -- Frontend access flag
   frontend_accessible tinyint(1) unsigned DEFAULT 0 NOT NULL,

   -- Permission scoping
   context varchar(50) DEFAULT '' NOT NULL,
   scope_pid int(11) unsigned DEFAULT 0 NOT NULL,

   -- Many-to-many relation tables, one per tier
   CREATE TABLE tx_nrvault_secret_begroups_mm (
       uid_local int(11) unsigned,    -- Secret UID
       uid_foreign int(11) unsigned,  -- Backend group UID (read tier)
   );

   CREATE TABLE tx_nrvault_secret_writegroups_mm (
       uid_local int(11) unsigned,    -- Secret UID
       uid_foreign int(11) unsigned,  -- Backend group UID (write tier)
   );

AccessControlService
--------------------

.. code-block:: php
   :caption: Classes/Security/AccessControlService.php

   final readonly class AccessControlService implements AccessControlServiceInterface
   {
       public function canRead(Secret $secret): bool
       {
           return $this->checkAccess($secret, self::PERMISSION_READ);
       }

       private function checkAccess(Secret $secret, string $permission): bool
       {
           $backendUser = $GLOBALS['BE_USER'] ?? null;

           if ($backendUser === null) {
               return $this->checkCliAccess($secret);
           }

           // THE single admin-bypass seam. Never inline isAdmin() or
           // isSystemMaintainer() in a caller: an override that is only
           // half-disabled is worse than one that is not disabled at all,
           // because the deployment believes it is protected.
           if ($this->adminBypassActive($backendUser->isAdmin())) {
               return true;
           }

           // Owner has full access
           $userUid = (int) ($backendUser->user['uid'] ?? 0);
           if ($userUid === $secret->getOwnerUid()) {
               return true;
           }

           // Group tiers are per-permission: read reads both tiers, write
           // reads write_groups only, delete has no group tier at all.
           $secretGroups = $this->secretGroupsForPermission($secret, $permission);

           return array_intersect($this->currentUserGroups(), $secretGroups) !== [];
       }
   }

Under :php:`SecurityProfile::Hardened` with ``disableAdminOverride`` set,
:php:`adminBypassActive()` denies a real administrator unless a break-glass
window is open. That is the whole reason the bypass has exactly one
implementation.

Enforcement points
------------------

Access checks are enforced in :php:`VaultService` and, for the FormEngine
path, in :php:`SecretTcaHook`. Every enforcement point combines **both** gates
rather than either one alone.

A read asserts the per-secret tier via :php:`canRead()` and the
``secret.use`` operation permission; a reveal additionally asserts
``secret.reveal``. A write asserts :php:`canWrite()` plus ``secret.create`` or
``secret.rotate`` depending on whether the secret already exists, and
``secret.manage_policy`` when the submitted data changes the owner or the
group tiers. A delete asserts :php:`canDelete()` plus ``secret.delete``.

Every denial writes an ``access_denied`` audit row before the
:php:`AccessDeniedException` leaves the service, so a refusal is evidence
rather than a silent gap.

A FormEngine edit of a ``tx_nrvault_secret`` record never reaches
:php:`VaultService` for its metadata columns, so :php:`SecretTcaHook` applies
the same two gates in ``processDatamap_preProcessFieldArray()``, before
DataHandler writes anything. Core's ``tables_modify`` grant is a *table*
permission and is not the vault ACL: without this the holder of that grant
could change any secret's columns. The hook therefore refuses the whole
record — by nulling the by-ref field array, which makes DataHandler skip it —
unless :php:`canWrite()` passes, and it drops the **privileged columns** from
an otherwise authorized save unless the actor is an administrator or the
owner holding ``secret.manage_policy``:

``owner_uid``, ``scope_pid``, ``allowed_groups``, ``write_groups``
   Who may reach the secret, and under which page scope.

``frontend_accessible``
   Flips the secret from ACL-gated to readable by any frontend request.

``hidden``
   The same column ``SecretsController::toggleAction()`` gates on
   ``secret.manage_policy``; leaving the record path open would make that
   gate bypassable.

``expires_at``
   Honoured at runtime, so backdating denies the secret to every consumer
   and clearing it revives a retired one.

``metadata``
   Machine-consumed provenance that :php:`OrphanCleanupTask` reads to decide
   whether a secret is an orphan to delete.

``context``
   The inventory dimension the listing and analytics filter on.

``description`` is deliberately not privileged: it is free-text documentation
with no machine consumer, and write access to a secret should carry the right
to document it.

TCA configuration
-----------------

.. code-block:: php
   :caption: Configuration/TCA/tx_nrvault_secret.php

   'owner_uid' => [
       'label' => 'Owner',
       'config' => [
           'type' => 'group',
           'allowed' => 'be_users',
           'maxitems' => 1,
       ],
   ],

   'allowed_groups' => [
       'label' => 'Allowed Groups (read)',
       'config' => [
           'type' => 'group',
           'allowed' => 'be_groups',
           'MM' => 'tx_nrvault_secret_begroups_mm',
           'maxitems' => 20,
       ],
   ],

   'write_groups' => [
       'label' => 'Write Groups (read + write)',
       'config' => [
           'type' => 'group',
           'allowed' => 'be_groups',
           'MM' => 'tx_nrvault_secret_writegroups_mm',
           'maxitems' => 20,
       ],
   ],

Actor context
-------------

.. code-block:: php
   :caption: Getting current actor information

   public function getCurrentActorUid(): int
   {
       return (int) ($GLOBALS['BE_USER']->user['uid'] ?? 0);
   }

   public function getCurrentActorType(): string
   {
       if (Environment::isCli()) {
           return 'cli';
       }
       if ($GLOBALS['BE_USER'] ?? null) {
           return 'backend';
       }
       return 'api';
   }

Field-level permissions (TSconfig)
----------------------------------

Additional field-level control via TSconfig:

.. code-block:: typoscript
   :caption: TSconfig for field permissions

   vault.permissions {
       default {
           reveal = 1
           copy = 1
           edit = 1
           readOnly = 0
       }

       tx_myext_settings.api_key {
           reveal = 0
           copy = 0
       }
   }

``reveal`` and ``copy`` only affect the rendered form element. ``edit`` and
``readOnly`` are additionally enforced on the DataHandler write path for TCA
vault fields: a value submitted for a protected field is discarded and reported
to the editor, so stripping the ``readonly`` attribute in the browser gains
nothing. Two limits remain: the settings are read from the global (page 0)
TSconfig rather than from the edited record's page, and vault fields embedded in
FlexForms — which resolve their permissions under the *FlexForm column* name —
are not re-checked on write.

Consequences
============

Positive
--------

-  **Familiar model**: Uses TYPO3 users and groups
-  **Simple reasoning**: Owner and group membership are clear concepts
-  **Admin override**: Expected TYPO3 behavior preserved
-  **Audit integration**: All access attempts logged with actor info
-  **Flexible scoping**: Context and scope_pid for additional filtering

Negative
--------

-  **No per-operation ACL**: Read/write/delete not separately controlled.
   **Superseded.** Ten operation permissions now exist as
   :php:`VaultPermission` cases (``secret.use``, ``secret.reveal``,
   ``secret.create``, ``secret.rotate``, ``secret.delete``,
   ``secret.manage_policy``, ``audit.view``, ``audit.export``,
   ``master_key.rotate``, ``vault.configure``), each granted per backend user
   group through the ``tx_nrvault:<permission>`` custom option and enforced
   centrally via :php:`AccessControlServiceInterface::isGranted()`. They are a
   second gate alongside the per-secret tiers described here, not a
   replacement for them. See :ref:`security-operation-permissions`.
-  **Group proliferation**: May need many groups for fine-grained control
-  **No inheritance**: Secrets don't inherit from parent pages

Risks
-----

-  Orphaned secrets if owner is deleted
-  Group changes affect access immediately (no caching)

Mitigation
----------

-  Default to admin ownership for orphaned secrets
-  Document group membership implications
-  Provide cleanup commands for orphaned secrets

Related decisions
=================

-  :ref:`adr-006-audit-logging` - Access attempts are logged

References
==========

-  `TYPO3 Backend User API <https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/ApiOverview/BackendUserObject/Index.html>`_
