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

   1. Is user a TYPO3 admin or system maintainer?
      → YES: ALLOW (full access)

   2. Is user the secret's owner (owner_uid)?
      → YES: ALLOW (full access)

   3. Is user a member of any allowed_groups?
      → YES: ALLOW (read/write access)

   4. Is this a CLI/scheduler context with CLI access enabled?
      → YES: Check CLI access groups
      → Group matches: ALLOW

   5. Is this frontend context with frontend_accessible=true?
      → YES: ALLOW (read only)

   6. Default: DENY

Database schema
---------------

.. code-block:: sql
   :caption: Access control columns

   -- Single owner
   owner_uid int(11) unsigned DEFAULT 0 NOT NULL,

   -- Multiple groups (many-to-many)
   allowed_groups text,

   -- Frontend access flag
   frontend_accessible tinyint(1) unsigned DEFAULT 0 NOT NULL,

   -- Permission scoping
   context varchar(50) DEFAULT '' NOT NULL,
   scope_pid int(11) unsigned DEFAULT 0 NOT NULL,

   -- Many-to-many relation table
   CREATE TABLE tx_nrvault_secret_begroups_mm (
       uid_local int(11) unsigned,    -- Secret UID
       uid_foreign int(11) unsigned,  -- Backend group UID
   );

AccessControlService
--------------------

.. code-block:: php
   :caption: Classes/Security/AccessControlService.php

   final readonly class AccessControlService implements AccessControlServiceInterface
   {
       public function canRead(Secret $secret): bool
       {
           return $this->checkAccess($secret);
       }

       public function canWrite(Secret $secret): bool
       {
           return $this->checkAccess($secret);
       }

       public function canDelete(Secret $secret): bool
       {
           return $this->checkAccess($secret);
       }

       private function checkAccess(Secret $secret): bool
       {
           $backendUser = $GLOBALS['BE_USER'] ?? null;

           if ($backendUser === null) {
               return $this->checkCliAccess($secret);
           }

           // Admins and system maintainers have full access
           if ($backendUser->isAdmin() || $backendUser->isSystemMaintainer()) {
               return true;
           }

           // Owner has full access
           $userUid = (int) ($backendUser->user['uid'] ?? 0);
           if ($userUid === $secret->getOwnerUid()) {
               return true;
           }

           // Check group membership
           $userGroups = $backendUser->userGroupsUID ?? [];
           $allowedGroups = $secret->getAllowedGroups();

           return count(array_intersect($userGroups, $allowedGroups)) > 0;
       }
   }

Enforcement points
------------------

Access checks are enforced in :php:`VaultService`:

.. code-block:: php
   :caption: Classes/Service/VaultService.php

   public function retrieve(string $identifier): ?string
   {
       $secret = $this->repository->findByIdentifier($identifier);

       if (!$this->accessControl->canRead($secret)) {
           $this->auditLog->log($identifier, 'access_denied', false);
           throw new AccessDeniedException('Access denied');
       }

       // ... decrypt and return
   }

   public function delete(string $identifier, string $reason = ''): void
   {
       $secret = $this->repository->findByIdentifier($identifier);

       if (!$this->accessControl->canDelete($secret)) {
           throw new AccessDeniedException('Delete access denied');
       }

       // ... delete secret
   }

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
       'label' => 'Allowed Groups',
       'config' => [
           'type' => 'group',
           'allowed' => 'be_groups',
           'MM' => 'tx_nrvault_secret_begroups_mm',
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

-  **No per-operation ACL**: Read/write/delete not separately controlled
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
