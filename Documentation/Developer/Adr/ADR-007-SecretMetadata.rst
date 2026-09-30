.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-007-secret-metadata:

============================
ADR-007: Secret metadata
============================

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

Vault secrets need associated metadata for:

-  Access control decisions (owner, groups)
-  Lifecycle management (expiration, versioning)
-  Operational insights (read counts, last access)
-  Application context (source, purpose)

This metadata must be queryable without decrypting secrets.

Problem statement
=================

How should secret metadata be stored and structured to enable efficient
queries and management without exposing encrypted values?

Decision drivers
================

-  **Query efficiency**: Filter secrets without decryption
-  **Access control**: Check permissions before decryption attempt
-  **Lifecycle management**: Expiration, versioning, rotation tracking
-  **Flexibility**: Support custom application metadata
-  **Performance**: Metadata operations should be fast

Considered options
==================

Option 1: Metadata in encrypted payload
---------------------------------------

Store metadata inside the encrypted blob.

**Pros:**

-  Single encrypted unit
-  Metadata protected

**Cons:**

-  Must decrypt to query anything
-  Cannot check permissions without decryption
-  Expiration checks require decryption

Option 2: Separate metadata table
---------------------------------

Store metadata in a separate linked table.

**Pros:**

-  Clean separation
-  Different access patterns possible

**Cons:**

-  Join overhead
-  Potential inconsistency
-  More complex queries

Option 3: Metadata columns alongside encrypted value
----------------------------------------------------

Store metadata as plaintext columns in the same table as encrypted data.

**Pros:**

-  Single table, atomic operations
-  Efficient queries on metadata
-  No joins required
-  Access control before decryption

**Cons:**

-  Metadata not encrypted (acceptable for non-sensitive fields)
-  Wider table

Decision
========

We chose **metadata columns alongside encrypted value** because:

1. **Query efficiency**: Filter by owner, context, expiration without decryption
2. **Access control**: Check permissions before attempting decryption
3. **Atomic operations**: Single table ensures consistency
4. **Practical security**: Metadata (owner, groups) is not sensitive

Implementation
==============

Secret entity structure
-----------------------

.. code-block:: php
   :caption: Classes/Domain/Model/Secret.php

   final class Secret
   {
       // Identification
       private ?int $uid = null;
       private string $identifier = '';
       private string $description = '';

       // Encrypted data (only sensitive part)
       private ?string $encryptedValue = null;
       private string $encryptedDek = '';
       private string $dekNonce = '';
       private string $valueNonce = '';
       private string $valueChecksum = '';
       private int $encryptionVersion = 1;

       // Access control (plaintext, needed for permission checks)
       private int $ownerUid = 0;
       private array $allowedGroups = [];
       private string $context = '';
       private bool $frontendAccessible = false;

       // Lifecycle (plaintext, needed for queries)
       private int $version = 1;
       private int $expiresAt = 0;
       private int $lastRotatedAt = 0;
       private int $readCount = 0;
       private int $lastReadAt = 0;

       // Storage
       private string $adapter = 'local';
       private string $externalReference = '';
       private int $scopePid = 0;

       // TYPO3 standard fields
       private int $pid = 0;
       private int $crdate = 0;
       private int $tstamp = 0;
       private int $cruserId = 0;
       private bool $deleted = false;
       private bool $hidden = false;

       // Custom metadata (JSON)
       private array $metadata = [];
   }

Database schema
---------------

.. code-block:: sql
   :caption: Metadata columns

   CREATE TABLE tx_nrvault_secret (
       -- Primary key
       uid int(11) unsigned NOT NULL auto_increment,

       -- Identification (queryable)
       identifier varchar(255) NOT NULL,
       description text,

       -- Encrypted data (protected)
       encrypted_value mediumblob,
       encrypted_dek text,
       dek_nonce varchar(24) NOT NULL,
       value_nonce varchar(24) NOT NULL,
       encryption_version int(11) unsigned DEFAULT 1,
       value_checksum char(64) NOT NULL,

       -- Access control (queryable, not sensitive)
       owner_uid int(11) unsigned DEFAULT 0,
       allowed_groups text,
       context varchar(50) DEFAULT '',
       frontend_accessible tinyint(1) unsigned DEFAULT 0,

       -- Lifecycle (queryable)
       version int(11) unsigned DEFAULT 1,
       expires_at int(11) unsigned DEFAULT 0,
       last_rotated_at int(11) unsigned DEFAULT 0,
       read_count int(11) unsigned DEFAULT 0,
       last_read_at int(11) unsigned DEFAULT 0,

       -- Storage adapter
       adapter varchar(50) DEFAULT 'local',
       external_reference varchar(500) DEFAULT '',
       scope_pid int(11) unsigned DEFAULT 0,

       -- Custom metadata (JSON)
       metadata text,

       -- TYPO3 standard
       pid int(11) DEFAULT 0,
       tstamp int(11) unsigned DEFAULT 0,
       crdate int(11) unsigned DEFAULT 0,
       cruser_id int(11) unsigned DEFAULT 0,
       deleted tinyint(1) unsigned DEFAULT 0,
       hidden tinyint(1) unsigned DEFAULT 0,

       PRIMARY KEY (uid),
       UNIQUE KEY identifier (identifier, deleted),
       KEY owner_uid (owner_uid),
       KEY context (context),
       KEY expires_at (expires_at),
       KEY adapter (adapter)
   );

Metadata categories
-------------------

**Identification:**

-  ``identifier`` - Unique secret name (queryable)
-  ``description`` - Human-readable description

**Access Control:**

-  ``owner_uid`` - Backend user who owns the secret
-  ``allowed_groups`` - Backend groups with access
-  ``context`` - Permission scoping context (e.g., "payment", "reporting")
-  ``frontend_accessible`` - Allow frontend access

**Lifecycle:**

-  ``version`` - Incremented on rotation
-  ``expires_at`` - Unix timestamp for expiration (0 = never)
-  ``last_rotated_at`` - Last rotation timestamp
-  ``read_count`` - Total access count
-  ``last_read_at`` - Last access timestamp

**Storage:**

-  ``adapter`` - Storage backend (currently: local; planned: hashicorp, aws, azure)
-  ``external_reference`` - Reference for external adapters (reserved for future use)
-  ``scope_pid`` - TYPO3 page for hierarchical scoping

**Custom:**

-  ``metadata`` - JSON object for application-specific data

Metadata-only access
--------------------

.. code-block:: php
   :caption: Classes/Service/VaultService.php

   public function getMetadata(string $identifier): array
   {
       $secret = $this->repository->findByIdentifier($identifier);

       // No decryption needed - metadata is plaintext
       return [
           'uid' => $secret->getUid(),
           'identifier' => $secret->getIdentifier(),
           'description' => $secret->getDescription(),
           'owner' => $secret->getOwnerUid(),
           'groups' => $secret->getAllowedGroups(),
           'context' => $secret->getContext(),
           'version' => $secret->getVersion(),
           'createdAt' => $secret->getCrdate(),
           'updatedAt' => $secret->getTstamp(),
           'expiresAt' => $secret->getExpiresAt(),
           'lastRotatedAt' => $secret->getLastRotatedAt(),
           'metadata' => $secret->getMetadata(),
           'scopePid' => $secret->getScopePid(),
       ];
   }

   public function updateMetadata(string $identifier, array $metadata): void
   {
       // Update metadata without touching encrypted value
       $secret = $this->repository->findByIdentifier($identifier);

       if (isset($metadata['description'])) {
           $secret->setDescription($metadata['description']);
       }
       if (isset($metadata['context'])) {
           $secret->setContext($metadata['context']);
       }
       // ... other metadata fields

       $this->repository->save($secret);
   }

Expiration handling
-------------------

.. code-block:: php
   :caption: Expiration check without decryption

   public function retrieve(string $identifier): ?string
   {
       $secret = $this->repository->findByIdentifier($identifier);

       // Check expiration from metadata (no decryption)
       if ($secret->isExpired()) {
           throw new SecretExpiredException($identifier);
       }

       // Check access from metadata (no decryption)
       if (!$this->accessControl->canRead($secret)) {
           throw new AccessDeniedException();
       }

       // Only now decrypt
       return $this->decrypt($secret);
   }

Custom metadata
---------------

.. code-block:: php
   :caption: Using custom metadata

   $vault->store('api_key', $value, [
       'metadata' => [
           'source' => 'tca_field',
           'table' => 'tx_myext_settings',
           'field' => 'api_key',
           'uid' => 42,
           'environment' => 'production',
       ],
   ]);

   // Query by custom metadata
   $secrets = $vault->list();
   $tcaSecrets = array_filter($secrets, fn($s) =>
       ($s['metadata']['source'] ?? '') === 'tca_field'
   );

Consequences
============

Positive
--------

-  **Fast queries**: Filter secrets without decryption
-  **Access control first**: Permissions checked before crypto operations
-  **Expiration enforcement**: Check timestamps without decryption
-  **Flexible metadata**: JSON field for application-specific data
-  **Atomic updates**: Single table ensures consistency
-  **Efficient lifecycle**: Version, rotation, read stats always available

Negative
--------

-  **Metadata exposure**: Plaintext metadata visible in database
-  **Schema rigidity**: Adding new metadata may require migrations
-  **JSON querying**: Custom metadata requires application-level filtering

Risks
-----

-  Sensitive data accidentally stored in metadata
-  Metadata inconsistency with encrypted value

Mitigation
----------

-  Document which fields are encrypted vs plaintext
-  Validate metadata doesn't contain secrets
-  Use database transactions for consistency

Related decisions
=================

-  :ref:`adr-002-envelope-encryption` - Encrypted value storage
-  :ref:`adr-005-access-control` - Uses metadata for permission checks

References
==========

-  `AWS Secrets Manager Metadata <https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_secret_json_structure.html>`_
