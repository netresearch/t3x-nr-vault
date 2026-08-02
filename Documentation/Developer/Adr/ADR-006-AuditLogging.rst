.. include:: /Includes.rst.txt

.. _adr-006-audit-logging:

=========================
ADR-006: Audit logging
=========================

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

Secret management systems require comprehensive audit trails for:

-  Security incident investigation
-  Compliance requirements (SOC 2, ISO 27001, GDPR)
-  Debugging access issues
-  Detecting unauthorized access attempts

The audit system must capture who accessed what, when, and from where,
while being tamper-evident to ensure log integrity.

Problem statement
=================

How should vault operations be logged to provide complete auditability
while preventing log tampering?

Decision drivers
================

-  **Completeness**: All operations must be logged
-  **Tamper evidence**: Modifications to logs must be detectable
-  **Performance**: Logging should not significantly impact operations
-  **Queryability**: Logs must be filterable and searchable
-  **Extensibility**: External systems should be able to react to events

Considered options
==================

Option 1: TYPO3 sys_log
-----------------------

Use TYPO3's built-in logging system.

**Pros:**

-  Already integrated
-  Familiar to TYPO3 administrators

**Cons:**

-  No tamper detection
-  Limited structure for vault-specific data
-  Mixed with other system logs

Option 2: External logging service
----------------------------------

Send logs to external SIEM (Splunk, ELK, etc.).

**Pros:**

-  Enterprise-grade features
-  Centralized logging

**Cons:**

-  Requires external infrastructure
-  Network dependency
-  Complex configuration

Option 3: Dedicated audit table with hash chain
-----------------------------------------------

Custom table with tamper-evident hash chain linking entries.

**Pros:**

-  Self-contained, no external dependencies
-  Cryptographic tamper evidence
-  Structured for vault operations
-  Combined with PSR-14 events for extensibility

**Cons:**

-  Additional storage
-  Hash chain verification overhead

Decision
========

We chose **dedicated audit table with hash chain** combined with
**PSR-14 events** because:

1. **Self-contained**: No external dependencies required
2. **Tamper-evident**: SHA-256 hash chain detects modifications
3. **Extensible**: PSR-14 events allow external system integration
4. **Structured**: Purpose-built schema for vault operations

Implementation
==============

Audit log entry structure
-------------------------

.. code-block:: php
   :caption: Classes/Audit/AuditLogEntry.php

   final readonly class AuditLogEntry implements JsonSerializable
   {
       public function __construct(
           public ?int $uid,
           public string $secretIdentifier,
           public string $action,              // create, read, update, delete, rotate
           public bool $success,
           public ?string $errorMessage,
           public ?string $reason,
           public int $actorUid,
           public string $actorType,           // backend, cli, api, scheduler
           public string $actorUsername,
           public string $actorRole,
           public string $ipAddress,
           public string $userAgent,
           public string $requestId,
           public string $previousHash,        // Links to prior entry
           public string $entryHash,           // SHA-256 of this entry
           public string $hashBefore,          // Value checksum before
           public string $hashAfter,           // Value checksum after
           public int $crdate,
           public array $context,              // Structured JSON metadata
       ) {}
   }

Hash chain algorithm
--------------------

.. note::

   As of :ref:`adr-023-audit-hash-chain-hmac`, the hash chain uses
   HMAC-SHA256 keyed with an HKDF-derived key from the master key.
   New entries (epoch 1+) use ``hash_hmac()`` instead of plain ``hash()``.
   Legacy entries (epoch 0) remain verifiable with the original SHA-256
   algorithm.

Each entry's hash includes the previous entry's hash, creating an
unbroken chain:

.. code-block:: php
   :caption: Hash chain calculation (HMAC-SHA256, epoch 1+)

   private function calculateEntryHash(AuditLogEntry $entry, string $hmacKey): string
   {
       $data = implode('|', [
           $entry->uid,
           $entry->secretIdentifier,
           $entry->action,
           $entry->actorUid,
           $entry->crdate,
           $entry->previousHash,
       ]);

       return hash_hmac('sha256', $data, $hmacKey);
   }

   public function verifyHashChain(
       ?int $fromUid = null,
       ?int $toUid = null,
       ?int $minEpoch = null,
   ): HashChainVerificationResult {
       $entries = $this->getEntriesInRange($fromUid, $toUid);
       $errors = [];

       foreach ($entries as $i => $entry) {
           // Verify entry hash
           $expectedHash = $this->calculateEntryHash($entry);
           if ($entry->entryHash !== $expectedHash) {
               $errors[$entry->uid] = 'Hash mismatch';
           }

           // Verify chain link
           if ($i > 0 && $entry->previousHash !== $entries[$i - 1]->entryHash) {
               $errors[$entry->uid] = 'Chain break';
           }
       }

       return $errors === []
           ? HashChainVerificationResult::valid(...)
           : HashChainVerificationResult::invalid(...);
   }

The return value is a :php:`HashChainVerificationResult` value object, not an
array. Besides ``errors`` it carries ``warnings``, the missing-uid set and its
count, and — since :ref:`adr-034-audit-chain-tip-anchor` — the
``anchorStatus`` verdict for the in-database chain tip, which an array shape
had no room for.

Database schema
---------------

.. code-block:: sql
   :caption: Audit log table

   CREATE TABLE tx_nrvault_audit_log (
       uid int(11) unsigned NOT NULL auto_increment,

       -- What happened
       secret_identifier varchar(255) NOT NULL,
       action varchar(50) NOT NULL,
       success tinyint(1) unsigned DEFAULT 1 NOT NULL,
       error_message text,
       reason text,

       -- Who did it
       actor_uid int(11) unsigned DEFAULT 0 NOT NULL,
       actor_type varchar(50) NOT NULL,
       actor_username varchar(255) NOT NULL,
       actor_role varchar(100) NOT NULL,

       -- Context
       ip_address varchar(45) NOT NULL,
       user_agent varchar(500) NOT NULL,
       request_id varchar(100) NOT NULL,

       -- Tamper detection
       previous_hash varchar(64) NOT NULL,
       entry_hash varchar(64) NOT NULL,

       -- Change tracking
       hash_before char(64) NOT NULL,
       hash_after char(64) NOT NULL,

       -- Metadata
       crdate int(11) unsigned NOT NULL,
       context text,

       PRIMARY KEY (uid),
       KEY secret_identifier (secret_identifier),
       KEY action (action),
       KEY actor_uid (actor_uid),
       KEY crdate (crdate)
   );

Logged operations
-----------------

.. code-block:: php
   :caption: Operations logged

   // All vault operations:
   'create'        // New secret stored
   'read'          // Secret retrieved/decrypted
   'update'        // Secret value changed
   'delete'        // Secret removed
   'rotate'        // Secret rotated with new value
   'access_denied' // Permission check failed
   'http_call'     // VaultHttpClient API call

AuditLogService
---------------

.. code-block:: php
   :caption: Classes/Audit/AuditLogService.php

   final readonly class AuditLogService implements AuditLogServiceInterface
   {
       public function log(
           string $identifier,
           string $action,
           bool $success,
           ?string $errorMessage = null,
           ?string $reason = null,
           ?string $hashBefore = null,
           ?string $hashAfter = null,
           ?AuditContextInterface $context = null,
       ): void;

       public function query(
           ?AuditLogFilter $filter = null,
           int $limit = 100,
           int $offset = 0,
       ): array;

       public function count(?AuditLogFilter $filter = null): int;

       public function verifyHashChain(
           ?int $fromUid = null,
           ?int $toUid = null,
           ?int $minEpoch = null,
       ): HashChainVerificationResult;

       public function export(?AuditLogFilter $filter = null): array;
   }

Filtering and querying
----------------------

.. code-block:: php
   :caption: Classes/Audit/AuditLogFilter.php

   $filter = AuditLogFilter::forSecret('my_api_key')
       ->withAction('read')
       ->withDateRange($startTime, $endTime)
       ->withSuccess(true);

   $entries = $auditService->query($filter, limit: 50);

PSR-14 events
-------------

Events dispatched after logging for external integration:

.. code-block:: php
   :caption: Classes/Event/

   SecretCreatedEvent    // identifier, secret, actorUid
   SecretAccessedEvent   // identifier, actorUid, context
   SecretUpdatedEvent    // identifier, version, actorUid
   SecretDeletedEvent    // identifier, actorUid, reason
   SecretRotatedEvent    // identifier, newVersion, actorUid, reason
   MasterKeyRotatedEvent // secretsReEncrypted, actorUid, rotatedAt

Example listener:

.. code-block:: php
   :caption: Custom event listener

   final class SlackNotifier
   {
       public function __invoke(SecretAccessedEvent $event): void
       {
           if ($event->getContext() === 'production') {
               $this->slack->notify("Secret accessed: {$event->getIdentifier()}");
           }
       }
   }

Context objects
---------------

Type-safe context for structured metadata:

.. code-block:: php
   :caption: Classes/Audit/HttpCallContext.php

   final readonly class HttpCallContext implements AuditContextInterface
   {
       public function __construct(
           public string $method,
           public string $host,
           public string $path,
           public int $statusCode,
       ) {}

       public static function fromRequest(
           string $method,
           string $url,
           int $statusCode,
       ): self;
   }

Consequences
============

Positive
--------

-  **Tamper-evident**: Hash chain detects any modifications
-  **Complete trail**: All operations logged with full context
-  **Queryable**: Efficient filtering by secret, action, actor, time
-  **Extensible**: PSR-14 events enable SIEM integration
-  **Self-contained**: No external dependencies required
-  **Verifiable**: Chain integrity can be validated on demand

Negative
--------

-  **Storage growth**: Each operation creates a log entry
-  **Chain dependency**: Corrupted entry affects chain verification
-  **No real-time alerts**: Events are post-hoc (listeners can add alerts)

Risks
-----

-  Log table growth in high-volume environments
-  Database access required for verification

Mitigation
----------

-  Provide log rotation/archival commands
-  Index optimization for common queries
-  Background verification jobs

Related decisions
=================

-  :ref:`adr-005-access-control` - Failed access attempts are logged

References
==========

-  `Blockchain-style Audit Logs <https://www.cs.purdue.edu/homes/ninghui/papers/blockchain_audit_ccs17.pdf>`_
-  `PSR-14 Event Dispatcher <https://www.php-fig.org/psr/psr-14/>`_
