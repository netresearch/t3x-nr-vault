.. include:: /Includes.rst.txt

.. _developer:

=========
Developer
=========

.. toctree::
   :maxdepth: 2

   Api
   Commands
   TcaIntegration
   SecureOutbound
   TechnicalActorContext
   Adr/Index

.. _developer-architecture:

Architecture overview
=====================

nr-vault follows clean architecture principles with these main components:

Service layer
   :php:`VaultService` - Main facade for all vault operations.

Crypto layer
   :php:`EncryptionService` - Envelope encryption implementation.
   :php:`MasterKeyProvider` - Master key retrieval abstraction.

Storage layer
   :php:`SecretRepository` - Database persistence.
   :php:`VaultAdapterInterface` - Storage backend abstraction.

Security layer
   :php:`AccessControlService` - Permission checks.
   :php:`AuditLogService` - Operation logging.

.. _developer-extending:

Extending nr-vault
==================

.. _developer-custom-adapters:

Custom storage adapters
-----------------------

.. note::
   nr-vault currently includes only the **local database adapter**. External
   vault adapters (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) are
   planned for future releases. The adapter architecture below allows you to
   implement your own custom adapters in the meantime.

Implement :php:`VaultAdapterInterface` to add new storage backends:

.. code-block:: php
   :caption: EXT:my_extension/Classes/Adapter/CustomAdapter.php

   namespace MyVendor\MyExtension\Adapter;

   use Netresearch\NrVault\Adapter\VaultAdapterInterface;
   use Netresearch\NrVault\Domain\Model\Secret;

   final class CustomAdapter implements VaultAdapterInterface
   {
       public function getIdentifier(): string
       {
           return 'custom';
       }

       public function isAvailable(): bool
       {
           // Check if your backend is configured and reachable
       }

       public function store(Secret $secret): void
       {
           // Store secret in your backend
       }

       public function retrieve(string $identifier): ?Secret
       {
           // Retrieve secret from your backend
       }

       public function delete(string $identifier): void
       {
           // Delete from your backend
       }

       public function exists(string $identifier): bool
       {
           // Check if secret exists
       }

       public function list(?\Netresearch\NrVault\Domain\Dto\SecretFilters $filters = null): array
       {
           // List secret identifiers
       }

       public function getMetadata(string $identifier): ?array
       {
           // Get secret metadata
       }

       public function updateMetadata(string $identifier, array $metadata): void
       {
           // Update metadata
       }

       public function incrementReadCount(int $uid): void
       {
           // Increment read counter atomically
       }
   }

Register in :file:`Services.yaml`:

.. code-block:: yaml
   :caption: EXT:my_extension/Configuration/Services.yaml

   MyVendor\MyExtension\Adapter\CustomAdapter:
     tags:
       - name: nr_vault.adapter
         identifier: custom

.. _developer-custom-key-providers:

Custom master key providers
---------------------------

.. note::
   nr-vault includes three built-in master key providers: **typo3** (derives
   from TYPO3's encryption key), **file** (reads from filesystem), and **env**
   (reads from environment variable). The example below shows how to implement
   a custom provider for enterprise key management systems like HashiCorp Vault
   Transit or AWS KMS.

Implement :php:`MasterKeyProviderInterface` for custom key sources:

.. code-block:: php
   :caption: EXT:my_extension/Classes/Crypto/VaultKeyProvider.php

   namespace MyVendor\MyExtension\Crypto;

   use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;

   final class VaultKeyProvider implements MasterKeyProviderInterface
   {
       public function getIdentifier(): string
       {
           return 'hashicorp';
       }

       public function isAvailable(): bool
       {
           // Check if HashiCorp Vault is accessible
       }

       public function getMasterKey(): string
       {
           // Retrieve key from HashiCorp Vault
       }

       public function storeMasterKey(string $key): void
       {
           // Store key in HashiCorp Vault
       }

       public function generateMasterKey(): string
       {
           return random_bytes(32);
       }
   }

.. _developer-events:

Events
======

nr-vault dispatches PSR-14 events for extensibility:

SecretAccessedEvent
   Dispatched when a secret is read.

SecretCreatedEvent
   Dispatched when a new secret is created.

SecretRotatedEvent
   Dispatched when a secret is rotated with a new value.

SecretUpdatedEvent
   Dispatched when a secret value is updated (without rotation).

SecretDeletedEvent
   Dispatched when a secret is deleted.

MasterKeyRotatedEvent
   Dispatched after master key rotation commits, carrying the number of secrets
   and of consumer-owned envelopes re-encrypted. This is a notification, not a
   participation hook: a listener cannot re-wrap anything, because the master
   keys are gone by the time it runs. To have your own envelopes rotated,
   implement :php:`ForeignEnvelopeRotatorInterface`
   (:ref:`ADR-033 <adr-033-foreign-envelope-rotation>`).

Example listener:

.. code-block:: php
   :caption: EXT:my_extension/Classes/EventListener/SecretAccessLogger.php

   namespace MyVendor\MyExtension\EventListener;

   use Netresearch\NrVault\Event\SecretAccessedEvent;

   final class SecretAccessLogger
   {
       public function __invoke(SecretAccessedEvent $event): void
       {
           // Custom logging or alerting
           $identifier = $event->getIdentifier();
           $actorUid = $event->getActorUid();
       }
   }

.. _developer-testing:

Testing
=======

.. _developer-testing-setup:

Development setup
-----------------

Use DDEV for local development:

.. code-block:: bash
   :caption: Start DDEV environment

   ddev start
   ddev install-v14
   ddev vault-init

.. _developer-testing-running:

Running tests
-------------

.. code-block:: bash
   :caption: Run test suites

   # Unit tests
   Build/Scripts/runTests.sh -s unit

   # Functional tests
   Build/Scripts/runTests.sh -s functional

.. _developer-testing-quality:

Code quality
------------

.. code-block:: bash
   :caption: Run code quality tools

   # Code style (PHP-CS-Fixer)
   Build/Scripts/runTests.sh -s cgl

   # Static analysis (PHPStan)
   Build/Scripts/runTests.sh -s phpstan

.. _developer-testing-mutation:

Mutation testing (Infection)
----------------------------

Mutation testing validates the **strength** of the unit suite: Infection
rewrites operators, return values, and array/ternary constructs in the
production code and checks whether the test suite detects each mutation.
A test suite that still passes after a mutation = a missing assertion.

.. code-block:: bash
   :caption: Run mutation tests locally

   # Full run (initial tests must be green)
   composer ci:test:php:mutation

   # or via make
   make test-mutation

   # Inspect reports
   $BROWSER .Build/infection/infection.html

The current baseline and top escape concentrations are tracked in
:file:`Documentation/Developer/mutation-baseline.md` (Markdown — developer
artifact, not rendered in public docs).

Interpreting MSI
~~~~~~~~~~~~~~~~

:MSI (Mutation Score Indicator):
   % of all generated mutants that were detected (killed) by the test suite.
   Raw indicator of assertion density across the whole codebase.

:Covered Code MSI:
   % of mutants **in code reachable by tests** that were killed. Removes
   noise from intentionally untested code (e.g. interfaces, enums).

:Mutation Code Coverage:
   % of source lines that carry at least one mutant with a test. Closely
   tracks line coverage.

CI thresholds
~~~~~~~~~~~~~

Thresholds live in :file:`infection.json5`:

.. code-block:: json5
   :caption: infection.json5

   {
       "minMsi": 85,
       "minCoveredMsi": 95
   }

A run that falls below either threshold fails CI. Ratchet these numbers
upward as test coverage improves; avoid ratcheting them downward (use a
brief TODO with a ticket instead).

Badge generation
~~~~~~~~~~~~~~~~

After a successful Infection run, emit a shields.io-compatible badge:

.. code-block:: bash
   :caption: Generate MSI badge JSON

   ./Build/Scripts/check-msi.sh > .Build/infection/badge.json

The output matches the shields.io endpoint schema and can be served from
any HTTPS endpoint (GitHub Pages, CDN, …) and referenced from the README.

.. _developer-testing-security:

Security scans
--------------

.. code-block:: bash
   :caption: Run ad-hoc security scans

   # Composer dependency audit (locked + strict abandoned-package policy)
   composer ci:audit

   # Semgrep crypto-hygiene ruleset (advisory; not wired into CI)
   semgrep --config=semgrep.yml Classes/

:file:`semgrep.yml` targets nr-vault-specific concerns such as
non-constant-time secret equality, missing :php:`sodium_memzero()`, and
debug dumps of secret-shaped variables.

.. _developer-contributing:

Contributing
============

See :file:`CONTRIBUTING.md` for contribution guidelines.

1. Fork the repository.
2. Create a feature branch.
3. Write tests for your changes.
4. Ensure all tests pass.
5. Submit a pull request.

.. _developer-api-reference:

API reference
=============

.. _developer-api-vault-service:

VaultService
------------

.. php:class:: Netresearch\\NrVault\\Service\\VaultService

   Main facade for vault operations.

   .. php:method:: retrieve(string $identifier)

      Retrieve a decrypted secret value.

      :returntype: string|null

   .. php:method:: store(string $identifier, string $secret, array $options = []): void

      Create or update a secret.

   .. php:method:: exists(string $identifier): bool

      Check if a secret exists and is accessible.

   .. php:method:: delete(string $identifier, string $reason = ''): void

      Delete a secret.

   .. php:method:: rotate(string $identifier, string $newSecret, string $reason = ''): void

      Rotate a secret with a new value.

   .. php:method:: list(string $pattern = null): array

      List accessible secrets.

      :param string|null $pattern: Optional filter pattern.

   .. php:method:: getMetadata(string $identifier): array

      Get metadata for a secret.

   .. php:method:: http(): VaultHttpClientInterface

      Get the Vault HTTP Client.

.. _developer-api-encryption-service:

EncryptionService
-----------------

.. php:class:: Netresearch\\NrVault\\Crypto\\EncryptionService

   Envelope encryption implementation.

   .. php:method:: encrypt(string $plaintext, string $identifier): array

      Encrypt a value using envelope encryption.

   .. php:method:: decrypt(string $encryptedValue, string $encryptedDek, string $dekNonce, string $valueNonce, string $identifier): string

      Decrypt an envelope-encrypted value.

   .. php:method:: generateDek(): string

      Generate a new Data Encryption Key.

   .. php:method:: calculateChecksum(string $plaintext): string

      Calculate value checksum for change detection.

   .. php:method:: reEncryptDek(string $encryptedDek, string $dekNonce, string $identifier, string $oldMasterKey, string $newMasterKey): array

      Re-encrypt a DEK with a new master key (for master key rotation).
