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

       public function store(Secret $secret, bool $persistGroupRelations = true): Secret
       {
           // Store secret in your backend and return the stored instance —
           // on INSERT it must carry the freshly assigned UID (see ADR-025).
           //
           // $persistGroupRelations = false means: leave the record's two
           // group tiers untouched, MM rows and count columns alike. The
           // FormEngine completion path passes false so it does not overwrite
           // ACL relations DataHandler has already written.
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

       public function listSecrets(?\Netresearch\NrVault\Domain\Dto\SecretFilters $filters = null): array
       {
           // List whole Secret objects, not just identifiers
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

Register in :file:`Services.yaml` by overriding the interface alias. Adapter
selection is **not** pluggable through a tag: nothing consumes a
``nr_vault.adapter`` tag, and :php:`VaultAdapterInterface` is a plain alias to
:php:`LocalEncryptionAdapter`. Repointing that alias is what swaps the
adapter, and it swaps it for the whole installation.

.. code-block:: yaml
   :caption: EXT:my_extension/Configuration/Services.yaml

   Netresearch\NrVault\Adapter\VaultAdapterInterface:
     alias: MyVendor\MyExtension\Adapter\CustomAdapter

..  note::

    The two tags nr-vault does consume are ``nr_vault.audit_sink`` and
    ``nr_vault.readiness_check``; both are collected as tagged iterators.

.. _developer-custom-key-providers:

Custom master key providers
---------------------------

.. note::
   nr-vault includes four built-in master key providers: **typo3** (derives
   from TYPO3's encryption key), **file** (reads from filesystem), **env**
   (reads from environment variable) and **transit** (unwraps the master key
   through HashiCorp Vault's transit engine — see the ``hashicorp.transit*``
   settings). The example below shows how to implement a custom provider for
   another key management system.

Implement :php:`MasterKeyProviderInterface` for custom key sources:

.. code-block:: php
   :caption: EXT:my_extension/Classes/Crypto/KmsKeyProvider.php

   namespace MyVendor\MyExtension\Crypto;

   use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;

   final class KmsKeyProvider implements MasterKeyProviderInterface
   {
       // Pick an identifier no shipped provider uses. 'hashicorp' and
       // 'transit' are taken by the built-in transit provider.
       public function getIdentifier(): string
       {
           return 'kms';
       }

       public function isAvailable(): bool
       {
           // Check if the KMS is accessible
       }

       public function getMasterKey(): string
       {
           // Retrieve key from the KMS
       }

       public function storeMasterKey(string $key): void
       {
           // Store key in the KMS
       }

       // Static: wipe the request-lifetime key cache (ADR-020).
       public static function clearCachedKey(): void
       {
           // Zero and drop this provider's cached key
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

AuditIntegrityAlertEvent
   Dispatched when audit verification produces a finding. Carries the alert,
   its stable reason code, and :php:`isTamperEvidence()` so a listener can
   page on tampering without also paging on a failed sink delivery.

BreakGlassActivatedEvent
   Dispatched when a break-glass window opens, carrying the actor uid and
   username, the mandatory justification, and the expiry.

BreakGlassDeactivatedEvent
   Dispatched when a window is closed deliberately. Note that a window which
   merely *expires* dispatches nothing — nothing runs at the moment it lapses.

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
   ddev exec vendor/bin/typo3 vault:init

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

Thresholds live in :file:`infection.json5`. They follow a **ratchet** strategy,
so the committed values track the currently measured MSI rather than the
long-term target:

.. code-block:: json5
   :caption: infection.json5

   {
       "minMsi": 72,
       "minCoveredMsi": 72
   }

A run that falls below either threshold fails CI. Ratchet these numbers
upward as test coverage improves; avoid ratcheting them downward (use a
brief TODO with a ticket instead). The dated ratchet schedule up to the
85 % / 95 % long-term target is kept next to the values in
:file:`infection.json5`.

Badge generation
~~~~~~~~~~~~~~~~

After a successful Infection run, emit a shields.io-compatible badge:

.. code-block:: bash
   :caption: Generate MSI badge JSON

   ./Build/Scripts/check-msi.sh > .Build/infection/badge.json

The output matches the shields.io endpoint schema and can be served from
any HTTPS endpoint (GitHub Pages, CDN, …) and referenced from the README.

.. _developer-testing-evidence:

Release evidence bundle
-----------------------

Tagged releases publish a bundle that records *what was actually verified* at
the tagged commit — test results, coverage, mutation score, dependency audit,
and the reference :bash:`vault:doctor` posture — together with pointers to the
signed release artifacts. It is assembled by
:file:`Build/Scripts/collect-evidence.php` and published by the
:file:`.github/workflows/release-evidence.yml` workflow.

.. code-block:: bash
   :caption: Build a bundle locally

   # Produce inputs first (any subset — a missing producer is recorded, not fatal)
   composer ci:test:php:coverage
   composer ci:test:php:mutation

   # Assemble into .Build/evidence/
   composer ci:evidence -- --tag=v1.2.3

In CI the producing jobs run on separate runners, so they upload their reports
into one flat drop-zone that the bundling job passes with ``--parts``:

.. code-block:: bash
   :caption: Assemble from a CI drop-zone

   php Build/Scripts/collect-evidence.php --parts=parts --tag=v1.2.3

Recognised names under ``--parts`` are :file:`junit-unit.xml`,
:file:`junit-fuzz.xml`, :file:`junit-functional.xml`, :file:`clover.xml`,
:file:`infection.json`, :file:`infection-security.json`,
:file:`infection-summary.log`, :file:`composer-audit.json` and
:file:`doctor.json`. Precedence per input is: an explicit flag, then the
drop-zone, then the in-tree default location, then absent. Run
:bash:`php Build/Scripts/collect-evidence.php --help` for the full flag list.

The bundle contains :file:`evidence-manifest.json` (machine-readable),
:file:`EVIDENCE.md` (the same data rendered for a human reader), and an
:file:`artifacts/` directory holding a verbatim, SHA-256-listed copy of every
input that was found.

Manifest schema
~~~~~~~~~~~~~~~

.. code-block:: json
   :caption: evidence-manifest.json (schemaVersion 1)

   {
     "schemaVersion": 1,
     "extension": "nr_vault",
     "version": "0.13.0",
     "commit": "9267b6abba37cbe3b7cbdb856b0dc5a00beb2e07",
     "builtAt": "2026-07-31T20:15:00+00:00",
     "checks": [
       {
         "id": "coverage-line",
         "status": "pass",
         "summary": "line 84.79% (6128/7227 statements), branch n/a — bar 80.00%",
         "source": "clover.xml"
       }
     ],
     "artifacts": [
       {"name": "clover.xml", "path": "artifacts/clover.xml", "sha256": "…"},
       {"name": "nr-vault-0.13.0.zip", "url": "https://github.com/…"}
     ]
   }

The ``checks`` array is emitted in a fixed order with stable ids:
``release-identity``, ``tests``, ``coverage-line``, ``coverage-security-dirs``,
``mutation-msi``, ``mutation-msi-security``, ``static-analysis``,
``dependency-audit``, ``vault-doctor``.

:status:
   One of ``pass``, ``warn``, ``fail`` or ``absent``.

:absent:
   The producing step did not run in this build. This is recorded, never
   hidden, and never fails the collector.

:tests:
   Aggregates every suite that left a JUnit log, keeping the per-suite counts in
   the summary. A suite that did not run is not listed — it is never counted as
   passing.

:mutation-msi-security:
   The same mutation analysis narrowed to ``Classes/Crypto``,
   ``Classes/Security``, ``Classes/Audit`` and ``Classes/Http``, held to the
   stricter thresholds in :file:`infection-security.json5`.

:vault-doctor:
   Read from ``highestSeverity`` (``pass``/``warning``/``critical``), falling
   back to ``exitCode`` (``0``/``1``/``2``). Two subtleties matter, because
   ``vault:doctor`` overloads exit code ``2``:

   - A run that could not start emits ``{"error": …, "exitCode": …}`` with **no**
     ``findings`` key — an unusable ``--profile`` value or an internal crash.
     That is recorded as ``fail``: the gate did not run, and an ungated release
     is not a clean one.
   - ``VaultDoctorService`` contains a crashing check by turning it into a
     ``check.crashed`` **critical** finding, so an unreachable database looks
     exactly like bad posture. When every critical is a ``check.crashed``, the
     check is downgraded to ``warn`` and the summary says ``INCOMPLETE``, naming
     the checks from ``details.check``. A real critical alongside a crash still
     fails, so a crash can never mask an actual control failure.

   An override is recorded too: ``--profile=hardened`` on a standard install
   renders as ``profile hardened (configured: standard)``, so the evidence never
   implies the live profile was the one evaluated.

Artifacts carry either a bundle-relative ``path`` plus ``sha256`` (copied into
the bundle) or a ``url`` (produced and signed by the release workflow, living on
the GitHub Release — the manifest references those, it does not reproduce them).

Graceful degradation
~~~~~~~~~~~~~~~~~~~~

The collector exits ``0`` whenever it can describe the release honestly,
including when producers are missing; a check status never changes the exit
code. It exits ``1`` only when an artifact is *present but unparseable*, because
then the bundle would misrepresent a check that really ran.

The schema, the per-producer degradation, and the malformed-artifact contract
are pinned by a fixture-driven self-check that runs as part of
:bash:`composer ci`:

.. code-block:: bash
   :caption: Verify the collector

   composer ci:test:evidence

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

The authoritative API reference — every interface, signature, exception and
event, kept in one place so it cannot drift against a second copy — lives in
:ref:`developer-api`.
