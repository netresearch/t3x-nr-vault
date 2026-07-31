.. include:: /Includes.rst.txt

.. _developer-commands:

============
CLI commands
============

nr-vault provides several CLI commands for DevOps automation and management.

.. _command-init:

vault:init
==========

Initialize the vault by creating a master key.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:init [options]

.. _command-init-options:

Options
-------

--output, -o
   Path to store the master key file (default: configured path or :file:`var/vault/master.key`).

--force, -f
   Overwrite existing master key (dangerous - existing secrets become unrecoverable!).

--env, -e
   Output key as environment variable format instead of file.

.. _command-init-example:

Example
-------

.. code-block:: bash
   :caption: vault:init examples

   # Initialize with default location
   vendor/bin/typo3 vault:init

   # Specify custom key file location
   vendor/bin/typo3 vault:init --output=/secure/path/vault.key

   # Output as environment variable
   vendor/bin/typo3 vault:init --env

.. warning::

   The master key file should be stored outside the webroot with restricted
   permissions (0400 or 0600). Never commit it to version control.

.. _command-store:

vault:store
===========

Store a secret in the vault.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:store <identifier> [options]

.. _command-store-arguments:

Arguments
---------

identifier
   Unique identifier for the secret.

.. _command-store-options:

Options
-------

--value=SECRET
   The secret value (will prompt if not provided).

--description=TEXT
   Optional description.

--context=CONTEXT
   Optional context for permission scoping.

--expires=TIMESTAMP
   Expiration timestamp or relative time (e.g., ``+90 days``).

--groups=GROUPS
   Comma-separated list of allowed backend user group IDs.

.. _command-store-example:

Example
-------

.. code-block:: bash
   :caption: vault:store examples

   # Interactive (prompts for secret)
   vendor/bin/typo3 vault:store stripe_api_key

   # With options (arbitrary metadata via repeatable --metadata key=value)
   vendor/bin/typo3 vault:store payment_key \
     --value="sk_live_..." \
     --metadata="description=Stripe production key" \
     --metadata="context=payment" \
     --groups="1,2"

.. _command-retrieve:

vault:retrieve
==============

Retrieve a secret from the vault.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:retrieve <identifier> [options]

.. _command-retrieve-options:

Options
-------

--quiet, -q
   Output only the secret value (for scripting).

.. _command-retrieve-example:

Example
-------

.. code-block:: bash
   :caption: vault:retrieve examples

   # Display with metadata
   vendor/bin/typo3 vault:retrieve stripe_api_key

   # For use in scripts
   API_KEY=$(vendor/bin/typo3 vault:retrieve -q stripe_api_key)

.. _command-list:

vault:list
==========

List all accessible secrets.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:list [options]

.. _command-list-options:

Options
-------

--pattern=PATTERN
   Filter by identifier pattern (supports ``*`` wildcard).

--format=FORMAT
   Output format: table (default), json, csv.

.. _command-list-example:

Example
-------

.. code-block:: bash
   :caption: vault:list examples

   # List all secrets
   vendor/bin/typo3 vault:list

   # Filter by pattern
   vendor/bin/typo3 vault:list --pattern="payment_*"

   # JSON output for automation
   vendor/bin/typo3 vault:list --format=json

.. _command-rotate:

vault:rotate
============

Rotate a secret with a new value.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:rotate <identifier> [options]

.. _command-rotate-options:

Options
-------

--value=SECRET
   The new secret value (will prompt if not provided).

--reason=TEXT
   Reason for rotation (logged in audit).

.. _command-rotate-example:

Example
-------

.. code-block:: bash
   :caption: vault:rotate example

   vendor/bin/typo3 vault:rotate stripe_api_key \
     --reason="Scheduled quarterly rotation"

.. _command-delete:

vault:delete
============

Delete a secret from the vault.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:delete <identifier> [options]

.. _command-delete-options:

Options
-------

--reason=TEXT
   Reason for deletion (logged in audit).

--force, -f
   Skip confirmation prompt.

.. _command-delete-example:

Example
-------

.. code-block:: bash
   :caption: vault:delete example

   vendor/bin/typo3 vault:delete old_api_key \
     --reason="Service deprecated" \
     --force

.. _command-audit:

vault:audit
===========

View the audit log.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:audit [options]

.. _command-audit-options:

Options
-------

--identifier, -i =ID
   Filter by secret identifier.

--action, -a =ACTION
   Filter by action (create, read, update, delete, rotate, access_denied).

--actor=UID
   Filter by actor (backend user UID).

--since=DATE
   Show entries since the given date (``Y-m-d`` or ``Y-m-d H:i:s``).

--until=DATE
   Show entries up to the given date (``Y-m-d`` or ``Y-m-d H:i:s``).

--success=BOOL
   Filter by success status (``true``/``false``).

--limit, -l =N
   Maximum number of results (default: 50).

--format, -f =FORMAT
   Output format: ``table`` (default), ``json``, ``csv``.

--verify
   Verify hash chain integrity instead of listing entries.

--export, -e =FILE
   Export results to a file (format taken from ``--format``).

.. _command-audit-example:

Example
-------

.. code-block:: bash
   :caption: vault:audit examples

   # View audit log since a given date
   vendor/bin/typo3 vault:audit --since=2026-05-01

   # Filter by secret
   vendor/bin/typo3 vault:audit --identifier=stripe_api_key

   # Export to JSON
   vendor/bin/typo3 vault:audit --format=json > audit.json

.. _command-audit-anchor:

vault:audit-anchor
==================

Publish the current audit log chain tip to the enabled external audit sinks.

The in-database hash chain proves that no stored row was altered, but it cannot
prove that the chain is still the *same* chain: an attacker with ``DELETE``
rights can truncate ``tx_nrvault_audit_log`` and let the service build a fresh,
internally consistent chain from uid 1. Nothing inside the database
distinguishes that from a young installation.

Each anchoring run records — outside the database — that the chain had reached a
given sequence with a given tip hash. :ref:`command-audit-verify` compares the
live chain against the newest anchor and reports ``TABLE_RESET`` when they
disagree.

.. important::

   The anchoring interval is the blind window: an attacker who resets the table
   can only hide entries written since the last anchor. Schedule it hourly for a
   vault under audit; daily is the loosest defensible setting. Use the
   *Vault Audit Chain Anchoring* scheduler task for this.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:audit-anchor [options]

.. _command-audit-anchor-options:

Options
-------

--dry-run
   Show the anchor that would be published without writing it to any sink.

--format, -f =FORMAT
   Output format: ``text`` (default) or ``json``.

.. _command-audit-anchor-exit-codes:

Exit codes
----------

0
   The anchor was accepted by at least one external sink.

1
   The chain tip could not be read, or **no sink accepted the anchor**. An
   anchor that reached nothing outside the database provides no table-reset
   protection, so this is a failure rather than a no-op — enable at least one of
   ``auditSinkFileEnabled``, ``auditSinkSyslogEnabled`` or
   ``auditSinkWebhookEnabled``.

.. _command-audit-anchor-example:

Example
-------

.. code-block:: bash
   :caption: vault:audit-anchor examples

   # Publish the current chain tip
   vendor/bin/typo3 vault:audit-anchor

   # Preview without writing
   vendor/bin/typo3 vault:audit-anchor --dry-run

   # Machine-readable output for a monitoring wrapper
   vendor/bin/typo3 vault:audit-anchor --format=json

.. _command-audit-verify:

vault:audit-verify
==================

Verify audit log integrity against both the hash chain and the external
chain-tip anchor.

This complements ``vault:audit --verify``, which runs the in-database hash-chain
pass only. In addition to that pass, this command compares the chain against the
newest anchor published by :ref:`command-audit-anchor` and classifies every
finding under a machine-readable reason code.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:audit-verify [options]

.. _command-audit-verify-options:

Options
-------

--format, -f =FORMAT
   Output format: ``text`` (default) or ``json``. The JSON form carries the full
   finding list, the compared anchor, the enabled sinks and their failure counts.

--tamper-only
   Only fail on tamper evidence; treat configuration and delivery findings
   (``NO_EXTERNAL_SINK``, ``SINK_FAILURE``) as warnings. Useful while external
   sinks are still being rolled out, so a pending integration does not keep the
   check permanently red and train operators to ignore a real alarm.

.. _command-audit-verify-reason-codes:

Reason codes
------------

HASH_MISMATCH
   A stored ``entry_hash`` or ``previous_hash`` does not match the recomputed
   value. Tamper evidence.

UID_GAP
   The uid sequence is not contiguous — rows were deleted from the chain. Tamper
   evidence (may also be a retention purge; confirm against your purge log).

TABLE_RESET
   The chain no longer contains the anchored tip: it is shorter than the anchored
   sequence, or the row at that sequence hashes differently. The signature of a
   truncate-and-rebuild. Tamper evidence.

EPOCH_DOWNGRADE
   The ``hmac_key_epoch`` was relabelled downward, moving rows onto a weaker or
   keyless verification algorithm. Tamper evidence.

NO_EXTERNAL_SINK
   The hardened security profile is active but no external audit sink is enabled
   and usable, or no anchor could be read. Configuration finding, not tamper
   evidence.

SINK_FAILURE
   An external sink could not be delivered to during this process. Availability
   finding, not tamper evidence.

.. _command-audit-verify-alerting:

Alerting
--------

Every finding is dispatched as
``\Netresearch\NrVault\Event\AuditIntegrityAlertEvent`` before the command
returns, so SIEM and notification listeners fire whether or not anyone reads this
output. When the webhook sink is enabled it receives the alerts by default via
the built-in ``nr-vault/audit-integrity-alert-sinks`` listener.

.. _command-audit-verify-exit-codes:

Exit codes
----------

0
   No findings — or, with ``--tamper-only``, no tamper evidence.

1
   At least one finding (see ``--tamper-only``), or verification could not run at
   all. A verifier that cannot run never reports success.

.. _command-audit-verify-example:

Example
-------

.. code-block:: bash
   :caption: vault:audit-verify examples

   # Full verification
   vendor/bin/typo3 vault:audit-verify

   # Machine-readable output for monitoring
   vendor/bin/typo3 vault:audit-verify --format=json

   # Only alarm on tamper evidence while sinks are being rolled out
   vendor/bin/typo3 vault:audit-verify --tamper-only

.. _command-rotate-master-key:

vault:rotate-master-key
=======================

Rotate the master encryption key. Re-encrypts all DEKs with a new master key.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:rotate-master-key [options]

.. _command-rotate-master-key-options:

Options
-------

--old-key=PATH
   Path to file containing the old master key (defaults to current configured key).

--new-key=PATH
   Path to file containing the new master key (defaults to current configured key).

--dry-run
   Simulate the rotation without making changes.

--confirm
   Required for actual execution (safety measure).

.. warning::

   Master key rotation re-encrypts all Data Encryption Keys (DEKs).
   Ensure you have a backup of the old key before proceeding.

.. _command-rotate-master-key-example:

Example
-------

.. code-block:: bash
   :caption: vault:rotate-master-key examples

   # Old key from file, new key from current config
   vendor/bin/typo3 vault:rotate-master-key \
     --old-key=/secure/path/old-master.key \
     --confirm

   # Both keys from files
   vendor/bin/typo3 vault:rotate-master-key \
     --old-key=/path/to/old.key \
     --new-key=/path/to/new.key \
     --confirm

   # Dry run to verify before actual rotation
   vendor/bin/typo3 vault:rotate-master-key \
     --old-key=/path/to/old.key \
     --dry-run

.. _command-scan:

vault:scan
==========

Scan for potential plaintext secrets in database and configuration.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:scan [options]

.. _command-scan-options:

Options
-------

--format, -f
   Output format: table (default), json, or summary.

--exclude, -e
   Comma-separated list of tables to exclude (supports wildcards).

--severity, -s
   Minimum severity to report: critical, high, medium, low (default: low).

--database-only
   Only scan database tables.

--config-only
   Only scan configuration files.

.. _command-scan-detection:

The command detects:

-  Database columns with secret-like names (password, api_key, token, etc.).
-  Known API key patterns (Stripe, AWS, GitHub, Slack, etc.).
-  Extension configuration secrets.
-  LocalConfiguration secrets (SMTP password, etc.).

.. _command-scan-severity:

Severity levels
---------------

critical
   Known API key pattern detected (Stripe, AWS, etc.).

high
   Password or private key column with non-empty value.

medium
   Token or API key column with suspicious value.

low
   Secret-like column name detected.

.. _command-scan-example:

Example
-------

.. code-block:: bash
   :caption: vault:scan examples

   # Scan all sources
   vendor/bin/typo3 vault:scan

   # Output as JSON for CI/CD
   vendor/bin/typo3 vault:scan --format=json

   # Exclude cache tables
   vendor/bin/typo3 vault:scan --exclude=cache_*,cf_*

   # Only show critical issues
   vendor/bin/typo3 vault:scan --severity=critical

.. _command-migrate-field:

vault:migrate-field
===================

Migrate existing plaintext database field values to vault storage.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:migrate-field <table> <field> [options]

.. _command-migrate-field-arguments:

Arguments
---------

table
   Database table name (e.g., ``tx_myext_settings``).

field
   Field name containing plaintext values to migrate.

.. _command-migrate-field-options:

Options
-------

--dry-run
   Show what would be migrated without making changes.

--batch-size, -b
   Number of records to process per batch (default: 100).

--where, -w
   Additional WHERE clause to filter records (e.g., ``pid=1``).

--force, -f
   Migrate even if field already contains vault identifiers.

--clear-source
   Clear the source field after migration (set to empty string).

--uid-field
   Name of the UID field (default: uid).

.. attention::

   Always backup your database before running migrations.

.. _command-migrate-field-example:

Example
-------

.. code-block:: bash
   :caption: vault:migrate-field examples

   # Preview migration
   vendor/bin/typo3 vault:migrate-field tx_myext_settings api_key --dry-run

   # Migrate with specific records
   vendor/bin/typo3 vault:migrate-field tx_myext_settings api_key --where="pid=1"

   # Migrate and clear source field
   vendor/bin/typo3 vault:migrate-field tx_myext_settings api_key --clear-source

.. _command-cleanup-orphans:

vault:cleanup-orphans
=====================

Clean up orphaned vault secrets from deleted TCA records.

When records with vault-backed fields are deleted, the corresponding vault
secrets may become orphaned. This command identifies and removes such orphaned
secrets.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:cleanup-orphans [options]

.. _command-cleanup-orphans-options:

Options
-------

--dry-run
   Show what would be deleted without making changes.

--retention-days, -r
   Only delete orphans older than this many days (default: 0).

--table, -t
   Only check secrets for this specific table.

--batch-size, -b
   Number of secrets to check per batch (default: 100).

.. _command-cleanup-orphans-example:

Example
-------

.. code-block:: bash
   :caption: vault:cleanup-orphans examples

   # Preview orphan cleanup
   vendor/bin/typo3 vault:cleanup-orphans --dry-run

   # Only clean up orphans older than 30 days
   vendor/bin/typo3 vault:cleanup-orphans --retention-days=30

   # Clean up orphans for specific table only
   vendor/bin/typo3 vault:cleanup-orphans --table=tx_myext_settings

.. _command-audit-migrate-hmac:

vault:audit-migrate-hmac
========================

Migrate existing audit log entries from plain SHA-256 (epoch 0) to
HMAC-SHA256 (target epoch configured via ``auditHmacEpoch``). This command
rehashes all audit log entries using an HMAC key derived from the master key,
upgrading the hash chain from tamper detection to adversarial tamper resistance.

See :ref:`adr-023-audit-hash-chain-hmac` for the architectural decision
behind this migration.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:audit-migrate-hmac [options]

.. _command-audit-migrate-hmac-options:

Options
-------

--dry-run
   Show what would be migrated without making changes.

.. _command-audit-migrate-hmac-example:

Example
-------

.. code-block:: bash
   :caption: vault:audit-migrate-hmac examples

   # Preview migration
   vendor/bin/typo3 vault:audit-migrate-hmac --dry-run

   # Run the migration
   vendor/bin/typo3 vault:audit-migrate-hmac

.. attention::

   This command requires a valid master key to derive the HMAC key.
   Always backup your database before running the migration. Once migrated,
   entries cannot be reverted to plain SHA-256 without restoring the backup.

.. _command-seed-demo:

vault:seed-demo
===============

Populate a development instance with realistic, historic demo secrets and a
matching audit-log history (useful for exploring the Analytics module).

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:seed-demo [options]

.. _command-seed-demo-options:

Options
-------

--force, -f
   Delete existing demo data and reseed.

.. _command-seed-demo-example:

Example
-------

.. code-block:: bash
   :caption: vault:seed-demo examples

   # Seed demo data (no-op if already seeded)
   vendor/bin/typo3 vault:seed-demo

   # Wipe existing demo data and reseed
   vendor/bin/typo3 vault:seed-demo --force

.. warning::

   Development only. The command refuses to run in a Production application
   context and creates dummy secrets with obviously-fake values.

.. _command-break-glass:

vault:break-glass
=================

Open, close or inspect a time-boxed break-glass window that temporarily
restores the administrator override removed by
:ref:`disableAdminOverride <ext-nrvault-disableAdminOverride>`.

Only a real backend administrator or system maintainer — or an operator with
CLI access to the host — may open or close a window. A justification is
mandatory, both transitions are written to the tamper-evident audit log, and
the window expires on its own. See :ref:`security-break-glass` for the full
operational contract.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:break-glass [options]

.. _command-break-glass-options:

Options
-------

--activate, -a
   Open a break-glass window. Requires ``--reason``.

--deactivate, -d
   Close the open window early. Requires ``--reason``. A no-op when no window
   is open.

--status, -s
   Show the current state. This is the default when no action is given.

--reason, -r
   Justification recorded in the audit log and shown in the backend warning
   banner. Mandatory for ``--activate`` and ``--deactivate``; an empty or
   whitespace-only value is rejected.

--minutes, -m
   Window length in minutes (default: 15). Values are clamped to the range
   1..60 rather than rejected.

.. _command-break-glass-example:

Example
-------

.. code-block:: bash
   :caption: vault:break-glass examples

   # Is a window open, and is the override disabled at all?
   vendor/bin/typo3 vault:break-glass --status

   # Open a 30-minute window for an incident
   vendor/bin/typo3 vault:break-glass --activate --reason="INC-4711 rotate leaked deploy key" --minutes=30

   # Close it as soon as the work is done
   vendor/bin/typo3 vault:break-glass --deactivate --reason="INC-4711 closed"

The ``--status`` output is line-oriented for monitoring probes and always
exits ``0`` — a closed window is a successful answer, not a failure:

.. code-block:: text
   :caption: --status output while a window is open

   securityProfile                  hardened
   disableAdminOverride             yes
   adminOverrideDisabledEffective   yes
   status: active
   activatedBy                      admin (uid 1)
   reason                           INC-4711 rotate leaked deploy key
   activatedAt                      2026-07-31T09:12:04+00:00
   expiresAt                        2026-07-31T09:42:04+00:00
   remainingSeconds                 1738

.. attention::

   While a window is open, administrators hold **every** vault permission and
   full access to **every** secret. Close it as soon as the work is done
   rather than waiting for the expiry.
