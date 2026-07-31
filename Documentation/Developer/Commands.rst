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
   Verify hash chain integrity instead of listing entries. The output includes
   a ``Tip anchor:`` line reporting the state of the truncation anchor (see
   :ref:`security-audit-chain-anchor`): ``ok``, ``NOT ARMED``, ``VIOLATED``,
   ``UNREADABLE``, ``disabled`` or ``inconclusive``.

--reset-anchor
   Clear the audit chain tip anchor, record the reset in the chain, and re-arm
   the anchor on that entry. Only after a wipe or purge of
   ``tx_nrvault_audit_log`` that you performed deliberately — the anchor
   otherwise reports a violation permanently, which is exactly what makes an
   undeclared truncation visible. Asks for confirmation. This is the only path
   that arms an anchor at all while
   :confval:`ext-nrvault-auditAnchorRequired` is enabled.

--force
   Skip the interactive confirmation of ``--reset-anchor`` (for unattended runs).

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

   # Verify the chain, including the truncation tip anchor
   vendor/bin/typo3 vault:audit --verify

   # Re-arm the anchor after a deliberate wipe of the audit log
   vendor/bin/typo3 vault:audit --reset-anchor --force

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
