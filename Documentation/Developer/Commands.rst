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

--stdin
   Read the secret value from stdin.

--file=PATH, -f PATH
   Read the secret value from a file.

--metadata=KEY=VALUE, -m KEY=VALUE
   Additional metadata as ``key=value``. **Repeatable** — pass the option once
   per pair. Recognised keys: ``description``, ``context``, ``expiresAt``,
   ``owner``, ``groups``, ``scopePid``. There are no separate
   ``--description`` / ``--context`` / ``--expires`` options.

--groups=UID, -g UID
   Backend user group ID that may access this secret. **Repeatable** — pass
   the option once per group (``--groups=1 --groups=2``). A comma-separated
   ``--groups="1,2"`` is *not* split: it is read as a single non-numeric value
   and becomes group 0.

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
     --groups=1 --groups=2

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

--output=PATH, -o PATH
   Write the secret to a file instead of stdout.

--no-newline
   Do not append a newline to the output. This is the option to use when
   capturing into a shell variable.

--reason=TEXT, -r TEXT
   Reason for retrieving this secret, recorded in the audit log.

.. important::

   This command asserts ``secret.reveal``. For the unattributed CLI actor that
   means ``allowCliAccess`` must be on **and** ``secret.reveal`` must be in
   :confval:`ext-nrvault-cliAllowedOperations`, which excludes it by default.
   Without both, the command exits 1. Prefer a named technical actor
   (:ref:`developer-technical-actor-context`) over widening the allowlist.

.. _command-retrieve-example:

Example
-------

.. code-block:: bash
   :caption: vault:retrieve examples

   # Display with metadata
   vendor/bin/typo3 vault:retrieve stripe_api_key

   # For use in scripts. Do NOT use -q: that is Symfony's global quiet flag
   # and suppresses the value entirely, yielding an empty string.
   API_KEY=$(vendor/bin/typo3 vault:retrieve --no-newline stripe_api_key)

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

--pattern=PATTERN, -p PATTERN
   Filter by identifier pattern (supports ``*`` wildcard).

--format=FORMAT
   Output format: table (default), json, csv. No short form.

--limit=N, -l N
   Maximum number of results (default: 100).

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

--stdin
   Read the new secret value from stdin.

--file=PATH, -f PATH
   Read the new secret value from a file.

--reason=TEXT, -r TEXT
   Reason for rotation, logged in the audit trail. Defaults to
   ``Manual rotation via CLI``, so the field is never empty — pass a real
   reason rather than relying on the placeholder.

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

--reason=TEXT, -r TEXT
   Reason for deletion, logged in the audit trail. Defaults to
   ``Manual deletion via CLI``.

--force, -f
   Skip confirmation prompt.

.. important::

   This command asserts ``secret.delete``, which
   :confval:`ext-nrvault-cliAllowedOperations` excludes by default. On the CLI
   it needs ``allowCliAccess`` **and** that operation in the allowlist.

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

--identifier=ID, -i ID
   Filter by secret identifier.

--action=ACTION, -a ACTION
   Filter by action — any :php:`AuditAction` value. The common ones are
   ``create``, ``read``, ``update``, ``delete``, ``rotate`` and
   ``access_denied``; the enum also covers ``metadata_update``, ``http_call``,
   the master-key and chain lifecycle (``master_key_rotate_start`` /
   ``_end``, ``audit_chain_rekey``, ``audit_anchor_reset``), break-glass
   (``break_glass_activated`` / ``_deactivated``) and the OAuth actions.

--actor=UID
   Filter by actor (backend user UID).

--since=DATE
   Show entries since the given date (``Y-m-d`` or ``Y-m-d H:i:s``).

--until=DATE
   Show entries up to the given date (``Y-m-d`` or ``Y-m-d H:i:s``).

--success=BOOL
   Filter by success status (``true``/``false``).

--limit=N, -l N
   Maximum number of results (default: 50).

--format=FORMAT, -f FORMAT
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

--export=FILE, -e FILE
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

--format=FORMAT, -f FORMAT
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

--format=FORMAT, -f FORMAT
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

.. important::

   This command asserts ``master_key.rotate``, which
   :confval:`ext-nrvault-cliAllowedOperations` excludes by default. On the CLI
   it needs ``allowCliAccess`` **and** that operation in the allowlist,
   otherwise it aborts with exit code 1. Granting it to the unattributed CLI
   actor hands the whole vault's key envelope to anyone with a shell; a named
   technical actor is the better carrier.

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
:confval:`disableAdminOverride <ext-nrvault-disableAdminOverride>`.

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

.. _command-doctor:

vault:doctor
============

Evaluate every deployment-readiness control and report each one with the risk it
carries and the command that fixes it.

Designed as the last step of a deployment pipeline: the exit code is the
contract, so the command can gate a release without anything parsing its prose.
See :ref:`security-deployment-gate` for how to wire it in.

.. code-block:: bash
   :caption: Command syntax

   vendor/bin/typo3 vault:doctor [options]

.. _command-doctor-options:

Options
-------

--profile=PROFILE, -p PROFILE
   Security profile to check against: ``standard`` or ``hardened``. Defaults to
   the configured profile.

   **This never changes any configuration.** ``--profile=hardened`` on a standard
   installation answers "would this pass if we hardened it?", so a hardening
   migration can be planned from the real finding list instead of by flipping the
   switch on production and seeing what breaks. The report states both the profile
   it checked and the profile actually in force.

--format=FORMAT, -f FORMAT
   Output format: ``text`` (default) or ``json``. The JSON form carries every
   control — passing ones included — under stable ids.

--active-probes
   Additionally push the current chain-tip anchor through every enabled audit
   sink to verify end-to-end delivery (the webhook collector must answer 2xx;
   the file sink must actually append; syslog must accept the message). Adds
   one ``audit.sink_probe.<sink>`` finding per enabled sink; a refused probe
   is critical. Talks to external systems, so it is never run implicitly —
   neither by the passive checks nor by the backend status panel.

.. _command-doctor-exit-codes:

Exit codes
----------

The verdict is the **worst severity present**, never an average: a long list of
passing controls can never offset a critical finding.

0
   Every control passed. The configuration is audit-ready for the checked profile.

1
   Warnings only. Deployable; fix before an audit.

2
   At least one critical finding — or the profile value was unusable, or the run
   could not complete at all. A gate that cannot run never reports success.

.. _command-doctor-controls:

Control catalogue
-----------------

Control ids are **stable API**: they appear in ``--format=json``, in CI gate
allow-lists and in monitoring rules. A new control gets a new id rather than
reusing an old one.

Severities below are given as ``standard`` / ``hardened`` where they differ.

.. rst-class:: dl-parameters

provider.configured
   A master-key provider is chosen and permitted by the profile. ``typo3`` (the
   zero-configuration default) is *warning* / *critical* — the hardened profile
   forbids it, and its factory refuses to boot. An empty value is critical in
   both.

provider.known
   The configured provider identifier resolves to something this installation can
   build. Critical when it does not — a provider from a later release, or from an
   extension that is not installed here.

provider.available
   A key source is reachable at runtime. Critical when none is. *Warning* when
   standard-profile auto-detection resolved a different provider than the one
   configured: the vault works, but not the way the configuration says, and
   hardening removes the fallback.

provider.master_key_readable
   A non-empty key was actually read and envelope encryption is operational.
   Critical otherwise.

provider.key_permissions
   File provider only. Critical when the key file is readable, writable or
   executable beyond its owner. Only the octal mode is reported, never the path.

profile.valid
   The configured ``securityProfile`` is a known profile. Critical otherwise —
   the extension refuses to guess, so an unknown value is an outage.

profile.admin_override
   ``disableAdminOverride`` agrees with the profile. Warning in both mismatch
   directions: the flag set under ``standard`` (where it is inert, so the
   configuration implies a control that does not exist), and ``hardened`` without
   it (a hardened deployment that kept its widest bypass).

breakglass.window_open
   Warning while a :ref:`break-glass window <security-break-glass>` is open,
   naming who opened it, why, and when it closes. Warning rather than critical on
   purpose: an open window is a justified deliberate act, and a red gate would
   push operators to close it mid-incident just to deploy.

audit.reads_logged
   ``auditReads`` is enabled. *Warning* / *critical* — a stolen credential is
   *read*, not written, so an unlogged read defeats what the hardened profile
   exists for.

audit.retention
   ``auditLogRetention`` is 0 (keep forever) or at least 365 days. Warning for a
   shorter window, which cannot cover the previous review cycle.

audit.hash_chain
   The newest 1000 audit entries verify against the hash chain. Critical on any
   hash error or uid gap. **Bounded on purpose** — a full-table HMAC
   recomputation does not belong on a page load — so a pass means "the recent
   tail verifies", never "the chain is intact". :ref:`command-audit-verify` is
   the authoritative full-range verifier and belongs on a schedule.

audit.hmac_epoch
   :confval:`ext-nrvault-auditHmacEpoch` is at least 1. **Critical** in both
   profiles below that: the one integer switches off three controls at once —
   rows are hashed with keyless SHA-256, the epoch-downgrade floor equals the
   configured epoch and so can never be undercut, and the in-DB tip anchor is
   disabled. The finding names all three, because "epoch is 0" on its own reads
   like a version marker rather than a disabled chain. The shipped default is 3.

audit.db_anchor
   The IN-DATABASE tip anchor in ``sys_registry`` — a different control from
   ``audit.anchor``, which covers the copy published to the external sinks. Pass
   when the anchor is present and its MAC verifies; *warning* when it is not
   armed yet on a non-empty chain, when ``sys_registry`` and
   ``tx_nrvault_audit_log`` are mapped to different database connections (no
   vault-side action fixes that), and when the anchor is disabled by
   ``auditHmacEpoch = 0``. **Critical** when it is missing while
   :confval:`ext-nrvault-auditAnchorRequired` is enabled, when the stored anchor
   is present but unreadable (tampered value or a master key changed without a
   re-seal), and for the contradiction ``auditAnchorRequired = 1`` together with
   ``auditHmacEpoch = 0`` — verification reports ``Disabled`` and returns before
   the requirement is ever consulted, so that combination protects nothing while
   reading as the stricter configuration. An empty audit log is a pass: the
   anchor arms itself on the first audit write. Like ``audit.hash_chain`` this
   control states its scope — a pass means the anchor authenticates, not that
   the anchored row still carries the anchored hash; that comparison is
   :ref:`command-audit-verify`.

audit.external_sink
   At least one external audit sink is enabled. *Pass* / *critical*: sinks are
   documented as opt-in under ``standard``, and flagging a default installation
   for having no SIEM would train operators to ignore the hardened finding.
   Carries ``details.reasonCode = NO_EXTERNAL_SINK``, the same code
   ``vault:audit-verify`` uses.

audit.anchor
   A chain-tip anchor exists and the chain has not shrunk below it. Missing
   anchor is *pass* / *critical*. A chain shorter than the anchored sequence is
   critical in both (``TABLE_RESET``) — an append-only chain cannot get shorter.
   Only the shrinkage comparison is done here; the tip-hash comparison is
   :ref:`command-audit-verify`.

audit.sink_delivery
   No sink refused delivery in this process. Warning with the per-sink counts
   otherwise. Zero means "not in this run" — the cross-process question is
   answered by ``audit.sink_state.<sink>``.

audit.sink_state.<sink>
   One finding per enabled sink, based on the PERSISTED delivery state
   (``sys_registry``): consecutive failures or a last successful delivery
   older than ``auditSinkStaleDeliveryHours`` are *warning* / **critical**
   (hardened); an enabled sink with no recorded delivery yet is *pass* /
   *warning* (hardened). A freshly started ``vault:doctor`` can therefore no
   longer report a collector that has been unreachable for days as healthy.

audit.sink_probe.<sink>
   Emitted only with ``--active-probes``: the current chain-tip anchor is
   pushed through every enabled sink end-to-end (webhook: the collector must
   answer 2xx). A refused probe is **critical** in both profiles — the sink
   is enabled but demonstrably not accepting evidence.

   When ``--active-probes`` runs with **no** sink enabled there is nothing to
   probe, and a single literal ``audit.sink_probe.none`` finding is emitted
   instead of the per-sink family, so an empty probe run cannot be mistaken
   for a clean one.

cli.access
   ``allowCliAccess``. Pass when off. When on: *pass* / **critical**
   (hardened) — deployment automation legitimately needs it under the
   standard profile, but the hardened profile promises attributability and a
   bare CLI actor breaks that promise.

cli.access_groups
   Emitted only when CLI access is on. Warning when ``cliAccessGroups`` is empty,
   leaving the grant unscoped with no group boundary left to review.

cli.allowed_operations
   Emitted only when CLI access is on. Reports which operations
   :confval:`ext-nrvault-cliAllowedOperations` actually grants the unattributed
   CLI actor. Warning when the list contains a high-risk operation
   (``secret.reveal``, ``secret.delete``, ``audit.export``,
   ``master_key.rotate``, ``vault.configure``) or an unknown value. Unknown
   values are called out because they are silently inert — a typo revokes the
   grant the operator believes is configured rather than failing loudly.

   Of the five high-risk entries, three currently change what a CLI command
   can do: ``secret.reveal`` (``vault:retrieve``), ``secret.delete``
   (``vault:delete`` and the orphan cleanup) and ``master_key.rotate``
   (``vault:rotate-master-key``). ``audit.export`` and ``vault.configure``
   gate the corresponding **backend** actions; ``vault:audit --export``
   asserts no operation permission of its own. They are still called out
   here, because the allowlist is the record of what the CLI actor has been
   granted, not only of what it can currently reach.

secrets.expired
   No stored secret is past its expiry. Warning with the count otherwise: an
   expired secret still decrypts, so the credential stays recoverable from a
   database dump.

secrets.never_rotated
   No secret has gone unrotated beyond ``staleNeverRotatedDays``. Warning with
   the count otherwise.

secrets.dead
   No stored secret shows zero read activity. Warning with the count otherwise.
   No identifier appears in any of these three findings — an identifier names a
   credential and the JSON report travels into CI logs. Use the Analytics module
   to see which secrets.

environment.production_context
   ``Environment::getContext()`` is Production. *Pass* / *warning* — a
   Development context is the normal state of a developer machine, and only a
   hardened deployment contradicts itself by running in one.

environment.backend_lock_ssl
   ``[BE][lockSSL]`` is set. Warning otherwise, in both profiles: the reveal
   endpoint returns secret plaintext to a browser.

version.extension
   The extension version was read from ``ext_emconf.php``. Warning otherwise — a
   report that cannot state which version produced it is not evidence.

version.typo3_supported
   The running core is inside the range the extension declares. Warning
   otherwise.

check.crashed
   Not a control but a containment result: emitted as **critical** when a check
   throws, naming the failing check in ``details.check``. A diagnostic whose
   output degrades to "no findings" when part of it breaks is worse than none,
   because the silence reads as a pass — so a crashed check is louder than a
   failing one.

.. _command-doctor-json:

JSON output
-----------

.. code-block:: json
   :caption: vault:doctor --format=json (abridged)

   {
     "profile": "hardened",
     "configuredProfile": "standard",
     "profileOverridden": true,
     "auditReady": false,
     "highestSeverity": "critical",
     "exitCode": 2,
     "summary": { "total": 22, "pass": 19, "warning": 2, "critical": 1 },
     "findings": [
       {
         "id": "provider.configured",
         "severity": "pass",
         "summary": "Master-key provider \"file\" is explicitly configured.",
         "risk": "",
         "remediation": "",
         "docsUrl": "https://docs.typo3.org/p/netresearch/nr-vault/main/en-us/Configuration/Index.html#configuration-master-key-providers",
         "details": { "provider": "file" }
       },
       {
         "id": "audit.external_sink",
         "severity": "critical",
         "summary": "The hardened profile requires an external audit sink, but none is enabled and usable.",
         "risk": "The audit trail exists only in the database it is meant to protect. …",
         "remediation": "Enable at least one of \"auditSinkFileEnabled\", \"auditSinkSyslogEnabled\" or \"auditSinkWebhookEnabled\", then schedule the anchoring command. …",
         "docsUrl": "https://docs.typo3.org/p/netresearch/nr-vault/main/en-us/Configuration/Index.html#configuration-audit-sinks",
         "details": { "sinks": "", "reasonCode": "NO_EXTERNAL_SINK" }
       }
     ]
   }

Field notes for anything parsing this:

*  ``findings`` lists **every** evaluated control, passing ones included, so
   ``summary.pass`` / ``summary.total`` needs no second source of truth.
*  ``severity`` is one of ``pass``, ``warning``, ``critical``.
*  ``risk`` and ``remediation`` are empty strings for passing controls, never
   absent.
*  ``docsUrl`` may be an empty string.
*  ``details`` holds scalars only, and never key material, a master-key path or a
   secret identifier.
*  ``exitCode`` duplicates the process exit code, for wrappers that swallow it.
*  On a rejected ``--profile`` value or a run that could not start, the payload is
   ``{"error": "…", "exitCode": 2}`` instead — check for ``error`` before reading
   ``findings``.

.. _command-doctor-example:

Example
-------

.. code-block:: bash
   :caption: vault:doctor examples

   # Is this deployment ready for the profile it claims?
   vendor/bin/typo3 vault:doctor

   # Would it pass as hardened? Changes nothing.
   vendor/bin/typo3 vault:doctor --profile=hardened

   # Machine-readable, for a CI gate or a monitoring probe
   vendor/bin/typo3 vault:doctor --format=json

   # Verify end-to-end sink delivery (talks to the collector)
   vendor/bin/typo3 vault:doctor --active-probes
