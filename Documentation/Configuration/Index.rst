.. include:: /Includes.rst.txt

.. _configuration:

=============
Configuration
=============

.. _configuration-extension:

Extension configuration
=======================

Configure nr-vault in :guilabel:`Admin Tools > Settings > Extension Configuration`.

.. confval:: storageAdapter
   :name: ext-nrvault-storageAdapter
   :type: string
   :Default: local
   :Options: local

   Where secrets are stored.

   local
      Store secrets in the TYPO3 database (default). Secrets are encrypted
      with envelope encryption before storage.

   .. note::
      **External vault adapters (HashiCorp Vault, AWS Secrets Manager) are
      planned for future releases.** The adapter architecture is designed to
      support external backends, but currently only the local database adapter
      is implemented. See :ref:`developer-custom-adapters` for information on
      implementing custom adapters.

.. confval:: securityProfile
   :name: ext-nrvault-securityProfile
   :type: string
   :Default: standard
   :Options: standard, hardened

   The vault's operating profile — a single, internally consistent policy
   rather than a bag of independent toggles. Enforcement happens in code
   (provider selection, access control, audit anchoring), never only in
   documentation.

   standard
      Secure defaults with zero-configuration TYPO3 integration.

   hardened
      Fail-closed and audit-ready. Requires an explicit external
      master-key provider (``file`` or ``env``), disables provider
      auto-detection and any fallback to the TYPO3 encryption key, and
      makes vault operations refuse to run on a misconfigured or
      unavailable provider. It is also the prerequisite for
      :confval:`disableAdminOverride <ext-nrvault-disableAdminOverride>`.

   An unrecognised value throws rather than degrading to ``standard`` — a
   typo in a hardened deployment must never weaken the effective policy.

.. confval:: masterKeyProvider
   :name: ext-nrvault-masterKeyProvider
   :type: string
   :Default: typo3
   :Options: typo3, file, env, transit

   How to retrieve the master encryption key.

   typo3
      Derive from TYPO3's encryption key. This is the recommended default
      as it requires no additional configuration and works out of the box.

   file
      Read from a file on the filesystem.

   env
      Read from an environment variable.

   transit
      Unwrap through HashiCorp Vault's transit secrets engine. Only the
      Vault-encrypted ciphertext is stored locally — see
      :ref:`configuration-master-key-transit`.

.. confval:: masterKeySource
   :name: ext-nrvault-masterKeySource
   :type: string
   :Default: NR_VAULT_MASTER_KEY

   Source location for the master key. Interpretation depends on the provider:

   -  **file**: Path to the key file (e.g., :file:`/secure/path/vault.key`).
   -  **env**: Environment variable name (e.g., :samp:`NR_VAULT_MASTER_KEY`).
   -  **typo3**: Not used (key derived from TYPO3's encryption key).
   -  **transit**: Not used (configured via the ``hashicorp.*`` settings below).

.. confval:: hashicorp.address
   :name: ext-nrvault-hashicorp-address
   :type: string
   :Default: (empty)

   Vault server base address, e.g. :samp:`https://vault.example.com:8200`.
   Required by the ``transit`` master key provider.

.. confval:: hashicorp.authMethod
   :name: ext-nrvault-hashicorp-authMethod
   :type: string
   :Default: token
   :Options: token, kubernetes, approle

   Vault authentication method. The ``transit`` master key provider implements
   ``token`` only and refuses to start on the other values rather than silently
   downgrading. See :ref:`configuration-master-key-transit`.

.. confval:: hashicorp.tokenEnvVar
   :name: ext-nrvault-hashicorp-tokenEnvVar
   :type: string
   :Default: VAULT_TOKEN

   Name of the environment variable holding the Vault token. Read in preference
   to :confval:`hashicorp.token <ext-nrvault-hashicorp-token>`.

.. confval:: hashicorp.token
   :name: ext-nrvault-hashicorp-token
   :type: string
   :Default: (empty)

   Vault token stored in the extension configuration. Development fallback only
   — a token stored here is readable in the Install Tool and ends up in
   configuration exports. Prefer the environment variable.

.. confval:: hashicorp.transitMount
   :name: ext-nrvault-hashicorp-transitMount
   :type: string
   :Default: transit

   Mount path of the transit secrets engine, without the ``/v1/`` prefix.
   Nested mounts such as :samp:`platform/transit` are supported.

.. confval:: hashicorp.transitKeyName
   :name: ext-nrvault-hashicorp-transitKeyName
   :type: string
   :Default: nr-vault-master

   Name of the transit key that wraps the vault master key.

.. confval:: hashicorp.transitWrappedKeyPath
   :name: ext-nrvault-hashicorp-transitWrappedKeyPath
   :type: string
   :Default: (empty)

   File holding the Vault-wrapped master key. Empty resolves to
   :file:`<var-path>/secrets/vault-master.key.transit`. The file contains
   ciphertext only, never key material.

.. confval:: hashicorp.path
   :name: ext-nrvault-hashicorp-path
   :type: string
   :Default: secret/data/typo3

   Path prefix for secrets in Vault. **Reserved** — it belongs to the
   not-yet-implemented HashiCorp storage adapter and has no effect on the
   transit master-key provider, which uses the ``transit*`` settings above.

.. _configuration-aws:

AWS Secrets Manager
===================

..  note::

    The AWS Secrets Manager adapter is **planned but not implemented**. Both
    settings below are reserved; setting them changes nothing today. They are
    documented so an operator who finds them in the Settings module knows they
    are inert rather than misconfigured.

.. confval:: aws.region
   :name: ext-nrvault-aws-region
   :type: string
   :Default: (empty)

   AWS region for Secrets Manager, for example ``eu-central-1``.

.. confval:: aws.secretPrefix
   :name: ext-nrvault-aws-secretPrefix
   :type: string
   :Default: typo3/

   Prefix for secret names in AWS Secrets Manager.

.. _configuration-cli:

CLI access
==========

.. confval:: allowCliAccess
   :name: ext-nrvault-allowCliAccess
   :type: boolean
   :Default: false

   Allow CLI commands to access secrets without a backend user session.

.. confval:: cliAccessGroups
   :name: ext-nrvault-cliAccessGroups
   :type: string
   :Default: empty

   Comma-separated list of backend user group UIDs that CLI can access.
   Empty means all secrets are accessible when CLI access is enabled.

.. confval:: cliAllowedOperations
   :name: ext-nrvault-cliAllowedOperations
   :type: string
   :Default: ``secret.use,secret.create,secret.rotate``

   Operation permissions the unattributed CLI actor may hold while
   :confval:`allowCliAccess <ext-nrvault-allowCliAccess>` is on.
   The default covers deployment automation (store, rotate, consume).
   High-risk operations — ``secret.reveal`` (:bash:`vault:retrieve`
   printing plaintext), ``secret.delete``, ``audit.export``,
   ``master_key.rotate`` (:bash:`vault:rotate-master-key`),
   ``vault.configure`` — are **excluded by default** and must be added
   explicitly where a workflow genuinely needs them. Prefer a named
   technical actor (``TechnicalActorContext::runAs()``) over widening
   this list: the audit trail then names the responsible identity.
   Note that the scheduled orphan cleanup deletes secrets and therefore
   needs ``secret.delete`` when it runs as the bare CLI actor.

   Three of those five change what a CLI command can do today:
   ``secret.reveal``, ``secret.delete`` and ``master_key.rotate``.
   ``audit.export`` and ``vault.configure`` gate the corresponding **backend**
   actions — the audit module's export and the migration wizard —
   and :bash:`vault:audit --export` asserts no operation permission of its
   own. Withholding them here still matters: the list is the record of what
   the unattributed CLI actor has been granted, and a CLI surface for either
   would inherit it.

.. confval:: frontendPlaceholderLegacyCli
   :name: ext-nrvault-frontendPlaceholderLegacyCli
   :type: boolean
   :Default: false

   Restore the pre-hardening command-line behaviour, in which *every*
   frontend-accessible :typoscript:`%vault(id)%` placeholder resolves on
   the CLI, whoever authored the string it appears in.

   Off by default: the CLI enforces the same allow-set as a frontend
   request, so an identifier has to be published through an admin-only
   source — TypoScript setup, site configuration,
   :typoscript:`plugin.tx_nrvault.frontendResolvableIdentifiers`, or
   :php:`FrontendPlaceholderPolicyInterface::allowIdentifier()`. See
   :ref:`adr-035-frontend-placeholder-allow-set`.

   .. warning::

      Turning this on re-opens a real path, not a theoretical one.
      :bash:`scheduler:run` authenticates the ``_cli_`` administrator, so
      the admin bypass grants the read and this allow-set is the only
      remaining gate between an editor-authored ``tt_content`` field and
      a secret in the output of a scheduled newsletter or export job.

      Pin the value out of admin reach in
      :file:`config/system/additional.php`, or a compromised admin can
      simply tick the box in the backend Settings module. The example pins
      the flag **off** — the recommended state; a deployment that
      deliberately runs with the legacy behaviour pins ``true`` instead,
      which keeps the *decision* out of admin reach either way:

      .. code-block:: php

         // Pin the strict default so no backend admin can enable the bypass.
         $GLOBALS['TYPO3_CONF_VARS']['SYS']['nrVault']['frontendPlaceholderLegacyCli'] = false;

   Enable it only for a deployment whose internal render jobs genuinely
   need the old behaviour and cannot publish their identifiers. The
   narrower remedy is one :typoscript:`frontendResolvableIdentifiers`
   line, or one :php:`allowIdentifier()` call in the job itself.

   The flag is CLI-only: it never weakens a web request, and it never
   changes *which* secrets exist — a secret without
   ``frontend_accessible`` stays unreadable either way.

.. confval:: auditLogRetention
   :name: ext-nrvault-auditLogRetention
   :type: integer
   :Default: 365

   Number of days to retain audit log entries. Set to 0 for unlimited retention.

.. confval:: auditReads
   :name: ext-nrvault-auditReads
   :type: boolean
   :Default: true

   Log every secret *read* to the audit log. Disable only for
   high-throughput scenarios where read logging is not required.

   .. warning::

      Disabling read logging means secret retrievals leave no audit
      trail. The toggle is configurable by design
      (see :ref:`adr-019-configurable-audit-read-logging`), but flipping
      it does not itself emit a sentinel entry. For tamper-resistant
      deployments, pin the value filesystem-only via
      :file:`config/system/additional.php` so it cannot be changed from
      the backend Settings module:

      .. code-block:: php

         $GLOBALS['TYPO3_CONF_VARS']['SYS']['nrVault']['auditReads'] = true;

.. confval:: disableAdminOverride
   :name: ext-nrvault-disableAdminOverride
   :type: boolean
   :Default: false

   Remove the unconditional "administrators and system maintainers may do
   anything" bypass — both the operation permissions and the per-secret
   read/write/delete tiers. Administrators then hold exactly what their
   groups were granted and reach only the secrets they own or share a
   group with.

   **Only effective when** :confval:`securityProfile
   <ext-nrvault-securityProfile>` **is** ``hardened``. In the standard
   profile the flag is inert — a lockout guard, since setting it without
   the rest of the hardened policy is more likely a misunderstanding than
   a decision. ``vault:break-glass --status`` reports
   ``adminOverrideDisabledEffective`` so the mismatch is visible.

   .. warning::

      Removing the override without an escape hatch turns the first
      genuine incident into an outage. The hatch is
      :ref:`break-glass mode <security-break-glass>`
      (:ref:`vault:break-glass <command-break-glass>`) — a justified,
      audited, time-boxed window that restores full admin power.

      Pin the value out of admin reach in
      :file:`config/system/additional.php`, or a compromised admin can
      simply untick it in the backend Settings module:

      .. code-block:: php

         $GLOBALS['TYPO3_CONF_VARS']['SYS']['nrVault']['disableAdminOverride'] = true;

   See :ref:`security-disable-admin-override` for what exactly is removed.

.. confval:: auditHmacEpoch
   :name: ext-nrvault-auditHmacEpoch
   :type: integer
   :Default: 3

   Hash-algorithm version marker for the audit log hash chain:

   0
      Legacy SHA-256 without HMAC.

   1
      HMAC-SHA256 over identity fields only.

   2
      HMAC-SHA256 over identity **and** forensic fields (``success``,
      ``error_message``, ``reason``, ``ip_address``, ``user_agent``,
      ``context``).

   3
      Additionally binds the epoch selector ``hmac_key_epoch`` itself plus the
      attribution fields ``actor_type``, ``actor_username``, ``actor_role``
      and ``request_id``.

   Epoch 2 binds the forensic surface into the chain, so a DB-write attacker
   cannot flip ``success`` or rewrite ``error_message`` without breaking it.
   The shipped default (``3``) additionally closes the algorithm-downgrade
   forgery — with the epoch selector inside the hash, an attacker can no
   longer relabel a row to epoch 0, re-sign it with keyless SHA-256 and keep
   the chain consistent — and makes actor attribution tamper-evident.

   After raising this value, run the Install Tool wizard *Migrate audit hash
   chain* (or the :ref:`vault:audit-migrate-hmac <command-audit-migrate-hmac>`
   command) to re-hash existing rows. See
   :ref:`adr-023-audit-hash-chain-hmac`.

   :bash:`vault:doctor` grades the three states apart under
   ``audit.hmac_epoch``: pass at 3 and above, **warning** at 1 and 2 naming the
   columns that epoch leaves outside the MAC, and **critical** at 0. A stalled
   or partially applied migration is the usual way an installation ends up at
   1 or 2, so treat that warning as "the migration did not finish", not as a
   pending nice-to-have.

.. confval:: auditAnchorRequired
   :name: ext-nrvault-auditAnchorRequired
   :type: boolean
   :Default: false

   Treat a missing audit chain tip anchor as an **error** instead of a
   warning.

   The anchor pins "audit row ``uid = A`` still exists with
   ``entry_hash = H``" in ``sys_registry``, signed with a key that is not
   in the database. It is what makes removal of the *end* of the audit
   log detectable — a truncation leaves no UID gap and no broken link,
   so the chain walk alone reports it as valid. See
   :ref:`adr-034-audit-chain-tip-anchor`.

   The anchor arms itself on the next audit log write. Leave this
   setting off until that has happened: before the first write after the
   upgrade, an installation that never had an anchor is
   indistinguishable from one whose anchor an attacker deleted, and
   every chain would report invalid.

   Once enabled, an attacker with database write access can no longer
   silence the control by deleting the anchor row, because this setting
   lives in a configuration file rather than the database. It does two
   things, not one: verification reports a missing anchor as an error,
   **and** ordinary audit writes stop arming an anchor that is not
   there. Without the second half the error would clear itself within
   seconds — one audited read is enough to mint a fresh anchor on a
   truncated log.

   The second half applies whatever the log contains, including an empty
   one. "The log still holds an earlier entry" cannot stand in for "this
   anchor was never armed": the audit write that would arm the anchor
   has just inserted the only row the chain has, so a log emptied
   outright is indistinguishable from a new installation.

   Arming is therefore always explicit while this is on:
   :ref:`vault:audit --reset-anchor <command-audit>` arms the anchor and
   writes the reset into the chain. That includes the first arming — one
   more reason to enable the setting only after the anchor exists.

   Requires :confval:`ext-nrvault-auditHmacEpoch` >= 1; at epoch 0 the
   chain is keyless and the anchor is disabled.

.. confval:: encryptionAlgorithm
   :name: ext-nrvault-encryptionAlgorithm
   :type: string
   :Default: (empty)

   AEAD algorithm recorded per secret at encrypt time. Empty selects
   XChaCha20-Poly1305, which is the recommended value: it is available in
   every libsodium build, and its 24-byte nonce makes random-nonce collisions
   a non-concern, so vault contents stay portable across hosts with differing
   CPU capabilities.

   Set it to ``aes256gcm`` only on hosts with hardware AES support. An unknown
   or host-unavailable value makes encryption fail loudly at the crypto
   boundary rather than silently falling back.

.. confval:: preferXChaCha20
   :name: ext-nrvault-preferXChaCha20
   :type: boolean
   :Default: false

   Prefer XChaCha20-Poly1305 over AES-256-GCM **for legacy secrets only** —
   those stored under encryption version 1, before the per-secret algorithm
   marker existed. New secrets record their algorithm explicitly and take it
   from :confval:`ext-nrvault-encryptionAlgorithm`; this setting has no effect
   on them.

.. _configuration-audit-sinks:

External audit sinks
====================

The database table ``tx_nrvault_audit_log`` is the chain-authoritative audit
sink. External sinks are additional, best-effort *copies* whose purpose is to
put audit evidence somewhere a database-write attacker cannot reach.

Two properties are worth stating up front:

*  A sink failure **never** fails the audited vault operation. Fan-out happens
   after the chain row has committed and after the audit lock has been released,
   so a slow or broken destination cannot roll back a secret operation or
   serialise every other vault call behind itself. Failures are logged, counted,
   and reported by :ref:`vault:audit-verify <command-audit-verify>`.
*  Only an external sink makes a **full audit table reset** detectable. See
   :ref:`vault:audit-anchor <command-audit-anchor>` for why the in-database hash
   chain structurally cannot catch a truncate-and-rebuild.

Under the hardened security profile (``securityProfile = hardened``), having no
usable external sink is reported as a ``NO_EXTERNAL_SINK`` finding.

.. confval:: auditSinkSyslogEnabled
   :name: ext-nrvault-auditSinkSyslogEnabled
   :type: boolean
   :Default: false

   Mirror every audit entry, chain-tip anchor and integrity alert to the local
   syslog as an RFC 5424 structured-data message on facility ``local0``. The
   cheapest useful sink: on any host with a log shipper the audit trail leaves
   the TYPO3 database with no extra infrastructure.

.. confval:: auditSinkSyslogIdent
   :name: ext-nrvault-auditSinkSyslogIdent
   :type: string
   :Default: 'nr-vault'

   ``openlog()`` ident, which becomes RFC 5424's APP-NAME. Vary it when several
   TYPO3 instances share a host. An empty value falls back to the default — an
   unattributable syslog line would defeat the purpose of the sink.

.. confval:: auditSinkFileEnabled
   :name: ext-nrvault-auditSinkFileEnabled
   :type: boolean
   :Default: false

   Append audit evidence to newline-delimited JSON files (one JSON object per
   line). This is also the sink that writes the chain-tip anchors
   :ref:`vault:audit-verify <command-audit-verify>` reads back, so enabling it is
   the minimum for table-reset detection.

   Files are created with mode ``0600`` and only ever appended to.

.. confval:: auditSinkFilePath
   :name: ext-nrvault-auditSinkFilePath
   :type: string
   :Default: '' (resolves to :file:`var/log/nr-vault-audit.ndjson`)

   Absolute path of the append-only audit entry stream.

   .. warning::

      A path inside the public web root **disables** the sink rather than
      writing there: the stream names every secret identifier, actor, IP address
      and chain hash, so publishing it over HTTP would be worse than having no
      external sink at all. The refusal is logged with the resolved path.

      The default is outside the document root on every Composer-based
      installation. A legacy (non-Composer) layout, where ``var/`` lives under
      :file:`typo3temp/`, must configure an explicit path.

.. confval:: auditSinkAnchorPath
   :name: ext-nrvault-auditSinkAnchorPath
   :type: string
   :Default: '' (resolves to :file:`var/log/nr-vault-audit-anchor.ndjson`)

   Absolute path of the append-only chain-tip anchor stream, written by
   :ref:`vault:audit-anchor <command-audit-anchor>` and read back by
   :ref:`vault:audit-verify <command-audit-verify>`. Integrity alerts are
   appended here too, so this one file tells the whole chain-health story.

   Deliberately separate from ``auditSinkFilePath``: this is the evidence that
   survives a table reset, so point it at append-only or off-host storage.
   Verification always takes the anchor with the **highest sequence**, never the
   last line — appending a low-sequence anchor therefore cannot weaken the
   baseline.

   The public-web-root refusal described above applies to this path as well.

.. confval:: auditSinkWebhookEnabled
   :name: ext-nrvault-auditSinkWebhookEnabled
   :type: boolean
   :Default: false

   POST every audit entry, anchor and integrity alert as JSON to an HTTP
   endpoint — typically a SIEM collector. Each payload carries a ``type``
   discriminator (``entry``, ``anchor``, ``alert``) so one endpoint can route all
   three.

   When enabled, the webhook also receives integrity alerts by default through
   the built-in ``nr-vault/audit-integrity-alert-sinks`` event listener.

.. confval:: auditSinkWebhookUrl
   :name: ext-nrvault-auditSinkWebhookUrl
   :type: string
   :Default: ''

   ``https://`` (or ``http://``) endpoint receiving the payloads. Only
   ``http``/``https`` are accepted, so a ``file://`` or ``php://`` value cannot
   turn audit fan-out into a local write.

.. confval:: auditSinkStaleDeliveryHours
   :name: ext-nrvault-auditSinkStaleDeliveryHours
   :type: integer
   :Default: 24

   Hours after which the last successful external delivery of an enabled
   sink counts as **stale** for :bash:`vault:doctor` (finding
   ``audit.sink_state.<sink>``: warning under the standard profile, critical
   under hardened). The per-sink delivery state — last success, last
   failure, consecutive failures — is persisted in ``sys_registry`` by the
   sink registry, so a freshly started process still knows a collector has
   been unreachable for days. Use
   :bash:`vault:doctor --active-probes` to verify delivery end-to-end.

   .. note::

      Outbound calls go through the hardened HTTP client, inheriting the
      extension-wide SSRF and DNS-rebinding defences. A collector on a
      private/RFC1918 address is therefore **refused** unless the host is
      allow-listed literally in
      :php:`$GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts']`.

      That is intentional. This URL is settable from the backend Settings
      module, so without the guard a compromised administrator could repoint it
      at a cloud metadata service and use the vault as an SSRF pivot.
      ``allowed_hosts`` is filesystem-bound and out of the backend's reach,
      which keeps that pivot closed while leaving the legitimate on-premise path
      available. A refusal is not silent — it is logged, counted, and reported
      as a ``SINK_FAILURE`` finding.

.. _configuration-audit-sink-scheduling:

Scheduling
----------

Two scheduler tasks accompany the CLI commands:

Vault Audit Chain Anchoring
   Publishes the current chain tip (``vault:audit-anchor``). The interval is the
   blind window — entries written since the last anchor are what an attacker who
   resets the table can still hide. Hourly is a reasonable starting point.

Vault Audit Integrity Verification
   Verifies the chain against the anchor (``vault:audit-verify``) and dispatches
   an integrity alert event per finding. Set *Fail on tamper evidence only*
   while sinks are still being rolled out, so a pending integration does not keep
   the task permanently red and train operators to ignore it.

.. _configuration-master-key-providers:

Master key providers
====================

.. _configuration-master-key-typo3:

TYPO3 provider (default)
------------------------

Uses TYPO3's built-in encryption key to derive the master key. This is the
recommended default because:

-  **Zero configuration**: Works immediately after installation.
-  **No server access required**: Ideal for users without shell access.
-  **Unique per installation**: Each TYPO3 instance has its own key.
-  **Already secured**: TYPO3's encryption key is already protected.

The master key is derived from the encryption key using HKDF-SHA256 with a
nr-vault-specific context, ensuring it cannot be used to compromise other
TYPO3 functionality.

.. code-block:: php
   :caption: Master key derivation (internal)

   // How it works internally
   $masterKey = hash_hkdf(
       'sha256',
       $GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey'],
       32,
       'nr-vault-master-key'
   );

.. note::

   If you rotate TYPO3's encryption key, all secrets will need to be
   re-encrypted. Use the key rotation command before changing the
   encryption key.

.. _configuration-master-key-file:

File provider
-------------

Store the master key in a file with restrictive permissions:

.. code-block:: bash
   :caption: Create master key file

   # Generate a new key
   openssl rand -base64 32 > /secure/path/vault-master.key
   chmod 0400 /secure/path/vault-master.key

Configure in extension settings:

-  :confval:`masterKeyProvider <ext-nrvault-masterKeyProvider>`: file
-  :confval:`masterKeySource <ext-nrvault-masterKeySource>`: /secure/path/vault-master.key

.. warning::

   The key file must be:

   -  Outside the web root.
   -  Readable only by the web server user.
   -  Not in version control.
   -  Backed up separately from the database.

.. _configuration-master-key-env:

Environment provider
--------------------

Store the master key in an environment variable:

.. code-block:: bash
   :caption: Set master key via environment

   export NR_VAULT_MASTER_KEY="base64-encoded-key"

Configure in extension settings:

-  :confval:`masterKeyProvider <ext-nrvault-masterKeyProvider>`: env
-  :confval:`masterKeySource <ext-nrvault-masterKeySource>`: NR_VAULT_MASTER_KEY

This is ideal for containerized deployments where secrets are injected
via environment variables.

.. _configuration-master-key-transit:

HashiCorp Vault Transit provider
--------------------------------

The master key is generated once, wrapped by Vault's transit secrets engine,
and only the resulting ciphertext (:samp:`vault:v1:…`) is stored on the local
filesystem. Every start-up unwraps it through a Vault API call, so no key
material sits at rest next to the database.

Set up the transit engine and a key:

.. code-block:: bash
   :caption: Enable transit and create the wrapping key

   vault secrets enable transit
   vault write -f transit/keys/nr-vault-master

Grant the TYPO3 instance encrypt and decrypt on that one key — nothing else:

.. code-block:: text
   :caption: Vault policy nr-vault-transit.hcl (HCL)

   path "transit/encrypt/nr-vault-master" {
     capabilities = ["update"]
   }

   path "transit/decrypt/nr-vault-master" {
     capabilities = ["update"]
   }

.. code-block:: bash
   :caption: Apply the policy and issue a token

   vault policy write nr-vault-transit nr-vault-transit.hcl
   vault token create -policy=nr-vault-transit -period=768h

Provide the token through the environment, never in the extension
configuration:

.. code-block:: bash
   :caption: Vault token via environment

   export VAULT_TOKEN="hvs...."

Configure in extension settings:

-  :confval:`masterKeyProvider <ext-nrvault-masterKeyProvider>`: transit
-  :confval:`hashicorp.address <ext-nrvault-hashicorp-address>`: https://vault.example.com:8200
-  :confval:`hashicorp.authMethod <ext-nrvault-hashicorp-authMethod>`: token
-  :confval:`hashicorp.tokenEnvVar <ext-nrvault-hashicorp-tokenEnvVar>`: VAULT_TOKEN
-  :confval:`hashicorp.transitMount <ext-nrvault-hashicorp-transitMount>`: transit
-  :confval:`hashicorp.transitKeyName <ext-nrvault-hashicorp-transitKeyName>`: nr-vault-master

Then create and wrap the master key:

.. code-block:: bash
   :caption: Initialize the vault with a Vault-wrapped master key

   vendor/bin/typo3 vault:init

The wrapped key is written to
:confval:`hashicorp.transitWrappedKeyPath <ext-nrvault-hashicorp-transitWrappedKeyPath>`
with ``0600`` permissions. Back that file up together with the Vault key: the
blob is worthless without Vault, and Vault is worthless without the blob.

Rotating the transit key (:samp:`vault write -f transit/keys/nr-vault-master/rotate`)
re-wraps future ciphertexts without touching any secret in the TYPO3 database.
Rotating the vault master key itself is unchanged — the new key is wrapped
through Vault and the local blob replaced:

.. code-block:: bash
   :caption: Rotate the vault master key

   vendor/bin/typo3 vault:rotate-master-key

.. note::

   Only ``token`` authentication is implemented. ``approle`` and ``kubernetes``
   are rejected with a clear error instead of being treated as token auth;
   AppRole login support is a planned follow-up.

.. warning::

   What Transit does and does not protect.

   It protects **key custody**: the master key can be rotated, centrally
   audited and revoked in Vault, a stolen database plus a stolen webroot is
   useless without Vault access, and there is no key file on disk to
   exfiltrate.

   It does **not** protect against a fully compromised PHP process. Such a
   process holds the same Vault token the extension holds and can simply call
   ``decrypt`` itself. Transit raises the cost of offline attacks and makes
   access observable — it is not a sandbox around a live intruder.

.. note::

   The provider talks to Vault through TYPO3's HTTP client, so
   :php:`$GLOBALS['TYPO3_CONF_VARS']['HTTP']` settings (proxy, TLS verification,
   timeouts) apply. Use an ``https`` address: the Vault token travels in the
   ``X-Vault-Token`` request header.

.. _configuration-access-control:

Access control
==============

Access to secrets is controlled by:

1. **Ownership**: The user who created the secret has full access.
2. **Group membership**: Secrets can be shared with backend user groups, in
   two tiers — ``allowed_groups`` grants read, ``write_groups`` grants read
   and write. Neither grants delete.
3. **Admin access**: Backend administrators have access to all secrets —
   unless the hardened profile withdrew that bypass via
   :confval:`disableAdminOverride <ext-nrvault-disableAdminOverride>`, after
   which an administrator holds only what their own groups grant.
4. **CLI access**: Configurable via :confval:`allowCliAccess <ext-nrvault-allowCliAccess>`,
   narrowed by :confval:`cliAllowedOperations <ext-nrvault-cliAllowedOperations>`.
5. **Operation permissions**: independently of all of the above, every
   privileged operation (``secret.create``, ``secret.rotate``,
   ``secret.delete``, ``secret.manage_policy``, …) is granted per backend user
   group and asserted centrally. Passing the per-secret tiers never implies
   holding the operation. See :ref:`security-operation-permissions`.

.. _configuration-analytics:

Analytics thresholds
====================

These decide when the usage-analytics dashboard and the ``secrets.dead`` /
``secrets.never_rotated`` readiness controls flag a secret. They are
reporting thresholds only — nothing expires or is deleted because of them.

.. confval:: staleNeverReadDays
   :name: ext-nrvault-staleNeverReadDays
   :type: integer
   :Default: 30

   A secret that has **never** been read and is older than this many days is
   flagged *dead* — a strong candidate for redaction, since nothing has ever
   consumed it.

.. confval:: staleNotReadDays
   :name: ext-nrvault-staleNotReadDays
   :type: integer
   :Default: 90

   A secret not read for this many days is flagged *dead*.

.. confval:: staleNeverRotatedDays
   :name: ext-nrvault-staleNeverRotatedDays
   :type: integer
   :Default: 180

   A secret not rotated — or, if it never was, not created — within this many
   days is flagged *never rotated*.

.. _configuration-context:

Context-based scoping
=====================

Organize secrets by context for easier management:

-  :samp:`payment` - Payment gateway credentials.
-  :samp:`email` - Email service API keys.
-  :samp:`api` - Third-party API tokens.
-  :samp:`database` - External database credentials.

Contexts are user-defined strings that help organize and filter secrets.

.. _configuration-site:

Site configuration integration
==============================

Use the :yaml:`%vault(identifier)%` syntax in site configuration files:

.. code-block:: yaml
   :caption: config/sites/main/config.yaml

   settings:
     payment:
       stripeSecretKey: '%vault(stripe_api_key)%'
     email:
       mailchimpKey: '%vault(mailchimp_key)%'

References are resolved on demand, in the reading context, via
:php:`SiteConfigurationVaultProcessor` — not automatically when the site
configuration is loaded:

.. code-block:: php
   :caption: Resolve at read time

   use Netresearch\NrVault\Configuration\SiteConfigurationVaultProcessor;
   use TYPO3\CMS\Core\Utility\GeneralUtility;

   $site = $request->getAttribute('site');
   $processor = GeneralUtility::makeInstance(SiteConfigurationVaultProcessor::class);
   $config = $processor->processConfiguration($site->getConfiguration(), $site);
   $stripeKey = $config['settings']['payment']['stripeSecretKey'];

This keeps sensitive values out of version control while allowing configuration
through the standard TYPO3 site settings.

.. note::

   Resolution is deliberately caller-driven. TYPO3 caches the loaded site
   configuration to an on-disk file; resolving :yaml:`%vault()%` references
   eagerly at load time would persist the decrypted secrets there in cleartext
   and would enforce access control only once, at cache-warm time. Read-time
   resolution avoids both. See :ref:`Site configuration <usage-site-configuration>`
   in the Usage chapter for the full example.

.. _configuration-frontend:

Frontend-accessible secrets
===========================

By default, secrets cannot be resolved in frontend context (TypoScript).
To allow a secret to be used in TypoScript:

1. Create the secret with :php:`frontend_accessible` metadata.
2. Use the :typoscript:`%vault(identifier)%` syntax in TypoScript.

``frontend_accessible`` says the secret *may* appear in a page; it does not say
which placeholders get expanded. In a frontend request — and on the command
line, unless :confval:`frontendPlaceholderLegacyCli
<ext-nrvault-frontendPlaceholderLegacyCli>` is on — the identifier must also
be published through an admin-only source — the TypoScript setup array, the site
configuration, :typoscript:`plugin.tx_nrvault.frontendResolvableIdentifiers`, or
:php:`FrontendPlaceholderPolicyInterface::allowIdentifier()`. Step 2 satisfies
that on its own; an identifier used only in a Fluid template file or an eID
handler needs one of the last two. See
:ref:`Which placeholders resolve in the frontend <usage-typoscript-frontend-scope>`.

.. code-block:: php
   :caption: Store frontend-accessible secret

   $this->vaultService->store(
       'google_maps_key',
       $apiKey,
       [
           'metadata' => [
               'frontend_accessible' => true,
           ],
       ],
   );

.. warning::

   Frontend-accessible secrets may be exposed in rendered HTML output.
   Only use this for secrets that are intended to be public (like
   client-side API keys).
