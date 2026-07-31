:navigation-title: Control mapping
.. include:: /Includes.rst.txt

.. _auditor-control-mapping:

===============
Control mapping
===============

Implemented controls mapped to BSI IT-Grundschutz modules and OWASP ASVS
chapters, each with an implementation pointer and an evidence source.

..  note::

    **How to read this mapping.** References are **chapter- and
    module-level**, deliberately. Individual requirement identifiers are not
    cited: they change between editions of the IT-Grundschutz-Kompendium and
    between ASVS versions, and a fabricated requirement number is worse than no
    number at all. Confirm the mapping against the edition in force for your
    engagement.

    A row means "this control contributes to that module", **not** "this module
    is satisfied". Most IT-Grundschutz modules extend well beyond what a TYPO3
    extension can implement — see :ref:`auditor-target-of-evaluation`.

.. _auditor-control-mapping-crypto:

Cryptography
============

*BSI IT-Grundschutz: CON.1 (Kryptokonzept). OWASP ASVS v4: chapter 6
(Stored Cryptography), chapter 8 (Data Protection).*

..  list-table::
    :header-rows: 1
    :widths: 26 38 36

    *   -   Control
        -   Implementation
        -   Evidence source

    *   -   Secrets encrypted at rest with authenticated encryption
        -   :php:`EncryptionService::encrypt()` —
            XChaCha20-Poly1305 or AES-256-GCM, identifier as associated data
        -   ``tx_nrvault_secret`` contains no plaintext column;
            :ref:`security-cryptography-envelope`

    *   -   Per-secret key separation (bounded blast radius)
        -   One DEK per secret, wrapped by the master key
            (``encrypted_dek``, ``dek_nonce``)
        -   Schema; :ref:`adr-002-envelope-encryption`

    *   -   Master key never stored with the ciphertext
        -   :php:`Typo3MasterKeyProvider`,
            :php:`FileMasterKeyProvider`,
            :php:`EnvironmentMasterKeyProvider`
            (and ``transit``)
        -   ``masterKeyProvider`` setting;
            :ref:`operations-key-custody`

    *   -   Domain-separated key derivation
        -   :php:`hash_hkdf()` with three distinct ``info`` strings
        -   :ref:`security-cryptography-hkdf`

    *   -   Recorded, not inferred, algorithm selection
        -   ``encryption_version`` + ``encryption_algorithm`` markers;
            unknown marker is a hard error
        -   :ref:`security-cryptography-agility`

    *   -   Cryptographically secure randomness for keys and nonces
        -   :php:`random_bytes()`; fresh nonce per operation and per re-wrap
        -   :ref:`security-cryptography-key-lengths`

    *   -   Constant-time comparison of secrets and integrity tags
        -   :php:`hash_equals()` in chain verification, anchor comparison and
            token handling
        -   :ref:`security-cryptography-constant-time`

    *   -   Minimised plaintext lifetime in memory
        -   :php:`sodium_memzero()` on success and in ``finally``;
            :php:`#[SensitiveParameter]`
        -   :ref:`security-cryptography-memory`

    *   -   Key rotation without plaintext exposure
        -   :php:`EncryptionService::reEncryptDek()` — DEK layer only
        -   ``vault:rotate-master-key`` output;
            :ref:`operations-key-rotation`

.. _auditor-control-mapping-access:

Access control and authorization
================================

*BSI IT-Grundschutz: ORP.4 (Identitäts- und Berechtigungsmanagement).
OWASP ASVS v4: chapter 2 (Authentication), chapter 4 (Access Control).*

..  list-table::
    :header-rows: 1
    :widths: 26 38 36

    *   -   Control
        -   Implementation
        -   Evidence source

    *   -   Authentication required for every vault surface
        -   TYPO3 backend authentication; frontend requests hold no operation
            permission
        -   :php:`AccessControlService::isGranted()`;
            :ref:`security-trust-boundaries-frontend`

    *   -   Least privilege by operation
        -   :php:`VaultPermission` — ten distinct permissions as TYPO3 custom
            permission options
        -   ``be_groups.custom_options``;
            :ref:`security-operation-permissions`

    *   -   Separation of machine consumption from human disclosure
        -   ``secret.use`` and ``secret.reveal``, neither implying the other
        -   Permission table; :ref:`auditor-verification-procedures`

    *   -   Separation of duties for privileged operations
        -   Distinct ``master_key.rotate``,
            ``secret.manage_policy``,
            ``vault.configure``,
            ``audit.view`` / ``audit.export``
        -   Group grants per backend group

    *   -   Object-level authorization independent of operation permission
        -   Per-secret owner / group tiers via
            :php:`canRead()` / ``canWrite()`` / ``canDelete()``
        -   :ref:`adr-005-access-control`

    *   -   Server-side enforcement at every entry point
        -   :php:`AjaxController` re-asserts method and permission; modules
            registered ``access => 'user'`` with per-action checks
        -   Route configuration plus controller code

    *   -   No privileged short-circuit in the grant lookup
        -   Grant evaluation deliberately avoids
            :php:`BackendUserAuthentication::check()`, which returns ``true``
            unconditionally for admins
        -   :php:`hasCustomPermissionOption()`

    *   -   Administrative override is a single, withdrawable seam
        -   :php:`adminBypassActive()`; ``disableAdminOverride`` in the
            hardened profile, pinnable outside the backend
        -   ``vault:break-glass --status`` reporting
            ``adminOverrideDisabledEffective``

    *   -   Emergency access is time-boxed, justified and evidenced
        -   :php:`BreakGlassService` — mandatory reason, TTL clamped to 1–60
            minutes, audit written before the grant
        -   ``break_glass_activated`` /
            ``break_glass_deactivated`` rows;
            :ref:`security-break-glass`

    *   -   Disabled accounts cannot act on a stale session
        -   Defence-in-depth ``disable`` checks in
            :php:`AccessControlService` and :php:`BreakGlassService`
        -   Code review

    *   -   Attributable impersonation for headless code
        -   :php:`TechnicalActorContext::runAs()` — validates the target user,
            restores scope on exceptions, never mutates
            :php:`$GLOBALS['BE_USER']`
        -   ``actor_type = 'technical'`` audit rows;
            :ref:`adr-029-technical-actor-context`

    *   -   Unattended CLI access closed by default
        -   ``allowCliAccess`` defaults to ``0``
        -   Configuration; :ref:`configuration`

.. _auditor-control-mapping-logging:

Logging and audit
=================

*BSI IT-Grundschutz: OPS.1.1.5 (Protokollierung), DER.1 (Detektion von
sicherheitsrelevanten Ereignissen). OWASP ASVS v4: chapter 7 (Error Handling
and Logging).*

..  list-table::
    :header-rows: 1
    :widths: 26 38 36

    *   -   Control
        -   Implementation
        -   Evidence source

    *   -   Every access, mutation and denial is logged
        -   :php:`AuditLogService::log()` on read, create, update, rotate,
            delete, metadata change and ``access_denied``
        -   ``tx_nrvault_audit_log``;
            :ref:`adr-006-audit-logging`

    *   -   Log entry precedes the effect where order matters
        -   Break-glass audits **before** granting; delete/store compensate a
            failed audit write by rolling the data change back
        -   :php:`BreakGlassService::activate()`,
            :php:`VaultService::delete()`

    *   -   Complete attribution
        -   ``actor_uid``, ``actor_type``, ``actor_username``,
            ``actor_role``, ``ip_address``, ``user_agent``, ``request_id``
        -   Schema; bound into the hash from epoch 3

    *   -   Only known actions can enter the chain
        -   :php:`AuditAction::tryFrom()` rejects unknown actions loudly
        -   Code review

    *   -   Tamper detection on stored entries
        -   HMAC-SHA256 hash chain; verification with
            :php:`hash_equals()`
        -   ``vault:audit-verify``;
            :ref:`adr-023-audit-hash-chain-hmac`

    *   -   Adversarial resistance against a database writer
        -   Chain key derived from the master key, which the database does not
            contain
        -   :ref:`security-audit-evidence-claims`

    *   -   Deletion detection
        -   uid-sequence gap analysis → ``UID_GAP``
        -   Verification output

    *   -   Algorithm-downgrade detection
        -   Per-row epoch comparison, chain-level epoch floor, and the epoch
            bound into the hash from epoch 3
        -   ``EPOCH_DOWNGRADE`` findings

    *   -   Reset detection through external evidence
        -   :php:`ChainTipAnchorService` — shrinkage, substitution and epoch
            regression against a published anchor
        -   ``TABLE_RESET`` findings;
            anchor file / SIEM records

    *   -   Log copies outside the protected store
        -   Syslog (RFC 5424), append-only NDJSON, webhook — fan-out after
            commit, contained per sink
        -   :ref:`security-audit-evidence-sinks`

    *   -   Availability of the audit pipeline is observable
        -   Per-sink failure counters; ``SINK_FAILURE`` and
            ``NO_EXTERNAL_SINK`` reason codes
        -   :ref:`operations-monitoring-counters`

    *   -   Machine-readable alerting
        -   :php:`AuditIntegrityAlertEvent` with stable reason codes and
            :php:`isTamperEvidence()`
        -   :ref:`operations-monitoring-events`

    *   -   Scheduled, unattended detection
        -   :php:`AuditAnchorTask`, :php:`AuditVerifyTask`
        -   Scheduler records;
            :ref:`operations-monitoring-scheduler`

    *   -   No secrets in logs or exceptions
        -   ``[REDACTED]`` placeholders; token redaction in transport errors;
            response bodies not surfaced
        -   Code review; :php:`SecretRedactor`

.. _auditor-control-mapping-data:

Data protection and secret handling
===================================

*BSI IT-Grundschutz: CON.1 (Kryptokonzept), CON.3 (Datensicherungskonzept).
OWASP ASVS v4: chapter 8 (Data Protection).*

..  list-table::
    :header-rows: 1
    :widths: 26 38 36

    *   -   Control
        -   Implementation
        -   Evidence source

    *   -   Disclosure responses are never cached
        -   ``Cache-Control: no-store`` and ``Pragma: no-cache`` on every
            reveal response, success and error alike
        -   :php:`AjaxController::withNoStore()`; HTTP response inspection

    *   -   Client-side exposure is bounded
        -   ``startRevealLifecycle()`` — 30 s auto-hide, wipe on
            ``visibilitychange`` and ``pagehide``
        -   :file:`vault-reveal-lifecycle.js`;
            :ref:`security-known-limitations-js`

    *   -   No client-side secret cache
        -   Every reveal re-hits ``vault_reveal``, so every reveal is audited
        -   Two reveals produce two audit rows

    *   -   Clipboard exposure removed where it cannot be controlled
        -   ``copyAllowed = false`` under the hardened profile; no copy button
        -   Reveal response payload

    *   -   Frontend disclosure is a property of the secret, not the visitor
        -   ``frontend_accessible``; frontend requests hold no operation
            permission
        -   :ref:`security-trust-boundaries-frontend`

    *   -   Change detection without a plaintext oracle
        -   ``value_checksum`` is a keyed MAC over the **ciphertext**, keyed
            per secret from the DEK
        -   :ref:`security-cryptography-checksum`

    *   -   Recoverability of encrypted data
        -   Documented separation of database and key-material backups, with a
            probe-decrypt verification step
        -   :ref:`operations-backup-and-restore`

    *   -   Detection of plaintext secrets elsewhere in the installation
        -   :php:`SecretDetectionService`, ``vault:scan``
        -   Scan output

.. _auditor-control-mapping-config:

Configuration, fail-closed behaviour and supply chain
=====================================================

*BSI IT-Grundschutz: CON.8 (Software-Entwicklung), OPS.1.1.5
(Protokollierung), DER.2.1 (Behandlung von Sicherheitsvorfällen). OWASP ASVS
v4: chapter 10 (Malicious Code), chapter 14 (Configuration).*

..  list-table::
    :header-rows: 1
    :widths: 26 38 36

    *   -   Control
        -   Implementation
        -   Evidence source

    *   -   Security policy is enforced in code, not documentation
        -   :php:`SecurityProfile` consulted by provider selection, access
            control and audit verification
        -   :ref:`security-profiles-differences`

    *   -   Fail closed on misconfiguration
        -   Unknown profile → ``1753900001``; forbidden provider →
            ``1753900002``; no hardened fallback or auto-detection
        -   :php:`MasterKeyProviderFactory`;
            :ref:`auditor-verification-procedures`

    *   -   Security-critical settings can be placed out of admin reach
        -   :php:`$GLOBALS['TYPO3_CONF_VARS']['SYS']['nrVault']` pins
        -   :file:`config/system/additional.php`;
            ``--status`` output

    *   -   Deployment-time policy gate
        -   ``vault:doctor --profile=hardened``; exit ``0`` pass, ``1``
            warnings, ``2`` critical
        -   Pipeline logs and ``--format=json`` artefact

    *   -   Outbound requests hardened against SSRF and DNS rebinding
        -   :php:`SecureHttpClientFactory`; scheme restricted to http/https;
            private targets need ``allowed_hosts``
        -   :ref:`adr-026-dns-rebinding-defence`

    *   -   Static analysis, security scanning and code review in CI
        -   Shared ``security.yml``, ``codeql.yml``,
            ``license-check.yml``, ``dependency-review.yml``,
            ``fuzz.yml``; in-repo :file:`semgrep.yml`,
            :file:`.gitleaks.toml`
        -   :file:`.github/workflows/checks.yml`;
            :ref:`auditor-evidence-collection`

    *   -   Broad compatibility test matrix
        -   PHP 8.2–8.5 × TYPO3 ``^13.4`` and ``^14.3``, unit and functional,
            coverage uploaded
        -   :file:`.github/workflows/ci.yml`

    *   -   Release provenance
        -   Tag-triggered release with ``id-token: write`` and
            ``attestations: write``
        -   :file:`.github/workflows/release.yml`;
            GitHub attestations

    *   -   Software Bill of Materials and artefact signing
        -   SPDX and CycloneDX SBOMs plus Cosign keyless signatures and
            SHA-256 checksums, produced for every tagged release. Delivered
            by the shared reusable ``release-typo3-extension.yml``
            (``include-sbom`` and ``sign-artifacts`` both default ``true``);
            this repository's :file:`release.yml` opts out of neither.
        -   Release assets (``*.sbom.spdx.json``, ``*.sbom.cdx.json``,
            ``*.sigstore.json``, ``checksums.txt``); verify with
            ``cosign verify-blob`` and ``gh attestation verify``

    *   -   Continuous security posture measurement
        -   OpenSSF Scorecard on schedule and on default-branch pushes
        -   :file:`.github/workflows/checks.yml`; Scorecard results

    *   -   Documented incident and emergency procedures
        -   Runbooks for exposure, tampering and break-glass review
        -   :ref:`operations-incident-response`

.. _auditor-control-mapping-gaps:

Declared gaps
=============

Stated here so an assessment does not have to discover them, and does not
credit them as controls.

..  list-table::
    :header-rows: 1
    :widths: 34 66

    *   -   Gap
        -   Status

    *   -   No protection against a compromised PHP process
        -   **By design.** Architecturally unfixable in-process; the
            alternative is recorded in :ref:`adr-016-sidecar-option` and is
            **not implemented**.

    *   -   No HSM or cloud-KMS integration
        -   Only indirectly, via HashiCorp Vault Transit. No provider exists
            for AWS KMS, Azure Key Vault or GCP KMS.

    *   -   Audit chain is tamper-evident, not tamper-proof
        -   **By design.** Detection only; prevention would require
            append-only external storage, which is an operator responsibility.

    *   -   Metadata and the audit trail are unencrypted
        -   Accepted. Identifiers, ownership, timestamps and the access history
            are readable to anyone with database access;
            ``audit.view`` / ``audit.export`` gate the application path only.

    *   -   ``vault:delete`` is a soft delete
        -   Accepted. The ciphertext row remains until removed at the database
            level; crypto-erasure is the disposal mechanism —
            :ref:`operations-decommissioning`.

    *   -   Revealed plaintext in the browser cannot be zeroized
        -   Accepted, mitigated by a bounded exposure window and by disabling
            clipboard copy under the hardened profile.

    *   -   ``runAs()`` is not an authentication boundary
        -   **Explicitly documented as such.** Any extension code can act as
            any enabled backend user; the control provided is attribution, not
            prevention.

    *   -   Supply-chain controls are delivered by a shared reusable pinned
            to ``@main``, not by in-repo workflow steps
        -   Accepted, by netresearch convention. SBOM generation, Cosign
            signing and build-provenance attestation live in
            ``netresearch/typo3-ci-workflows`` (referenced at ``@main`` so
            upstream fixes propagate), not in this repository's
            :file:`release.yml`. An assessment verifies them against the
            resolved reusable and the produced release assets, not against
            this repository's workflow files alone.
