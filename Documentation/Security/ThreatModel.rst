:navigation-title: Threat model
.. include:: /Includes.rst.txt

.. _security-threat-model:

============
Threat model
============

This page states what nr-vault defends, who it defends against, and where a
defence stops. It is written to be falsifiable: every control names the class
or command that implements it, and every scenario ends in a residual risk
rather than in a reassurance.

For the limits that no configuration removes, read
:ref:`security-known-limitations`. For the two policy bundles that decide how
strictly the controls below are enforced, read :ref:`security-profiles`.

.. _security-threat-model-assets:

Assets
======

..  list-table::
    :header-rows: 1
    :widths: 22 38 40

    *   -   Asset
        -   Where it lives
        -   Why it matters

    *   -   Master key
        -   Outside the database: derived from
            :php:`$GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey']`
            (``typo3`` provider), a key file (``file``), an environment
            variable (``env``), or unwrapped on demand from a KMS
            (``transit``). Cached for the duration of one request in
            :php:`AbstractMasterKeyProvider`.
        -   Root of trust. It unwraps every DEK and derives the audit HMAC
            key. Its loss is data loss; its compromise is total compromise.

    *   -   Data encryption keys (DEKs)
        -   One per secret, stored wrapped in the envelope
            (``encrypted_dek`` + ``dek_nonce``).
        -   A DEK opens exactly one secret. That bounded blast radius is the
            reason for the envelope scheme.

    *   -   Plaintext secret values
        -   Never at rest. Transient in PHP memory during
            :php:`EncryptionService::decrypt()`, and on screen for at most
            30 seconds during a reveal.
        -   The thing being protected.

    *   -   Audit chain
        -   ``tx_nrvault_audit_log``, HMAC-chained, mirrored to external
            sinks and anchored outside the database.
        -   The only evidence of who touched what. Its integrity is what
            makes every other control auditable.

    *   -   Audit HMAC key
        -   Not stored. Derived per request from the master key with
            :php:`hash_hkdf('sha256', $masterKey, 32, 'nr-vault-audit-hmac-v1')`.
        -   Without it, a database-write attacker cannot forge chain hashes
            from epoch 1 upwards.

    *   -   Backend sessions
        -   TYPO3 core (``be_sessions``), outside this extension.
        -   A stolen session with ``secret.reveal`` reveals secrets. nr-vault
            inherits TYPO3's session security wholesale.

    *   -   KMS token
        -   ``transit`` provider only: an environment variable, preferred over
            the stored setting.
        -   Holding it is equivalent to holding the master key while Vault is
            reachable.

    *   -   Chain-tip anchors
        -   NDJSON lines written by the ``file`` sink, plus whatever the
            syslog and webhook sinks shipped off-host.
        -   The external facts that make a full table reset detectable.

.. _security-threat-model-actors:

Actors
======

..  list-table::
    :header-rows: 1
    :widths: 22 78

    *   -   Actor
        -   Reach over the vault

    *   -   Anonymous visitor
        -   None. Every vault surface requires a backend context; frontend
            requests hold no operation permission at all.

    *   -   Frontend user
        -   Reads only secrets flagged ``frontend_accessible``, and only
            through resolution code. A valid backend session carried by a
            frontend visitor grants nothing extra:
            :php:`AccessControlService::isGranted()` returns ``false`` for
            any frontend request, because frontend output is shared with
            anonymous visitors through the page cache.

    *   -   Backend editor
        -   Whatever their groups were granted (see
            :ref:`security-operation-permissions`), intersected with
            per-secret ownership and group tiers. Typically ``secret.use``
            so vault-backed form fields resolve.

    *   -   Backend administrator
        -   By default every operation permission and every secret, through
            the single bypass seam
            :php:`AccessControlService::adminBypassActive()`. The hardened
            profile can withdraw that — see
            :ref:`security-disable-admin-override`.

    *   -   System maintainer
        -   As an administrator, plus the Install Tool. Reaches the
            extension configuration and therefore the provider choice, so a
            system maintainer is inside the trust boundary of every setting
            that is not pinned in :file:`config/system/additional.php`.

    *   -   DBA / hoster
        -   Full read and write on the database, no PHP execution assumed.
            Reads ciphertext and wrapped DEKs (useless without the master
            key), and can rewrite audit rows — which the HMAC chain and the
            anchors make evident, not impossible.

    *   -   Technical actor
        -   A named backend user impersonated by headless code through
            :ref:`TechnicalActorContext::runAs() <developer-technical-actor-context>`.
            Not an authentication boundary: any code with DI access can open
            a scope. Its value is validation, guaranteed scope restoration
            and honest audit attribution.

    *   -   CLI operator
        -   A shell on the host. Reaches :file:`settings.php`, the key file
            and the environment, so CLI is treated as trusted where it is
            trusted at all. Secret reads over CLI stay gated on
            ``allowCliAccess`` (off by default); break-glass deliberately is
            not, because a shell already reaches the master key.

.. _security-threat-model-boundaries:

Trust boundaries
================

.. code-block:: text
   :caption: Five boundaries; crossing each one requires something different.

   ┌────────────────────────────────────────────────────────────────┐
   │  Browser (backend operator)                                    │
   │  · revealed plaintext, max 30 s, no-store, no copy in hardened │
   └───────────────────────────┬────────────────────────────────────┘
                               │  (1) HTTPS + BE session + CSRF
                               │      + secret.reveal AND secret.use
   ┌───────────────────────────┴────────────────────────────────────┐
   │  PHP process  ── the trust anchor ──                           │
   │  · master key cached for one request                           │
   │  · plaintext exists here and only here                         │
   │  · AccessControlService decides every access                   │
   └──┬──────────────────┬───────────────────┬──────────────────────┘
      │ (2) SQL          │ (3) filesystem    │ (4) HTTPS + token
      │                  │                   │
   ┌──┴────────────┐  ┌──┴─────────────┐  ┌──┴────────────────┐
   │  Database     │  │  Filesystem    │  │  KMS (Transit)    │
   │  ciphertext,  │  │  key file,     │  │  unwraps the      │
   │  wrapped DEKs,│  │  wrapped key,  │  │  master key;      │
   │  audit chain  │  │  anchor NDJSON │  │  audits each call │
   └───────────────┘  └────────────────┘  └───────────────────┘
      │
      │ (5) syslog / NDJSON / webhook — one-way, after commit
   ┌──┴──────────────────────────────────────────────────────────┐
   │  SIEM / log pipeline                                        │
   │  · holds evidence the database owner cannot reach           │
   └─────────────────────────────────────────────────────────────┘

:ref:`security-trust-boundaries` describes what crossing each boundary
requires, and what each boundary does *not* stop.

.. _security-threat-model-stride:

STRIDE-lite
===========

..  list-table::
    :header-rows: 1
    :widths: 16 42 42

    *   -   Category
        -   Concern
        -   Control

    *   -   Spoofing
        -   Acting as another operator, or as a technical identity that was
            never authorised.
        -   TYPO3 backend authentication; ``runAs()`` validates the target
            user (deleted, disabled and time-restricted users are refused)
            and never mutates :php:`$GLOBALS['BE_USER']`; audit rows carry
            ``actor_type``, ``actor_uid`` and ``actor_username``, bound into
            the chain from epoch 3.

    *   -   Tampering
        -   Editing or deleting audit rows; downgrading the chain algorithm;
            substituting ciphertext.
        -   AEAD tags reject modified ciphertext; the HMAC chain plus
            ``hash_equals()`` verification detects row edits; the epoch is
            bound into the hash from epoch 3 and floored at the configured
            epoch; anchors detect truncate-and-rebuild.

    *   -   Repudiation
        -   "I never read that credential."
        -   Every read, write, rotation, deletion and denial writes a row
            before the plaintext is returned; rows are chained and mirrored
            to external sinks after commit.

    *   -   Information disclosure
        -   Plaintext reaching a log, a cache, a clipboard or a screen that
            outlives the operator.
        -   :php:`sodium_memzero()` after use; ``[REDACTED]`` in logs and
            exceptions; ``Cache-Control: no-store`` on every reveal
            response; 30-second auto-hide plus wipe on
            ``visibilitychange``/``pagehide``; copy disabled in the hardened
            profile.

    *   -   Denial of service
        -   Losing access to secrets, or hanging vault operations.
        -   Sink fan-out happens after commit and outside the audit advisory
            lock, so a hanging collector cannot serialise vault operations;
            sink failures are contained per sink and counted; break-glass
            keeps a hardened installation recoverable.

    *   -   Elevation of privilege
        -   Turning ``secret.use`` into ``secret.reveal``, or admin into
            unlimited plaintext access.
        -   Ten distinct operation permissions with no implication between
            ``secret.use`` and ``secret.reveal``; grant lookup deliberately
            avoids :php:`BackendUserAuthentication::check()`, which
            short-circuits to ``true`` for admins; the admin bypass is one
            seam and can be withdrawn.

.. _security-threat-model-scenarios:

Attack scenarios
================

Each scenario names the control that answers it and the risk that remains.

Stolen database dump
--------------------

**Attack.** A backup, a replica or a SQL injection elsewhere on the host
yields the full contents of ``tx_nrvault_secret``.

**Control.** Values are AEAD ciphertext; DEKs are wrapped by a master key that
is not in the database under any provider. The ``typo3`` provider derives it
from ``encryptionKey`` in :file:`settings.php`, the others from a file, an
environment variable or a KMS.

**Residual risk.** If the dump was taken together with the key material, the
secrets are readable. With the ``typo3`` provider, "the key material" means a
file most backup jobs already include — see
:ref:`security-known-limitations`, and :ref:`operations-backup-and-restore`
for the separation that avoids it.

Audit-row deletion by a database writer
---------------------------------------

**Attack.** An actor with ``DELETE`` on the audit table removes the rows that
name them.

**Control.** ``vault:audit-verify`` reports ``UID_GAP`` from the uid sequence
and ``HASH_MISMATCH`` for every row whose recomputed hash no longer matches.
From epoch 1 the hash is an HMAC under a key derived from the master key, so
an attacker without the master key cannot re-sign the chain.

**Residual risk.** Detection, not prevention. The window between the deletion
and the next verification run is the exposure — which is why anchoring and
verification belong on a schedule (:ref:`operations-monitoring-and-alerting`).

Full audit-table reset
----------------------

**Attack.** ``TRUNCATE TABLE tx_nrvault_audit_log``, then let the service
build a fresh, internally consistent chain from uid 1. Nothing inside the
database distinguishes that from a young installation.

**Control.** Chain-tip anchoring. An anchor records outside the database that
sequence *N* once carried entry hash *H*, plus the HMAC epoch in force.
Verification then checks that the chain did not shrink, that the row at *N*
still hashes to *H*, and that its epoch did not regress — reported as
``TABLE_RESET`` and ``EPOCH_DOWNGRADE``.

**Residual risk.** The anchor is only as trustworthy as its storage. An
anchor file on the same host that the attacker owns can be rewritten;
:php:`AnchorFileReader` takes the *highest* anchored sequence rather than the
last line, so appending a weaker anchor is useless, but truncating the file is
not. Ship anchors off-host (syslog or webhook) for the property to hold. Under
the hardened profile a missing sink or missing anchor is itself reported, as
``NO_EXTERNAL_SINK``.

Algorithm downgrade of the audit chain
--------------------------------------

**Attack.** Relabel rows to ``hmac_key_epoch = 0``, whose hash is a keyless
SHA-256, then recompute a self-consistent chain without ever holding the HMAC
key.

**Control.** Three layers. A decrease between consecutive rows is an
``EPOCH_DOWNGRADE`` finding; a uniform downgrade of the whole chain is caught
by the chain-level epoch floor, which defaults to the configured epoch; and
from epoch 3 the epoch column itself is bound into the hash payload, so
re-signing after flipping it needs the key anyway.

**Residual risk.** A chain that is genuinely still at epoch 0 carries no
keyed evidence at all. Migrate with ``vault:audit-migrate-hmac``.

Compromised administrator account
---------------------------------

**Attack.** An attacker reaches an account with the TYPO3 admin flag.

**Control.** By default: none worth claiming — an admin holds every vault
permission on purpose. In the hardened profile, ``disableAdminOverride``
withdraws the bypass everywhere at once (operation permissions, per-secret
tiers, the privileged-column policy, and the technical-actor equivalents), and
pinning it in :file:`config/system/additional.php` puts it out of the
backend's reach. Regaining full power then requires a break-glass window: a
named actor, a mandatory reason, a hash-chained audit row written *before* the
window opens, a PSR-14 event, a banner in the module, and an expiry between 1
and 60 minutes.

**Residual risk.** Break-glass restores full admin power while it is open —
it prevents nothing. Its value is evidence and time boxing. And an
administrator who also has filesystem access can unpin the flag.

Reveal left on screen
---------------------

**Attack.** An operator reveals a credential and walks away, or a shoulder
surfer photographs the screen.

**Control.** ``startRevealLifecycle()`` wipes the value after 30 seconds and
immediately when the tab is hidden or the page goes away. Every reveal
re-hits the ``vault_reveal`` endpoint, so nothing is cached client-side and
each reveal writes its own audit row. The response carries
``Cache-Control: no-store``. In the hardened profile the reveal response
reports ``copyAllowed = false`` and no copy button is offered, because
clipboard contents outlive the dialog and cannot be cleared reliably.

**Residual risk.** JavaScript strings cannot be zeroized; the engine may
retain copies after the field is cleared. The guarantee is a short exposure
window, not cleared memory. A screenshot or a photograph defeats all of it.

Vault used as an SSRF pivot
---------------------------

**Attack.** A compromised administrator repoints the audit webhook at a cloud
metadata endpoint and reads the response through the sink's error reporting.

**Control.** The webhook sink is built on
:php:`SecureHttpClientFactory`, so it inherits the extension-wide SSRF and
DNS-rebinding defences (:ref:`adr-026-dns-rebinding-defence`) and refuses
private, loopback and RFC1918 targets unless the host is allow-listed in
:php:`$GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts']` — which is
filesystem-bound and out of the backend's reach. The scheme is restricted to
``http`` and ``https``, so a ``file://`` value cannot turn an audit fan-out
into a local write. Refusals are not silent: they surface as a
``SINK_FAILURE``.

**Residual risk.** An operator who allow-lists a host broadly re-opens the
pivot for that host. Keep ``allowed_hosts`` narrow.

Headless code impersonating a privileged user
---------------------------------------------

**Attack.** An unrelated extension opens a ``runAs()`` scope for an
administrator and reads every secret.

**Control.** None at the impersonation step, and the code says so: ``runAs()``
is not an authentication boundary, because any code with DI access already
reaches :php:`$GLOBALS['BE_USER']`. What is enforced: a non-admin technical
actor holds only what the bypass seam allows, a ``runAs()`` scope may never
open a break-glass window even when its snapshot carries the admin flag, and
every row written inside a scope carries ``actor_type = 'technical'`` with the
actor's uid and username, sealed into the chain.

**Residual risk.** Any installed extension is inside the PHP trust boundary.
Auditing installed extensions is the control; the vault only makes the
resulting access attributable.

Fully compromised PHP process
-----------------------------

**Attack.** Arbitrary PHP execution in the TYPO3 process (an RCE, a malicious
extension, a hostile Composer dependency).

**Control.** None. This is the boundary the design accepts.

**Residual risk.** Total, for every secret the process can legitimately
request. A KMS moves custody but not runtime protection: the process holds a
token it may legitimately use. What remains is attribution — reads still
write audit rows, and with a KMS every unwrap is centrally logged and
revocable. See :ref:`security-known-limitations` and
:ref:`adr-016-sidecar-option` for the boundary that would change this answer.
