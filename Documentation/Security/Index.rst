.. include:: /Includes.rst.txt

.. _security:

========
Security
========

The sections on this page are the security overview. The pages listed below go
deeper on the parts an assessment or a hardened deployment needs.

.. toctree::
   :maxdepth: 2

   ThreatModel
   SecurityProfiles
   TrustBoundaries
   Cryptography
   AuditEvidence
   KnownLimitations

..  warning::

    Read :ref:`security-known-limitations` before relying on any control
    described here. It states, honestly, where each defence stops — including
    the ones that cannot be fixed inside a TYPO3 extension.

.. _security-encryption-architecture:

Encryption architecture
=======================

nr-vault uses envelope encryption, an industry-standard pattern for
protecting sensitive data.

.. code-block:: text
   :caption: Envelope encryption: Each secret has its own DEK encrypted by the master key.

   +-------------------+
   |    Master Key     |
   +--------+----------+
            |
            | encrypts
            |
      +-----+------+--------+
      |            |         |
      v            v         v
   +------+    +------+   +------+
   | DEK1 |    | DEK2 |   | DEK3 |
   +--+---+    +--+---+   +--+---+
      |           |          |
      | encrypts  | encrypts | encrypts
      v           v          v
   +------+    +------+   +------+
   |Value1|    |Value2|   |Value3|
   +------+    +------+   +------+

   Secret 1    Secret 2   Secret 3

.. _security-how-it-works:

How it works
------------

1. **Data Encryption Key (DEK)**: Each secret gets a unique 256-bit key
   generated using cryptographically secure random bytes.

2. **Value encryption**: The secret value is encrypted with its DEK using
   AES-256-GCM (or XChaCha20-Poly1305).

3. **DEK encryption**: The DEK is encrypted with the Master Key and stored
   alongside the encrypted value.

4. **Decryption**: To read a secret, first decrypt the DEK with the Master Key,
   then use the DEK to decrypt the value.

.. _security-benefits:

Benefits
--------

-  **Key rotation**: Rotating the master key only requires re-encrypting DEKs,
   not the actual secret values.
-  **Blast radius**: If a DEK is compromised, only one secret is affected.
-  **Performance**: Bulk operations on secrets don't require the master key
   for each operation.

.. _security-algorithms:

Algorithms
==========

AES-256-GCM (default)
   Advanced Encryption Standard with 256-bit keys in Galois/Counter Mode.
   Provides authenticated encryption with hardware acceleration on modern CPUs.

XChaCha20-Poly1305 (optional)
   ChaCha20 stream cipher with extended nonce and Poly1305 MAC.
   Recommended when hardware AES is not available.

Both algorithms provide:

-  256-bit key strength.
-  Authenticated encryption (AEAD).
-  Protection against tampering.

.. _security-master-key:

Master key security
===================

The master key is the root of trust for all secrets.

.. _security-master-key-providers:

Provider security comparison
----------------------------

**TYPO3 provider** (default, recommended for most users)
   Security depends on TYPO3's encryption key protection. Suitable for
   environments where the encryption key is properly secured in :file:`settings.php`.
   No additional configuration required.

**File provider** (recommended for high-security environments)
   Allows storing the key outside the database and web root with strict
   permissions. Requires server access to configure.

**Environment provider** (recommended for containers)
   Ideal for containerized deployments where secrets are injected at runtime.
   Follows 12-factor app methodology.

.. _security-file-storage:

File storage recommendations
----------------------------

When using the file provider:

1. **Outside web root**: Never store in publicly accessible directories.

2. **Restrictive permissions**: Use 0400 (read-only by owner).

3. **Separate backup**: Back up the master key separately from the database.

4. **Access logging**: Monitor access to the key file.

5. **Key rotation**: Rotate the master key periodically.

.. warning::

   If the master key is compromised, all secrets must be considered compromised.
   Rotate the master key and all secrets immediately.

.. _security-audit-logging:

Audit logging
=============

All secret operations are logged with:

-  Timestamp.
-  Action (create, read, update, delete).
-  Actor (user ID, username, type).
-  Secret identifier.
-  IP address.
-  Result (success/failure).

.. _security-hash-chain:

Hash chain integrity
--------------------

Audit log entries form a hash chain where each entry includes a hash of
the previous entry. This provides:

-  **Tamper detection**: Any modification to log entries breaks the chain.
-  **Completeness**: An entry deleted from the middle of the log leaves a UID
   gap, which the verifier reports as an error even if the surrounding
   ``previous_hash`` values were patched to match.
-  **Non-repudiation**: Actions cannot be denied after logging.

Removing the *tail* of the log leaves no gap and no broken link, so the chain
walk alone cannot see it. That case is covered by the tip anchor below.

.. _security-audit-chain-anchor:

Tip anchor (truncation detection)
---------------------------------

The chain proves that what is stored was not altered. It cannot, on its own,
prove *how much* should be stored — any counter kept inside
``tx_nrvault_audit_log`` is deleted along with the rows.

nr_vault therefore records one signed assertion outside that table, in the core
table ``sys_registry``:

   Audit row ``uid = A`` still exists and its ``entry_hash`` is still ``H``.

The assertion is authenticated with HMAC-SHA256 under a key derived from the
master key with its own HKDF context string (``"nr-vault-audit-anchor-v1"``),
which is not stored in the database. It advances on every audit write, inside
the same transaction as the audit row, and is re-recorded by master-key rotation
and by both HMAC re-seal paths. See :ref:`adr-034-audit-chain-tip-anchor`.

What this adds: ``DELETE FROM tx_nrvault_audit_log WHERE uid > N``, deletion of
the last row, ``TRUNCATE``, and a truncate followed by refilling the same UIDs
with fresh entries are all reported as an invalid chain — by
``vault:audit --verify``, by the backend verification view, and by the gates
that guard master-key rotation and the HMAC migration.

What this does not add: an attacker with database write access who deletes the
``sys_registry`` row *before* truncating returns the installation to
undetectable truncation. That is reported as a warning (``Tip anchor: NOT
ARMED``) rather than an error, because an installation that has not yet written
an audit entry since the upgrade is indistinguishable from one whose anchor was
deleted.

.. _security-audit-anchor-required:

``auditAnchorRequired``
~~~~~~~~~~~~~~~~~~~~~~~

Setting ``auditAnchorRequired = 1`` in the extension configuration is the
operator's assertion that this installation is already anchored. It is off by
default, and it changes two things:

-  verification reports a missing anchor as an **error** instead of a warning;
-  an ordinary audit write no longer *creates* an anchor that is not there — at
   all, whatever the log currently contains.

The second half is what makes the first half worth anything. An attacker with
database write access can delete the anchor row — or merely blank its value —
and truncate the log; if the next audit write then armed a fresh anchor on the
shortened chain, the error would disappear within seconds and the installation
would report a valid chain permanently, now with a signed attestation that the
truncated tip is genuine.

The refusal has to be unconditional, and that is a deliberate change of
behaviour rather than a strictness for its own sake. "The log still holds an
earlier entry" is not a usable test for "this anchor was never armed": the audit
write that triggers the check has just inserted the only row the chain has, so a
log emptied outright looks exactly like a brand-new installation. Anything that
armed on an apparently-fresh chain would be bypassed by deleting *every* audit
row, which is easier than deleting some.

So with the setting on, arming is always an explicit operator action:
``vault:audit --reset-anchor``, which writes the reset into the chain. That
includes the very first arming — an installation that enables the setting before
its anchor exists reports ``Tip anchor: NOT ARMED`` as an error until the command
is run. This is why the setting is off by default and why the documented order
matters: enable it once, *after* the first audit write following the upgrade.
The setting is worth having because extension configuration lives in a settings
*file*: an attacker who only has database write access cannot turn it back off.

Blanking the anchor value (``UPDATE sys_registry SET entry_value = NULL``) is
not a way around this at any setting: a row that is present but unreadable is an
``Unreadable`` **error**, and it is never repaired by an audit write.

Restoring a legitimately wiped log
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After a deliberate purge or wipe, the anchor stays behind and reports a
violation permanently. Clear it with:

.. code-block:: bash

   vendor/bin/typo3 vault:audit --reset-anchor

The command records the reset as an audit entry in the same transaction, so it
cannot be performed invisibly, and re-arms the anchor on that entry. It is the
only path that arms an anchor at all while ``auditAnchorRequired`` is enabled.


.. _security-hmac-audit-chain:

HMAC-keyed audit chain
----------------------

The audit hash chain is authenticated with HMAC-SHA256, using a key derived
from the master key via HKDF (see :ref:`adr-023-audit-hash-chain-hmac`).
This provides adversarial tamper resistance in addition to tamper detection:

-  **Adversarial resistance**: An attacker with database access but without
   the master key cannot forge valid HMAC values or recompute the hash chain.
-  **Cryptographic separation**: The HMAC key is derived with a dedicated
   context string (``"nr-vault-audit-hmac-v1"``), ensuring independence from
   encryption key material.
-  **Backward compatibility**: Legacy entries (epoch 0) created before the
   HMAC migration remain verifiable using the original SHA-256 algorithm.
   New entries (epoch 1+) use HMAC-SHA256.

Use the ``vault:audit-migrate-hmac`` command to migrate existing legacy
entries to HMAC-SHA256. See :ref:`command-audit-migrate-hmac` for details.

.. _security-access-control:

Access control
==============

Access is decided by two independent gates. **Both** must pass.

*Per-secret access* answers "may this actor touch *this* secret?":

1. **Authentication**: Backend user must be logged in.
2. **Ownership**: Creator has full access.
3. **Group membership**: Shared access via backend groups.
4. **Admin override**: Administrators can access all secrets.

*Operation permissions* answer "may this actor perform this *kind* of
operation at all?" — see the next section.

.. note::

   CLI access requires explicit configuration and can be restricted
   to specific groups.

.. _security-operation-permissions:

Operation permissions
---------------------

Each vault operation has its own permission, granted **per backend user
group** in the Backend Users module (field *Custom module options*,
group *Vault: operation permissions*). They are registered as TYPO3
custom permission options under
``$GLOBALS['TYPO3_CONF_VARS']['BE']['customPermOptions']['tx_nrvault']``
and checked server-side via
``AccessControlServiceInterface::isGranted()``.

=================================== ==============================================================
Permission                          Governs
=================================== ==============================================================
``tx_nrvault:secret.use``           Programmatic consumption of a plaintext value (FormEngine
                                    vault widgets, FlexForm/TCA placeholders, site config, HTTP
                                    clients).
``tx_nrvault:secret.reveal``        Displaying a plaintext to a human (the ``vault_reveal``
                                    endpoint, ``vault:retrieve``).
``tx_nrvault:secret.create``        Creating new secrets.
``tx_nrvault:secret.rotate``        Replacing the value of an existing secret.
``tx_nrvault:secret.delete``        Deleting secrets.
``tx_nrvault:secret.manage_policy`` Enabling/disabling secrets and editing their
                                    ``allowed_groups`` / ``write_groups`` tiers.
``tx_nrvault:audit.view``           Reading the audit log, its usage analytics, and verifying the
                                    hash chain.
``tx_nrvault:audit.export``         Downloading the audit log (JSON / CSV).
``tx_nrvault:master_key.rotate``    Rotating the master key.
``tx_nrvault:vault.configure``      Running the migration wizard.
=================================== ==============================================================

Notes on the model:

-  **``secret.use`` does not imply ``secret.reveal``**, and neither
   implies the other. A non-admin needs **both** for an end-to-end
   reveal: the endpoint asserts ``secret.reveal`` (displaying plaintext),
   and the shared read path asserts ``secret.use`` (obtaining it at all).
   An integration account gets ``secret.use`` only.
-  **Non-admin backend users need ``secret.use`` for every plaintext
   read**, including FormEngine vault field widgets and FlexForm /
   TypoScript placeholder resolution. Grant it to the groups whose
   editors work with vault-backed fields.
-  **Mutations are enforced centrally in the service, not only in the
   module controllers.** ``VaultService::store()`` requires
   ``secret.create`` (new identifier) or ``secret.rotate`` (existing
   identifier, plus ``secret.manage_policy`` when the call also changes
   owner, group tiers or frontend availability); ``rotate()`` requires
   ``secret.rotate``; ``delete()`` requires ``secret.delete``. A direct
   DataHandler/FormEngine request or a programmatic caller therefore
   faces the same gates as the secrets module. Editors whose forms
   write vault-backed TCA fields need ``secret.create`` /
   ``secret.rotate`` in addition to ``secret.use``.
-  **Technical actors** (``TechnicalActorContext::runAs()``) hold
   ``secret.use`` implicitly — headless consumption is their purpose —
   and every other operation permission only if one of their
   provisioned backend groups grants it via the same
   ``tx_nrvault:*`` custom permission options.
-  **Admins and system maintainers hold every permission**
   unconditionally, and have full per-secret access to every secret.
   That override lives in a single seam
   (``AccessControlService::adminBypassActive()``) and can be removed —
   see :ref:`security-disable-admin-override`.
-  **The backend modules are registered ``access => 'user'``.** That is
   deliberate: authorization is asserted by each controller action, not
   by the module registration, so granular grants are usable by
   non-admins. The same holds for the ``vault_reveal`` / ``vault_rotate``
   AJAX routes.
-  **CLI**: a trusted CLI operator has no backend user record and thus no
   group grants. Operation permissions follow the vault's
   :ref:`allowCliAccess <configuration>` switch (**off by default**),
   narrowed to the ``cliAllowedOperations`` allowlist (default:
   ``secret.use,secret.create,secret.rotate``). High-risk operations are
   excluded by default: ``vault:retrieve`` (needs ``secret.reveal``),
   ``vault:delete`` / the scheduled orphan cleanup (``secret.delete``),
   ``vault:rotate-master-key`` (``master_key.rotate``) and the audit
   export require adding the respective operation to the allowlist — or,
   preferably, a named technical actor via
   ``TechnicalActorContext::runAs()``.
-  **Frontend requests never hold operation permissions**, regardless of
   any backend session the visitor carries — frontend visibility remains
   a property of the secret (``frontend_accessible``) alone.

.. _security-disable-admin-override:

Disabling the admin override
----------------------------

By default a TYPO3 administrator holds every vault permission and full
read/write/delete access to every secret. For most installations that is
the right answer: an admin already controls :file:`settings.php`, the
master-key provider and the extension configuration, so withholding
vault permissions from them would be theatre.

It stops being theatre in two situations: an installation where "TYPO3
administrator" and "may read production credentials" are genuinely
different roles, and an audit regime that requires every plaintext
access to be attributable to a *granted* permission rather than to a
role. For those, set

.. code-block:: none
   :caption: Extension configuration

   securityProfile = hardened
   disableAdminOverride = 1

and administrators are treated like every other backend user: they hold
exactly the operation permissions their groups were granted, and reach
only the secrets they own or share a group with.

What is removed
~~~~~~~~~~~~~~~

Both gates, in one place. The override is a single private seam
(``AccessControlService::adminBypassActive()``) consulted by:

-  ``isGranted()`` — the operation permissions;
-  ``canRead()`` / ``canWrite()`` / ``canDelete()`` — the per-secret tiers;
-  ``isCurrentActorAdmin()`` — the privileged-column policy in the TCA
   hook and the ``secret.use`` / ``owner_uid`` / ``frontend_accessible``
   exemptions in ``VaultService``;
-  the technical-actor equivalents of all of the above, so a
   ``runAs()`` snapshot carrying the admin flag does not keep what the
   interactive admin lost.

An override that were removed from only some of these would be worse
than none, because the deployment would believe it is protected.

.. note::

   Ownership still applies. An administrator keeps full access to the
   secrets they own, exactly like any other user — which is what makes
   the disabled state workable day to day.

Two deliberate constraints
~~~~~~~~~~~~~~~~~~~~~~~~~~

**The flag only takes effect in the hardened profile.** In the standard
profile it is inert. Setting it alone, without the rest of the hardened
policy (an explicit external master-key provider, no fallback to the
TYPO3 encryption key), is far more likely to be a misunderstanding than
a decision — and its failure mode is locking every administrator out of
the vault. Choosing ``hardened`` is the explicit statement that the
fail-closed contract has been read. Run
:ref:`vault:break-glass --status <command-break-glass>` to see whether
the flag is effective; it reports ``adminOverrideDisabledEffective``
alongside the raw setting, so a "flag set, profile standard" mismatch is
visible rather than silent.

**Pin the value outside the backend.** The setting is editable in
:guilabel:`Admin Tools > Settings`, which means a compromised admin
could untick it. Pin it in :file:`config/system/additional.php`, where
only filesystem access can change it:

.. code-block:: php

   $GLOBALS['TYPO3_CONF_VARS']['SYS']['nrVault']['disableAdminOverride'] = true;

The pinned value wins in both directions and is the same mechanism
:confval:`auditReads <ext-nrvault-auditReads>` uses.

.. _security-break-glass:

Break-glass mode
----------------

A disabled override needs an escape hatch, or the first genuine incident
becomes an outage. Break-glass mode is that hatch: a deliberate,
justified, time-boxed restoration of the admin override.

.. code-block:: bash
   :caption: The full flow

   # 1. Confirm the state
   vendor/bin/typo3 vault:break-glass --status

   # 2. Open a window with a justification
   vendor/bin/typo3 vault:break-glass --activate --reason="INC-4711 rotate leaked deploy key" --minutes=30

   # 3. Do the work in the backend or on the CLI

   # 4. Close it — do not wait for the expiry
   vendor/bin/typo3 vault:break-glass --deactivate --reason="INC-4711 closed"

Who may open a window
~~~~~~~~~~~~~~~~~~~~~

Only a real backend administrator or system maintainer — the actual
TYPO3 ``isAdmin()`` flag, checked independently of the disabled override
so the escape hatch is reachable in the very state it exists for — or an
operator in a real CLI context. Break-glass is deliberately **not**
gated on a ``VaultPermission``: it exists to recover from a state where
the granular grants are what is missing, so gating it on one would make
it unreachable exactly when it is needed. CLI is likewise not gated on
:confval:`allowCliAccess <ext-nrvault-allowCliAccess>` — a shell on the host
already reaches the master key.

A ``TechnicalActorContext::runAs()`` scope may **never** open a window,
even for an actor whose snapshot carries the admin flag. ``runAs()`` is
not an authentication boundary (any code with DI access can open a
scope), so accepting it would let arbitrary extension code mint its own
bypass with a synthetic justification.

Mandatory justification
~~~~~~~~~~~~~~~~~~~~~~~

``--reason`` is required for both activation and deactivation, and an
empty or whitespace-only value is rejected. The reason is stored
verbatim in the audit row, carried in the PSR-14 event, and displayed in
the backend banner. Reference the incident, ticket or change record —
"testing" tells a later reviewer nothing.

Time boxing
~~~~~~~~~~~

The window defaults to 15 minutes and is clamped to 1..60. Out-of-range
values are clamped rather than rejected: a fat-fingered ``--minutes=600``
during an incident should yield the one-hour ceiling, not an error to
re-read under pressure.

Expiry is evaluated **at read time**, on every access-control decision.
There is no scheduled task to close a window, and therefore no stalled
cron job that can silently extend one. A forgotten window stops granting
anything the moment it lapses.

Audit evidence
~~~~~~~~~~~~~~

Activation and deactivation each write one row to the tamper-evident
audit log under the pseudo-identifier ``__break_glass__`` (the same
convention ``vault:rotate-master-key`` uses for ``__master_key__``):

===================================== ========================================
Action                                Written when
===================================== ========================================
``break_glass_activated``             A window is opened. Context carries the
                                      actor, the expiry and the TTL.
``break_glass_deactivated``           A window is closed early. Context also
                                      carries the original activation reason.
===================================== ========================================

Both rows are sealed into the HMAC hash chain like any other entry, so
the evidence cannot be edited away without breaking verification. The
activation row is written **before** the window opens: the two stores
cannot be updated atomically, and only that order makes "window open
without evidence" impossible.

A window that simply expires writes **no** row — nothing runs at the
moment it lapses. Reconstruct the closed interval from the activation
row's ``expiresAt`` context value.

For alerting, listen to
``Netresearch\NrVault\Event\BreakGlassActivatedEvent`` and
``BreakGlassDeactivatedEvent``. The audit log proves what happened; a
listener is what makes someone *look*.

Visible warning
~~~~~~~~~~~~~~~

While a window is open, the vault Overview and Secrets modules show a
danger callout naming who opened it, the stated reason, and when it
expires. Visibility is half the control — a window nobody notices is
just the admin override with extra steps.

.. warning::

   **Break-glass restores full admin power.** While a window is open, an
   administrator has exactly what they had before the override was
   disabled: every operation permission, and read/write/delete on every
   secret. Break-glass prevents nothing.

   Its value is evidence and time boxing — a named actor, a typed
   justification, a hash-chained audit row, an event observers can alert
   on, a banner every operator sees, and an expiry nobody has to
   remember. Treat an activation as an incident to review, not as
   routine maintenance.

Technical actors
----------------

Headless code (messenger workers, scheduler runs) can act as a named
technical backend user through the scoped
:ref:`TechnicalActorContext::runAs() API
<developer-technical-actor-context>` instead of the global CLI switch.

Threat-model notes:

-  ``runAs()`` is **not** an authentication boundary: any PHP code with
   DI access can act as any enabled backend user — the same power that
   ``$GLOBALS['BE_USER']`` mutation already grants every installed
   extension.
   Its security value is validation (deleted/disabled/time-restricted
   users are refused), guaranteed scope restoration (also on
   exceptions), and honest audit attribution.
-  ``$GLOBALS['BE_USER']`` is never mutated, so a technical identity
   cannot leak into other code sharing the PHP process.
-  Audit entries written inside a scope carry ``actor_type =
   'technical'`` plus the actor's uid and username, sealed into the
   HMAC hash chain — impersonation is always attributable and
   tamper-evident.
-  Restrict the technical user like any backend account: no admin flag
   unless required, minimal group membership, and monitor its
   ``access_denied`` events.

.. _security-deployment-gate:

Deployment gate
===============

Every control described on this page is checkable from a shell.
:ref:`command-doctor` evaluates them all and reduces the result to a process exit
code, which makes it usable as the last step of a deployment pipeline rather than
as a document somebody is supposed to have read.

.. code-block:: bash
   :caption: Deployment gate — refuse the release on any critical finding

   vendor/bin/typo3 vault:doctor --profile=hardened

Exit-code contract
------------------

======  ==========================================================
Code    Meaning
======  ==========================================================
``0``   Every control passed — audit-ready for the checked profile.
``1``   Warnings only. Deployable; fix before an audit.
``2``   At least one critical finding, an unusable ``--profile``
        value, or the run could not complete.
======  ==========================================================

The verdict is the **worst severity present**, never an average, so a long list
of passing controls cannot offset one critical finding. And ``2`` covers "could
not check" as well as "checked and found a problem" — a gate that cannot run must
never be readable as a gate that found nothing.

Two ways to wire it, and they answer different questions:

.. code-block:: bash
   :caption: Fail the pipeline only on critical findings

   vendor/bin/typo3 vault:doctor
   test $? -le 1

.. code-block:: bash
   :caption: Require a fully clean report

   vendor/bin/typo3 vault:doctor

The stricter form is the one to aim for. Accepting exit ``1`` indefinitely means
a warning nobody ever removes, which is the state in which a *new* warning goes
unnoticed.

Checking a profile you have not adopted yet
-------------------------------------------

``--profile=hardened`` evaluates the live configuration against the hardened
policy **without changing anything**. That is how to plan the migration described
in :ref:`security-disable-admin-override` — from the actual finding list, rather
than by switching the profile on production and finding out which service stops
booting.

The report always states both the profile it checked and the profile in force, so
a passing dry run cannot be mistaken for hardening already being live.

What the gate does not cover
----------------------------

``vault:doctor`` bounds its own cost so it can run in a pipeline and on a backend
page load. Two limits matter, and both are stated in the findings themselves:

*  the hash-chain pass covers the newest 1000 audit entries, not the whole chain;
*  the anchor comparison detects a chain that has *shrunk*, not one whose
   anchored row now hashes differently.

:ref:`command-audit-verify` does both in full and is the authoritative integrity
verifier. Schedule it — the gate is a pre-flight check, not a substitute for
continuous verification.

Backend surface
---------------

The vault Overview module shows the same controls: the active profile, an
"N of M controls passed" ratio, and the open findings with their risk and
remediation. The detailed finding list requires the ``vault.configure``
permission — it names this installation's concrete weak points and the files to
edit. Everyone else sees the profile badge and the ratio, which is enough to
escalate.

.. _security-best-practices:

Security best practices
=======================

1. **Regular key rotation**: Rotate the master key annually or after
   security incidents.

2. **Audit log review**: Regularly review audit logs for suspicious access.

3. **Minimal permissions**: Grant access only to users who need it.

4. **Secret rotation**: Rotate secrets when personnel changes occur.

5. **Monitoring**: Set up alerts for access_denied events.

6. **Backup security**: Encrypt backups and store them securely.

.. _security-reporting-vulnerabilities:

Reporting vulnerabilities
=========================

If you discover a security vulnerability, please report it responsibly:

**DO NOT** create a public GitHub issue.

Use GitHub's private security reporting feature:
`Report a vulnerability <https://github.com/netresearch/t3x-nr-vault/security/advisories/new>`__

See :file:`SECURITY.md` for the full security policy.
