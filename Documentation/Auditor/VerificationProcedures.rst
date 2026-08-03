:navigation-title: Verification procedures
.. include:: /Includes.rst.txt

.. _auditor-verification-procedures:

=======================
Verification procedures
=======================

Reproducible procedures that demonstrate a control **works**, rather than that
it is configured. Each one states its expected result, so a deviation is a
finding rather than a matter of interpretation.

..  danger::

    **Procedures marked STAGING-ONLY deliberately misconfigure the vault or
    manipulate the audit table.** Never run them on production. Run them on a
    staging system with production-like configuration and throwaway data,
    restore the original state afterwards, and expect the manipulated system's
    audit chain to stay permanently broken — that is the point of the test, and
    it is why the system must be disposable.

Read-only evidence collection is in :ref:`auditor-evidence-collection`.

..  note::

    The ``vault:audit`` queries below assert ``audit.view``, and so do
    ``vault:audit --verify`` and ``vault:audit-verify`` — verification is a
    read of the chain. The one procedure that publishes a baseline anchor
    (``vault:audit-anchor``) asserts ``vault.configure`` instead, because it
    mutates tamper evidence. Both permissions are excluded from the
    :confval:`ext-nrvault-cliAllowedOperations` default, so grant them to the
    actor running the procedure (see :ref:`auditor-evidence-collection`) or
    read the same rows through the audit module.

.. _auditor-verify-reveal-audited:

Procedure 1 — A reveal writes an audit row
==========================================

**Claim under test.** Every disclosure of a plaintext to a human produces one
audit entry. There is no client-side cache that could serve a second reveal
without a server round trip.

**Safe on production.** Yes.

**Preconditions.** A backend user holding ``secret.reveal`` and ``secret.use``
and per-secret read access; one known identifier.

**Steps**

#.  Record the current row count for the identifier:

    ..  code-block:: bash

        vendor/bin/typo3 vault:audit --identifier=<identifier> --action=read \
            --format=json --limit=1000 > before.json

#.  In :guilabel:`Vault > Secrets`, reveal that secret. Wait for the value to
    appear.
#.  Close the modal, then reveal the **same** secret again.
#.  Re-run the query into ``after.json``.

**Expected result**

*   ``after.json`` contains exactly **two** more ``read`` rows than
    ``before.json`` — one per reveal. A second reveal producing no row means a
    client-side cache exists, which would break the audit guarantee.
*   Each row carries ``actor_uid``, ``actor_username``, ``actor_type =
    'backend'``, ``ip_address`` and ``success = 1``.
*   The chain still verifies:

    ..  code-block:: bash

        vendor/bin/typo3 vault:audit-verify

**Also verify, in the browser's developer tools**

*   The ``vault_reveal`` response carries ``Cache-Control: no-store``.
*   The response body contains ``copyAllowed`` — ``false`` under the hardened
    profile, in which case **no copy button is rendered**.
*   The value disappears on its own after 30 seconds.
*   Switching to another browser tab clears it **immediately** (the
    ``visibilitychange`` wipe), without waiting for the countdown.

..  note::

    The last two checks must be done in a real browser. A unit test cannot
    demonstrate ``visibilitychange`` or ``pagehide`` behaviour.

.. _auditor-verify-use-vs-reveal:

Procedure 2 — ``secret.use`` does not grant ``secret.reveal``
=============================================================

**Claim under test.** Machine consumption and human disclosure are separate
permissions, and neither implies the other. An integration account cannot read
a plaintext with someone's eyes.

**Safe on production.** Yes — it only produces denials.

**Preconditions.** A backend group granted ``secret.use`` and **not**
``secret.reveal``, and a test user in only that group with read access to a
test secret.

**Steps**

#.  As that user, open a record whose form contains a vault-backed field. The
    field must resolve — that is ``secret.use`` working.
#.  As the same user, attempt a reveal from :guilabel:`Vault > Secrets`.
#.  Query the audit log for denials:

    ..  code-block:: bash

        vendor/bin/typo3 vault:audit --action=access_denied --actor=<uid> --format=json

**Expected result**

*   Step 1 succeeds. If the field does not resolve, ``secret.use`` is not
    granted — recheck the group.
*   Step 2 is refused with **HTTP 403** and no plaintext in the response body.
*   An ``access_denied`` row exists for that actor.

**The mirror test.** Grant ``secret.reveal`` and remove ``secret.use``. The
reveal must **still** fail: the endpoint asserts ``secret.reveal``, but the
shared read path asserts ``secret.use``, so a non-admin needs both. A reveal
that succeeds with only ``secret.reveal`` is a serious finding.

**Frontend check (safe).** With a valid backend session, request a frontend
page that resolves a vault value. Frontend requests hold no operation
permission regardless of the session, so the session may not widen the
outcome. For a :typoscript:`%vault(id)%` placeholder the flag is necessary but
not sufficient: the identifier must also be in the request's allow-set
(:ref:`adr-035-frontend-placeholder-allow-set`). A ``frontend_accessible``
secret that resolves from editor-authored content it was never published to is
a finding.

.. _auditor-verify-admin-override:

Procedure 3 — The administrator override is effectively withdrawn
=================================================================

**Claim under test.** In the hardened profile with ``disableAdminOverride``
set, an administrator holds only what their groups grant — on **both** gates,
not just one.

**Safe on production.** The read-only parts, yes. Removing grants from a live
administrator is not.

**Steps**

#.  Confirm the flag is effective, not merely set:

    ..  code-block:: bash

        vendor/bin/typo3 vault:break-glass --status

    ``adminOverrideDisabledEffective`` must read ``yes``. A raw ``1`` with an
    effective ``no`` means the profile is ``standard`` and the flag is inert.

#.  As an administrator whose groups grant **no** vault permissions, attempt to
    reveal a secret they do **not** own and share no group with.
#.  Attempt an operation-level action they were not granted — for example
    opening the audit module without ``audit.view``.

**Expected result**

*   Step 2 is refused; the secret is not readable. This is the per-secret gate.
*   Step 3 is refused. This is the operation gate — and it is the more
    important half of the test, because a grant lookup routed through TYPO3's
    :php:`BackendUserAuthentication::check()` would return ``true``
    unconditionally for an admin and silently defeat it.
*   Ownership still works: the same administrator retains full access to
    secrets they **own**. That is expected, not a finding.
*   Both refusals appear as ``access_denied`` audit rows.

**Finding if:** the operation gate refuses but the per-secret gate allows, or
vice versa. A half-disabled override is worse than none, because the
deployment believes it is protected.

.. _auditor-verify-break-glass:

Procedure 4 — Break-glass leaves a complete evidence trail
==========================================================

**Claim under test.** Emergency access cannot happen without evidence, a named
actor, a justification and an expiry.

**Safe on production.** Technically yes — but it grants full admin power for
the duration. Prefer staging; if run on production, treat it as a real
activation and review it (:ref:`operations-incident-response-breakglass`).

**Steps**

#.  Attempt activation **without** a reason, and with a whitespace-only reason:

    ..  code-block:: bash

        vendor/bin/typo3 vault:break-glass --activate
        vendor/bin/typo3 vault:break-glass --activate --reason="   "

#.  Activate properly, with an out-of-range TTL:

    ..  code-block:: bash

        vendor/bin/typo3 vault:break-glass --activate \
            --reason="AUDIT-1 break-glass evidence test" --minutes=600

#.  Check the status, and the backend UI.
#.  Deactivate:

    ..  code-block:: bash

        vendor/bin/typo3 vault:break-glass --deactivate --reason="AUDIT-1 complete"

#.  Read the evidence and verify the chain:

    ..  code-block:: bash

        vendor/bin/typo3 vault:audit --identifier=__break_glass__ --format=json
        vendor/bin/typo3 vault:audit-verify

**Expected result**

*   Both attempts in step 1 are **rejected**. A reason is mandatory and an
    empty or whitespace-only value does not satisfy it.
*   Step 2 succeeds with the TTL **clamped to 60 minutes**, not rejected — the
    ceiling carries the security property either way, and an error under
    incident pressure would not help.
*   The vault Overview and Secrets modules show a danger callout naming the
    actor, the reason and the expiry. A window nobody notices is the admin
    override with extra steps.
*   A ``break_glass_activated`` row exists whose context carries
    ``actorUid``, ``actorUsername``, ``expiresAt`` and ``ttlMinutes``, and
    whose ``reason`` is the text supplied.
*   A ``break_glass_deactivated`` row exists, whose context also carries the
    **original activation reason**.
*   The chain still verifies with both rows inside it.

**Expiry variant (STAGING-ONLY, and slow).** Activate with ``--minutes=1``, do
not deactivate, wait past the expiry, then confirm the bypass is gone
(``--status``) and that **no** row was written for the expiry. Nothing runs at
the moment a window lapses — the closed interval must be reconstructed from the
activation row's ``expiresAt``. Verify that is genuinely the case rather than
assuming it.

..  note::

    Also confirm that a ``TechnicalActorContext::runAs()`` scope cannot open a
    window, even for an actor whose snapshot carries the admin flag. This needs
    a code-level test rather than a CLI step; the invariant is asserted in the
    test suite and stated in :ref:`security-break-glass`.

.. _auditor-verify-fail-closed:

Procedure 5 — Fail-closed provider behaviour (STAGING-ONLY)
===========================================================

..  danger::

    **STAGING-ONLY.** This procedure deliberately misconfigures the master-key
    provider. On production it makes every secret unreadable for the duration.

**Claim under test.** A misconfigured hardened vault stops. It never silently
continues on weaker key material.

**Test 5a — the forbidden provider is refused**

..  code-block:: none
    :caption: Extension configuration, staging

    securityProfile = hardened
    masterKeyProvider = typo3

Attempt any vault operation that needs the master key.

*Expected:* a :php:`ConfigurationException` with code **1753900002** and a
message naming the provider as not permitted in the hardened profile. **No
secret is decrypted**, and the operation does not fall back to another
provider.

*Finding if:* the operation succeeds. That would mean the hardened profile is
not enforced in code, only documented.

**Test 5b — no auto-detection fallback**

..  code-block:: none
    :caption: Extension configuration, staging

    securityProfile = hardened
    masterKeyProvider = file
    masterKeySource = /nonexistent/path/vault-master.key

*Expected:* the operation fails with a master-key error naming the missing
path. It does **not** silently fall through to the TYPO3 encryption key, an
environment variable, or an auto-generated development key.

*Contrast, to prove the difference is the profile and not the path:* set
``securityProfile = standard`` with the same broken path. Now the provider
chain **does** fall back (configured → ``typo3`` → ``env`` → ``file``) and the
operation may succeed. Two different outcomes from the same broken
configuration is exactly the evidence sought — the profile changes behaviour,
not just documentation.

**Test 5c — an unknown profile is refused**

..  code-block:: none
    :caption: Extension configuration, staging

    securityProfile = paranoid

*Expected:* a :php:`ConfigurationException` with code **1753900001** and a
message stating it refuses to fall back to a weaker profile. **Not** a silent
default to ``standard``.

**Test 5d — the hardened sink requirement**

Disable every audit sink, keep ``securityProfile = hardened``, and run:

..  code-block:: bash

    vendor/bin/typo3 vault:audit-verify --format=json

*Expected:* a ``NO_EXTERNAL_SINK`` finding. Repeat with a sink enabled but no
anchor ever published — also ``NO_EXTERNAL_SINK``, this time about the missing
anchor. Then set ``securityProfile = standard`` and repeat: **no** such finding,
because the standard profile treats sinks as opt-in.

**Restore** the original configuration and confirm with a probe decrypt and
``vault:doctor``.

.. _auditor-verify-tamper:

Procedure 6 — Tamper detection (STAGING-ONLY)
=============================================

..  danger::

    **STAGING-ONLY.** These steps manipulate ``tx_nrvault_audit_log`` directly
    and permanently break the chain on that system. Never on production. Take a
    dump first if you want to repeat individual tests.

**Claim under test.** Row edits, deletions, full resets and algorithm
downgrades are all detected, and each produces its own reason code.

Establish a baseline first — a chain that verifies, and a published anchor:

..  code-block:: bash

    vendor/bin/typo3 vault:audit-verify        # must be clean
    vendor/bin/typo3 vault:audit-anchor        # publish the baseline
    cp <auditSinkAnchorPath> baseline-anchor.ndjson

**Test 6a — row edit →** ``HASH_MISMATCH``

..  code-block:: sql

    UPDATE tx_nrvault_audit_log SET actor_username = 'someone.else' WHERE uid = <mid>;

*Expected:* ``HASH_MISMATCH``. Note **which** field you changed: from epoch 3
the attribution fields are bound into the hash, so this proves blame cannot be
reassigned. Repeat with ``success`` (bound from epoch 2) and with
``reason``. On an epoch-1 chain the attribution edit will **not** be detected —
which is itself the finding, and the reason to migrate.

**Test 6b — row deletion →** ``UID_GAP``

..  code-block:: sql

    DELETE FROM tx_nrvault_audit_log WHERE uid = <mid>;

*Expected:* ``UID_GAP``, with the missing-uid count in the finding context, and
``HASH_MISMATCH`` on the following rows.

**Test 6c — full reset →** ``TABLE_RESET``

..  code-block:: sql

    TRUNCATE TABLE tx_nrvault_audit_log;

Then perform a few normal vault operations so a fresh chain is built, and
verify with both verifiers:

..  code-block:: bash

    vendor/bin/typo3 vault:audit --verify
    vendor/bin/typo3 vault:audit-verify --format=json

*Expected:* **both** anchors fire.

``vault:audit --verify`` reports ``Tip anchor: VIOLATED`` and an **invalid**
chain: the in-database anchor in ``sys_registry`` still names a row the
truncation removed, and verification raises that as a hard error. This is what
an attacker limited to ``tx_nrvault_audit_log`` runs into.

``vault:audit-verify`` additionally raises ``TABLE_RESET`` from the external
anchor comparison.

*Finding if:* no ``TABLE_RESET`` appears. Then either no anchor was published,
or the anchor file was truncated along with the table — check that
``baseline-anchor.ndjson`` still contains the pre-truncate anchor, and restore
it if the sink wrote to a file the truncation also removed. **An anchor stored
only on the compromised host is not independent evidence**, and this test is
how that becomes visible.

**Test 6e — full reset with the in-database anchor removed first**

This is the case Test 6c's "the chain alone cannot see a reset" claim actually
describes, and it is the one worth demonstrating to a sceptical assessor.

..  code-block:: sql

    DELETE FROM sys_registry WHERE entry_namespace = 'tx_nrvault_audit_anchor';
    TRUNCATE TABLE tx_nrvault_audit_log;

Rebuild a fresh chain as above, then verify.

*Expected:* ``vault:audit --verify`` now reports a **valid**, perfectly
self-consistent chain with ``Tip anchor: NOT ARMED`` — the internal evidence
is gone, and only ``vault:audit-verify``'s external ``TABLE_RESET`` still
detects the reset. This demonstrates both halves at once: what the in-database
anchor buys, and why it does not remove the need for an off-host one.

**Test 6f —** ``auditAnchorRequired`` **closes the downgrade**

Repeat Test 6e with ``auditAnchorRequired = 1`` in the extension
configuration.

*Expected:* the missing anchor is now reported as **critical** rather than as
the ``NOT ARMED`` warning, and ``vault:doctor`` fails on ``audit.db_anchor``.
Because the setting lives in the extension configuration rather than in a
table, deleting the ``sys_registry`` row no longer silences the control.

*Finding if:* the run still reports only a warning. Then the setting is not in
force — confirm it is set, and remember a backend administrator can still
clear it from the Settings module, since this key is **not** among the three
that accept a ``$TYPO3_CONF_VARS`` pin.

**Test 6d — algorithm downgrade →** ``EPOCH_DOWNGRADE``

..  code-block:: sql

    -- Partial: a decrease between consecutive rows.
    UPDATE tx_nrvault_audit_log SET hmac_key_epoch = 0 WHERE uid = <mid>;

    -- Uniform: every row, which no per-row comparison would notice.
    UPDATE tx_nrvault_audit_log SET hmac_key_epoch = 0;

*Expected:* the partial case raises ``EPOCH_DOWNGRADE`` from the per-row
comparison. The uniform case is caught by the **chain-level epoch floor** — the
chain's highest epoch must reach the configured ``auditHmacEpoch`` — and, on an
epoch-3 chain, also by ``HASH_MISMATCH``, because the epoch column is itself
bound into the hash.

Run the uniform test explicitly. It is the case a naive implementation misses,
and the one an attacker with full table write access would actually attempt.

**Test 6e — sink independence**

With a sink enabled, perform an audited operation, confirm the record arrived
at the collector, then delete the corresponding row from the database and
verify. *Expected:* the database reports the gap, **and** the collector still
holds the record. Diffing the two is the comparison that turns a suspicion into
proof — see :ref:`operations-incident-response-tampering`.

**Restore** the staging system from the pre-test dump, or accept that its audit
chain is permanently broken and record why.

.. _auditor-verify-summary:

Summary
=======

..  list-table::
    :header-rows: 1
    :widths: 42 20 38

    *   -   Procedure
        -   Environment
        -   Demonstrates

    *   -   1 — Reveal writes an audit row
        -   Production safe
        -   Non-repudiation of disclosure; no client-side cache; bounded
            exposure

    *   -   2 — ``use`` versus ``reveal``
        -   Production safe
        -   Separation of machine consumption from human disclosure

    *   -   3 — Admin override withdrawn
        -   Production safe (read-only parts)
        -   Both gates honour the withdrawal

    *   -   4 — Break-glass evidence trail
        -   Prefer staging
        -   Mandatory justification, TTL clamp, complete audit evidence

    *   -   5 — Fail-closed provider
        -   **STAGING-ONLY**
        -   The hardened profile is enforced in code, not documented

    *   -   6 — Tamper detection
        -   **STAGING-ONLY**
        -   Edit, deletion, reset and downgrade each detected, with the anchor
            supplying what the chain cannot
