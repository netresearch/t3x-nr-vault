:navigation-title: Hardened deployment
.. include:: /Includes.rst.txt

.. _operations-hardened-deployment:

===================
Hardened deployment
===================

A step-by-step deployment of the hardened profile, in an order that never
leaves the installation in a state where secrets are unreadable or every
administrator is locked out.

Read :ref:`security-profiles` first for what the profile changes, and
:ref:`security-known-limitations` for what it does not. If you are converting
an existing standard installation rather than deploying a new one, follow
:ref:`security-profiles-migration` — the sequence there rotates the key
*before* switching the profile, which is the part that matters.

..  note::

    Do the whole sequence on staging first. Step 6 withdraws the administrator
    override, and the recovery path for a mistake is a break-glass window —
    which is fine, but you want to have exercised it deliberately rather than
    for the first time under pressure.

.. _operations-hardened-deployment-step1:

Step 1 — Choose a master-key provider
=====================================

The hardened profile **rejects the ``typo3`` provider** with exception code
``1753900002``, and there is no auto-detection fallback that could quietly put
you back on it. Pick one of the others; the trade-offs are in
:ref:`operations-key-custody`.

..  list-table::
    :header-rows: 1
    :widths: 16 84

    *   -   Provider
        -   Choose it when

    *   -   ``file``
        -   Traditional server deployment with configuration management. The
            key is a file outside the web root at ``0400``, owned by the PHP
            user.

    *   -   ``env``
        -   Containers, or any platform with a secret-injection mechanism.
            Check first that your platform does not leak the environment into
            logs or inspection output.

    *   -   ``transit``
        -   You already run HashiCorp Vault. Best custody story: only the
            wrapped ciphertext is stored locally and every unwrap is centrally
            audited and revocable.

..  code-block:: none
    :caption: Extension configuration — file provider

    masterKeyProvider = file
    masterKeySource = /var/lib/typo3-secrets/vault-master.key

Initialise the key if this is a new vault:

..  code-block:: bash

    vendor/bin/typo3 vault:init

..  warning::

    On an existing vault, do **not** run ``vault:init`` to move providers. Use
    ``vault:rotate-master-key`` (:ref:`operations-key-rotation`).
    ``vault:init`` generates a fresh key, and a fresh key over an existing
    vault makes every secret unreadable — its own ``--force`` warning says so.

Back up the new key material **now**, separately from the database, and verify
the backup: :ref:`operations-backup-and-restore`.

.. _operations-hardened-deployment-step2:

Step 2 — Set the profile
========================

..  code-block:: none
    :caption: Extension configuration

    securityProfile = hardened

From this point the vault is fail-closed: no provider auto-detection, no
fallback to the TYPO3 encryption key, and a misconfigured provider stops vault
operations instead of continuing on weaker key material. An unknown value for
the setting is refused outright with code ``1753900001``.

Verify immediately, before going further:

..  code-block:: bash

    vendor/bin/typo3 vault:list
    vendor/bin/typo3 vault:doctor --profile=hardened

A ``vault:list`` that works only proves the database is reachable — it reads
metadata and never touches the master key. The real check comes in step 7.

.. _operations-hardened-deployment-step3:

Step 3 — Grant the operation permissions
========================================

Do this **before** step 6. With the override withdrawn, administrators hold
exactly what their groups were granted — so if the grants are not in place
first, nobody can operate the vault and the only way back in is break-glass.

Grants live per backend user group in :guilabel:`Backend Users > Groups`, field
:guilabel:`Custom module options`, group :guilabel:`Vault: operation
permissions`. The full table of ten permissions and what each governs is in
:ref:`security-operation-permissions`.

A workable starting split:

..  list-table::
    :header-rows: 1
    :widths: 26 74

    *   -   Group
        -   Grants

    *   -   Editors
        -   ``secret.use`` only. Required for FormEngine vault widgets and
            FlexForm / TypoScript placeholder resolution — without it, forms
            containing vault-backed fields break for non-admins. Deliberately
            **not** ``secret.reveal``.

    *   -   Vault operators
        -   ``secret.use``, ``secret.reveal``, ``secret.create``,
            ``secret.rotate``, ``secret.delete``.

    *   -   Vault administrators
        -   The operator set plus ``secret.manage_policy`` and
            ``vault.configure``.

    *   -   Auditors
        -   ``audit.view``, and ``audit.export`` only if they genuinely need to
            take the history off-system.

    *   -   Key custodians
        -   ``master_key.rotate``. Keep this separate from everything else —
            it is the operation that can render the whole vault unreadable.

    *   -   Integration accounts
        -   ``secret.use`` only. An integration has no eyes; it must not gain
            ``secret.reveal`` as a side effect.

..  note::

    ``secret.use`` and ``secret.reveal`` do not imply one another in either
    direction. A non-admin needs **both** for an end-to-end reveal: the
    endpoint asserts ``secret.reveal``, and the shared read path asserts
    ``secret.use``.

Remember that operation permissions are only one of two gates. Per-secret
ownership and group tiers still apply — see
:ref:`security-access-control`.

..  note::

    The table above grants *named* backend groups. Under this profile
    ``allowCliAccess = 1`` is itself a **critical** doctor finding, so a
    deployment that leaves it on does not pass Step 7's gate.

    If it has to stay on anyway, the unattributed CLI actor is granted
    separately by :confval:`ext-nrvault-cliAllowedOperations`, which defaults
    to ``secret.use,secret.create,secret.rotate``. Keep it at or below that,
    and scope ``cliAccessGroups`` as well. Of the high-risk entries,
    ``secret.reveal``, ``secret.delete`` and ``master_key.rotate`` directly
    hand ``vault:retrieve``, ``vault:delete`` and ``vault:rotate-master-key``
    to anyone with a shell on the host, under an actor the audit trail cannot
    name; ``audit.export`` and ``vault.configure`` gate the corresponding
    backend actions. Prefer a named technical actor —
    :ref:`developer-technical-actor-context` — for those workflows.
    ``vault:doctor`` reports the list as ``cli.allowed_operations``.

.. _operations-hardened-deployment-step4:

Step 4 — Enable an external audit sink
======================================

The hardened profile **requires** one. Without an enabled and usable sink,
``vault:audit-verify`` reports ``NO_EXTERNAL_SINK``: the audit trail would
exist only in the database it is meant to protect, and no chain-tip anchor
could be published.

Cheapest sufficient configuration, if the host already has a log shipper:

..  code-block:: none
    :caption: Extension configuration

    auditSinkSyslogEnabled = 1
    auditSinkSyslogIdent = nr-vault-prod

    auditSinkFileEnabled = 1
    auditSinkFilePath = /var/log/typo3/nr-vault-audit.ndjson
    auditSinkAnchorPath = /var/log/typo3/nr-vault-anchors.ndjson

Enable the ``file`` sink even when shipping to syslog: it is what writes the
NDJSON anchor stream that :php:`AnchorFileReader` reads back during
verification. Both paths must be outside any public root, or the sink reports
itself disabled rather than writing anyway.

For a webhook collector, read the ``allowed_hosts`` note in
:ref:`operations-monitoring-and-alerting` before configuring the URL — a
private-address collector is refused by design.

.. _operations-hardened-deployment-step5:

Step 5 — Schedule anchoring and verification
============================================

Two separate jobs, doing different things (see
:ref:`operations-monitoring-scheduler`):

..  code-block:: bash

    vendor/bin/typo3 vault:audit-anchor    # publish the tip — hourly
    vendor/bin/typo3 vault:audit-verify    # verify chain + anchor — every 15 min

Register :php:`AuditAnchorTask` and :php:`AuditVerifyTask` in
:guilabel:`Scheduler > Add task`, or run the commands from cron.

Publish the first anchor by hand now, so verification has a baseline
immediately rather than after the first scheduled run:

..  code-block:: bash

    vendor/bin/typo3 vault:audit-anchor
    vendor/bin/typo3 vault:audit-verify

Wire the alerting at the same time — a scheduled check whose failures nobody
receives is not a control. :ref:`operations-monitoring-what-to-page` says what
to page on.

The external anchor above is only half of the control. A second, independent
tip anchor lives in ``sys_registry`` (:ref:`adr-034-audit-chain-tip-anchor`)
and is what makes a full
wipe of ``tx_nrvault_audit_log`` detectable from inside the installation. It
arms itself on the next audit write; confirm it did, then require it:

..  code-block:: bash

    vendor/bin/typo3 vault:audit --verify   # "Tip anchor: ok" — not "NOT ARMED"

..  note::

    ``vault:audit --verify`` asserts ``vault.configure``; the listing form used
    further down asserts ``audit.view``. Neither is in the
    :confval:`ext-nrvault-cliAllowedOperations` default, and with the admin
    override disabled an admin no longer holds them implicitly — grant them to
    the group these checks run as, or run them as a named technical actor.

..  code-block:: none
    :caption: Extension configuration — only after the anchor reports ``ok``

    auditAnchorRequired = 1

Order matters. Turned on before the anchor is armed, every verification
reports a violation: an install that never had an anchor and one whose anchor
an attacker deleted look identical. Once on, the requirement lives in the
extension configuration rather than in a table, so a database-write attacker
can no longer silence the control by deleting the anchor row.
``vault:doctor`` reports the state as ``audit.db_anchor``.

Unlike ``disableAdminOverride`` and ``frontendPlaceholderLegacyCli``, this
setting accepts **no** ``$TYPO3_CONF_VARS`` pin — only those three keys do —
so a compromised administrator can still clear it from the Settings module.
It closes the database-writer path, not the backend-administrator one.

.. _operations-hardened-deployment-step6:

Step 6 — Withdraw the administrator override, and pin it
========================================================

..  code-block:: none
    :caption: Extension configuration

    disableAdminOverride = 1

This withdraws the bypass in one place and therefore everywhere it was
consulted: the operation permissions, the per-secret read/write/delete tiers,
the privileged-column policy, and the technical-actor equivalents. An override
disabled in only some of those would be worse than none, because the
deployment would believe it is protected.

**Then pin it**, or the control is only as strong as the backend it is
configured in — a compromised administrator can untick a checkbox:

..  code-block:: php
    :caption: config/system/additional.php

    $GLOBALS['TYPO3_CONF_VARS']['SYS']['nrVault']['disableAdminOverride'] = true;

    // Pin the strict CLI placeholder policy off-limits too (ADR-035). The
    // value below is the DEFAULT — pinning false is what stops an
    // administrator from turning the legacy CLI bypass back on. A deployment
    // that genuinely needs the old behaviour pins true instead.
    $GLOBALS['TYPO3_CONF_VARS']['SYS']['nrVault']['frontendPlaceholderLegacyCli'] = false;

Only three settings accept such a pin: ``disableAdminOverride``,
``frontendPlaceholderLegacyCli`` and ``auditReads``. Everything else in the
hardened set stays editable from the Settings module by whoever holds
``vault.configure``.

``frontendPlaceholderLegacyCli`` matters here because
:bash:`scheduler:run` authenticates the ``_cli_`` administrator: the admin
bypass grants the read, so the allow-set is the only remaining gate between an
editor-authored ``tt_content`` field and a secret in the output of a scheduled
newsletter or export job.

The pinned value wins in both directions and requires filesystem access to
change. Confirm it took effect:

..  code-block:: bash

    vendor/bin/typo3 vault:break-glass --status

The output reports ``adminOverrideDisabledEffective`` alongside the raw
setting, so a "flag set, profile standard" mismatch is visible rather than
silent.

..  note::

    Ownership still applies. An administrator keeps full access to the secrets
    they own, exactly like any other user — which is what makes the disabled
    state workable day to day.

Exercise break-glass once, deliberately, before you need it:

..  code-block:: bash

    vendor/bin/typo3 vault:break-glass --activate --reason="Verify break-glass path after hardening" --minutes=1
    vendor/bin/typo3 vault:break-glass --status
    vendor/bin/typo3 vault:break-glass --deactivate --reason="Verification complete"
    vendor/bin/typo3 vault:audit --identifier=__break_glass__

Both rows must appear. See :ref:`security-break-glass` and
:ref:`operations-incident-response-breakglass`.

.. _operations-hardened-deployment-step7:

Step 7 — Gate the deployment on ``vault:doctor``
================================================

..  code-block:: bash

    vendor/bin/typo3 vault:doctor --profile=hardened

Exit codes are the contract:

..  list-table::
    :header-rows: 1
    :widths: 12 88

    *   -   Code
        -   Meaning

    *   -   ``0``
        -   Every control passed. Deploy.

    *   -   ``1``
        -   Warnings only. Deployable, but each warning needs a decision and a
            ticket — do not normalise a permanently yellow gate.

    *   -   ``2``
        -   At least one critical finding. **Do not deploy.** The hardened
            policy is not satisfied. An unusable ``--profile`` value and an
            internal crash also exit ``2``, deliberately — a gate that could
            not check must never read as "checked and fine".

Severity is worst-wins, so a long list of passes cannot average a critical
finding away.

Use it as an actual gate in the pipeline, and keep the JSON for the deployment
record:

..  code-block:: bash
    :caption: Deployment gate

    set -e
    vendor/bin/typo3 vault:doctor --profile=hardened --format=json > vault-doctor.json
    # A non-zero exit stops the deploy; the artefact goes to the release record.

The machine-readable output is what makes this auditable rather than a
screenshot: each finding carries a stable identifier, so a pipeline can assert
on specific findings and an auditor can compare runs over time. See
:ref:`auditor-evidence-collection`.

Run it periodically too, not only at deploy time —
:ref:`operations-monitoring-doctor`.

.. _operations-hardened-deployment-step8:

Step 8 — Smoke test
===================

Verify the behaviour that actually changed. A green ``doctor`` says the
configuration is coherent; these steps say the deployment works.

**Crypto and provider**

*   [ ] A real secret decrypts: ``vault:retrieve <identifier>``, or a reveal in
      the backend module. Metadata listing is not proof.
*   [ ] Probe at least two secrets, ideally one from each encryption version —
      see :ref:`operations-backup-and-restore-verification`.

**Reveal lifecycle**

*   [ ] A reveal shows the value and **no copy button** — the hardened profile
      reports ``copyAllowed = false``.
*   [ ] The value disappears after 30 seconds, and immediately when the tab is
      switched away or the page is left.
*   [ ] The reveal response carries ``Cache-Control: no-store``.
*   [ ] Each reveal writes its own ``read`` audit row — reveal twice and check
      for two rows.

**Permissions**

*   [ ] A non-admin editor with ``secret.use`` can load a form containing a
      vault-backed field.
*   [ ] That editor **cannot** reveal (HTTP 403), and the denial appears as an
      ``access_denied`` audit row.
*   [ ] An administrator without explicit grants cannot reach a secret they do
      not own. **This is the check that proves step 6 took effect** — if they
      still can, the flag is not effective, and ``--status`` will show why.
*   [ ] The audit module is reachable by a group holding ``audit.view`` and not
      by one without it.
*   [ ] The strict CLI placeholder policy is in force: :bash:`vault:doctor`
      reports ``cli.frontend_placeholder_legacy`` as a pass (it is critical
      under this profile when the flag is on). Confirm it empirically as well —
      put a ``%vault(id)%`` placeholder for a ``frontend_accessible`` secret
      into an editor-editable field, run a scheduled render over it
      (:bash:`scheduler:run`), and confirm the placeholder does **not**
      resolve. If it does, ``frontendPlaceholderLegacyCli`` is on — check the
      pin.

**Audit pipeline**

*   [ ] ``vault:audit-verify`` reports a valid chain and no findings.
*   [ ] An anchor exists and is recent — check the newest ``timestamp`` in the
      anchor file.
*   [ ] ``vault:audit --verify`` reports ``Tip anchor: ok``, and
      ``auditAnchorRequired`` is on so a deleted anchor cannot silence the
      control.
*   [ ] Records actually arrive at the collector: run
      :bash:`vault:doctor --active-probes` (every enabled sink must accept
      the chain-tip anchor end-to-end), then perform a reveal and look for it
      in syslog or the SIEM. Do not infer delivery from the absence of
      errors.
*   [ ] Break the delivery on purpose once (point the webhook at an
      unreachable host, or make the NDJSON directory read-only), confirm a
      ``SINK_FAILURE`` alert reaches your alerting, then restore it. An
      untested alert path is not an alert path.

**Recovery**

*   [ ] Break-glass opens and closes, and both rows are in the chain.
*   [ ] The key-material backup restores on a scratch system and a probe
      decrypt succeeds there.

.. _operations-hardened-deployment-summary:

Configuration summary
=====================

..  code-block:: none
    :caption: The hardened set, for review

    securityProfile = hardened
    disableAdminOverride = 1        # and pinned in additional.php

    masterKeyProvider = file        # or env / transit — never typo3
    masterKeySource = /var/lib/typo3-secrets/vault-master.key

    allowCliAccess = 0              # default; 1 is a CRITICAL doctor finding
                                    # under --profile=hardened, i.e. exit 2
    cliAllowedOperations = secret.use,secret.create,secret.rotate
                                    # default; only read when allowCliAccess = 1
    frontendPlaceholderLegacyCli = 0  # default; pin it in additional.php
    auditReads = 1
    auditHmacEpoch = 3
    auditAnchorRequired = 1         # only after the in-DB anchor reports ok

    auditSinkSyslogEnabled = 1
    auditSinkSyslogIdent = nr-vault-prod
    auditSinkFileEnabled = 1
    auditSinkFilePath = /var/log/typo3/nr-vault-audit.ndjson
    auditSinkAnchorPath = /var/log/typo3/nr-vault-anchors.ndjson

Per-setting reference: :ref:`configuration`.
