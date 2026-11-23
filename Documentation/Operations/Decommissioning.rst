:navigation-title: Decommissioning
.. include:: /Includes.rst.txt

.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. _operations-decommissioning:

===============
Decommissioning
===============

Retiring a vault, or an installation that contains one. The order matters, and
one step is irreversible by design.

.. _operations-decommissioning-secrets:

Secret disposal
===============

..  warning::

    **``vault:delete`` is a soft delete.** :php:`SecretRepository::delete()`
    sets ``deleted = 1`` and updates ``tstamp``; the row — with its ciphertext,
    its wrapped DEK and its nonces — stays in ``tx_nrvault_secret``. The same
    is true of ``vault:cleanup-orphans``, which routes through the same
    :php:`VaultService::delete()`.

    There is no hard-delete path in the extension. Do not read "deleted" as
    "gone".

That is the right default for a live system: it keeps the operation auditable,
and the row is unreadable to anyone without the master key anyway. It does
**not** make the delete reversible. The vault has no restore operation, and
the backend refuses TYPO3's ``undelete`` command on ``tx_nrvault_secret`` — a
restore would hand back the ciphertext, the wrapped DEK, ``frontend_accessible``
and both ACL tiers with no vault check at all, and nothing in the audit chain
would say it happened. Recovering a deleted secret means acting on the database
directly, deliberately and visibly. See
:ref:`usage-record-operations-refused`.

The soft delete is the wrong assumption when decommissioning. For actual
disposal you have two options, and they compose:

**Crypto-erasure (recommended).** Destroy the master key and every secret in
the vault becomes permanently unreadable in one step — including soft-deleted
rows, including rows in every backup already taken. This is the only measure
that reaches copies you no longer control. See
:ref:`operations-decommissioning-keys`.
The same holds for rows deleted before a master-key rotation:
``vault:rotate-master-key`` re-wraps live and disabled secrets only, so a
soft-deleted row stays wrapped under the retired key and becomes unreadable
once that key is destroyed.

**Row removal (for completeness).** Drop or truncate the tables at the
database level once the audit-retention obligations below are satisfied:

..  code-block:: sql
    :caption: Only after the evidence export is complete and verified

    -- Secrets, including soft-deleted rows, and their two ACL relation
    -- tables. Dropping only the secret table leaves the MM rows behind.
    DROP TABLE tx_nrvault_secret;
    DROP TABLE tx_nrvault_secret_begroups_mm;
    DROP TABLE tx_nrvault_secret_writegroups_mm;
    -- Audit chain. Check your retention obligations FIRST.
    DROP TABLE tx_nrvault_audit_log;

    -- Vault state also lives in the core registry: the chain tip anchor,
    -- and the break-glass session plus per-sink delivery state.
    DELETE FROM sys_registry WHERE entry_namespace = 'tx_nrvault_audit_anchor';
    DELETE FROM sys_registry WHERE entry_namespace = 'tx_nrvault';

..  note::

    Row removal on its own is weaker than it looks: database backups,
    replicas, binlogs, filesystem snapshots and storage-level copies keep the
    ciphertext for as long as their own retention allows. Crypto-erasure is
    what makes those copies worthless. Do both if the policy demands it; do
    crypto-erasure if you can only do one.

.. _operations-decommissioning-rotate-out:

Rotate credentials out, do not just delete them
===============================================

A secret in the vault is a *copy* of a credential that also exists in the
system it authenticates against. Deleting the vault copy does not revoke
anything.

Before disposal, for every secret still in use: rotate the credential at its
origin — the API provider, the SMTP relay, the OAuth client, the deploy key —
so that the value the vault held stops working. Then dispose of the vault
copy. In that order: a rotation performed after the vault is gone has to be
done without the ability to read what is being replaced.

.. _operations-decommissioning-evidence:

Final evidence export
=====================

Do this **before** anything destructive. Once the master key is gone, the
audit chain can no longer be verified — the HMAC key was derived from it — so
a verification run after key destruction proves nothing.

The evidence set has to end at the final, externally retained anchor. A row
written after that anchor is still checked against its HMAC while the key
exists, but nothing outside the installation witnesses it; once the key is
destroyed, nothing distinguishes it from a row fabricated before the export.
So the steps below run against a vault nobody writes to.

#.  **Stop every audit writer, and keep them stopped until the key is
    destroyed.** Finish every in-vault operation first: rotating credentials
    at their origin and storing, rotating or ``vault:delete``-ing the vault
    copies (:ref:`operations-decommissioning-rotate-out`) all write audit
    rows. From here on, disposal is crypto-erasure or dropping tables only.
    Then stop:

    *   **Web traffic that reads or writes secrets** — frontend placeholders,
        the backend module, the AJAX reveal, and the vault HTTP client
        including outbound OAuth calls, whose token refresh stores and audits
        (:ref:`security-known-limitations-rotation-gap`). Put the site into
        maintenance mode at the web server or load balancer, and lock the
        backend:

        ..  code-block:: bash

            vendor/bin/typo3 backend:lock

        This locks administrators out too, but not the CLI. It writes a lock
        file on the node it runs on (``[BE][lockBackendFile]``), so in a
        cluster run it on every node or rely on the load balancer.

    *   **The scheduler.** Disable whatever invokes ``scheduler:run`` —
        crontab, systemd timer, Kubernetes CronJob, a scheduler container — on
        every node. Removing the trigger does not stop a run already in
        progress: wait until ``vendor/bin/typo3 scheduler:list`` shows no
        task as running (the scheduler backend module is unreachable once the
        backend is locked). A task that still shows as running with no
        scheduler process left is a crashed run; clear it with
        ``vendor/bin/typo3 scheduler:run --task=<uid> --stop``, or the anchor
        run below is skipped every time.

    *   **Everything else that reaches the vault** — message and queue
        consumers, other workers, deploy hooks and CLI jobs that call
        ``vault:*`` commands or the vault API.

    Check that the chain has stopped growing: run the same query twice, a few
    minutes apart, and continue only when both return the same value.

    ..  code-block:: sql

        SELECT MAX(uid) FROM tx_nrvault_audit_log;

#.  **Verify the chain while the key still exists**, and keep the output:

    ..  code-block:: bash

        vendor/bin/typo3 vault:audit-verify --as-auditor > decommission-verify.txt
        grep -q 'Audit log integrity verified' decommission-verify.txt \
            && echo "chain verified"

    Stop if it did not print ``chain verified``: a failed verification is
    not fixed by re-running the later steps. The command also exits with 0
    when every finding was acknowledged by an administrator (``No open
    findings: …``); the evidence set then has a known break, and this step
    does not pass either. Whether to destroy the key anyway is a decision for
    the decommission owner: copy the acknowledged findings from
    ``decommission-verify.txt`` into the decommissioning record with that
    decision before continuing, and skip the ``grep`` command of the first
    check below. The export check below compares
    the export only with the newest anchor, which is the one published in the
    next step; a mismatch with an earlier anchor, such as a reset chain that
    has grown again, is reported by this verification alone.

#.  **Export the audit log, publish the final anchor, then verify the
    export** — in that order, as one chain:

    ..  code-block:: bash

        vendor/bin/typo3 vault:audit --as-audit-reader --export=decommission-audit.json \
            && vendor/bin/typo3 scheduler:run --task=<anchor-task-uid> --force \
            && vendor/bin/typo3 vault:audit --as-audit-reader --verify-export=decommission-audit.json \
                > decommission-export-verify.txt \
            && grep -Eq 'Whole chain +yes' decommission-export-verify.txt \
            && echo "export verified as the whole chain"

    The export covers the entire retained period with the hash columns
    included — ``uid``, ``previous_hash``, ``entry_hash``,
    ``hmac_key_epoch``. Without them the export is a log, not evidence.
    ``vault:audit --export`` without filters writes every entry up to the
    newest and carries all of these (:ref:`command-audit-export`). The file
    is written readable by its owner only.

    The anchor is published after the export, so the external witness covers
    every exported row. ``scheduler:run`` exits non-zero when no sink
    accepted the anchor, which stops the chain; do not work around that
    failure. Verifying the export last catches a row written after it:
    ``--verify-export`` then reports ``Whole chain`` as
    ``not confirmed``, with a note such as "This installation stores 1 entry
    after uid …" or, with a file sink, "The newest external anchor is at uid
    …, beyond the end of the export". Each command runs only when the one
    before it succeeded, so the verification never checks an older file left
    at that path. Keep ``decommission-export-verify.txt`` with the export.

    ``Whole chain yes`` is necessary, but not sufficient: an anchor run that
    published nothing new leaves the previous anchor in place, and an export
    that ends after that older anchor still passes. The next step closes that
    gap.

    ..  note::

        The verification, the anchor and the export each assert an operation
        permission (breaking change; they previously asserted none):
        ``vault:audit-verify`` needs ``audit.view``, anchoring needs
        ``vault.configure``, and the export needs ``audit.export``. All
        three are excluded from the
        :confval:`ext-nrvault-cliAllowedOperations` default. The anchor is
        published by the *Vault Audit Chain Anchoring* task, run once above:
        :bash:`scheduler:run` authenticates the ``_cli_`` user, which holds
        ``vault.configure`` through the admin bypass or, under
        ``disableAdminOverride``, through its group. ``vault:audit-verify``
        runs as a named user with ``--as-auditor`` and
        :confval:`ext-nrvault-auditorBeUserUid`, and the export with
        ``vault:audit --as-audit-reader`` and
        :confval:`ext-nrvault-auditReaderBeUserUid`. The audit reader needs
        both ``audit.export`` (for the export) and ``audit.view`` (for the
        verification). None of these writes an audit row, so the trail does
        not record who ran them. Sort the grant out before the
        decommissioning window: after the master key is destroyed there is no
        second chance at this output.

#.  **Confirm that the final anchor ends the export.** This is a gate, not a
    convenience: destroy the key only after it passed. Three numbers must be
    equal — the chain length (max uid) the verification reported, the
    export's last uid (``.export.lastUid``), and the final anchor's
    ``sequence`` — and the anchor's ``chainTip`` must equal that row's
    ``entry_hash``. The comparison is needed even though the anchor step
    succeeded: a scheduled run still in progress makes ``scheduler:run``
    skip the task and exit with 0 without a new anchor, and a file sink can
    accept the anchor while the off-host copy is missing.

    First, in every sink configuration, check that the verification passed
    and ended where the export ends:

    ..  code-block:: bash

        grep -q 'Audit log integrity verified' decommission-verify.txt \
            || { echo 'CHAIN NOT VERIFIED: see the verification step' >&2; false; }
        jq -er \
            --argjson verified "$(sed -n 's/^ *Chain length (max uid) *\([0-9][0-9]*\).*/\1/p' decommission-verify.txt)" \
            'if .export.lastUid == $verified
             then "verified and exported up to uid \($verified)"
             else error("NOT CONFIRMED: verified up to \($verified), exported up to \(.export.lastUid)")
             end' \
            decommission-audit.json

    ``CHAIN NOT VERIFIED`` means the chain verification did not pass: stop,
    that is not fixed by publishing again. Where the decommission owner
    decided to proceed over acknowledged findings (verification step), skip
    the ``grep`` command only. ``NOT CONFIRMED`` here means a row was
    written between the verification and the export: a writer is still
    running. Stop it and start again at the verification step.

    Then, with a file sink, compare against the anchor file
    (:confval:`ext-nrvault-auditSinkAnchorPath`). Like the extension's own
    reader, the command takes the anchor with the highest ``sequence`` and
    skips a truncated line:

    ..  code-block:: bash

        jq -R 'fromjson? | objects | select(.type == "anchor") | .anchor' <anchor-file> \
            | jq -s 'max_by(.sequence)' > decommission-final-anchor.json \
            && jq -r \
                --argjson verified "$(sed -n 's/^ *Chain length (max uid) *\([0-9][0-9]*\).*/\1/p' decommission-verify.txt)" \
                --slurpfile anchor decommission-final-anchor.json \
                '.export.lastUid as $last
                | ([.rows[] | select(.uid == $last)][0].entry_hash) as $tip
                | "verified \($verified), exported \($last), anchored \($anchor[0].sequence // "none")",
                  if $verified == $last and $anchor[0].sequence == $last and $anchor[0].chainTip == $tip
                  then "export ends at the final anchor"
                  else error("NOT CONFIRMED: the final anchor does not end the export")
                  end' \
                decommission-audit.json

    It prints the three numbers and then ``export ends at the final anchor``.
    Anything else — ``NOT CONFIRMED``, or an error because a file is missing
    or the chain length could not be read — means the final anchor is missing
    or older than the export: it was not published. Find out why, and run the
    anchor step and both checks again.

    The anchor check reads a host-local file, which is weak evidence
    (:ref:`auditor-evidence-chain`). The anchor record that is kept is the
    off-host copy, so make the same comparison there by hand: in the syslog
    archive or the SIEM, the newest anchor event (``vault audit chain
    anchored at sequence …`` in syslog, ``type`` ``anchor`` from the
    webhook) must carry ``sequence`` equal to ``.export.lastUid`` and
    ``chainTip`` equal to that row's ``entry_hash``. With only webhook or
    syslog sinks configured, the first check plus this hand comparison is the
    whole gate.

#.  **Collect the external evidence** from where it actually lives: the anchor
    file, the syslog archive, the SIEM's retained records. This is the half
    the installation cannot fabricate, and after decommissioning it is the
    only half left.

#.  **Record the decommissioning itself** — date, operator, which artefacts
    were exported, which tables were dropped, when and how the key was
    destroyed. A ``TABLE_RESET`` finding against the final anchor is
    indistinguishable from a malicious reset without this record.

:ref:`auditor-evidence-collection` lists the artefacts in the form an assessor
expects.

.. _operations-decommissioning-retention:

Retention obligations versus deletion
=====================================

These pull in opposite directions and nr-vault cannot resolve the conflict for
you — it can only make sure you notice it.

*   **The secrets are the deletion obligation.** Credentials have no reason to
    outlive the system that used them, and a retained ciphertext is a retained
    risk for as long as any copy of the key might exist.

*   **The audit log is the retention obligation.** It is the record of who
    accessed which credential and when — frequently the artefact an audit
    regime requires to be kept, and often for years. It contains no secret
    values.

**They are separable, and separating them is the answer.** Destroy the key and
drop ``tx_nrvault_secret``; keep the exported audit evidence for as long as
policy requires. The exported chain remains internally verifiable — each row's
``previous_hash`` still links to its predecessor — but note honestly what is
lost: **without the master key, HMAC recomputation is no longer possible**, so
from epoch 1 upwards the export becomes a *sequence* whose links can be
inspected rather than a chain whose authenticity can be re-proved. That is why
the chain verification in :ref:`operations-decommissioning-evidence`
(``decommission-verify.txt``) matters: it is the last point at which
authenticity was demonstrable, and it must be captured then, not later.

..  note::

    ``tx_nrvault_audit_log`` also holds personal data — ``actor_username``,
    ``ip_address``, ``user_agent``. A deletion request under data-protection
    law collides with the tamper-evident design: editing or removing a row
    breaks the chain by construction, which is the entire point.
    :ref:`adr-017-audit-metadata-retention` is where that trade-off is
    recorded; resolve it as a policy decision before decommissioning, not
    during.

.. _operations-decommissioning-keys:

Key destruction
===============

Irreversible. There is no escrow and no vendor-side reset — see
:ref:`security-known-limitations-key-loss`.

..  list-table::
    :header-rows: 1
    :widths: 16 84

    *   -   Provider
        -   How to destroy the key

    *   -   ``typo3``
        -   Rotate or remove ``SYS/encryptionKey`` in
            :file:`config/system/settings.php`, and destroy every backup of
            that file. **Harder than it sounds** — the config directory is
            usually in more backups than anyone expects, and ``encryptionKey``
            is also used by TYPO3 core for unrelated purposes, so removing it
            has effects beyond the vault.

    *   -   ``file``
        -   Delete the key file and every copy, including the separate key
            backup. On a copy-on-write filesystem or a storage layer with
            snapshots, deletion is not erasure — destroy the snapshots too.

    *   -   ``env``
        -   Remove the variable from the injection mechanism and restart. Then
            check where it was *also* recorded: CI secret stores, deployment
            manifests, container inspection output, shell history.

    *   -   ``transit``
        -   **The cleanest case.** Delete the transit key in HashiCorp Vault
            (or revoke every policy granting ``decrypt`` on it) and the
            locally stored wrapped blob becomes undecryptable immediately —
            including in every backup that contains it. Then delete the
            wrapped file as well.

#.  Confirm the evidence export is complete and stored elsewhere.
#.  Confirm, immediately before destroying the key, that the chain still ends
    where the evidence ends: ``SELECT MAX(uid) FROM tx_nrvault_audit_log``
    still returns the export's ``.export.lastUid``, or a re-run of
    ``--verify-export`` still prints ``Whole chain yes``. A row written after
    the evidence was closed is in no retained evidence; stop its writer and
    start the evidence export again.
#.  Confirm no other installation shares the key material. A key file copied
    to a staging system is still a live key.
#.  Destroy the key.
#.  Verify destruction by attempting a read: a probe decrypt must now fail
    with ``Master key not found at: …`` or
    ``Authentication failed - data may have been tampered with``. A successful
    read means a copy survived somewhere — find it.
#.  Drop the tables, if row removal is also required.

.. _operations-decommissioning-cleanup:

Installation cleanup
====================

*   **Keep the audit writers stopped** until the key is destroyed
    (:ref:`operations-decommissioning-evidence`). Re-enabling the scheduler,
    the backend or the site before then writes rows that no retained
    evidence covers.
*   **Remove the sinks** last, not first: they are what records the
    decommissioning steps. Turn off ``auditSinkWebhookEnabled`` and friends
    only after the final anchor has been published and compared.
*   **Unschedule the tasks** — the audit anchor and audit verify scheduler
    tasks, and orphan cleanup — or they will start failing loudly against a
    vault that no longer exists.
*   **Revoke the grants.** Remove the ``tx_nrvault:*`` custom options from
    ``be_groups``, so a later reinstall does not silently inherit a permission
    model nobody reviewed.
*   **Unpin the settings.** Remove the
    :php:`$GLOBALS['TYPO3_CONF_VARS']['SYS']['nrVault']` entries from
    :file:`config/system/additional.php`, and the extension configuration
    block itself from :file:`config/system/settings.php` — the pins are only
    the part that lives in ``additional.php``.
*   **Remove the extension**, and remember that removing it does not remove
    its tables.
*   **Clean up the KMS side** if ``transit`` was used: revoke the token, remove
    the policy, delete the transit key.
