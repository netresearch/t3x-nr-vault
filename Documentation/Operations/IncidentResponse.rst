:navigation-title: Incident response
.. include:: /Includes.rst.txt

.. _operations-incident-response:

=================
Incident response
=================

Three runbooks. Each starts with the step that preserves evidence, because
several of the useful actions — rotation, restore, re-anchoring — destroy or
overwrite the state an investigation needs.

..  note::

    Read the whole runbook before executing step 1. In particular: do not
    rotate before exporting, and do not re-anchor before comparing against the
    existing anchor.

.. _operations-incident-response-exposure:

Suspected secret exposure
=========================

**Trigger:** a credential from the vault appears somewhere it should not — a
log, a ticket, a screenshot, a public repository — or an account is compromised
that held ``secret.reveal``, or a host running the PHP process is compromised.

Step 1 — preserve, before you change anything
---------------------------------------------

..  code-block:: bash

    # Chain state as it stands now, plus the anchor comparison.
    vendor/bin/typo3 vault:audit-verify > incident-verify-before.txt

    # Snapshot the external anchor file as it stands now.
    cp <auditSinkAnchorPath> incident-anchor-before.ndjson

..  important::

    Every vault command in this runbook asserts an operation permission, and
    :confval:`ext-nrvault-cliAllowedOperations` excludes all of them:
    ``audit.view`` for reading and verifying (``vault:audit``,
    ``vault:audit-verify``), ``audit.export`` for ``--export``, and
    ``vault.configure`` for re-anchoring (``vault:audit-anchor``) in step 5.
    Under time pressure this is the moment the command exits 1 — sort the grant
    out before the incident, not during it. A named technical actor for the
    response runbook is the clean answer: the trail then names who responded.

Copy the audit rows for the affected identifiers and the suspected time window
out of the system as well (see :ref:`auditor-evidence-collection` for the
export). A rotation in step 3 changes ``hash_before`` / ``hash_after`` and adds
rows; the pre-incident picture is not recoverable afterwards.

Step 2 — determine scope from the audit log
-------------------------------------------

..  code-block:: bash

    # Everything that happened to one identifier.
    vendor/bin/typo3 vault:audit --identifier=<identifier>

..  note::

    Reading the audit log asserts ``audit.view`` — the same permission the
    verification in step 1 needs — and ``--export`` asserts ``audit.export``;
    :confval:`ext-nrvault-cliAllowedOperations` excludes both. The audit module
    in the backend needs the same two permissions and no CLI allowlist entry.

Answer these, and write down the answers:

*   **Which secrets?** Only the one observed, or every secret the compromised
    actor could reach? Check the actor's group grants and the per-secret tiers.
*   **``use`` or ``reveal``?** A ``read`` row written through a machine path
    (``secret.use``) means the plaintext went into an integration. A reveal
    means a human saw it. Both are exposure; they imply different blast radii.
*   **How long?** First and last relevant row, not just the one that triggered
    the incident.
*   **Which actor type?** ``backend``, ``cli`` or ``technical``. A
    ``technical`` actor means code, not a person — find the code.
*   **Any ``access_denied`` rows?** Denials around the same window often show
    the attacker's reconnaissance and widen the scope.
*   **Any ``break_glass_activated`` rows?** If so, treat
    :ref:`operations-incident-response-breakglass` as part of this incident.

Step 3 — rotate at the origin, then in the vault
------------------------------------------------

Rotate the credential **at its source first** — the API provider, the SMTP
relay, the OAuth client — so the exposed value stops working. Only then store
the replacement:

..  code-block:: bash

    vendor/bin/typo3 vault:rotate <identifier>

Rotating only the vault copy changes nothing about the exposure: the old value
still authenticates.

Rotate every secret in scope, not only the one that was observed. If the PHP
process or the host was compromised, the master key was reachable, so **every**
secret is in scope, and the master key itself has to be rotated as well —
:ref:`operations-key-rotation`.

Step 4 — close the path
-----------------------

Whatever made the exposure possible: revoke the session and reset the account;
remove over-broad grants (an editor holding ``secret.reveal`` who only needs
``secret.use`` is the common finding); withdraw the admin override and pin it
(:ref:`security-disable-admin-override`); switch off ``allowCliAccess`` if it
was enabled for a one-off and never turned back off, and where it must stay on,
narrow :confval:`ext-nrvault-cliAllowedOperations` back to the automation
default — a pipeline that was granted ``secret.reveal``, ``master_key.rotate``
or ``secret.manage_policy`` for one
task and kept it is the same class of finding as the over-broad editor grant;
consider the hardened profile (:ref:`security-profiles-migration`).

Step 5 — record and re-anchor
-----------------------------

..  code-block:: bash

    vendor/bin/typo3 vault:audit-verify > incident-verify-after.txt
    vendor/bin/typo3 vault:audit-anchor

Keep the before and after artefacts together with the scope notes.

.. _operations-incident-response-tampering:

Suspected audit tampering
=========================

**Trigger:** ``vault:audit-verify`` or the verify scheduler task reports
``HASH_MISMATCH``, ``UID_GAP``, ``TABLE_RESET`` or ``EPOCH_DOWNGRADE``; or an
``AuditIntegrityAlertEvent`` with
:php:`AuditIntegrityReason::isTamperEvidence()` true reaches your alerting.

..  warning::

    **Do not re-anchor.** Publishing a new anchor overwrites your best
    evidence: the existing anchor is the external fact that contradicts the
    current chain. Re-anchor only after the investigation is complete.

    Do not run ``vault:audit-migrate-hmac`` either — it rewrites hashes.

Step 1 — freeze the evidence
----------------------------

..  code-block:: bash

    # Full table dump, unaltered. Not a filtered export.
    mysqldump <db> tx_nrvault_audit_log > incident-audit-table.sql

    # The external anchor file, byte for byte.
    cp <auditSinkAnchorPath> incident-anchor.ndjson

    # The verification output, with the findings.
    vendor/bin/typo3 vault:audit-verify > incident-verify.txt

Also pull the same period from the sinks the database owner cannot reach — the
syslog archive, the SIEM. **That is the comparison that decides the case.** If
the SIEM holds rows the database no longer does, you have proof of deletion
rather than a suspicion.

Step 2 — rule out the benign causes first
-----------------------------------------

Most findings are operational, and confusing the two wastes the window in
which real evidence is still available.

..  list-table::
    :header-rows: 1
    :widths: 26 74

    *   -   Finding
        -   Benign explanation to exclude

    *   -   ``TABLE_RESET``
        -   A database restore to an earlier point in time produces exactly
            this. Check your restore records and
            :ref:`operations-backup-and-restore-chain`. Also: a database clone
            from production into staging, then anchoring in staging.

    *   -   ``HASH_MISMATCH`` on every row from one uid onwards
        -   The audit table and the master key came from different points in
            time, or the master key was rotated without the chain rekey
            completing.

    *   -   ``EPOCH_DOWNGRADE``
        -   ``auditHmacEpoch`` was lowered in the configuration, or a
            restored configuration does not match the restored data. An
            *increase* between consecutive rows is a legitimate migration
            boundary and is reported as a warning, not an error.

    *   -   ``UID_GAP``
        -   Rows lost in a partial restore, or a manual cleanup someone
            performed and did not document.

    *   -   ``SINK_FAILURE`` /
            ``NO_EXTERNAL_SINK``
        -   Availability, not integrity: an unreachable collector, a full
            disk, an ``allowed_hosts`` entry removed. Fix the delivery — but
            note that a sink which has been failing since before the suspect
            window means you have no independent evidence for it.

Step 3 — establish what happened
--------------------------------

*   **Compare the anchor to the chain.** The anchored sequence and tip say
    what the chain looked like at anchoring time. A shorter chain, a missing
    row at that sequence, or a different hash there is a rebuild.
*   **Bound the window.** Between the last anchor that still matches and the
    first one that does not.
*   **Diff against the external sink.** Rows present in syslog or the SIEM but
    absent from the table are deleted rows, and they name the actor.
*   **Ask who could.** Chain rewriting from epoch 1 up requires the master
    key, not just database write access. If the hashes recompute correctly
    under the current key but contradict the anchor, consider that the key
    holder is in scope.

Step 4 — respond
----------------

Treat a confirmed tamper as a full compromise of the database, and — if the
hashes are internally consistent yet contradict the anchor — of the master key
as well. That means :ref:`operations-key-rotation` and the exposure runbook
above for every secret.

Only when the investigation is closed: re-anchor, and record the incident
alongside the frozen artefacts so the next verification run has a documented
baseline.

.. _operations-incident-response-breakglass:

Break-glass usage policy and review
===================================

Break-glass restores **full** administrator power for the duration of the
window — every operation permission, and read, write and delete on every
secret. It prevents nothing; its value is a named actor, a typed
justification, a hash-chained audit row, a PSR-14 event, a visible banner, and
an expiry. See :ref:`security-break-glass` for the mechanism.

Policy
------

*   **Only for incidents.** Not for routine maintenance and not for
    convenience. If a task needs break-glass every week, the group grants are
    wrong — fix the grants.
*   **Reference a real record.** ``--reason`` is mandatory and rejects empty or
    whitespace-only values, but nothing forces it to be *useful*. Require an
    incident, ticket or change-record identifier; "testing" tells a later
    reviewer nothing.
*   **Take the smallest window that works.** The default is 15 minutes, the
    range is 1 to 60, and out-of-range values are clamped rather than rejected
    so a fat-fingered ``--minutes=600`` yields the ceiling instead of an error
    to re-read under pressure.
*   **Close it explicitly.** Do not wait for the expiry:

    ..  code-block:: bash

        vendor/bin/typo3 vault:break-glass --deactivate --reason="INC-4711 closed"

    An expiring window writes **no** audit row — nothing runs at the moment it
    lapses. Only an explicit deactivation produces the closing evidence.
*   **Alert on activation.** Listen for
    :php:`Netresearch\NrVault\Event\BreakGlassActivatedEvent` and
    ``BreakGlassDeactivatedEvent``. The audit log proves what happened; a
    listener is what makes someone look.

Post-incident review checklist
------------------------------

Run this after every activation, without exception. An activation nobody
reviews is the admin override with extra steps.

..  code-block:: bash

    # The evidence: both rows live under the pseudo-identifier __break_glass__.
    vendor/bin/typo3 vault:audit --identifier=__break_glass__

*   [ ] An ``break_glass_activated`` row exists, with the actor, the reason,
      the ``ttlMinutes`` and the ``expiresAt`` in its context.
*   [ ] The reason names a real incident or change record.
*   [ ] The actor was authorised to declare an emergency.
*   [ ] A ``break_glass_deactivated`` row exists. If not, the window expired —
      reconstruct the closed interval from the activation row's ``expiresAt``
      and note that nobody closed it.
*   [ ] The window length was proportionate to the work.
*   [ ] **Every vault operation performed inside the window is accounted for.**
      Filter the audit log to the interval between activation and closure and
      confirm each row was part of the incident. This is the actual point of
      the exercise.
*   [ ] Nothing was done that the actor's normal grants would have covered —
      if so, they used break-glass instead of asking for the right grant.
*   [ ] The chain still verifies, and both rows are inside it:

      ..  code-block:: bash

          vendor/bin/typo3 vault:audit-verify

*   [ ] ``adminOverrideDisabledEffective`` reads ``yes`` again:

      ..  code-block:: bash

          vendor/bin/typo3 vault:break-glass --status

*   [ ] Whatever made break-glass necessary has a follow-up action — a grant
      to add, a runbook to write, a permission model to fix.
*   [ ] If the window was opened by an actor you did not expect, treat it as
      :ref:`operations-incident-response-exposure` and escalate.

..  note::

    An administrator with filesystem access can unpin
    ``disableAdminOverride`` in :file:`config/system/additional.php` instead of
    using break-glass at all. That path leaves evidence in the filesystem and
    in configuration management, not in the audit log — so file integrity
    monitoring on :file:`config/system/` is a genuine complement to this
    control, not a nice-to-have.
