:navigation-title: Audit evidence
.. include:: /Includes.rst.txt

.. _security-audit-evidence:

==============
Audit evidence
==============

What the audit log proves, against whom, and what has to be exported for the
proof to survive outside the installation. The design decisions behind it are
in :ref:`adr-006-audit-logging`, :ref:`adr-023-audit-hash-chain-hmac` and
:ref:`adr-024-audit-hash-forensic-fields`.

.. _security-audit-evidence-claims:

What the log proves — and against whom
======================================

..  list-table::
    :header-rows: 1
    :widths: 34 33 33

    *   -   Claim
        -   Holds against
        -   Does not hold against

    *   -   A recorded access happened, by that actor, at that time
        -   Anyone without database write access; and, from epoch 1, anyone
            with database write access but without the master key.
        -   Someone holding the master key. They can recompute the chain.

    *   -   No recorded row was edited
        -   A database writer: recomputing an HMAC needs the derived key.
        -   Nothing further — this is the chain's core property.

    *   -   No row was deleted
        -   A database writer: gaps in the uid sequence are reported as
            ``UID_GAP``.
        -   A writer who also rewrites ``uid`` values *and* holds the key.

    *   -   The chain is the same chain as before
        -   A database writer — **only if** an external anchor exists.
        -   A truncate-and-rebuild with no anchor published. The rebuilt chain
            is perfectly self-consistent.

    *   -   The protection level was never lowered
        -   A database writer relabelling ``hmac_key_epoch``: caught per row,
            at chain level by the epoch floor, and against the anchored epoch.
        -   A chain that is genuinely still at epoch 0 and was never migrated.

**Tamper-evident, not tamper-proof.** Every row of that table is detection.
None of it is prevention.

.. _security-audit-evidence-epochs:

Epochs: what each one binds
===========================

``hmac_key_epoch`` is a per-row algorithm selector. Verification dispatches on
it row by row, so a chain may legitimately span epochs at a migration
boundary. The default for new installations is ``auditHmacEpoch = 3``.

..  list-table::
    :header-rows: 1
    :widths: 10 26 64

    *   -   Epoch
        -   Algorithm
        -   Bound into the hash

    *   -   0
        -   SHA-256, **keyless**
        -   ``uid``, secret identifier, action, actor uid, ``crdate``,
            ``previous_hash``. Verifiable by anyone — and therefore forgeable
            by anyone who can write the table. Legacy only.

    *   -   1
        -   HMAC-SHA256
        -   The same identity fields, now keyed. A database writer without the
            master key can no longer re-sign a row.

    *   -   2
        -   HMAC-SHA256
        -   Adds the forensic payload: ``success``, ``error_message``,
            ``reason``, ``ip_address``, ``user_agent``, ``hash_before``,
            ``hash_after``, ``context``. Before this, a row's *outcome* could
            be flipped without breaking the chain.

    *   -   3
        -   HMAC-SHA256
        -   Adds ``hmac_key_epoch`` itself — closing the downgrade path, since
            flipping the selector now invalidates the hash — plus the
            human-readable attribution fields ``actor_type``,
            ``actor_username``, ``actor_role`` and ``request_id``. Before
            this, blame could be reassigned on any row without breaking the
            chain.

The HMAC key is never stored. It is derived per request as
:php:`hash_hkdf('sha256', $masterKey, 32, 'nr-vault-audit-hmac-v1')`, giving
the chain cryptographic separation from encryption key material.

Epoch 0 chains carry no keyed evidence. Migrate them with
``vault:audit-migrate-hmac`` (see :ref:`command-audit-migrate-hmac`).

.. _security-audit-evidence-verification:

Chain verification
==================

:php:`AuditLogService::verifyHashChain()` walks the chain and checks, per row,
that the stored ``previous_hash`` matches the predecessor's ``entry_hash`` and
that the stored ``entry_hash`` recomputes — both with
:php:`hash_equals()`. It reports missing uids as structured data alongside
the per-row errors.

Two epoch checks sit on top:

*   **Per-row.** A *decrease* between consecutive rows is a downgrade finding.
    An increase is a legitimate migration boundary and is reported as a
    warning, not an error.
*   **Chain level.** The chain's highest observed epoch must reach the
    configured floor (``auditHmacEpoch``). This catches the uniform case — a
    downgrade of *every* row to keyless epoch 0, which no per-row comparison
    would notice. The floor is only applied to a full-chain verification; a
    ranged verification may legitimately exclude the higher-epoch rows.

.. _security-audit-evidence-anchoring:

Anchoring
=========

An anchor records, outside the database, that sequence *N* once carried entry
hash *H* under HMAC epoch *E*:

..  code-block:: json
    :caption: One anchor record, as written to the NDJSON stream

    {"type":"anchor","source":"nr-vault","anchor":{"sequence":4821,"chainTip":"…","timestamp":1753900000,"hmacEpoch":3}}

Verification then checks three things the database alone cannot answer:

#.  **Shrinkage.** The chain is append-only, so its highest uid can never go
    down. ``currentSequence < anchoredSequence`` is a ``TABLE_RESET``.
#.  **Substitution.** The row at the anchored sequence must still exist and
    still hash to the anchored tip — also ``TABLE_RESET``.
#.  **Epoch regression.** That row's epoch must not be below the anchored one
    — ``EPOCH_DOWNGRADE``. The in-chain check only sees relabelling relative
    to other rows; the anchor sees it relative to the level actually in force.

Two properties of the reader are load-bearing. It takes the **highest**
anchored sequence rather than the last line, so an attacker cannot weaken the
baseline by appending a low anchor — they must rewrite or truncate the file.
And a corrupt or truncated line is skipped rather than aborting the scan, so
one bad line does not cost the verification its whole baseline.

..  warning::

    An anchor is only as trustworthy as its storage. An anchor file on a host
    the attacker controls can be truncated. Ship anchors off-host — syslog to
    a collector, or a webhook to a SIEM — for the reset-detection property to
    actually hold.

.. _security-audit-evidence-sinks:

Sinks
=====

Sinks mirror three record kinds — entries, anchors and alerts — outside the
database. Fan-out happens after the transaction commits and after the advisory
audit lock is released, so a slow collector cannot serialise vault operations,
and a delivery failure never fails the audited operation.

..  list-table::
    :header-rows: 1
    :widths: 14 20 66

    *   -   Sink
        -   Setting
        -   Behaviour

    *   -   ``syslog``
        -   ``auditSinkSyslogEnabled``,
            ``auditSinkSyslogIdent``
        -   RFC 5424 structured data at facility ``LOG_LOCAL0`` (fixed —
            the conventional slot for application audit streams). Severity:
            ``LOG_INFO`` for a successful entry, ``LOG_WARNING`` for a failed
            one, ``LOG_NOTICE`` for an anchor, ``LOG_CRIT`` for tamper
            evidence, ``LOG_ERR`` for a delivery failure. The cheapest useful
            sink: any host with a log shipper gets the chain off the database.

    *   -   ``file``
        -   ``auditSinkFileEnabled``,
            ``auditSinkFilePath``,
            ``auditSinkAnchorPath``
        -   Append-only NDJSON, one JSON object per line, written under an
            exclusive ``flock()``. Files are created ``0600`` and directories
            ``0700``; a path under a public root makes the sink report itself
            disabled rather than writing anyway. Entries go to the entry
            path; anchors *and* alerts go to the anchor path, which is also
            what :php:`AnchorFileReader` reads.

    *   -   ``webhook``
        -   ``auditSinkWebhookEnabled``,
            ``auditSinkWebhookUrl``
        -   One JSON POST per record with a ``type`` discriminator
            (``entry`` / ``anchor`` / ``alert``) and a ``source`` marker, so a
            single collector endpoint routes all three. Built on the hardened
            HTTP client, so private and loopback targets need an entry in
            :php:`$GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts']` — see
            :ref:`operations-monitoring-and-alerting`.

Failure handling is uniform: each sink call is wrapped individually, so one
broken destination does not blind the others; failures are logged, counted per
sink, and raised as ``SINK_FAILURE``. A sink whose own enablement probe throws
is treated as disabled rather than being allowed to take the audited operation
down. An enabled-but-unconfigured webhook reports itself disabled, because
claiming to be external evidence while delivering nothing is precisely the
false confidence the hardened check exists to catch.

Custom destinations are a tagged service: implement
:php:`AuditSinkInterface` and tag it ``nr_vault.audit_sink``.

.. _security-audit-evidence-reasons:

Alert reason codes
==================

Per-code definitions are in the command reference:
:ref:`command-audit-verify-reason-codes`. What matters for evidence, rather
than for reading CLI output:

*   **They are external contract.** The strings appear in webhook payloads,
    syslog structured data and the NDJSON stream, and ``vault:audit-verify``
    prints and exits on them. Treat them as stable API, not as labels — a SIEM
    rule switching on ``TABLE_RESET`` must keep working across releases.
*   **Four are tamper evidence, three are not.**
    ``HASH_MISMATCH``, ``UID_GAP``, ``TABLE_RESET`` and ``EPOCH_DOWNGRADE``
    indicate manipulation; ``SINK_FAILURE`` and ``NO_EXTERNAL_SINK`` are
    availability and configuration findings, and ``BREAK_GLASS`` is reserved
    for the emergency-access flow. :php:`AuditIntegrityReason::isTamperEvidence()`
    is the intended switch between "page someone now" and "log it" — see
    :ref:`operations-monitoring-what-to-page`.
*   **One finding is raised per reason code, not per erroring row.** A broken
    chain commonly fails every row after the break, and ten thousand identical
    alerts would bury the signal; the affected row count travels in the finding
    context instead.
*   **A delivery finding still has integrity consequences.** ``SINK_FAILURE``
    is not tamper evidence, but while it holds you have no independent copy of
    the entries written during the outage.

Findings are dispatched as :php:`AuditIntegrityAlertEvent`, so listeners fire
even when nobody reads the CLI output. A throwing listener costs neither the
remaining findings nor the report.

.. _security-audit-evidence-export:

What an auditor should export
=============================

The chain is only evidence if the tip can be tied to something outside the
installation. Export **both**:

#.  **The entry sequence** — the audit rows themselves, over the period under
    review, including ``uid``, ``previous_hash``, ``entry_hash`` and
    ``hmac_key_epoch``. Without the hash columns the export is a log, not
    evidence.
#.  **The anchored tip** — the anchor records covering the same period, taken
    from the external store rather than from the installation, plus the output
    of a verification run.

An export leaves the tamper-evident store behind: the downloaded copy has no
hash chain of its own, no retention policy and no further access control.
That is why ``audit.export`` is a separate permission from ``audit.view``, and
why the export should itself be treated as sensitive material.

:ref:`auditor-evidence-collection` gives the exact commands and the full
artefact list.
