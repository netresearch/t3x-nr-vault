.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-055-audit-finding-acknowledgement:

===============================================
ADR-055: Acknowledging audit integrity findings
===============================================

Status
======

Accepted. Builds on :ref:`adr-023-audit-hash-chain-hmac` and
:ref:`adr-034-audit-chain-tip-anchor`.

Date
====

2026-11-14

Context
=======

The backend "Verify chain" view ran only ``verifyHashChain()`` and printed bare
error strings. ``vault:audit-verify`` runs the full verification (chain, external
anchor, reason codes), so an administrator who saw a finding in the backend could
neither see the full picture nor close the finding without the command line. The
only repair path on the command line is ``vault:audit --reset-anchor``, which
clears the in-database anchor and records that in the chain, and
``vault:audit-migrate-hmac``, which re-seals the chain and refuses to run on a
chain that fails verification.

A finding about history that cannot be re-written has no repair. Rows that
failed their hash stay failed, a deleted row stays deleted, and a restored
database stays shorter than the external anchor says. Without a way to record
"this was investigated and accepted", the readiness check stays red forever,
and the only way back to green is to re-seal, which turns tampering into a
valid-looking chain.

Decision
========

The backend runs the same verification as the command line
(``ChainTipAnchorServiceInterface::verify()``) and shows the reason code of every
finding, the verified range, the epoch distribution, the chain tip and the
comparison with the external anchor. It checks ``audit.view``, the permission
``vault:audit-verify`` asserts as well.

An administrator can acknowledge the open findings. The acknowledgement is an
append-only audit row, never a repair:

*   One chained row with the action ``audit_findings_acknowledged``. Its
    ``reason`` is the mandatory free-text reason; its context holds the keys of
    the acknowledged findings, the old chain tip, the optional ticket reference,
    the reason codes, the affected uid ranges and, under switch-user, the
    original backend user. The acting administrator is the row's own actor.
*   The flagged rows are not touched. They keep failing their own hash, and
    ``verifyHashChain()``, ``verifyChainForReseal()`` and with them every
    re-seal path (HMAC migration, master-key rotation, rotation-gap repair)
    keep refusing the chain.
*   The acknowledgement is an overlay one level above the raw chain pass
    (``AuditFindingOverlay``). ``ChainTipAnchorService`` (and with it
    ``vault:audit-verify``, the scheduler task and the backend view) and the
    bounded ``audit.hash_chain`` check read through it, so they agree.
    ``vault:audit --verify`` reports the raw result and stays unaffected.
*   When the in-database tip anchor is part of the finding, it is reset and
    re-armed in the same transaction, the sequence ``--reset-anchor`` uses. The
    external anchor is published afresh after the commit, which starts the new
    verified segment: the acknowledgement row is the new tip.

What an acknowledgement covers
------------------------------

Findings fall in three classes:

*   **Row and gap findings.** The item key is a hash over the reason code, the
    position and the complete stored content of the affected row (the digest of
    the whole row as stored, byte for byte). The verifier treats the item as
    acknowledged only when all of this holds:

    #.  The acknowledgement row lists the item's key. Editing the flagged row
        again, in any column, produces another key and reopens the finding. A
        finding that appears later has another key and fails.
    #.  The acknowledgement row is itself not reported as failing, so a
        tampered or forged acknowledgement proves nothing.
    #.  The row was written at HMAC epoch 3 or higher, where the MAC covers
        ``reason``, ``context`` and the actor columns. At epoch 2 or below a
        database-write attacker could forge or edit an acknowledgement without
        the key, so the backend refuses to write one.
    #.  The row was chained directly after the tip it recorded
        (``previous_hash`` equals the recorded tip hash). A row from a
        concurrent writer landing in between makes the acknowledgement inert,
        which cannot cover rows written later. The flow reads the verdict back
        after writing and reports "not in effect, run it again".
    #.  The row follows the flagged row in the chain.

*   **Chain-level findings without a row**: the chain-wide epoch-floor error and
    the comparison with the external anchor (``TABLE_RESET``, and the
    anchored-epoch ``EPOCH_DOWNGRADE``). The key of an external-anchor finding
    is the compared anchor, not how the chain differs from it: after a restore
    the same anchor reads first as a shrunken and later as a substituted chain.
    What stops a later incident from inheriting the acknowledgement is a binding
    to the chain prefix the administrator saw. The acknowledgement records the
    tip uid and hash it was chained after; the finding is covered only while the
    row at that uid still carries that hash. Rewriting or truncating the chain
    up to that tip uncovers it again. A finding against the external anchor is
    additionally covered only while the anchors published since stay
    consistent with the chain. The acknowledgement records how many anchor
    records the file held; of the records after that position, each one that
    reaches the acknowledgement row (sequence at or above its uid) must carry the
    stored entry hash of the row at its sequence, and at least one must exist.
    A later truncation below such an anchor, an appended record with a wrong tip
    and a replayed old anchor file all reopen the finding; the timestamp of a
    record decides nothing, because whoever can append to the file could set it
    to anything. The flow publishes the fresh anchor; without an external sink
    the request is refused before anything is written. The reader keeps the
    anchor with the highest sequence, which after a restore stays the old one, so
    the later anchors are read from the file directly.
*   **The in-database anchor errors** are never covered. They carry no
    per-incident state, so an acknowledgement would also hide a later incident
    of the same kind. The flow resets and re-arms the in-database anchor in the
    same transaction, the finding stops being reported, and a recurrence is new.

The administrator is shown the findings and confirms a fingerprint over their
keys. If the set of open findings differs when the request arrives, the request
is refused as stale. Ordinary appends do not change the set, so a live chain
does not make the flow unusable.

Flow and access
---------------

*   Administrator only, through the same bypass seam as the other vault
    operations (``isCurrentActorAdmin()``, so a hardened profile with
    ``disableAdminOverride`` needs an open break-glass window), plus
    ``audit.view``. No new group-grantable permission.
*   ``POST`` only; the route token that every backend module route carries is the
    CSRF protection. A GET is answered with 405. The administrator ticks an
    explicit confirmation and states a reason (at most 1000 characters; the
    ticket reference at most 100).
*   Idempotent: after the first success the findings are acknowledged, so a
    repeated request is refused as "nothing to acknowledge".
*   At most 200 findings per acknowledgement. Beyond that the chain has been
    damaged wholesale, and the evidence export and an investigation come first.
*   Before acting, the administrator can download the evidence (JSON or CSV):
    the affected rows with five neighbours on each side, the anchor and the
    verification report. The export needs ``audit.export``, like every export.
*   Only tamper evidence can be acknowledged (``HASH_MISMATCH``, ``UID_GAP``,
    ``TABLE_RESET``, ``EPOCH_DOWNGRADE``). ``NO_EXTERNAL_SINK`` and
    ``SINK_FAILURE`` are configuration and delivery findings; they get fixed.

Consequences
============

*   The readiness check can return to green without the command line and
    without re-sealing, while the history keeps the incident, who accepted it
    and why.
*   The raw chain pass and the re-seal guards are unchanged by design. A chain
    that was acknowledged and later needs an HMAC migration is refused until
    the findings are resolved outside the vault.
*   An acknowledgement is not a verification of the acknowledged rows. It states
    that an administrator accepted them for a reason. The auditor reads that
    reason; ``vault:audit-verify --format=json`` lists the acknowledged items
    next to the open ones.
*   ``vault:audit-verify`` dispatches an alert event per open finding on every
    run. The backend view, the acknowledgement flow and the evidence export use
    ``inspect()``, which does not dispatch, so a page load by any ``audit.view``
    user does not alert the sinks and one action does not alert three times.
