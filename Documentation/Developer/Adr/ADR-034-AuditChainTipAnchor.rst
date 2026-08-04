.. include:: /Includes.rst.txt

.. _adr-034-audit-chain-tip-anchor:

==================================
ADR-034: Audit chain tip anchor
==================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-07-30

Context
=======

``AuditLogService::verifyHashChain()`` walks the rows that are present in
``tx_nrvault_audit_log`` and checks that each one links to its predecessor.
Every one of its checks — UID-gap detection, per-row ``previous_hash`` and
``entry_hash`` verification, the epoch-downgrade checks — is a statement about
rows that still exist.

That leaves one whole class of tampering invisible. A single statement:

.. code-block:: sql

   DELETE FROM tx_nrvault_audit_log WHERE uid > 4711;

removes the tail of the log. The remaining rows still form a perfect chain: no
gap, every link intact, every hash correct. A ``TRUNCATE`` is the same case
taken to its limit — an empty table is a valid chain of length zero. Every
tamper-evidence control in the extension reported VALID for both.

The chain proves that *what is there* was not altered. Nothing in the database
proved *how much should be there*, because any counter kept inside the same
table is deleted along with the rows.

..  note::

    Two anchors exist and they are different mechanisms. This ADR covers the
    **in-database** anchor in ``sys_registry``, driven by ``vault:audit
    --verify`` and ``vault:audit --reset-anchor`` and reported as the
    ``audit.db_anchor`` readiness control. The **external** anchor published
    to the audit sinks is :php:`ChainTipAnchorService`, driven by
    ``vault:audit-anchor`` and ``vault:audit-verify`` and reported as
    ``audit.anchor``. The in-database anchor still works when no sink is
    configured; the external one survives an attacker who owns the whole
    database. Neither replaces the other.

Decision
========

Store one MAC-signed assertion about the chain's tip **outside**
``tx_nrvault_audit_log``:

   Audit row ``uid = A`` still exists **and** its ``entry_hash`` is still ``H``.

Not a count and not a ``max(uid)``
----------------------------------

An aggregate has to be compared against something the verifier observes, and a
concurrent append changes it between the observation and the anchor read. An
earlier attempt stored a row count and reported "truncation detected" on a
perfectly intact chain whenever an append landed mid-verification.

An existence-and-equality claim about **one already-committed row** has no such
failure mode. An append only adds a row with a higher uid; it never deletes row
``A`` and never rewrites row ``A``'s ``entry_hash``. No interleaving — before,
during or after the walk — can change the answer. Correctness does not depend on
timing at all.

The hash is load-bearing
------------------------

Anchoring the uid alone is not enough. After ``DELETE ... WHERE uid > N`` the
auto-increment counter is reused on two of the three supported platforms:

-  SQLite: ``rowid`` without ``AUTOINCREMENT`` is ``max(rowid) + 1``, effective
   immediately.
-  MariaDB/MySQL (InnoDB): ``AUTO_INCREMENT`` is re-derived as ``max(uid) + 1``
   on server start.

Ordinary appends then refill uids ``N+1 … A``, so the anchored uid exists again
and the surviving chain re-links correctly from row ``N``'s genuine hash. Only
the hash comparison catches it: the refilled row ``A`` carries a different
``entry_hash`` than the anchored ``H``.

``sys_registry`` — without the Registry API
-------------------------------------------

The anchor lives in the core table ``sys_registry``
(``entry_namespace = 'tx_nrvault_audit_anchor'``,
``entry_key = 'auditChainTip'``), reached exclusively through our own
Doctrine QueryBuilder in ``Classes/Audit/AuditChainAnchorStore.php``.

It gets its **own** namespace, never ``tx_nrvault``. The anchor value is
deliberately raw rather than PHP-serialized, while core's ``Registry::get()``
unserializes every row of a namespace it loads. Other extension state — the
break-glass session, the per-sink delivery state — lives in ``tx_nrvault``
via the core Registry API, so sharing a namespace with the raw anchor would
make every one of those reads throw a ``DeserializerException``.

Two alternatives were considered and rejected, both of which created a new table
``tx_nrvault_audit_anchor`` in ``ext_tables.sql``:

-  **Fail closed while the table is missing.** Between "extension files updated"
   and "``database:updateschema`` run", the anchor write throws from ``log()``.
   ``VaultService::retrieve()`` logs without a try/catch and read logging is on
   by default, so every vault read — including an unauthenticated frontend
   render through ``TypoScriptVaultListener`` — returns a 500 for the whole
   upgrade window. That is a site-down availability regression traded for a
   tamper-evidence gap.
-  **Fail open while the table is missing.** That makes the control
   attacker-selectable: ``DROP TABLE tx_nrvault_audit_anchor`` returns the
   installation to the old silent-truncation behaviour on every subsequent
   append, not just on the verify.

``sys_registry`` removes the dilemma instead of resolving it. It ships in core's
own ``ext_tables.sql``, so it exists in every installation before nr_vault is
installed: **no schema change, therefore no upgrade window, therefore no
fail-closed/fail-open trade at all.** ``ext_tables.sql`` is deliberately
untouched by this change.

``TYPO3\CMS\Core\Registry`` itself is off limits. Its ``get()`` routes through
``loadEntriesByNamespace()``, which ``unserialize()``s every row of a namespace
with no ``allowed_classes`` — an object-injection sink fed by bytes a
database-write attacker controls. Our read path is one ``SELECT``, one anchored
``preg_match()`` and one ``hash_equals()``; a regex cannot emit a PHP object.
``ArchitectureTest::testAuditAnchorNeverUsesCoreRegistry()`` (PHPat, same shape
as :ref:`adr-028-phpat-http-client-lock`) turns any reintroduction into a build
failure.

Value format and MAC
--------------------

``entry_value`` is plain ASCII, bound as ``Connection::PARAM_LOB`` on write (as
core's own ``Registry::set()`` does, which is what makes the ``mediumblob`` /
``bytea`` column work on PostgreSQL):

.. code-block:: text

   nrvault-audit-tip.v1|<uid>|<entry_hash>|<tstamp>|<mac>

Parsed with one anchored pattern and nothing else accepted. The MAC is
HMAC-SHA256 over a canonical JSON payload, under a key derived from the master
key with a **distinct** HKDF info string ``nr-vault-audit-anchor-v1`` — separate
from the chain key's ``nr-vault-audit-hmac-v1``, so an anchor MAC and a row hash
are not interchangeable. The key is zeroed with ``sodium_memzero()`` in a
``finally``.

Anchor exists ⇒ same connection
-------------------------------

Every mutator is *given* the caller's ``Connection`` and refuses to write unless
``getConnectionForTable('sys_registry')`` is identical to it — the same
precondition style ``VaultRotateMasterKeyCommand`` already uses when
``tx_nrvault_secret`` and ``tx_nrvault_audit_log`` are split. Same connection
means the upsert runs inside the caller's already-open transaction and commits
or rolls back with the audit row; the store therefore never resolves its own
connection for a write, and can never end up ahead of a rolled-back audit write.
A split connection is reported as a warning and nothing is written.

Monotone advance
----------------

``advance()`` moves the anchor only forward in uid, and only while the anchor's
own assertion still holds. A violated or unparseable anchor is left in place —
it must not be repaired or overtaken by ordinary traffic, or an attacker could
truncate the log, wait for it to regrow past the anchored uid, and get a clean
verdict back. Rewriting an existing row's hash is ``reseal()``'s job.

Re-sealing is constrained too
-----------------------------

``reseal()`` cannot use the guard above, because rewriting the anchored row's
hash is exactly what it does. It therefore asserts the part a re-seal does *not*
change: the anchored row must still **exist**, and the new tip's uid must not be
below the stored one. All three legitimate re-seal paths (master-key rotation,
the HMAC upgrade wizard, ``vault:audit-migrate-hmac``) rewrite
``entry_hash``/``previous_hash`` ``WHERE uid = …`` and preserve every uid, so
neither condition can false-alarm on them — and both fail on a truncated chain.

Both assertions need an *authenticated* stored anchor to check against, and
master-key rotation is the one path that cannot authenticate it under the key
it signs with: it passes the NEW key, while the stored anchor still carries
the current key's MAC. Parsing under the new key therefore always fails, which
originally skipped the guard on exactly that path (#283). ``reseal()`` falls
back to the provider's current key to authenticate the stored anchor before
re-signing, so the rotation path takes the same guard as the two migration
paths.

Without it, the re-seal paths launder a truncation. The gate in front of them,
``verifyChainForReseal()``, lets a chain through when no row carries
``hmac_key_epoch >= 1``, on the grounds that a keyless epoch-0 chain has no
tamper evidence in its rows. That premise is attacker-selectable:
``UPDATE tx_nrvault_audit_log SET hmac_key_epoch = 0`` is one statement and
needs no master key, and it *also* makes the upgrade wizard advertise itself as
pending in the Install Tool, so a routine administrator click finishes the job.
The anchor's validity does not depend on any row's epoch, so the gate still runs
the **anchor** check on that path; the row walk is what it skips.

Arming is not the same operation as advancing
---------------------------------------------

The guards above all concern an anchor that *is there*. An anchor that is
**gone** takes none of them, and creating one from nothing is the strongest
thing this code can do: it signs a claim that the current tip is genuine. An
attacker with database write access and no master key gets that for free unless
arming is constrained — delete the ``sys_registry`` row (or blank its
``entry_value``), truncate the log, let one ordinary audited read append a row,
and the next ``advance()`` mints a fresh, correctly signed anchor on the
shortened chain. The installation then reports ``Ok`` permanently: silent, as
before this ADR, *plus* a MAC-attested statement that the truncated tip is
authentic. That is worse than not having the control.

Two rules constrain it:

-  **A present row with no usable value is not an absent anchor.** ``readRaw()``
   reads the ROW (``fetchAssociative()``), not the value, so
   ``UPDATE sys_registry SET entry_value = NULL`` yields "row present,
   unreadable" — the corrupted-anchor branch, which writes nothing and reports
   ``Unreadable`` (an error). Reading it as "no anchor" would also make the
   upsert attempt an INSERT against the ``entry_identifier`` unique key and
   break every subsequent audit write.
-  **With** ``auditAnchorRequired`` **on, an absent anchor is refused
   unconditionally.** The flag is the operator's assertion that this
   installation is already anchored, and it is the only available
   disambiguation between "never anchored" and "anchor deleted", which database
   state alone cannot provide. It lives in a settings file, out of a
   database-write attacker's reach. ``advance()`` and ``reseal()`` both consult
   it; neither creates an anchor that is not there once it is set.

   The refusal deliberately does **not** probe the audit table first. An earlier
   revision refused only when a row still sat below the tip being anchored, so
   that a genuinely fresh installation could still bootstrap under the flag.
   That probe cannot work: at the moment ``advance()`` runs, the audit insert
   has just written the one row the chain has, so a log emptied with
   ``DELETE FROM tx_nrvault_audit_log`` — no ``WHERE`` — is indistinguishable
   from a fresh installation. The uid gap does not substitute for it either,
   because the walk starts at ``previousUid = -1`` and a chain that now begins
   at uid 7 has no leading gap. Any emptiness probe therefore rewards the
   attacker for deleting *more* rows, which is cheaper than deleting some. The
   state the probe must observe is exactly the state the attacker deletes, so
   there is nothing to observe.

Nothing legitimate needs implicit arming while the flag is set: the flag means
"this installation is already anchored", and its documented enable point is
"after the first audit write following the upgrade". Bootstrap therefore stays
possible in exactly two shapes, so the flag can never wedge an installation:
with the flag off (the shipped default, and the documented upgrade path — let
the next audit write arm the anchor, then enable the flag); and explicitly
through ``AuditChainAnchorStoreInterface::arm()``, reachable only from
``vault:audit --reset-anchor``, which records the fact in the chain itself.

Double-read stability
---------------------

The three legitimate re-seal paths (master-key rotation, the HMAC upgrade
wizard, ``vault:audit-migrate-hmac``) rewrite row hashes **and** re-record the
anchor in one transaction. The verifier therefore reads
``anchor V1 → row → anchor V2``:

-  ``V1 !== V2`` (byte comparison of the raw stored value) means a re-seal
   committed mid-check ⇒ retry once, then report ``InFlight`` as a **warning**,
   never an error.
-  ``V1 === V2`` means no re-seal commit landed in that window, so a hash
   mismatch is genuine.

This needs no transaction, no lock and no isolation level, so it behaves
identically on SQLite, MariaDB/MySQL and PostgreSQL. A "consistent snapshot"
read transaction would not have worked: PostgreSQL's default READ COMMITTED
gives each statement a new snapshot.

Retention purges must be head-first
-----------------------------------

There is no ``DELETE`` against ``tx_nrvault_audit_log`` anywhere in ``Classes/``
today. If a retention purge is ever added it **must** delete oldest-first, which
never touches the tip. A purge that removed the newest rows would be
indistinguishable from the attack this control exists to detect.

Escape hatch
------------

After a legitimate full wipe the anchor can never advance again, so
``vault:audit --reset-anchor`` clears it — and writes an audit entry
(``AuditAction::AuditAnchorReset``) recording the reset in the same transaction,
so the reset cannot be performed invisibly. It then arms the anchor on that very
entry through ``arm()``, rather than relying on the audit write to do it: with
``auditAnchorRequired`` on, ``advance()`` deliberately refuses to, so the escape
hatch would otherwise stop working on exactly the installations that hardened
themselves.

Consequences
============

Positive
--------

-  Tail truncation, deletion of the last row, and a full wipe of the audit log
   are now detected — against an attacker with database write access but
   without the master key.
-  No schema change, so no upgrade window and no new failure mode during
   deployment.
-  The verification check is read-only.

Cost
----

Not free, and measurably more than "one lookup". Per audit write, inside the
lock and transaction that ``log()`` already opens, ``advance()`` runs up to
three statements against indexed columns:

#. the ``sys_registry`` row read (unique key ``entry_identifier``);
#. the anchored row's ``entry_hash`` by primary key, when an anchor is present;
#. the INSERT or UPDATE of the anchor row, skipped whenever a guard declines.

An absent anchor costs the registry read alone: with ``auditAnchorRequired``
on, ``advance()`` returns immediately rather than probing the chain, because
it refuses to arm implicitly either way.

A full-chain verification adds the ``sys_registry`` read, one primary-key
lookup, and — only when the tip hash mismatches — a second ``sys_registry`` read
for the double-read stability rule.

Negative / accepted limits
--------------------------

These are the stated limit of the control, not oversights.

R1 — with the flag off, anchor deletion degrades to the old behaviour
   An attacker with database write access can delete the ``sys_registry`` row
   and then truncate. With ``auditAnchorRequired`` off — the shipped default —
   the result is ``Unanchored`` plus a warning until the next audit write, which
   arms a fresh anchor on the truncated chain and returns the installation to
   ``Ok``. That is the pre-anchor behaviour, and it is the price of a default
   that must not make every not-yet-anchored installation report an invalid
   chain: "never anchored" and "anchor deleted" are indistinguishable from
   database state alone.

   ``auditAnchorRequired = 1`` is what closes it, and it closes it in both
   places: verification reports the missing anchor as an error, **and**
   ``advance()``/``reseal()`` refuse to create an absent anchor at all — on a
   populated chain, on a truncated one, and on an emptied one alike — so the
   state cannot be laundered back to ``Ok`` by ordinary traffic. Only
   ``vault:audit --reset-anchor`` — an operator action written into the chain —
   arms it again, and that includes the first arming of an installation that
   enables the flag before its anchor exists. Enable the flag after the first
   audit write following the upgrade. A pure warning-level flag would have been
   useless here: it would have gone quiet again seconds later, as soon as one
   audited read landed.

R2 — anchor replay
   A captured older anchor value can be restored and its MAC still verifies.
   This narrows the undetectable window down to the captured tip but does not
   close it. Defeating replay requires state outside the database and is
   deliberately out of scope.

R3 — consistent whole-database rollback
   Anchor and chain move together, so restoring a consistent snapshot of the
   whole database reports ``Ok``. Detecting that needs off-box evidence (log
   shipping, WORM export) — deployment guidance, not a code fix.

R4 — anchor corruption is a denial of service on rotation
   Corrupting the ``sys_registry`` row yields a permanent ``Unreadable`` error,
   which blocks master-key rotation and both re-seal paths until an operator
   runs ``vault:audit --reset-anchor``. This is no new capability: the same
   attacker can already produce a false alarm by editing any audit row.

R5 — a dormant installation stays unanchored
   The anchor arms on the next append (any read at the default
   ``auditReads = 1``, any write) or when the HMAC wizard / migrate command
   runs. Until then the installation keeps the old behaviour, with the warning
   visible.

R6 — audit HMAC epoch 0 gets nothing
   By design. At epoch 0 the chain is keyless and carries no tamper evidence to
   protect; arming the anchor there would add a brand-new master-key dependency
   to the audit write path. The verifier reports ``Disabled``.

R7 — deployments that wipe ``sys_registry``
   Some dump/restore pipelines treat ``sys_registry`` as disposable. Those land
   in ``Unanchored`` and re-arm on the next append — same shape as R5.

What an attacker with database write access and **no** master key still cannot
do: forge or advance the anchor, or make a truncation or a wipe report ``Ok``
while leaving the anchor in place. The one-statement invisible truncation
becomes a two-target attack whose second target cannot be forged, only
destroyed — and destroying it changes the reported verdict.

References
==========

-  :ref:`adr-023-audit-hash-chain-hmac` — the HMAC-keyed chain this anchors
-  :ref:`adr-024-audit-hash-forensic-fields` — the forensic payload
-  :ref:`adr-028-phpat-http-client-lock` — the architectural-lock precedent
-  ``Classes/Audit/AuditChainAnchorStore.php``
-  ``Tests/Functional/Audit/AuditChainAnchorTest.php``
