.. include:: /Includes.rst.txt

.. _adr-036-mutation-audit-atomicity:

==============================================
ADR-036: Mutation and audit are all-or-nothing
==============================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-08-02

Context
=======

:ref:`adr-006-audit-logging` requires that every vault operation is logged, and :ref:`adr-023-audit-hash-chain-hmac` makes the resulting entries tamper-evident.
Neither says what happens when the audit write itself fails.

The default answer anywhere else in a PHP application is to log the error and carry on: the user's change succeeded, the log line is a side effect.
Applied here, that answer is wrong in a way the rest of the audit design cannot repair.

The hash chain proves that *what is there* was not altered.
:ref:`adr-034-audit-chain-tip-anchor` extends that to rows that were deleted.
Neither control can see an entry that was **never written**: the surviving rows link perfectly, the anchor advances on the next entry, and verification reports ``VALID``.
A mutation whose audit write failed is not "logged with a warning somewhere" — it is invisible to every tamper-evidence control the extension has, and it is indistinguishable from a mutation that never happened.
The one document an auditor is asked to trust would then be complete only when nothing went wrong, which is the opposite of what an audit trail is for.

The obvious implementation is unavailable.
A single database transaction around the mutation and ``AuditLogServiceInterface::log()`` cannot be opened, because ``log()`` owns its own transaction lifecycle and cross-process serialisation — SQLite ``BEGIN EXCLUSIVE``, MySQL/MariaDB ``GET_LOCK("nr_vault_audit", 5)``, see ``Classes/Audit/AuditChainLockTrait.php``.
Nesting it inside an outer transaction would either error or commit the mutation prematurely, which is the failure this ADR exists to prevent.

Decision
========

A mutation and its audit entry are **all-or-nothing**.
A change that cannot be audited must not persist.

The rule governs mutations — create, update, rotate, delete, metadata change, and the ACL tiers written alongside them.
Reads are logged too, configurably (:ref:`adr-019-configurable-audit-read-logging`), and a read has no mutation to undo; see :ref:`adr-036-guarantee-limits`.

Two mechanisms implement the rule, and they are **ordered**: refuse before writing wherever the decision can be made before the write, and compensate afterwards only where it cannot.

Refusing beats compensating
---------------------------

A refusal leaves nothing behind — no row to remove, no relations to purge, no audit entry to retract, and no possibility that the compensation itself fails.
Every gate that *can* run before the write therefore does.

On the FormEngine path the authorization gates live in ``SecretTcaHook::processDatamap_preProcessFieldArray()``, before DataHandler has written anything:

-  the per-secret write ACL for an existing record (``isUpdateAuthorized()``, the same ``canWrite()`` the programmatic path asserts, :ref:`adr-005-access-control`);
-  both create gates for a new one — ``canCreate()`` plus the ``secret.create`` operation permission (``isCreationGranted()``).

Both abort the record by invalidating the by-reference field array, ``$fieldArray = null``, which is core's contract for a ``preProcessFieldArray`` hook — present verbatim in v12.4, v13.4 and v14.3 alike.
Immediately after each hook call DataHandler re-checks the argument it just passed,

.. code-block:: php

   if (!is_array($incomingFieldArray)) { continue 2; }

and skips the record before ``newFieldArray()``, ``insertDB()`` and the deferred MM queuing.
``[]`` is not a substitute — the guard is ``is_array()``, and ``newFieldArray()`` would refill the TCA defaults and insert the row anyway.

The unauthorized privileged-column change is handled with the same preference: ``enforcePrivilegedColumnPolicy()`` **drops** the column from the field array rather than writing the stored value back afterwards, so there is no second write and nothing to undo.

Compensation therefore exists only where the decision genuinely cannot be made before the write — where the outcome depends on the audit write itself, or on a uid that does not exist until the insert has happened.

Compensation where refusal is impossible
----------------------------------------

On the programmatic path the mutation is applied, then audited, and a failed audit write is compensated by reverting the mutation: ``VaultService::compensateAuditFailure()``.
It is used by ``store()`` (restore the prior envelope on update, delete the just-inserted record on create), ``delete()`` (re-insert the record), ``rotate()`` (restore the pre-rotation envelope and version) and ``setEnabled()`` (restore the previous availability).

``setEnabled()`` is worth naming separately, because it is the mutation whose loss is hardest to notice.
Disabling a secret withdraws it from every read path at once — the record carries TCA's ``disabled`` enable column, so the ``HiddenRestriction`` in every restriction-honouring query removes it — and it leaves the value, the identifier and every other column untouched.
An unaudited disable is therefore a silent revocation of access that looks exactly like a secret nobody has used lately.
It carries the same two gates as the other mutations (the per-secret ``canWrite()`` tier plus ``secret.manage_policy``), and it sets an ABSOLUTE state rather than toggling: two concurrent toggles cancel out and leave two entries claiming opposite outcomes, whereas two concurrent ``setEnabled($id, false)`` calls converge on the state their caller asked for.
Setting the state a secret already has writes nothing and audits nothing — there is no mutation — while a refusal is audited either way.

Three properties make it a control rather than a gesture:

-  **One failure type.**
   ``AuditLogService::log()`` either persisted the entry or throws ``AuditWriteException`` — a genuine write failure, a lock timeout and a failed anchor write are all wrapped in that single type, so no failure mode can slip past the ``catch`` the compensation keys on.
   An unknown audit action is deliberately *not* wrapped: that is a programming error, not a write failure, and it must surface.
-  **The revert is itself guarded.**
   If reverting also fails — typically the same database fault that broke the audit write — the invariant is already violated, and that fact is logged at ``CRITICAL`` with the identifier (never the value) for manual reconciliation.
   The revert failure is chained as ``previous``; the thrown type stays ``AuditWriteException`` so the caller sees the real cause.
-  **The caller always fails.**
   ``compensateAuditFailure()`` returns ``never``.
   A compensated mutation is an error, not a degraded success.

An MM-backed ACL can only be restored from a pre-captured snapshot
------------------------------------------------------------------

This is the non-obvious part, and it is the reason the FormEngine path needs state captured in an *earlier* hook rather than a rollback written in the same one.

``allowed_groups`` and ``write_groups`` are MM relations.
Two facts collide:

#. DataHandler writes the new MM rows during ``checkValue()`` — i.e. **before** ``processDatamap_afterDatabaseOperations()``, where the audit write happens and its failure is observed.
   By the time the failure is known, the widened ACL set is already committed.
#. The row column holds only the relation **count**, not the group list.
   The effective ACL is read from the MM tables (``SecretRepository::loadGroupsForSecret()``), so writing the old count back restores nothing.
   It is in fact worse than doing nothing: the row would claim the old number of groups while the MM tables still granted the widened set.

Nothing observable at rollback time can reconstruct the previous group list.
The only thing that can is a snapshot taken before DataHandler overwrote it, so ``processDatamap_preProcessFieldArray()`` captures the MM rows — ``uid_foreign``, ``sorting`` and ``sorting_foreign``, because ordering is part of the record — for every privileged ACL column the datamap submits (``snapshotMmRelations()``).
``restoreMmRelations()`` writes it back.

Four details follow from the snapshot being the only source of truth:

-  **An empty captured list is meaningful.**
   It records "this tier had no groups", which the rollback honours by deleting the rows the failed change added.
-  **An unreadable tier is skipped, not snapshotted empty.**
   Recording an empty snapshot for a tier whose read failed would make the rollback delete the record's real relations.
-  **The restore is transactional per tier.**
   An insert failing after the delete would leave the tier empty — locking out the legitimate groups, which is worse than the unaudited widening the rollback set out to undo.
-  **A partial result is reported as not reverted.**
   The change counts as reverted only when the row values *and* every snapshotted tier came back; a changed ACL column missing from the snapshot forces the same verdict.
   The DataHandler log then says "NOT revertible; manual reconciliation required" rather than hiding the inconsistency.

The snapshot is also assigned unconditionally, empty result included, so a save that submits no ACL column clears any snapshot a previous save left on a DI-shared hook instance instead of "restoring" a state two edits old.

A reverted creation must purge relations that do not exist yet
--------------------------------------------------------------

The create path is not the update path with a different verb — its MM writes are ordered the other way round.

For a ``NEW`` record the uid is unknown during ``checkValue()``, so DataHandler **defers** the MM writes to ``$dbAnalysisStore`` and flushes them in ``dbAnalysisStoreExec()``, *after* every ``processDatamap_afterDatabaseOperations()`` hook has run.
A creation reverted in that hook — because its audit write failed, or because the submitted secret value was refused — therefore deletes the row **before** its relation rows are written.
Those writes still land, pointing at a uid that no longer exists.

The reverted uid is queued in ``$revertedCreations`` and the relations are purged in ``processDatamap_afterAllOperations()``, which core calls after the deferred flush.
Deleting by ``uid_local`` is idempotent and order-independent, and it keeps the fix on a documented extension point rather than filtering DataHandler's public-but-internal ``$dbAnalysisStore``.
Only a genuinely removed row is queued: if the revert failed, the record still exists and its relations rightfully belong to it.

A refusal whose audit write fails is still a refusal
----------------------------------------------------

Where the audit entry records a **denial**, the exception is deliberately swallowed (``SecretTcaHook::auditDenial()``, ``refuseCreation()``).
There is no mutation to undo — the change was already refused — and letting the audit failure propagate would abort the refusal, turning a failed log write into a grant.
The failure is surfaced in the DataHandler log instead.

This is the same invariant read from the other side: the audit write may never be the reason a change *becomes* permitted.

One mutation, one entry
-----------------------

The corollary is that exactly one component audits a given mutation, so the compensation has one place to live.

Value mutations submitted through FormEngine are audited by ``VaultService`` (``store()``/``rotate()``), with its own compensation; the hook adds nothing for them.
The hook is responsible only for what the service never sees — the creation of a value-less record and metadata-only column changes.
A FormEngine delete is routed *through* ``VaultService::delete()`` in ``processCmdmap_preProcess()`` and core's own ``deleteAction`` is suppressed in ``processCmdmap()``, so the per-secret tier, the ``secret.delete`` permission, the audit entry and its compensation all apply exactly as on the programmatic path — in both outcomes: on success the service has already soft-deleted the record, on refusal it must survive untouched.

A refused creation writes no ``create`` entry at all.
A success entry for a creation that never happened would put a verifiable-looking falsehood into the tamper-evident chain, directly next to the truthful denial.

.. _adr-036-guarantee-limits:

Where the guarantee stops
=========================

These are stated limits, not oversights.
An auditor should read them as the boundary of the claim.

L1 — multi-field record copy and delete are preflight plus best-effort
   A record spanning several vault fields is **not** covered by this ADR's all-or-nothing rule.
   A delete asserts every field's delete gate before removing the first secret and a copy that cannot clone every secret deletes the ones it made and blanks every vault field, but a failure the preflight cannot predict leaves the already-deleted secrets unrestorable.
   The residuals are enumerated in :ref:`tca-record-operations` and declared in :ref:`auditor-control-mapping-access`; they are not restated here.

L2 — compensation is not a transaction
   The revert is a second write and can fail on its own.
   When it does, the mutation has persisted without an audit record.
   That state is not silent — ``CRITICAL`` in the application log on the programmatic path, a "manual reconciliation required" entry in the DataHandler log on the FormEngine path — but it is real, and only an operator can resolve it.

L3 — a compensated mutation is invisible in the audit trail
   By construction: the audit write is what failed.
   The evidence that anything was attempted lives in the application log, not in the chain.
   The chain's guarantee is that it contains no *committed* unaudited mutation, not that it contains every attempt.

L4 — reads are not compensated, and cannot be
   A read has nothing to undo.
   It fails closed instead: the audit write in ``VaultService::doRetrieve()`` is not wrapped, so a failure propagates and no plaintext is returned.
   The only residue is the already-incremented read counter.
   With ``auditReads`` disabled (:ref:`adr-019-configurable-audit-read-logging`) no read entry is written in the first place — a configured deviation, not a failure.

L5 — the rule binds our own write paths only
   A direct ``UPDATE`` against ``tx_nrvault_secret`` or its MM tables bypasses every mechanism described here.
   That attacker is in scope for :ref:`adr-034-audit-chain-tip-anchor`, not for this ADR.

Consequences
============

Positive
--------

-  A committed mutation always has its audit entry, so the absence of an entry is meaningful evidence rather than an unknown.
-  The tamper-evidence controls (:ref:`adr-023-audit-hash-chain-hmac`, :ref:`adr-034-audit-chain-tip-anchor`) rest on a complete log; without this rule, a ``VALID`` verdict would only ever have meant "nothing was tampered with *among the entries that happened to be written*".
-  The ACL tiers are covered on both write paths, so an unaudited *widening* of who may read a secret cannot survive a failed audit write.
-  Refusing before writing removes whole failure classes rather than compensating them: an unauthorized create leaves no squatted identifier, no orphaned MM rows and no retracted audit entry.

Cost
----

-  One extra read per FormEngine update: the pre-change column values, plus one ``SELECT`` per submitted privileged ACL column for the MM snapshot.
   Both are indexed lookups on a single uid, and only for ``tx_nrvault_secret`` datamaps.
-  Compensation doubles the write of an already-failing operation.
-  The correctness of the FormEngine path depends on DataHandler's ordering — MM writes during ``checkValue()`` on update, deferred to ``dbAnalysisStoreExec()`` on create.
   That ordering is exercised by the functional test listed below rather than assumed; a core change to it would fail there.

Negative
--------

-  An audit-store outage stops vault writes rather than degrading them.
   That is the intended trade: availability is given up for the integrity of the evidence.
   Deployments that cannot accept it must give the audit store the same availability as the vault itself.
-  Two rollback implementations exist — ``VaultService`` for the programmatic path, ``SecretTcaHook`` for the FormEngine path — because their unit of mutation differs (an entity versus a datamap plus its MM relations).
   They must be kept in agreement by review; no shared abstraction fits both.

References
==========

-  :ref:`adr-004-tca-integration` — the TCA field type the FormEngine path serves
-  :ref:`adr-005-access-control` — the tiers a compensated rollback restores
-  :ref:`adr-006-audit-logging` — the audit entry this ADR makes mandatory
-  :ref:`adr-018-flexform-secret-lifecycle` — the FlexForm counterpart
-  :ref:`adr-034-audit-chain-tip-anchor` — what the chain proves once complete
-  :ref:`tca-record-operations` — record copy/delete semantics and their residuals
-  ``Classes/Service/VaultService.php`` — ``compensateAuditFailure()``, ``setEnabled()``
-  ``Classes/Hook/SecretTcaHook.php`` — snapshot, restore and purge
-  ``Classes/Audit/AuditChainLockTrait.php`` — why one shared transaction is impossible
-  ``Tests/Functional/Hook/SecretTcaHookAuditAtomicityTest.php``
-  ``Tests/Functional/Service/VaultServiceAtomicityTest.php`` — the programmatic compensations, availability included
-  ``Tests/Functional/Service/SecretAvailabilityTest.php`` — that a disabled secret is unreadable yet still administrable
