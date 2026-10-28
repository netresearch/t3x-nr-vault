------------------------ MODULE VaultAuditAtomicity ------------------------
\* SPDX-License-Identifier: GPL-2.0-or-later
\* SPDX-FileCopyrightText: Netresearch DTT GmbH

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Requests, Atomic, AllowCrashes

\* Request IDs double as unique new secret-state tokens. Zero is the initial
\* state. A token abstracts the encrypted envelope, version and both ACL tiers;
\* it is not plaintext, a hash implementation or a SQL isolation model.
ASSUME /\ Requests = {1, 2}
       /\ Atomic \in BOOLEAN
       /\ AllowCrashes \in BOOLEAN

VARIABLES secret, committed, audit, tip, owner, pc, before,
          stagedAudit, stagedTip, staleCompensation

vars == <<secret, committed, audit, tip, owner, pc, before,
          stagedAudit, stagedTip, staleCompensation>>

Entry(r) == [writer |-> r, before |-> before[r], after |-> r,
             previous |-> tip]

AuditWriters == {audit[i].writer : i \in 1..Len(audit)}

Init ==
    /\ secret = 0
    /\ committed = {}
    /\ audit = <<>>
    /\ tip = 0
    /\ owner = 0
    /\ pc = [r \in Requests |-> "start"]
    /\ before = [r \in Requests |-> 0]
    /\ stagedAudit = [r \in Requests |-> FALSE]
    /\ stagedTip = [r \in Requests |-> FALSE]
    /\ staleCompensation = FALSE

Begin(r) ==
    /\ pc[r] = "start"
    /\ ~Atomic \/ owner = 0
    /\ pc' = [pc EXCEPT ![r] = "read"]
    /\ before' = [before EXCEPT ![r] = secret]
    /\ owner' = IF Atomic THEN r ELSE owner
    /\ UNCHANGED <<secret, committed, audit, tip,
                   stagedAudit, stagedTip, staleCompensation>>

Mutate(r) ==
    /\ pc[r] = "read"
    /\ pc' = [pc EXCEPT ![r] = "mutated"]
    /\ secret' = IF Atomic THEN secret ELSE r
    /\ committed' = IF Atomic THEN committed ELSE committed \cup {r}
    /\ UNCHANGED <<audit, tip, owner, before,
                   stagedAudit, stagedTip, staleCompensation>>

AppendAudit(r) ==
    /\ pc[r] = "mutated"
    /\ pc' = [pc EXCEPT ![r] = IF Atomic THEN "audited" ELSE "committed"]
    /\ stagedAudit' = [stagedAudit EXCEPT ![r] = TRUE]
    /\ audit' = IF Atomic THEN audit ELSE Append(audit, Entry(r))
    /\ tip' = IF Atomic THEN tip ELSE r
    /\ UNCHANGED <<secret, committed, owner, before,
                   stagedTip, staleCompensation>>

AdvanceTip(r) ==
    /\ pc[r] = "audited"
    /\ pc' = [pc EXCEPT ![r] = "anchored"]
    /\ stagedTip' = [stagedTip EXCEPT ![r] = TRUE]
    /\ tip' = IF Atomic THEN tip ELSE r
    /\ UNCHANGED <<secret, committed, audit, owner, before,
                   stagedAudit, staleCompensation>>

Commit(r) ==
    /\ pc[r] = "anchored"
    /\ stagedAudit[r] /\ stagedTip[r]
    /\ pc' = [pc EXCEPT ![r] = "committed"]
    /\ secret' = IF Atomic THEN r ELSE secret
    /\ committed' = committed \cup {r}
    /\ audit' = IF Atomic THEN Append(audit, Entry(r)) ELSE audit
    /\ tip' = IF Atomic THEN r ELSE tip
    /\ UNCHANGED <<owner, before, stagedAudit, stagedTip,
                   staleCompensation>>

Finish(r) ==
    /\ pc[r] = "committed"
    /\ pc' = [pc EXCEPT ![r] = "done"]
    /\ owner' = IF owner = r THEN 0 ELSE owner
    /\ UNCHANGED <<secret, committed, audit, tip, before,
                   stagedAudit, stagedTip, staleCompensation>>

\* A failed audit append/anchor/commit aborts the whole pending transaction.
\* In legacy mode the pre-audit mutation has already autocommitted. The catch
\* schedules a second write of the snapshot, which may now be stale.
Fail(r) ==
    /\ pc[r] \in {"read", "mutated", "audited", "anchored"}
    /\ Atomic \/ pc[r] = "mutated"
    /\ pc' = [pc EXCEPT ![r] = IF Atomic THEN "failed" ELSE "compensate"]
    /\ owner' = IF owner = r THEN 0 ELSE owner
    /\ stagedAudit' = [stagedAudit EXCEPT ![r] = FALSE]
    /\ stagedTip' = [stagedTip EXCEPT ![r] = FALSE]
    /\ UNCHANGED <<secret, committed, audit, tip, before, staleCompensation>>

Compensate(r) ==
    /\ ~Atomic
    /\ pc[r] = "compensate"
    /\ pc' = [pc EXCEPT ![r] = "failed"]
    /\ staleCompensation' = (staleCompensation \/ (secret # r /\ secret \in AuditWriters))
    /\ secret' = before[r]
    /\ UNCHANGED <<committed, audit, tip, owner, before, stagedAudit, stagedTip>>

\* Connection/process loss rolls back pending database work and releases its
\* lock. A crash after Commit keeps the already committed state. There is no
\* catch/finally execution in this action, matching process termination.
Crash(r) ==
    /\ AllowCrashes
    /\ pc[r] \notin {"start", "done", "failed", "crashed"}
    /\ pc' = [pc EXCEPT ![r] = "crashed"]
    /\ owner' = IF owner = r THEN 0 ELSE owner
    /\ stagedAudit' = [stagedAudit EXCEPT ![r] = FALSE]
    /\ stagedTip' = [stagedTip EXCEPT ![r] = FALSE]
    /\ UNCHANGED <<secret, committed, audit, tip, before, staleCompensation>>

Next == \E r \in Requests :
    Begin(r) \/ Mutate(r) \/ AppendAudit(r) \/ AdvanceTip(r) \/ Commit(r)
    \/ Finish(r) \/ Fail(r) \/ Compensate(r) \/ Crash(r)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ secret \in Requests \cup {0}
    /\ committed \subseteq Requests
    /\ audit \in Seq([writer : Requests, before : Requests \cup {0},
                      after : Requests, previous : Requests \cup {0}])
    /\ tip \in Requests \cup {0}
    /\ owner \in Requests \cup {0}
    /\ pc \in [Requests -> {"start", "read", "mutated", "audited", "anchored",
                             "committed", "done", "failed", "crashed", "compensate"}]
    /\ before \in [Requests -> Requests \cup {0}]
    /\ stagedAudit \in [Requests -> BOOLEAN]
    /\ stagedTip \in [Requests -> BOOLEAN]
    /\ staleCompensation \in BOOLEAN

CommittedAudit == committed = AuditWriters

\* Legacy gets until process termination/completion to produce the audit row.
\* Its counterexample therefore shows the actual write -> process-loss gap.
SettledAudit ==
    \A r \in Requests :
        (pc[r] \in {"crashed", "done"} /\ r \in committed) => r \in AuditWriters

TipMatchesAudit == tip = IF Len(audit) = 0 THEN 0 ELSE audit[Len(audit)].writer

ChainConsistent ==
    \A i \in 1..Len(audit) :
        /\ audit[i].previous = IF i = 1 THEN 0 ELSE audit[i - 1].writer
        /\ audit[i].before = IF i = 1 THEN 0 ELSE audit[i - 1].after

NoStaleCompensation == ~staleCompensation

\* Negated reachability checks: each separate cover configuration MUST produce
\* its intended counterexample, so a model disabling all work cannot pass.
NeverBothCommitted == committed # Requests
NeverFailed == \A r \in Requests : pc[r] # "failed"
NeverCrashed == \A r \in Requests : pc[r] # "crashed"

=============================================================================
