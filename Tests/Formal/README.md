<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- SPDX-FileCopyrightText: Netresearch DTT GmbH -->

# Audit mutation model

Run `bash Build/Scripts/check-formal.sh` with Java 11 or later, `curl`,
`sha256sum` and GNU `timeout` installed. No Composer dependency is added.
`JAVA` may name a Java executable; `TLA2TOOLS_JAR` may name an already downloaded
JAR, which must match the pinned digest. `FORMAL_RESULTS_DIR` preserves complete
logs and counterexample traces outside the otherwise disposable run directory.

The runner uses the [official TLA+ 1.7.4 release](https://github.com/tlaplus/tlaplus/releases/tag/v1.7.4)
(TLC reports its internal version as 2.19), verifies its SHA-256, and executes a
single-worker breadth-first search. A successful command requires all six
outcomes below. A parser error, timeout or wrong invariant is a failed check,
including for the negative controls.

| Configuration | Required result |
| --- | --- |
| `Atomic.cfg` | Complete state search, all six invariants hold |
| `LegacyCrash.cfg` | `SettledAudit` counterexample, TLC exit 12 |
| `LegacyCompensation.cfg` | `NoStaleCompensation` counterexample, TLC exit 12 |
| `AtomicBothCommitted.cfg` | `NeverBothCommitted` counterexample: both requests can commit |
| `AtomicFailure.cfg` | `NeverFailed` counterexample: a request can abort |
| `AtomicCrash.cfg` | `NeverCrashed` counterexample: a process can be lost |

The last three are non-vacuity checks: disabling all work, failures or crashes
must fail the runner instead of producing a reassuring but empty result. They
require the same exit-code and trace validation as the legacy controls.

## What is checked

`VaultAuditAtomicity.tla` has exactly two requests, each attempting one mutation
of the same secret. Each request has a unique resulting state token. A token
abstracts the envelope, version and both ACL tiers; it is not the numeric
version counter (`store()` updates need not increment that counter). There is no plaintext in the
model. `audit` contains only the successful mutation entries, excluding reads,
denied attempts and unrelated actions.

The positive configuration explores successful writes, failures before commit,
process loss at each pending phase, and process loss after commit. It checks:

- `TypeOK`: state stays inside the declared abstraction.
- `CommittedAudit`: every committed mutation has its matching committed audit
  entry, and every successful mutation entry has a committed mutation.
- `SettledAudit`: a finished or crashed request cannot leave its committed
  mutation without that entry.
- `TipMatchesAudit`: the abstract durable tip names the last durable entry.
- `ChainConsistent`: each append links the preceding tip and records the secret
  state produced by the preceding committed mutation.
- `NoStaleCompensation`: rollback never overwrites another audited mutation.

The legacy controls deliberately omit the common transaction. One trace is
`Begin(A) -> Mutate(A) -> Crash(A)`: the process cannot execute compensation.
The other is `Begin(A) -> Mutate(A) -> Fail(A) -> Begin(B) -> Mutate(B) ->
AppendAudit(B) -> Compensate(A)`: restoring A's snapshot overwrites B's audited
change. Legacy audit append and tip advancement are atomic with each other,
matching the existing audit writer; it is the secret write that was separate.

## Connection to PHP

This is a design model, not a formal refinement or equivalence proof of PHP.
Review this mapping whenever the transaction boundaries change, and exercise
the same failures against the actual database in functional tests.

| Model transition | Implementation obligation |
| --- | --- |
| `Begin` | The mutation coordinator owns the database transaction before the secret lookup, verifies that secret, both MM tables, audit and registry use the same real connection, and holds the audit serialization lock until commit |
| `Mutate` | Local adapter/repository writes envelope, version or availability and its applicable ACL relations inside that transaction |
| `AppendAudit` | `AuditLogService::log()` writes the matching successful mutation entry inside a nested savepoint, without committing the outer transaction |
| `AdvanceTip` | Healthy enabled in-database audit tip advancement participates in the same transaction |
| `Commit` | One outer database commit makes mutation, entry and applicable anchor write durable together |
| `Fail` | Any precommit exception rolls back that transaction; no second compensating secret write runs |
| `Crash` | Connection loss causes the database to roll back pending work and release locks; loss after commit preserves the entire commit |
| `Finish` | Release the coordinator lock; external sink delivery and success events may run after durability has been established |

The model serializes successful mutation transactions. MySQL achieves this with
the common advisory lock held through the outer commit. SQLite may allow
overlapping read transactions and abort a stale reader with `SQLITE_BUSY`; such
an aborted operation corresponds to `Fail`, not a successful stale commit.
This is an abstraction argument to validate against the database, not an SQL
isolation proof.

## Assumptions and limits

- The database provides atomic commit, rollback on connection loss, transactional
  tables and no dirty reads. This does not verify the database engine or storage
  durability settings. Commit acknowledgement loss may leave the whole commit
  durable; it must not split the mutation from the audit.
- Only the coordinated stock local-adapter `VaultService` mutation paths are
  covered. Custom adapters, direct repository writes, DataHandler/TCA hooks,
  master-key rotation, read counters and other extension writers require their
  own analysis. An already active caller transaction is rejected by the
  coordinated mutation path rather than silently weakening the boundary.
- The tip is an abstract healthy enabled database anchor. Disabled anchoring and
  intentionally preserved corrupt/missing anchors are separate integrity states.
  No HMAC security, crypto algorithm, key custody or tamper resistance is proved.
- External sinks and event listeners are outside the transaction. Delivery,
  retries, exactly-once notification and availability are not model properties.
- There are two requests and one operation each; no unbounded history, process
  restart, retry, fairness or eventual-completion claim is checked. Finished or
  aborted requests have no successor action, so deadlock checking is explicitly
  disabled. The check is of safety, not liveness.
- TLC enumerates this finite model using state fingerprints. Its result applies
  to the declared state space and assumptions; it is neither a Rocq-checked
  machine-code theorem nor a proof of every runtime execution of nr-vault.

See the [TLC documentation](https://docs.tlapl.us/using:tlc:start) for explicit
state exploration, configuration, fingerprints and exit behavior. TLC's pinned
[exit-code definitions](https://github.com/tlaplus/tlaplus/blob/v1.7.4/tlatools/org.lamport.tlatools/src/tlc2/output/EC.java)
are the basis for accepting only safety-violation exit 12 in the negative checks.
