<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
<!-- SPDX-FileCopyrightText: Netresearch DTT GmbH -->
# FlexForm final-link compensation

ADR046. Independent stack based on Clock PR417; specification first, implementation on the exact signed specification commit.

## Confirmed failure

A real FlexForm XML fixture drives the public copy hook. A source secret is read and a fresh clone is successfully stored. The final Core XML serialization or record-link write then throws RuntimeException or Error. Both calls currently sit outside the clone failure handler: the clone is never abandoned and the duplicate retains either the source reference or a link already written before the exception. Original native PHP8.5 execution: eight cases, 64 assertions, eight genuine assertion failures, zero framework Errors. The real Core serializer is used; connection/Vault callbacks capture writes and deletion attempts, so this proves hook logic, not native SQL or cryptographic integration. Constructor/LF fixture errors from earlier trials are explicitly excluded.

## Decision

1. Treat clone retrieval/storage and the final XML serialization/link write as one per-column compensation boundary. Keep the ordinary successful XML comparison/write path and plaintext zeroing.
2. On a Throwable in that boundary, attempt deletion of every clone whose store completed for that column. Never delete a source identity or an unrelated independently supplied value. Existing vault delete authorization/audit remain responsible for each compensation.
3. Clear every recognized source vault position in the duplicate's parsed column, preserving all other FlexForm data. Serialize it with Core and attempt an unconditional clearing update. Even if its bytes match the initially read copy XML, a failed link write may already have persisted different bytes; comparing against the old snapshot cannot prove the current database state.
4. Contain a failure of clearing serialization or its database write and report the existing cause-independent correlation diagnostic with an explicit state notice. Successful clearing says the column's vault references were cleared. Failed clearing says the duplicate may still reference source or abandoned cloned secrets and needs manual review; it must not promise an intact failed target or a fully reverted record.
5. Compensation is best-effort, not transactional record rollback. A refused/failed compensation may leave an orphan if clearing succeeds. If clearing also fails, a retained reference may instead point to a clone whose compensation was applied, including a delete that threw after persistence. Do not label every residual as an unreferenced orphan. No new restoration API, schema, global availability semantics or plain TCA hook change.
6. The bounded repair concerns one FlexForm column. Whole-record coordination across multiple FlexForm columns, plain/FlexForm interaction, mutations that throw after clone storage has been applied, and diagnostic-provider failure remain separate audit work. Keep those limitations explicit instead of claiming this repair makes every record copy atomic.

## Verification

Outside-catch assertions capture actual created identifiers, exact compensation attempts, final stored XML and correlation notices. Cover both Throwable families at serialization/write, a write that persists before throwing, an initially blank copied position whose cleared XML equals the original snapshot, and failed recovery serialization/write with honest uncertainty. Healthy copy retains fresh independent references and non-vault data. Selected faulty versions must fail actual assertions, not setup/framework errors; restore exact source bytes before final canonical Unit/Fuzz/static/style/Rector/full SQLite and relevant Core integration checks. Use real XML parsing/serialization; a mocked connection cannot establish SQL execution.
