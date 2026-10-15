# FlexForm hard-delete refusal and preflight

Status: proposed for independent review. Dependency: actual clock oracle PR417; ADR045 and this specification precede the implementation PR.

## Problem and evidence

The actual Core DataHandler removes a hard-deleting fixture record after the real VaultService has refused its foreign-owned secret deletion. The secret survives and the access_denied audit exists, while the record row disappears. The original native SQLite oracle has one genuine assertion failure and zero framework errors (original-real-core-delete-valid-red.log). A separate original hook oracle has the same missing cancellation flag (original-failed-delete-red.log). Earlier attempted Core fixture runs omitted the hardened profile and are not evidence for this defect.

## Required behavior

1. For a hard-deleting table, collect the currently recognized existing vault UUID references across all FlexForm columns before deleting any secret. Preserve existing XML/existence recognition and translation-sharing policy; this repair does not widen identifier parsing or redefine ordinary FlexForm values.
2. Deduplicate identifiers across columns. If any discovered column shows that an identifier is still embedded in another live record, exclude that identity from the complete cascade. Remove a previously selected occurrence and prevent a later occurrence in an unshared column from reintroducing it; both column orders preserve the shared secret. The existing per-column sharing resolver remains unchanged.
3. Run the existing VaultServiceInterface::assertDeletable for every selected reference before calling delete on the first reference. No new abstract API or alternative ACL path is introduced. Disabled-secret administrative lookup and access_denied auditing remain in the actual VaultService path.
4. On discovery, preflight or deletion failure, stop the cascade and set the existing recordWasDeleted flag before invoking the reporter or editor log, so Core skips its record removal even if diagnostics throw. Use VaultFailureReporter correlation in the existing editor diagnostic channel. Never copy raw exception causes or secret plaintext into that diagnostic.
5. Successful hard deletion leaves the flag unchanged so Core performs its normal record removal. Empty/no-secret and translation-shared-only records remain removable; each unique selected secret is deleted once.
6. FlexForm soft-delete/recycle preserves secret references and values for restoration as today. This differs from the plain TCA hook; do not silently change that boundary.
7. Preflight does not create a transaction across secret deletions. Any actual delete can throw after persistence, including from a SecretDeletedEvent observer. On an actual delete failure, keep the owning record, stop later deletions and disclose that secrets may already have been deleted and cannot be restored automatically. Already-applied deletions can include the failing current operation; do not imply that only earlier successful calls changed storage. This is ADR036 L1's residual, not a claim of full rollback.

## Scope and retained gaps

This decision covers the FlexForm cascade within its hook. It does not provide a cross-hook preflight coordinator for a record mixing plain TCA vault fields with FlexForm fields. That mixed-record guarantee remains a separate open audit item. Final-link write failure and cross-column copy compensation are separate defects and PRs. Ordinary UUID references outside configured vault elements retain the existing recognition policy pending an independent source/schema counterexample; this repair does not claim that broader question closed.

## Verification

- Actual Core + actual SQLite schema + actual VaultService ACL denial preserves the owning record, the undeleted secret and access_denied evidence. Confirm a healthy hard-delete counterpart through the same Core path.
- Unit oracles capture callbacks then assert outside Throwable catches: all preflights precede all deletes; denied second reference causes no delete; duplicate/shared IDs; RuntimeException/Error in preflight/delete/discovery; later failure stops the suffix and keeps the cancellation flag; a post-persistence observer failure changes the current target before throwing and produces an honest residual warning; diagnostic failure cannot prevent setting the cancellation flag; soft delete leaves vault calls untouched.
- Preserve original source counterexamples, exact final source snapshots, selected faults proving cancellation/preflight/suffix semantics with genuine assertions (framework errors separately), canonical eight-step CI, Rector, focused native SQLite/MariaDB and relevant full functional regression.
- Independent review covers whole changed hook, Core callers, sharing resolver, actual service preflight/delete contracts, docs and all new test methods. Repeat after corrections. Publish actual signed spec→implementation stack; no merge until the whole extension audit and external checks are complete.

## Execution boundaries

Native matrix evidence currently uses 64-bit PHP8.5 / TYPO3 14.3. Native narrower integer builds and every supported Core major are not inferred from these runs. Synthetic exception codes must remain representable. Test-owned SQL fixtures and locally generated keys contain no operational secrets. The initial seed envelope is sufficient for a real denied ACL path; do not claim it proves encryption or plaintext retrieval.
