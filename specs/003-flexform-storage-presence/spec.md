# FlexForm deletion must resolve storage presence separately from availability

Status: proposed for independent review. Dependency: actual deletion implementation PR432 (`3df8164b19577721cf802195c605a2f5ec60e02a`). This amendment precedes its implementation in a real dependent PR.

## Problem and actual evidence

The completed deletion preflight protects only the references its discovery selects. The default adapter's `exists()` excludes disabled rows, whereas administrative metadata and deletion include them. A disabled reference is therefore silently skipped. Actual Core/DataHandler and SQLite oracles on the PR432 head show two genuine assertion failures and zero framework errors: an owned disabled secret remains after its owning record is removed; a denied disabled reference is skipped, allowing an earlier permitted secret and the owning record to be removed.

The valid ten-case run has 56 assertions. Missing, already-deleted and shared disabled counterparts, including a foreign-owned shared disabled identity, pass on the original implementation. An earlier partial-envelope fixture caused a model-invariant error and is retained as invalid setup evidence, not as a counterexample. The corrected complete synthetic envelope is intentionally invalid ciphertext: it proves that administrative discovery and deletion need no value decryption, without claiming a cryptographic round trip.

## Decision

1. Keep the existing validated UUID syntax and column-bound sharing resolver. First collect candidates and complete identity-wide sharing exclusions across every FlexForm column. A shared identity is excluded before administrative presence lookup, including a foreign-owned disabled identity that this record has no need to delete.
2. For each remaining unique identity, resolve presence through the existing service: retain `exists()` as the fast availability path; when false, call `getMetadata()` to distinguish disabled custody from an absent/deleted identity. Only `SecretNotFoundException` means absence. Any permission, storage or other failure cancels Core deletion through the existing ADR045 discovery-failure path.
3. Resolve all selected identities' presence before the first `assertDeletable()` or `delete()`. Remove absent identities from the selection. Preflight each remaining identity through the same service and retain its existing denial audit; actual deletion still uses that service. No new abstract method, global availability change, direct adapter access, plaintext retrieval or alternative ACL path is introduced.
4. Metadata authorization is retained. The documented native delete-capable tiers (owner, administrator and context maintainer) also have read access; do not infer that any arbitrary external adapter or custom ACL has an undeclared storage-presence API. An administrative lookup denial fails closed and is audited by the existing service.
5. Preserve missing/already-deleted/shared-only record removability, identity-wide duplicate handling, cancellation-before-diagnostics, soft-delete/recycle behavior and the existing post-persistence residual. Mixed plain/FlexForm coordination and copy compensation remain separate open repairs.

## Verification

- Execute real Core/DataHandler, actual default adapter, native SQL row-state assertions and ACL/audit paths for owned disabled custody, denied disabled custody following a permitted reference, missing, deleted, shared-owned and shared-foreign disabled identities. Include intentionally undecipherable complete ciphertext and assert no read audit or plaintext request.
- Unit oracles assert outside Throwable catches: storage-presence calls finish before any preflight/deletion; only the precise missing exception skips an identity; permission/RuntimeException/Error failures cancel before mutations; shared identities never enter metadata lookup; an active identity retains the availability fast path.
- Challenge the final snapshot with selected faults that drop administrative fallback, broaden its catch and move it before sharing; report assertion failures separately from framework errors and restore exact hashes.
- Run canonical complete CI and Rector, focused native SQLite/MariaDB and relevant functional regression. Independently review the complete hook, metadata/availability/delete contracts, documentation and every new test method. Publish the reviewed specification then its exact child implementation; merge only after the whole audit and external checks are complete.

## Scope

This correction concerns presence resolution for the currently recognized FlexForm deletion candidates. It does not prove schema-specific UUID recognition, cross-hook atomicity, copy compensation, every external backend, or the complete extension audit. Native evidence will identify the actual PHP/Core/database matrix; no unexecuted narrower-platform claim is implied.
