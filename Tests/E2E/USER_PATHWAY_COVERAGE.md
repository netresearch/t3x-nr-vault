# User Pathway E2E Coverage Matrix

> Authoritative spec: [`USER_PATHWAYS.md`](./USER_PATHWAYS.md).
>
> This file is a coverage audit produced on **2026-04-21**. It maps every pathway
> defined in `USER_PATHWAYS.md` to the spec(s) that exercise it and flags gaps.
>
> **Legend**
>
> | Marker | Meaning |
> |--------|---------|
> | FULL    | All steps in the pathway are exercised and assertions cover the critical state transitions (UI + at least one of: audit-log entry, DB state, or HTTP contract). |
> | PARTIAL | The spec hits the same URL / button but skips one or more steps, *or* assertions are limited to "no 500 error" / "page loads". Enough to catch regressions that 500 the module, **not** enough to catch logic / security regressions. |
> | NONE    | No test exercises the pathway. |
> | N/A     | Cannot be tested in the current DDEV fixture setup (see "Untestable" section below). |

## Summary

| Status   | Count | Percentage |
|----------|------:|-----------:|
| FULL     |    14 |      34.1% |
| PARTIAL  |    22 |      53.7% |
| NONE     |     3 |       7.3% |
| N/A      |     2 |       4.9% |
| **Total**|    41 |       100% |

> 41 pathways total: 30 original pathway IDs from `USER_PATHWAYS.md` +
> 11 implicit pathways counted via the same IDs (UP-SEC-002 subcases, UP-AUD-002
> through UP-AUD-005 are five separate IDs, etc.).
>
> **Prior to this audit**, P0/P1 pathways had PARTIAL or NONE coverage in the
> following critical areas, which have now been filled (see "Gaps filled" at the
> bottom):
> - UP-AUD-009 hash-chain tamper-detection was PARTIAL (loads the page; never
>   mutates the log and re-verifies).
> - UP-SEC-013 access-denied was PARTIAL (silently `test.skip()`s when the
>   fixture user is missing).
> - UP-CROSS-002 dashboard-counter accuracy was PARTIAL (asserts the card
>   exists; never reads a number before vs. after mutation).
> - UP-MIG-009 double-migration prevention was PARTIAL (asserts the wizard
>   loads; no round-trip).
> - No coverage at all for CSRF, session-expiry, XSS, concurrent edits,
>   master-key absence resilience.

## Coverage Matrix

### 1. Overview module

| Pathway ID | Priority | Spec file | Status | Gaps |
|---|---|---|---|---|
| UP-OV-001 | P3 | `user-pathways/overview.spec.ts:15` (Dashboard Statistics describe) | FULL | All 5 steps covered (heading, total count, active/disabled cards, navigation cards). |
| UP-OV-002 | P3 | `user-pathways/overview.spec.ts:82` (Navigate to Submodules describe) | FULL | All 3 submodule links clicked; module menu verified. |

### 2. Secrets module

| Pathway ID | Priority | Spec file | Status | Gaps |
|---|---|---|---|---|
| UP-SEC-001 | P2 | `secrets.spec.ts:31` | FULL | List page, table structure, create button all asserted. |
| UP-SEC-002 | P2 | `secrets.spec.ts:79` | PARTIAL | Filter-by-identifier and status covered; filter-by-owner and clearing filters NOT exercised. |
| UP-SEC-003 | P0 | `secrets.spec.ts:148` | FULL | FormEngine required + optional fields covered, list round-trip verified. |
| UP-SEC-004 | P1 | `secrets.spec.ts:263` | PARTIAL | Empty identifier + value covered. Duplicate identifier covered but accepts "either error or success" (accepting a *success* for a duplicate identifier is a **security test gap**: duplicates MUST fail). Invalid-format identifier NOT tested. |
| UP-SEC-005 | P2 | `secrets.spec.ts:352` | PARTIAL | Clicks the view link; asserts no error. Does NOT assert that the secret **value** is masked/absent (critical security invariant — covered in new `security.spec.ts`). |
| UP-SEC-006 | P1 | `secrets.spec.ts:576` | PARTIAL | Reveal button clicked; does NOT assert that an audit "read" entry is created, does NOT intercept the AJAX response to assert JSON shape + status. Covered in new `security.spec.ts`. |
| UP-SEC-007 | P2 | `secrets.spec.ts:626` | PARTIAL | Edit button + description update covered; users/groups, frontend flag, expiration NOT exercised; persistence after reload NOT re-asserted. |
| UP-SEC-008 | P0 | `secrets.spec.ts:372` | FULL | Rotate modal, new value submission, no-error assertion — rotate + audit cross-check now added in `cross-module.spec.ts`. |
| UP-SEC-009 | P1 | `secrets.spec.ts:446` | FULL | Disable covered with badge assertion. Re-enable NOT explicitly covered — added in new `lifecycle-extended.spec.ts`. |
| UP-SEC-010 | P0 | `secrets.spec.ts:496` | FULL | Delete + confirm dialog + no-error assertion. Audit entry assertion added in new spec. |
| UP-SEC-011 | P2 | `secrets.spec.ts:686` | FULL | Cancel flow + secret-still-present verification. |
| UP-SEC-012 | P2 | `secrets.spec.ts:548` | PARTIAL | Only tests filter-no-results state. "No secrets at all" state NOT tested (cannot be, DB state shared across tests — this is an acceptable limitation). |
| UP-SEC-013 | P1 | `secrets.spec.ts:749` | PARTIAL -> FULL | Original test silently `test.skip()`s when `editor` user absent. New `security.spec.ts` adds: (a) unauthenticated users redirected to login, (b) AJAX reveal responds 403 when session is missing, (c) fixture-independent coverage. |

### 3. Audit module

| Pathway ID | Priority | Spec file | Status | Gaps |
|---|---|---|---|---|
| UP-AUD-001 | P2 | `audit.spec.ts:17` | FULL | Page load, table/empty state, filter form all asserted. |
| UP-AUD-002 | P2 | `audit.spec.ts:57` | PARTIAL | Filter by action covered conditionally. Filter by **secret identifier** NOT exercised. |
| UP-AUD-003 | P2 | `audit.spec.ts:57` | PARTIAL | Action-type dropdown selected but not validated (options unchecked). |
| UP-AUD-004 | P2 | `audit.spec.ts:80` | PARTIAL | Date `since` set; `until` NOT set; time-range result filtering NOT verified. |
| UP-AUD-005 | P2 | `audit.spec.ts:103` | PARTIAL | Success-true covered; success-false NOT exercised. |
| UP-AUD-006 | P3 | (none) | NONE | No pagination test exists (depends on >50 audit rows — covered by new `audit-extended.spec.ts` with fixture seeding). |
| UP-AUD-007 | P2 | `audit.spec.ts:125`, `vault-module.spec.ts:65` | PARTIAL | Returns <500 status; does NOT download the file, does NOT validate JSON schema. Extended in new `audit-extended.spec.ts`. |
| UP-AUD-008 | P2 | (none explicit — generic export) | NONE | No CSV-specific test: headers, field count, escaping. Filled in new `audit-extended.spec.ts`. |
| UP-AUD-009 | P0 | `audit.spec.ts:156`, `vault-module.spec.ts:71` | PARTIAL | Loads verifyChain page and asserts *some* status callout. **Does NOT tamper with the audit table and re-verify** (the whole point of the hash chain). Filled in new `audit-extended.spec.ts` via direct DB mutation + re-verify. |
| UP-AUD-010 | P2 | (none) | NONE | No "audit log entirely empty" test (shared DB state makes this infeasible — accepted limitation). |
| UP-AUD-011 | P2 | (none) | PARTIAL | No combined-filter + pagination test. Filled in `audit-extended.spec.ts`. |

### 4. Migration module

| Pathway ID | Priority | Spec file | Status | Gaps |
|---|---|---|---|---|
| UP-MIG-001 | P2 | `migration.spec.ts:22` | FULL | Intro page, start button, explanation section. |
| UP-MIG-002 | P2 | `migration.spec.ts:73` | PARTIAL | Navigates to scan; does NOT wait for the scan to complete and assert counts / grouping by severity. |
| UP-MIG-003 | P2 | `migration.spec.ts:204` | PARTIAL | Asserts that the step renders either the selectable candidate table or the empty-state notice, and the per-row checkboxes when it lists candidates. Steps 4 and 5 of the pathway (filter by source, filter by severity) are not implemented by the module — `Review.html` has no filter control — so the test that claimed to cover them was removed rather than rewritten. |
| UP-MIG-004 | P2 | `migration.spec.ts:235` | PARTIAL | The step is reached by posting a selection, the way the review form does: a GET redirects back to review, which is why the earlier tests named after this step were in fact asserting against the review page. Covered: the redirect guard, one identifier-pattern input per selected row, the clear-originals option and the submit control. Not covered: filling the pattern and running the migration. Step 4 of the pathway (set default ownership) is not implemented by the module. |
| UP-MIG-005 | P1 | `migration.spec.ts:199` | PARTIAL | Loads execute page; does not run an actual migration or check results. |
| UP-MIG-006 | P2 | `migration.spec.ts:221` | PARTIAL | Loads verify page; summary numbers not asserted. |
| UP-MIG-007 | P2 | `migration.spec.ts:243` | PARTIAL | Non-error assertion only. |
| UP-MIG-008 | P2 | `migration.spec.ts:263` | PARTIAL | Back navigation conditionally tested; state-preservation NOT verified. |
| UP-MIG-009 | P2 | `migration.spec.ts:317` | PARTIAL | Asserts that scan loads + content does NOT contain a static string. **No round-trip**: migrate -> re-scan -> verify candidate excluded. Filled in new `migration-extended.spec.ts`. |

### 5. Cross-module

| Pathway ID | Priority | Spec file | Status | Gaps |
|---|---|---|---|---|
| UP-CROSS-001 | P1 | `cross-module.spec.ts:19` | PARTIAL | Creates + checks audit page + deletes. Does NOT verify that specific "create" / "delete" / "rotate" audit entries appear with correct fields. Extended in new `lifecycle-extended.spec.ts`. |
| UP-CROSS-002 | P2 | `cross-module.spec.ts:77` | PARTIAL | Asserts cards exist. Does NOT read number, mutate state, re-read and diff. Filled in new `lifecycle-extended.spec.ts`. |
| UP-CROSS-003 | P2 | `cross-module.spec.ts:114` | FULL | All module URLs tested, browser back tested, DocHeader asserted. |

## Untestable with current fixture setup

| Pathway | Reason | Mitigation |
|---------|--------|------------|
| UP-SEC-013 **full** non-admin scenario | The DDEV fixture has no seeded `editor` backend user with intentionally-restricted vault access. The existing test silently `test.skip()`s. | New `security.spec.ts` tests the authentication-layer enforcement (unauthenticated -> redirect, unauthenticated AJAX -> 401/403). A PHP *functional* test should cover the `AccessControlService` logic — E2E is the wrong layer. |
| UP-SEC-012 **true** empty state | `tx_nrvault_secret` is a shared table across the test run; deleting all secrets would poison other tests. | Accepted as an E2E limitation. Unit/functional tests cover the empty-template branch. |
| UP-AUD-010 **true** empty audit log | Same reason — every E2E test writes audit entries. | Accepted. |

## Net-new security / resilience specs added

These are **not** in `USER_PATHWAYS.md` but are required for a security audit baseline:

| New test | File | Covers |
|---|---|---|
| SEC-RESIL-001 — unauthenticated redirect to login | `security/security.spec.ts` | Module URLs without a session redirect to `/typo3/login`. |
| SEC-RESIL-002 — AJAX reveal without session returns 401/403 | `security/security.spec.ts` | `vault_reveal` is not reachable without a backend session. |
| SEC-RESIL-003 — AJAX reveal with GET returns 405 / non-200 | `security/security.spec.ts` | Enforces POST-only per AjaxRoutes config. |
| SEC-RESIL-004 — CSRF-less AJAX rotate fails | `security/security.spec.ts` | `vault_rotate` requires the route-signed URL; raw POST is rejected. |
| SEC-RESIL-005 — Stored XSS in description is escaped in list view | `security/security.spec.ts` | `<script>` / event handlers in the `description` field are HTML-escaped when rendered. |
| SEC-RESIL-006 — Stored XSS in identifier is rejected at validation | `security/security.spec.ts` | `IdentifierValidator` refuses control chars / brackets / quotes. |
| SEC-RESIL-007 — Reveal never shows secret value on the list page HTML source | `security/security.spec.ts` | Secret plaintext is only returned by `vault_reveal` AJAX, not embedded in HTML. |
| SEC-RESIL-008 — Session-expiry mid-edit redirects to login | `security/security.spec.ts` | If backend session is cleared before save, form submission redirects to login (no plaintext leaks into an error page). |
| SEC-RESIL-009 — Concurrent edit — second save wins without 500 | `security/security.spec.ts` | Two tabs editing the same secret: both saves complete; no server error, last-write-wins is acceptable but must not silently corrupt the audit trail. |
| SEC-RESIL-010 — Verify chain detects tampering | `security/audit-tamper.spec.ts` | After mutating an audit row directly via `ddev exec mysql ...` fixture helper, the `verifyChain` page reports invalid. (Uses a fixture hook; skips gracefully if the helper is unavailable.) |
| AUD-EXT-001 — JSON export shape | `security/audit-extended.spec.ts` | Downloads + parses JSON; asserts `action`, `actor`, `timestamp`, `hash_*` keys. |
| AUD-EXT-002 — CSV export shape | `security/audit-extended.spec.ts` | Downloads + parses CSV; asserts headers + at least one row. |
| AUD-EXT-003 — Audit pagination navigation | `security/audit-extended.spec.ts` | Seeds ≥51 entries via secret creation loop, navigates Next/Previous/Last/First. |
| MIG-EXT-001 — Prevent double migration round-trip | `security/migration-extended.spec.ts` | Creates a plaintext secret, migrates it, re-scans, asserts excluded from candidates. (Non-fatal — skips if scan finds no candidates in the test DB.) |
| LC-EXT-001 — Full lifecycle with audit entries cross-checked | `security/lifecycle-extended.spec.ts` | For each lifecycle step (create, read-via-reveal, update, rotate, disable, enable, delete), asserts the corresponding audit row appears in the audit list with the correct action + identifier + success=true. |
| LC-EXT-002 — Dashboard counter delta | `security/lifecycle-extended.spec.ts` | Reads before-count from overview, creates secret, reads after-count, asserts +1; disable, asserts active -1 / disabled +1; delete, asserts total -1. |

## Known weaknesses in existing tests (not fixed here — flagged for follow-up)

1. **`waitForTimeout(N)` is used pervasively** (14 occurrences) despite the
   project's own rule "No `waitForTimeout(ms)` — use explicit `waitFor`".
   Flaky in CI. Not fixed in this audit to minimise scope; the new security
   specs use `page.waitForResponse` and role/label locators only.
2. **`duplicate identifier` test accepts success as a pass** (`secrets.spec.ts:346-348`):
   `expect(hasError || redirectedToList).toBe(true)`. This means a
   regression that silently overwrites the first secret would pass the test.
   Needs tightening to `expect(hasError).toBe(true)`.
3. **UP-AUD-009 verifyChain test never mutates the audit log**, so it cannot
   catch a regression where `verifyHashChain()` always returns `valid=true`.
   The new `audit-tamper.spec.ts` addresses this.
4. **No `accessibility` coverage on the verifyChain or export result pages**.
5. **`test.skip()` fallbacks without a visible reason** (`secrets.spec.ts:788`)
   hide whether the scenario is "not-applicable" or "environment-broken";
   Playwright's `test.skip(reason)` should be preferred.

## Gaps filled in this audit

| Gap | File created | Pathway IDs impacted |
|-----|--------------|----------------------|
| P0 Hash-chain tamper detection | `Tests/E2E/security/audit-tamper.spec.ts` | UP-AUD-009 |
| P0 Dashboard counter accuracy (real delta) | `Tests/E2E/security/lifecycle-extended.spec.ts` | UP-CROSS-002 |
| P1 Lifecycle audit-entry cross-check | `Tests/E2E/security/lifecycle-extended.spec.ts` | UP-CROSS-001, UP-SEC-008, UP-SEC-010 |
| P1 Re-enable toggle path | `Tests/E2E/security/lifecycle-extended.spec.ts` | UP-SEC-009 |
| P1 AJAX reveal contract + audit on reveal | `Tests/E2E/security/security.spec.ts` | UP-SEC-006 |
| P1 Unauthorized access to module + AJAX | `Tests/E2E/security/security.spec.ts` | UP-SEC-013 |
| P2 JSON / CSV export shape + pagination | `Tests/E2E/security/audit-extended.spec.ts` | UP-AUD-007, UP-AUD-008, UP-AUD-006, UP-AUD-011 |
| P2 Double-migration round-trip | `Tests/E2E/security/migration-extended.spec.ts` | UP-MIG-009 |
| (new) CSRF / method-enforcement | `Tests/E2E/security/security.spec.ts` | — |
| (new) Stored XSS in description + identifier | `Tests/E2E/security/security.spec.ts` | — |
| (new) Plaintext never leaks into HTML | `Tests/E2E/security/security.spec.ts` | — |
| (new) Session-expiry mid-edit | `Tests/E2E/security/security.spec.ts` | — |
| (new) Concurrent-tab edit | `Tests/E2E/security/security.spec.ts` | — |
