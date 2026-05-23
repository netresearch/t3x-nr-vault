# E2E Test Coverage Gap Analysis — nr-vault

**Date:** 2026-05-23  
**Scope:** READ-ONLY audit of `Tests/E2E/` test coverage for TYPO3 v13/v14 secrets-vault extension.  
**Baseline:** 140 total E2E tests across 14 spec files; 34.1% FULL coverage per `USER_PATHWAY_COVERAGE.md`.

---

## Executive Summary

The nr-vault E2E test suite covers the core happy paths (secret CRUD, audit filtering, migration steps) with a solid foundation. Recent security/lifecycle specs (audit-tamper, lifecycle-extended, security) have closed P0 gaps. However, **three high-risk areas** remain untested:

1. **Copy-to-clipboard timeout & wipe** (UX-critical, line 118–128 in `SecretReveal.js`) — no assertion that clipboard is cleared after 2 seconds.
2. **Form validation on edit/create collision** — concurrent saves, field-level XSS validation, unsaved-changes warnings.
3. **Clipboard access permission denial** (browser sandbox) — graceful fallback when Clipboard API is unavailable.

Additionally, **9 fragility risks** across existing specs (hardcoded timeouts, CSS selectors, missing waitFor patterns) should be flagged for follow-up refactoring.

---

## Coverage Inventory

| Spec File | Lines | Status | Summary |
|-----------|-------|--------|---------|
| `vault-module.spec.ts` | 83 | Foundational | Basic module load, page-title assertions. |
| `user-pathways/overview.spec.ts` | 223 | FULL | Dashboard stats, card navigation, link consistency. |
| `user-pathways/secrets.spec.ts` | 900 | PARTIAL | List, filter, create, edit, reveal, rotate, delete — all via FormEngine; no multi-form collision/unsaved-warning. |
| `user-pathways/audit.spec.ts` | 228 | PARTIAL | List, filter (action/date), download JSON — no CSV shape, combined filters, pagination. |
| `user-pathways/migration.spec.ts` | 420 | PARTIAL | Wizard steps (intro, scan, review, configure, execute, verify); scan-result counts NOT asserted. |
| `user-pathways/cross-module.spec.ts` | 365 | PARTIAL | Full lifecycle audit cross-check, dashboard counter deltas, browser navigation. |
| `security/security.spec.ts` | 454 | NEW | Unauthenticated redirect, AJAX 401/403, CSRF, XSS (description field), plaintext leakage, session-expiry, concurrent edits, method enforcement. |
| `security/csrf-cookies.spec.ts` | n/a | NEW | SameSite + secure-cookie posture for AJAX endpoints. |
| `security/lifecycle-extended.spec.ts` | 283 | NEW | Per-step audit-entry verification (create/read/update/rotate/enable/disable/delete), dashboard counter deltas. |
| `security/audit-tamper.spec.ts` | 140 | NEW | Direct DB mutation via fixture hook, hash-chain re-verify, status callout assertion. |
| `security/audit-extended.spec.ts` | 174 | NEW | JSON/CSV export shapes, pagination (Next/Prev/First/Last), combined filters. |
| `security/migration-extended.spec.ts` | 98 | NEW | Round-trip: migrate → re-scan → excluded-from-candidates. |
| `accessibility/vault-modules.spec.ts` | 334 | NEW | axe-core WCAG 2.1 AA on all module pages. |
| `tca/formengine.spec.ts` | 169 | NEW | FormEngine field widgets (vault-secret-input, vault-secret-element), password input on new records. |

**Total span:** 4,014 lines; 140 individual test cases.

---

## High-Priority Gaps (Security / Workflow-Critical)

### Gap 1: Clipboard Wipe After Copy (UX-critical, medium risk)

**Pathway:** Secret value revealed → user clicks "Copy" → AJAX posts secret → success toast → button text changes to "Copied!" → **2 seconds later, button text reverts AND clipboard variable is cleared** (line 125–128, `SecretReveal.js`).

**Current coverage:** None. The copy interaction is tested in `security.spec.ts` but **does NOT assert clipboard persistence or timeout-based clearing**.

**Why this matters:**
- User relies on 2-second window to paste; if clipboard persists > 2s, accidental paste into logs/chat is a security regression.
- Timeout-based wipe (`setTimeout(..., 2000)`) is fragile if delayed by slow test environment.

**Suggested test scenario (Given/When/Then):**

```
Given: A revealed secret in the modal
When:  User clicks "Copy to clipboard" button
Then:  Success toast appears
AND:   Button text changes to "Copied!"
AND:   navigator.clipboard.writeText is called with the secret value
AND:   After 1.5 seconds, button text has NOT yet reverted
AND:   After 2.1 seconds, button text reverts to original (e.g., "Copy")
AND:   The secretValue variable is null (cannot paste again after timeout)
```

**Implementation hint:** Use `page.clock.install()` to fast-forward time, mock `navigator.clipboard`, spy on the variable state (or check DOM state after timeout).

---

### Gap 2: Unsaved-Changes Warning on Multi-Tab Edit Conflict

**Pathway:** Tab A opens secret edit form → Tab B also opens the same secret → Tab A user modifies description → Tab B user modifies title → Both click Save.

**Current coverage:** `security.spec.ts` has "Concurrent edit — second save wins without 500" but **does NOT test the UI warning/confirmation that should appear** when the user on Tab B realizes their edits are stale.

**Why this matters:**
- TYPO3 FormEngine typically shows "This record has been modified by another user" warning (or similar via DataHandler hooks).
- If this warning is missing or not tested, users may silently lose edits without realizing.

**Suggested test scenario:**

```
Given: Two browser tabs open the same secret edit form
When:  Tab A modifies the description field and clicks Save
AND:   Tab B modifies the title field (unaware of Tab A's change)
AND:   Tab B user clicks Save (second save)
Then:  One of:
        a) A modal/callout warns "Record was modified by another user" 
           and offers "Reload" / "Overwrite" choices (test both outcomes)
        b) The save is rejected with a 409 Conflict response
AND:   The audit log shows both saves (Tab A first, Tab B second)
```

**Implementation hint:** Use `context.newPage()` twice with same credentials; coordinate via page.clock or DB-inserted delay on the backend side.

---

### Gap 3: Clipboard API Permission Denial Graceful Fallback

**Pathway:** User clicks "Copy" on a revealed secret → `navigator.clipboard.writeText()` throws `NotAllowedError` (e.g., browser denies clipboard access, HTTPS is required but page is HTTP, or Playwright test context lacks permission).

**Current coverage:** None. `SecretReveal.js` line 114–132 has a try/catch and calls `Notification.error(...)` on failure, but **no E2E test verifies this fallback**.

**Why this matters:**
- If clipboard API is unavailable, users should still see the secret (revealed) and an informative error, not a JS exception or silent failure.
- Playwright may not always have clipboard permissions in all test environments (especially CI).

**Suggested test scenario:**

```
Given: A revealed secret with copy button visible
When:  The browser context does NOT have clipboard permission
AND:   User clicks "Copy to clipboard"
Then:  An error notification appears: "Failed to copy to clipboard" or similar
AND:   The secret value remains visible (not cleared)
AND:   The button does NOT change state (remains in "Copy" text)
AND:   No JS exception in browser console
```

**Implementation hint:** Mock `navigator.clipboard.writeText` to reject; use `page.evaluate(() => { navigator.clipboard = undefined; })` or similar.

---

### Gap 4: Identifier Validation on Create/Edit Collision

**Pathway:** Identify UP-SEC-004 currently tests "duplicate identifier → submit → see error OR redirected to list" (line 346–348, `secrets.spec.ts`), accepting either outcome. This is a **security test gap**: duplicates MUST fail.

**Current coverage:** PARTIAL. The test uses `expect(hasError || redirectedToList).toBe(true)` instead of strictly `expect(hasError).toBe(true)`.

**Why this matters:**
- If a regression allows the second secret to overwrite the first (silently replacing the value), the test would still pass because `redirectedToList` is true.
- This violates the vault security model: identifiers are immutable unique keys.

**Suggested test scenario (tighten existing test):**

```
Given: A secret with identifier "vault_db_password" already exists
When:  User attempts to create a NEW secret with the SAME identifier
Then:  The form shows an inline validation error: "Identifier already exists"
AND:   The form is NOT submitted
AND:   The original secret's value is unchanged (audit log shows no "create" entry)
```

**Implementation hint:** Change line 346–348 assertion from `||` to strict `expect(hasError).toBe(true)`; verify the error message text.

---

### Gap 5: FormEngine Read-Only Field Interaction After Secret Readonly PR #142

**Pathway:** PR #142 converted `Secret` entity to `readonly`. Unknown whether the FormEngine widget (`vault-secret-input.js`) correctly handles read-only mode on the UI side (disabled input, no edit button, or similar).

**Current coverage:** `tca/formengine.spec.ts` tests basic FormEngine load but **does NOT explicitly test read-only mode or disabled-field UI state**.

**Why this matters:**
- TYPO3 v14 uses `#[ReadOnly]` attributes; if the FormEngine widget doesn't respect this, users might attempt to edit a field that the backend rejects.
- The UX should clearly indicate "read-only" (grayed out, disabled cursor, tooltip).

**Suggested test scenario:**

```
Given: A secret marked as read-only in the TCA
When:  Admin navigates to the edit form
Then:  The secret value input field is disabled or read-only (CSS class, disabled attribute, or ARIA)
AND:   The "Edit" button (if present) is hidden or disabled
AND:   A tooltip/icon indicates "Read-only field"
AND:   User cannot click into the field
```

**Implementation hint:** Check for `aria-readonly="true"`, `disabled` attribute, or `.form-control:disabled` CSS; inspect `vault-secret-input.js` element in the DOM tree.

---

## Medium-Priority Gaps (Nice-to-Have, UX Polish)

### Gap M1: Pagination UI Assertions

**Coverage:** `audit-extended.spec.ts` tests pagination navigation (Next, Previous, First, Last) but **does NOT assert UI state of pagination controls** (e.g., "Previous" button is disabled on page 1, "Next" is disabled on last page).

**Suggested test:** On page 1, assert `previousButton.isDisabled() === true` and `firstButton.isDisabled() === true`.

---

### Gap M2: Empty Audit Log State

**Coverage:** NONE (accepted limitation per `USER_PATHWAY_COVERAGE.md`). Cannot be tested due to shared DB across tests. **Acceptable since unit/functional tests cover this branch.**

---

### Gap M3: Migration Scan Result Grouping Assertion

**Coverage:** `migration.spec.ts` line 73 navigates to the scan step but **does NOT wait for scan completion** and **does NOT assert the result grouping by severity (high/medium/low)**.

**Suggested test:** Wait for progress indicator to finish; assert `<div class="severity-high">` / `<div class="severity-medium">` elements are present; count grouped items.

---

### Gap M4: Export File Content Schema Validation

**Coverage:** `audit-extended.spec.ts` downloads CSV and parses headers but **does NOT validate row escaping** (e.g., if description contains a comma or newline, is it properly quoted?).

**Suggested test:** Create a secret with `description="Test, with comma"` and `description="Test\nwith newline"`; export CSV; parse and assert fields are correctly unescaped.

---

### Gap M5: Filter Combination Persistence Across Pagination

**Coverage:** `audit-extended.spec.ts` tests "combined filters with pagination" but **does NOT re-assert that the filters are still active on page 2**.

**Suggested test:** Apply filter (e.g., action=read) → click Next → assert the new page still shows only "read" entries (no "create" or "delete").

---

### Gap M6: Focus Management on Modal Dismiss

**Coverage:** NONE. SecretReveal.js uses `Modal.confirm()` and `Modal.dismiss()` but **no test verifies focus is returned to the trigger button after dismiss**.

**Suggested test:** Click reveal button → modal opens → user presses Escape → modal closes → assert focus is back on reveal button (WCAG 2.1 AA requirement).

---

### Gap M7: Form Field Autofocus on Create Page

**Coverage:** NONE. FormEngine may autofocus the identifier field on the create form for UX, but **no test asserts this**.

**Suggested test:** Navigate to `/typo3/module/admin/vault/secrets/create` → assert `document.activeElement` is the identifier input field.

---

## Test Fragility Risks (Existing Specs)

The following patterns in existing specs are potential sources of flakiness in CI:

1. **Line 154–160 in `secrets.spec.ts`** — `waitForResponse(...).catch(() => undefined)` silently swallows timeout errors instead of asserting the response was received. May mask a stalled filter.

2. **Line 45 in `secrets.spec.ts`** — CSS selector `/admin_vault_secrets` is fragile; if the URL slug changes, the test breaks silently.

3. **14 occurrences of `waitForTimeout(N)`** across specs (per `USER_PATHWAY_COVERAGE.md`). Not fixed in the current audit; flagged for follow-up.

4. **Line 158 in `secrets.spec.ts`** — Button selector `:has-text("Filter")` is a substring match; if button text changes to "Apply Filter", the test fails.

5. **Line 348 in `secrets.spec.ts`** — Duplicate identifier test accepts `redirectedToList` as a pass condition, which is a **security regression risk** (see Gap 4 above).

6. **Line 788 in `secrets.spec.ts`** — `test.skip()` without a reason hides whether the scenario is N/A or environment-broken; should use `test.skip(reason)`.

7. **No timeout on `page.waitForLoadState('networkidle')`** (line 66 in `secrets.spec.ts`). If a background fetch stalls, the test hangs indefinitely.

8. **Missing aria-busy checks** — Many async operations (reveal, toggle, rotate) show a spinner but tests don't assert the spinner is visible before the disable (potential race).

9. **No explicit wait for DataHandler post-processing** — After form submission, the test waits for `networkidle` but not for TYPO3's backend post-redirect hooks (audit log write, cache clear). In slow CI, the next page load may see stale data.

---

## Recommended Priority Order

### Tier 1 (P0 — Implement Next Sprint)
- **Gap 1** (Clipboard wipe timeout): High UX/security risk; 1–2 hours.
- **Gap 4** (Identifier collision tightening): Existing test, fix is a 1-line change; 15 min.
- **Gap 5** (Read-only field UI after PR #142): Confirms PR #142 didn't introduce UI regression; 1 hour.

### Tier 2 (P1 — Follow-Up Sprint)
- **Gap 2** (Unsaved-changes warning on edit conflict): Medium risk, 2–3 hours.
- **Gap 3** (Clipboard API fallback): Good defensive UX test; 1–2 hours.
- **Fragility fix** (Replace waitForTimeout, CSS selectors, button text): 3–4 hours across all specs.

### Tier 3 (P2 — Backlog)
- Gap M1–M7: UX polish, WCAG compliance, edge cases; 1–2 hours each.

---

## When New UI Behavior Lands

After PRs #142–#146 and any future work, **audit the modified routes/templates** for new interactive elements:

1. Check `Classes/Controller/<Name>Controller.php` for new view variables.
2. Check `Resources/Private/Templates/<Module>/` for new buttons, inputs, or AJAX handlers.
3. Check `Resources/Public/JavaScript/*.js` for new event listeners or async operations.
4. If any of the above changed, add a corresponding test to the appropriate spec file.

---

## Notes

- **Existing safety net:** Unit tests (1700+) and functional tests (MasterKeyRotation, AjaxController) cover the backend logic; E2E tests focus on **user-facing workflows and JS interactions**.
- **DDEV-only tests:** All 140 tests target a running DDEV instance. CI must ensure DDEV is up before test run.
- **DB isolation:** Each E2E test generates a unique identifier (timestamp + UUID) to avoid collisions. Cleanup (delete created records) is manual; no automatic teardown.

---

**Report generated:** 2026-05-23  
**Audit scope:** READ-ONLY (no modifications to test files)  
**Next action:** Prioritize Tier 1 gaps and assign to the feature/security backlog.
