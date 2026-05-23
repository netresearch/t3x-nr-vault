# nr-vault UI/UX/DX Audit

**Reviewer:** Frontend Architect agent
**Date:** 2026-05-23
**Scope:** `Resources/Public/JavaScript/`, `Resources/Public/Css/`, `Resources/Private/{Templates,Partials,Layouts}/`, `Resources/Private/Language/`, `Classes/Controller/{SecretsController,AjaxController}.php`, `Classes/Form/Element/VaultSecret*Element.php`, plus verification reads in `Classes/Service/VaultService.php` and `Configuration/Backend/AjaxRoutes.php`.

## Executive summary

The module sits on a solid TYPO3-native foundation: native v14 ESM modules, `f:asset.module`, `Modal`/`Notification`/`Severity` APIs, an interface-driven `VaultAdapterInterface`, and broadly conscientious table semantics (scoped `<th>`, captions, `aria-label`, `role="region"`/`role="status"`). Three structural problems undermine that quality, however. First, the JavaScript reveal cache (`this.revealedSecrets = new Map()`) short-circuits the AJAX call on second-and-subsequent reveals, which means no `AuditLogService::log()` row is written — a direct violation of root AGENTS.md security rule #5 ("Audit every access"). Second, user-visible English strings are pervasive in JavaScript (~40 `Notification`/`Modal` literals) and in two Fluid templates (`VerifyChain.html`, `List.html` empty-states), so the `de.locallang_mod.xlf` translator cannot localise the most security-critical messages. Third, the forensic chain-break view tells the admin "may have been tampered with" but offers no guidance on what to preserve, no entry-range, and an inconsistent JS-side modal/`confirm()` pattern (`vault-secret-element.js:190` falls back to native `window.confirm`). Beyond these, smaller wins are obvious: focus management on modals, deduplicating the delete-confirm dialog (it lives twice), date-range presets for the audit filter, and exposing DOM `CustomEvent`s so downstream extensions can hook the reveal/rotate flows.

---

## 1. Accessibility

### A1. Native `confirm()` instead of TYPO3 Modal — HIGH
`Resources/Public/JavaScript/vault-secret-element.js:190`
```js
if (confirm('Are you sure you want to clear this secret? This action cannot be undone.')) {
```
Native `window.confirm` cannot be styled, is announced by screen readers as a generic system dialog (no `aria-describedby`, no focus trap reset to the trigger after dismissal), and is blocked by some user preferences. The rest of the codebase uses `Modal.confirm(..., Severity.warning, [...])` (e.g. `SecretsList.js:47-67`). Use the same pattern here.

### A2. Reveal-modal label is unassociated — MEDIUM
`Resources/Public/JavaScript/SecretsList.js:383-394` builds the modal DOM:
```js
const label = document.createElement('label');
label.className = 'form-label fw-bold';
label.textContent = 'Secret Value';
…
input.id = 'reveal-modal-secret';
```
No `label.setAttribute('for', 'reveal-modal-secret')`. Compare with the rotate modal at `:424` which correctly sets `for`. Assistive tech will not announce the input label.

### A3. No focus management on modal open/close — MEDIUM
The reveal modal in `SecretsList.js:228-273` opens, but never moves focus to the readonly input or the close button. The rotate modal (`:310-326`) focuses the input via a 100ms `setTimeout` (see A4). On close, neither modal restores focus to the triggering row button. WCAG 2.1 SC 2.4.3 (Focus Order) expects predictable restoration.

### A4. `setTimeout(..., 100)` race for modal handlers — MEDIUM
`SecretsList.js:247` and `:310`:
```js
setTimeout(() => {
    const toggleBtn = document.getElementById('reveal-modal-toggle');
```
A user clicking the visibility toggle within 100 ms of modal open hits a null listener silently. TYPO3 v14's `Modal.advanced()` returns a `modal` element that dispatches `typo3-modal-shown` — bind listeners to that event instead, or pass `callback:` into `Modal.advanced` per the v14 API.

### A5. Verify-chain page lacks live region for async results — LOW
`Resources/Private/Templates/Audit/VerifyChain.html` renders a static infobox; when triggered via `vault-backend.js` (`Notification.success/error`) the dynamic result is announced, but the on-page card lacks `role="status"`/`aria-live="polite"`. The list view's stats badge (`Audit/List.html:64`) gets this right and is the pattern to copy.

### A6. Icon-only buttons OK, with one regression — LOW
Most icon buttons in `Secrets/List.html` carry an explicit `aria-label` (`:125, :132, :150, :162, :172`). The `vault-backend.js:26` spinner replacement clobbers the trigger's original children including the icon's `aria-hidden` wrapper, and the loading text " Verifying..." is appended without an `aria-live` region — acceptable since `Notification` covers the announcement, but the in-place button text isn't read.

### A7. Custom focus ring is good — credit
`Resources/Public/Css/backend.css:112` provides `outline: 2px solid var(--nr-primary); outline-offset: 1px;` on `:focus-visible`. This is a strict win over Bootstrap's default and meets SC 2.4.7.

---

## 2. DX (downstream extension authors)

### D1. No JS-side extension surface — MEDIUM
`SecretsList.js`, `SecretReveal.js`, `vault-secret-element.js` are all `default export` classes that self-instantiate on DOM ready. There is no public API — no DOM `CustomEvent` (`vault:reveal:before`, `vault:reveal:after`, `vault:rotate:after`) — so a downstream extension cannot append a "send to password manager" action, augment audit context, or veto a reveal. Fix: dispatch typed `CustomEvent`s on `document` (or the row element) at each lifecycle point, and document them alongside the AJAX shapes.

### D2. AJAX response shape undocumented — MEDIUM
`Classes/Controller/AjaxController.php` returns `{success, secret}` (`:72`), `{success, error}` (`:54, :77, :84, :91, :96`), `{success, message, version}` (`:151`). The shape is consistent and well-formed but lives only in PHP — the developer documentation does not enumerate it for downstream authors. Add a brief "AJAX contract" page (table per route: method, request body, response shapes, error codes) under `Documentation/Developer/` so external consumers don't have to read the controller.

### D3. `VaultAdapterInterface` is a real extension seam — credit
`Classes/Adapter/VaultAdapterInterface.php` cleanly separates `store/retrieve/delete/exists/list/listSecrets/getMetadata/updateMetadata/incrementReadCount`. Adding a Hashicorp/AWS adapter is a matter of implementing this and tagging in `Services.yaml`. Strong DX baseline.

### D4. Duplicate delete-confirm code — LOW
`SecretReveal.js:144-171` and `SecretsList.js:40-68` are line-for-line near-identical. Extract a shared `vault/confirm-delete.js` helper exporting `confirmDelete(identifier, onConfirm)`.

### D5. Hard-coded English `console.error` — LOW
`vault-secret-input.js:67, :109` and `vault-secret-element.js:105, :178` write English to the console. Acceptable for developer logs, but be consistent (everywhere or nowhere).

---

## 3. UX of the secret reveal flow

### R1. Reveal cache bypasses audit log — HIGH (security/UX boundary) — **fixed in [#151](https://github.com/netresearch/t3x-nr-vault/pull/151)**
`SecretsList.js:12` initialises `this.revealedSecrets = new Map()` and `:187-190`:
```js
if (this.revealedSecrets.has(identifier)) {
    this.showRevealModal(identifier, this.revealedSecrets.get(identifier));
    return;
}
```
Cross-checked: `Classes/Service/VaultService.php:158` writes `auditLogService->log($identifier, 'read', true)` only when `retrieve()` is actually called. So once a secret is revealed in a session, every subsequent reveal/copy by the same admin is invisible to the audit log. Same anti-pattern in `vault-secret-input.js:72-75` and `vault-secret-element.js:65-68`. Fix options: (a) drop the cache entirely — reveals are rare and the round-trip is cheap; (b) keep the cache but POST a lightweight `cache_hit: true` ping so the audit row is still written; (c) auto-expire the cache after N seconds and force a re-fetch. Option (a) is the cleanest and respects the "audit every access" rule literally.

### R2. No audit visibility cue at reveal time — MEDIUM
The UI never tells the admin "your reveal will be recorded in the audit log." A small `text-body-secondary` line in the reveal modal — "This action is logged. View the audit log →" — closes the loop and aligns with the security-by-design messaging the Overview page already adopts.

### R3. Reveal modal never clears the revealed value — MEDIUM
The modal closes via `Close` button (`SecretsList.js:241`) but `this.revealedSecrets` still holds the plaintext, and the modal DOM is destroyed without `sodium`-style scrubbing (impossible in JS, but a `secret = ''` after copy and Map.delete on dismiss approximates the intent). Add a `modal.on('typo3-modal-hidden', () => this.revealedSecrets.delete(identifier))` to bound the in-memory exposure.

### R4. No focus-out auto-hide — MEDIUM
`SecretReveal.js:59-67` reveals into a persistent input field on a page (the FormEngine view) — switching tabs or windows leaves the secret in plaintext indefinitely. A `window.addEventListener('blur', () => this.hideSecret())` or `document.addEventListener('visibilitychange', …)` mirrors common password-manager UX.

### R5. `confirm()` regression — see A1.

### R6. Copy timeout is 2s but no auto-clear of clipboard — LOW
`SecretsList.js:266` toasts "Secret copied to clipboard" but the clipboard is not wiped after a timeout. Browsers don't expose a reliable clipboard-clear API to extensions, but the UI should at least warn ("The clipboard still contains this secret"). Out of scope for a frontend-only fix; document the constraint in the toast.

---

## 4. UX of the audit log view

### AL1. Forensic implication is undersold — MEDIUM
`Resources/Private/Templates/Audit/VerifyChain.html:18`:
```html
<f:be.infobox title="…audit.chain_invalid" state="2">
    Hash chain verification failed. The audit log may have been tampered with.
</f:be.infobox>
```
Two problems: (1) the body is a hard-coded English string (see I1); (2) it doesn't tell the admin what to do — "the chain is broken between entry #X and #Y. Entries after #Y cannot be relied upon. Snapshot the table now and notify your security officer." A chain break is a forensic event and the UI should treat it as one.

### AL2. Date filter has no time component or presets — MEDIUM
`Audit/List.html:45, :49`:
```html
<input type="date" id="filter-since" name="since" …>
<input type="date" id="filter-until" name="until" …>
```
For incident response the relevant window is often "the last 30 minutes." Add quick-presets ("last hour", "today", "7 days") and switch to `datetime-local` for at least the `from` field.

### AL3. No filter for "actor" or "action result" combinations — LOW
Filters cover identifier, action, success, since, until — but not actor. When investigating "what did backend user X do?" the admin has to grep the page. Add a be-user dropdown (the data already exists; see `SecretsController::getOwnerOptions`).

### AL4. Inline `style="width: 100px;"` — LOW
`Audit/List.html:79-84` uses inline `style` attributes for column widths. Strict CSP `style-src` would block this; move to `.col-time`, `.col-action`, `.col-status` utility classes in `backend.css`.

### AL5. Pagination is reachable but the page-input is read-only — LOW
`Audit/List.html:156-158` shows `Page {currentPage} / {totalPages}` as a `<span>`. Admins on multi-thousand-entry logs cannot jump. Convert to a number input or a dropdown of decade-pages.

### AL6. Grouped-by-date semantics are good — credit
`:72-74` groups rows under a `<h2>` per date and wraps each table in `role="region" aria-label="Audit log entries for {date}" tabindex="0"`. Solid screen-reader navigation.

---

## 5. UX of master-key rotation

### MK1. No backend-module UI — by design, but undocumented — MEDIUM
Master-key rotation is **CLI-only** (`Classes/Command/VaultRotateMasterKeyCommand.php`), referenced from `Resources/Private/Templates/Overview/Index.html:270` and `Overview/Help.html:89` only as documentation. There is **no UI confirmation, progress, or scope-of-impact card.** This is defensible — destructive long-running ops benefit from CLI friction — but the Help page should call it out explicitly: "Master-key rotation is intentionally CLI-only. Run `bin/typo3 vault:rotate-master-key --dry-run` first." Right now the user-facing copy at `Help.html:89` says "This re-encrypts all DEKs" without timing/lock guidance.

### MK2. No health-check warning when master key looks stale — LOW
`Overview/Index.html:43-48` shows a green "encryption active" alert when the master key is available, but no concept of "your master key hasn't been rotated in N days." The data model knows when each DEK was wrapped; surface a yellow alert at, say, 365 days.

---

## 6. i18n coverage

### I1. Hard-coded English in dynamic security messages — HIGH
`Resources/Private/Templates/Audit/VerifyChain.html:13`:
```html
The audit log hash chain has been verified successfully. No tampering or modifications have been detected.
```
And `:18`:
```html
Hash chain verification failed. The audit log may have been tampered with.
```
Body text is the most security-critical copy in the module and it is untranslated. The titles use `f:translate` correctly — extend the same to the bodies. Add `audit.chain_valid.description` and `audit.chain_invalid.description` keys to `locallang_mod.xlf`.

### I2. JS Notification/Modal strings all hard-coded — HIGH (structural)
Searched all `Resources/Public/JavaScript/*.js`: ~40 user-visible English literals across `Notification.success/error/warning` and `Modal.advanced/confirm` calls. Examples:
- `SecretsList.js:47` — `'Delete Secret'`, `:49` — `'Are you sure you want to delete the secret "..."? This action cannot be undone.'`
- `SecretsList.js:194` — `'Loading Secret'`, `:232` — `'Secret Value'`, `:289` — `'Rotate Secret: ' + identifier`
- `SecretsList.js:266` — `'Copied'`, `:268` — `'Failed to copy to clipboard'`
- `vault-secret-element.js:107, :161, :169, :180, :190` — all English.

There is no JS i18n helper at all. The fix is structural: assign relevant translations to `TYPO3.lang` via `<f:be.pageRenderer>` in the host template (or use the `lang.xlf` JS module pattern via `<typo3-backend-language-labels>`), then read `TYPO3.lang['vault.modal.deleteTitle']` from JS. This is one piece of work that retires ~40 findings.

### I3. Fluid empty-state titles untranslated — MEDIUM
`Secrets/List.html:192`: `<f:be.infobox title="No Secrets Found" state="-1">` — title literal English; body uses `f:translate`. Same shape in `Audit/List.html:191`: `<f:be.infobox title="No Audit Entries" state="-1">`. Add keys `secrets.empty.title`, `audit.empty.title`.

### I4. Fluid heading hard-coded — LOW
`Audit/VerifyChain.html:47` — `<h2 class="card-title">Warnings</h2>`. The list page heading on `Audit/List.html:65` does the same: `<span class="badge text-bg-info">{totalCount} entries</span>` and `<span class="badge text-bg-secondary">Page {currentPage} of {totalPages}</span>`.

### I5. Table footer untranslated — LOW
`Secrets/List.html:184`: `<span class="text-body-secondary">{totalCount} secrets total</span>`.

### I6. XLIFF key consistency — credit
596 `trans-unit` entries; key namespacing (`secrets.*`, `audit.*`, `overview.*`, `migration.*`) is disciplined. The base file at `Resources/Private/Language/locallang_mod.xlf` is the single source of truth.

---

## 7. Fluid template idiomaticity

### F1. Empty `Partials/` and missing `Layouts/` directories — LOW
`Resources/Private/Partials/` contains only `.gitkeep`; `Resources/Private/Layouts/` doesn't exist. `<f:layout name="Module"/>` resolves to TYPO3 core — which is fine — but the audit-row, filter-bar, and pagination markup are copy-pasted across `Secrets/List.html`, `Audit/List.html`, and the migration templates. Extract `Partials/FilterBar.html`, `Partials/Pagination.html`, `Partials/EmptyState.html`.

### F2. Namespace declarations are clean — credit
All templates use `xmlns:f="…" xmlns:core="…" data-namespace-typo3-fluid="true"` and avoid the legacy `{namespace f=…}` form. `core:icon` is used everywhere appropriately.

### F3. No `f:format.raw` on user-controlled data — credit
Searched: zero occurrences across `Resources/Private/`. Good escaping discipline.

### F4. Inline JS-only attributes (`data-vault-*`) are good — credit
The reveal/rotate/toggle/delete dataset binding (`data-vault-reveal="{secret.identifier}"` at `Secrets/List.html:122`) keeps templates declarative and JS testable. Match this with BEM-ish CSS (already partly there: `.t3js-vault-toggle-visibility`, `.t3js-vault-copy`, `.t3js-vault-clear`).

### F5. CSRF on raw `fetch()` — MEDIUM (informational)
`SecretsList.js:202`, `SecretReveal.js:75`, `vault-secret-input.js:86`, `vault-secret-element.js:85` all use raw `fetch()`. `Configuration/Backend/AjaxRoutes.php` declares `'access' => 'admin'` with no per-route token requirement, and TYPO3 backend cookies are `SameSite=Lax`, so CSRF is mitigated at the framework level. However, `Resources/AGENTS.md` (the JS section under *Security*) explicitly states "CSRF protected by `@typo3/core/ajax/ajax-request.js`" — the four JS call-sites contradict that documented contract. Either update the rule or migrate the four call-sites to `AjaxRequest` (as `vault-backend.js:29` already does).

### F6. `.badge !important` override — LOW
`Resources/Public/Css/backend.css:91-93` uses `!important` to brand `text-bg-info`/`text-bg-primary`. Specificity-only would be cleaner (`.vault-module .badge.text-bg-info`). Cosmetic.

---

## Summary of severities

| Severity | Count | Headline items |
|----------|-------|----------------|
| HIGH | 4 | R1 reveal cache bypasses audit log; A1 `confirm()` regression; I1 hard-coded VerifyChain body; I2 ~40 untranslated JS strings |
| MEDIUM | 13 | A2-A4 modal a11y; D1-D2 missing JS API + AJAX docs; R2-R4 reveal UX (audit cue, lifetime, focus-out); AL1-AL2 forensic copy + date presets; MK1 master-key UI documentation; I3 empty-state titles; F1 missing partials; F5 raw fetch vs. AGENTS.md |
| LOW | ~10 | A5-A6 live regions, D4-D5 duplication, AL3-AL5 audit polish, MK2 stale-key warning, I4-I5 minor strings, F6 CSS |

Total ~27 findings. Two structural fixes (drop the in-memory reveal cache; wire up a JS i18n channel via `TYPO3.lang`) resolve roughly half by themselves.

**Recommended order of work:**
1. R1 (audit-bypass) — security-critical, one-line fix.
2. I2 (JS i18n channel) — unlocks I1/I3/I4/I5 in one PR.
3. A1 (replace `confirm()`) — small, raises overall a11y floor.
4. A2-A4 (modal focus + label association + event-based init).
5. AL1 (forensic chain-break copy) — pair with I1.
6. D1 + D2 (DOM CustomEvents + AJAX contract docs).
7. The rest, ordered by severity.
