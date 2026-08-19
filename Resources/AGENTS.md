<!-- Managed by agent: keep sections and order; edit content, not structure -->
<!-- Last updated: 2026-08-19 | Last verified: 2026-08-19 -->

# AGENTS.md — Resources

## Overview
Fluid templates, backend JS/CSS, and XLIFF translation files for the nr-vault TYPO3 extension.

## Key Files
| File | Purpose |
|------|---------|
| `Resources/Private/Templates/Overview/Index.html` | Module landing page (status, shortcuts) |
| `Resources/Private/Templates/Overview/Help.html` | Docheader help tab |
| `Resources/Private/Templates/Secrets/List.html` | Secrets list + reveal/copy UI |
| `Resources/Private/Templates/Audit/List.html` | Audit log listing |
| `Resources/Private/Templates/Audit/VerifyChain.html` | HMAC chain verification view |
| `Resources/Private/Templates/Migration/*.html` | Migration wizard steps |
| `Resources/Private/Language/locallang_mod.xlf` | Main translation catalogue |
| `Resources/Public/JavaScript/SecretsList.js` | List interaction + AJAX reveal/rotate modals |
| `Resources/Public/JavaScript/vault-reveal-lifecycle.js` | Shared auto-hide/wipe guard for revealed plaintext |
| `Resources/Public/JavaScript/vault-secret-input.js` | TCA field widget |
| `Resources/Public/Css/backend.css` | Backend module styles |

## Golden Samples
| Pattern | Reference |
|---------|-----------|
| Fluid template with docheader | `Resources/Private/Templates/Overview/Index.html` |
| List/detail view | `Resources/Private/Templates/Secrets/List.html` |
| AJAX-driven JS module | `Resources/Public/JavaScript/SecretsList.js` |
| TCA input widget | `Resources/Public/JavaScript/vault-secret-input.js` |
| XLIFF structure | `Resources/Private/Language/locallang_mod.xlf` |

## Setup
- Templates consumed by `Classes/Controller/*Controller.php`
- JS loaded via `ext_localconf.php` / backend module registration
- XLIFF keys referenced in PHP as `LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:<key>`

## Build/Tests
| Task | Command |
|------|---------|
| Render templates (integration) | `make test-functional` |
| E2E through UI | See `Tests/E2E/AGENTS.md` |
| CS for JS (none yet) | `make lint` (PHP only) |

## Directory Structure
```
Resources/
├── Private/
│   ├── Language/        # XLIFF translations (locallang_mod.xlf + locales)
│   ├── Layouts/         # Fluid layouts
│   ├── Partials/        # Fluid partials
│   └── Templates/
│       ├── Audit/
│       ├── Migration/
│       ├── Overview/
│       └── Secrets/
└── Public/
    ├── Css/
    ├── Icons/
    └── JavaScript/
```

## Code Style
- **Fluid**:
  - Prefer `{variable -> f:format.htmlspecialchars()}` where raw rendering is needed; `{variable}` is auto-escaped.
  - Use `<f:be.pageRenderer>` for backend modules; `<f:be.container>` for docheader.
  - Keep logic in controllers — templates stay declarative.
- **JavaScript**:
  - ES modules (`import`/`export`), no jQuery.
  - Use TYPO3 backend APIs: `@typo3/backend/modal.js`, `@typo3/backend/notification.js`, `@typo3/core/ajax/ajax-request.js`.
  - CSP-compliant: no inline handlers, no `eval`.
- **CSS**: scope to `.module-body` / module-specific classes; no global resets.
- **XLIFF**: one `<trans-unit id="..."><source>...</source></trans-unit>` per string; keep IDs stable.

## Security
- **Auto-escape** — never `<f:format.raw>` on user-controlled values (secrets, identifiers, audit context).
- **CSP** — inline `<script>` forbidden; load JS via `<f:be.pageRenderer includeJsModules="...">`.
- **No secrets in templates** — secret values arrive via AJAX at reveal time, rendered to a short-lived container, then cleared.
- **No client-side secret cache** — every reveal MUST re-hit `vault_reveal` so `VaultService::retrieve()` writes an audit row. Never keep the plaintext in a JS field/Map across modal opens.
- **Bounded exposure** — plaintext revealed from the server goes through `startRevealLifecycle()` (`vault-reveal-lifecycle.js`): auto-wipe after `AUTO_HIDE_SECONDS`, plus immediate wipe on `visibilitychange` (hidden) and `pagehide`. JS strings cannot be zeroized — the guarantee is a short exposure window, not cleared memory.
- **Clipboard** — use `navigator.clipboard.writeText`, and only when the reveal response reports `copyAllowed !== false` (the hardened security profile disables copy: the clipboard outlives the dialog).
- **AJAX** — routes declared in `Configuration/Backend/AjaxRoutes.php`; CSRF protected by `@typo3/core/ajax/ajax-request.js`.

## Checklist
- [ ] New XLIFF keys added to base `locallang_mod.xlf` and referenced from PHP/Fluid
- [ ] Fluid output escaping verified (no `format.raw` on secret/user data)
- [ ] JS modules use `@typo3/backend/*` imports — no direct DOM globals
- [ ] No inline event handlers (CSP)
- [ ] Images optimized; stored under `Resources/Public/Icons/`
- [ ] Functional test exercising the controller → template render path

## Examples
```html
<!-- Backend module layout -->
<html xmlns:f="http://typo3.org/ns/TYPO3/CMS/Fluid/ViewHelpers"
      data-namespace-typo3-fluid="true">
  <f:layout name="Module"/>
  <f:section name="Content">
    <h1>{f:translate(key:'title.secrets')}</h1>
    <f:render partial="Secrets/ListTable" arguments="{secrets: secrets}"/>
  </f:section>
</html>
```

```js
// Backend JS module entry point
import Notification from '@typo3/backend/notification.js';
import AjaxRequest from '@typo3/core/ajax/ajax-request.js';

class RevealModal {
  async reveal(id) {
    const resp = await new AjaxRequest(TYPO3.settings.ajaxUrls['vault_reveal'])
      .post({ id });
    const body = await resp.resolve();
    // render, then wipe via startRevealLifecycle() — see vault-reveal-lifecycle.js
  }
}
```

## When Stuck
- Check `Classes/Controller/` for the assigned variables
- XLIFF reference: <https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/Internationalization/>
- Fluid ViewHelpers: <https://docs.typo3.org/other/typo3/view-helper-reference/main/en-us/>
- Backend JS modules: <https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/ApiOverview/JavaScript/>
