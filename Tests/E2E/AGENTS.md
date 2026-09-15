<!-- Managed by agent: keep sections and order; edit content, not structure -->
<!-- Last updated: 2026-08-19 | Last verified: 2026-08-19 -->

# AGENTS.md — Tests/E2E

## Overview
Playwright browser E2E tests for the nr-vault TYPO3 backend module. Targets the running DDEV instance.

## Key Files
| File | Purpose |
|------|---------|
| `Tests/E2E/vault-module.spec.ts` | Basic module loading |
| `Tests/E2E/fixtures/auth.ts` | Auth fixture + `getModuleFrame`, `waitForModuleContent` helpers; admin credentials from `E2E_ADMIN_USERNAME` / `E2E_ADMIN_PASSWORD` (DDEV defaults) |
| `Tests/E2E/fixtures/db.ts` | `runSql()` — direct SQL through `E2E_DB_EXEC`, or `ddev mysql -N -B` when unset |
| `Build/Scripts/e2e-provision.sh` | Provisions a TYPO3 instance outside DDEV (CI and local reproduction) |
| `.github/workflows/e2e.yml` | CI job: chromium against TYPO3 13.4 (PHP 8.2) and 14.3 (PHP 8.5) |
| `Tests/E2E/user-pathways/secrets.spec.ts` | Secret CRUD + reveal journey |
| `Tests/E2E/user-pathways/audit.spec.ts` | Audit log workflows |
| `Tests/E2E/user-pathways/migration.spec.ts` | Migration wizard |
| `Tests/E2E/user-pathways/overview.spec.ts` | Dashboard |
| `Tests/E2E/user-pathways/cross-module.spec.ts` | Multi-module interactions |
| `Tests/E2E/accessibility/` | axe-core accessibility assertions |
| `Tests/E2E/USER_PATHWAYS.md` | Journey catalogue |
| `playwright.config.ts` | Project + reporter config (repo root) |

## Golden Samples
| Pattern | Reference |
|---------|-----------|
| Iframe-aware test | `Tests/E2E/user-pathways/secrets.spec.ts` |
| Auth fixture usage | `Tests/E2E/fixtures/auth.ts` |
| Accessibility assertion | `Tests/E2E/accessibility/*.spec.ts` |

## Setup
```bash
# 1. Start the TYPO3 instance
make up

# 2. Install Node dependencies declared in package.json
#    (@playwright/test, @axe-core/playwright, etc.)
npm install

# 3. (First run) install Playwright browsers + system deps
npx playwright install --with-deps
```

## Build/Tests
| Task | Command |
|------|---------|
| All E2E | `npx playwright test` (from repo root) |
| Single file | `npx playwright test user-pathways/secrets.spec.ts` |
| Headed UI | `npx playwright test --ui` |
| Debug | `npx playwright test --debug` |
| Report | `npx playwright show-report .Build/playwright-report` |
| Via make | `make test-e2e` (`npm run test:e2e`) |

### CI (`.github/workflows/e2e.yml`)
CI does not use DDEV. It provisions each TYPO3 line with `Build/Scripts/e2e-provision.sh` (cms-base-distribution + this checkout as a path repository, `typo3 setup`, `extension:setup`, `vault:seed-demo` — the `install-v14` recipe), serves it with PHP's built-in server on `http://127.0.0.1:8080`, uses a MariaDB 10.11 service container, and runs **chromium only** with **one worker**. Every spec logs in as the same backend admin; with parallel workers TYPO3 itself races (a duplicate `core-formProtectionSessionToken:<uid>` row in `sys_registry` answers HTTP 500, overview counters move under other specs, and TYPO3 13 opens the vault parent module on another worker's last-used submodule). Per-worker backend users would allow parallelism again. On failure the artifact `playwright-typo3-<version>` holds the HTML report, traces, the PHP server log and `var/log`.

Reproduce a CI cell locally without DDEV (needs PHP with `pdo_sqlite`, or `mysqli` plus a MariaDB for the `mysqli` driver):
```bash
export E2E_INSTANCE_DIR=/tmp/nr-vault-e2e-v14 TYPO3_VERSION='^14.3' E2E_DB_DRIVER=sqlite
bash Build/Scripts/e2e-provision.sh
PHP_CLI_SERVER_WORKERS=8 php -S 127.0.0.1:8080 -t "$E2E_INSTANCE_DIR/public" "$E2E_INSTANCE_DIR/router.php" &
TYPO3_BASE_URL=http://127.0.0.1:8080 npx playwright test --project=chromium
```
With `E2E_DB_DRIVER=sqlite` the audit-tamper spec skips (it needs a MySQL-compatible client). Against a MariaDB, set `E2E_DB_EXEC="mysql -h127.0.0.1 -uroot -N -B typo3"` and `MYSQL_PWD`; once `E2E_DB_EXEC` is set, a failing client fails that spec instead of skipping it.

## Directory Structure
```
Tests/E2E/
├── fixtures/
│   ├── auth.ts
│   └── db.ts
├── user-pathways/
│   ├── audit.spec.ts
│   ├── cross-module.spec.ts
│   ├── migration.spec.ts
│   ├── overview.spec.ts
│   └── secrets.spec.ts
├── accessibility/
├── tca/
└── vault-module.spec.ts
```

## Code Style
- TypeScript, ES modules.
- Each test fully isolated — generate unique identifiers per run. Vault identifiers must start with a letter and contain only letters/digits/underscores (see `Classes/Utility/IdentifierValidator.php`), so use **underscores, not hyphens**:
  `const uniqueId = \`e2e_test_${Date.now()}_${crypto.randomUUID().slice(0, 8)}\`;`
- Always await inside tests; never mix fire-and-forget promises.
- Prefer role/label locators over CSS selectors.
- No `page.waitForTimeout(ms)` — use `waitForModuleContent` or explicit `waitFor`.
- Group pathways by domain (secrets, audit, migration) rather than by page.

## Security
- **Test credentials** (`admin` / DDEV default) are for local DDEV only — never commit production credentials.
- **Never** point E2E tests at a production instance.
- **Clipboard access** — tests that read clipboard require browser permissions in `playwright.config.ts`.
- **Fixtures** — no real secrets; use identifier-safe placeholders like `fixture_secret_<uniqueId>` (letters/digits/underscores only — see `IdentifierValidator`).

## Checklist
- [ ] Test uses `getModuleFrame(page)` for any assertion inside the module iframe
- [ ] `waitForModuleContent(page)` called after navigation
- [ ] No TYPO3 error page shown: assert absence of "Oops, an error occurred" / "503"
- [ ] Unique identifiers for isolation (no shared state across tests)
- [ ] No `waitForTimeout` — use explicit `waitFor`
- [ ] Accessibility added when a new UI surface is introduced
- [ ] Cleanup: tests delete the records they create

## Examples
### TYPO3 v14 iframe-aware test
```typescript
import { test, expect, getModuleFrame, waitForModuleContent } from '../fixtures/auth';

test('Secrets list renders', async ({ authenticatedPage: page }) => {
  await page.goto('/typo3/module/admin/vault/secrets');
  await waitForModuleContent(page);

  const frame = getModuleFrame(page);
  await expect(frame.locator('h1')).toContainText('Secrets');
  await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();
});
```

### Module URLs
| Module | URL |
|--------|-----|
| Overview | `/typo3/module/admin/vault` |
| Secrets list | `/typo3/module/admin/vault/secrets` |
| Create secret | `/typo3/module/admin/vault/secrets/create` |
| Audit log | `/typo3/module/admin/vault/audit` |

## When Stuck
| Issue | Resolution |
|-------|------------|
| Element not found | Content lives in iframe — use `getModuleFrame(page)` |
| Timeout waiting | Call `waitForModuleContent(page)` after `goto` |
| Flaky tests | Generate unique identifiers; replace `waitForTimeout` with `waitFor` |
| Auth failures | `make up` to ensure DDEV is running; outside DDEV check `E2E_ADMIN_USERNAME` / `E2E_ADMIN_PASSWORD` match the provisioned admin |

- Playwright docs: <https://playwright.dev/docs/intro>
- Invoke skill: `typo3-testing` for PHP-side integration tips
