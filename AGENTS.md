<!-- FOR AI AGENTS - Human readability is a side effect, not a goal -->
<!-- Managed by agent: keep sections and order; edit content, not structure -->
<!-- Last updated: 2026-08-19 | Last verified: 2026-08-19 -->

# AGENTS.md — nr-vault

> Secure secrets management for TYPO3 (envelope encryption, access control, tamper-evident audit log).

**Precedence:** the **closest `AGENTS.md`** to the files you're changing wins. Root holds global defaults only. Explicit user prompts override files.

## Project Overview

- **Stack:** PHP 8.2+, TYPO3 ^13.4 || ^14.3, libsodium (XChaCha20-Poly1305 / AES-256-GCM envelope encryption). Version: see `ext_emconf.php`.
- **Environment:** DDEV for local development · **License:** GPL-2.0-or-later
- **Namespace:** `Netresearch\NrVault\` (PSR-4 from `Classes/`) · **Extension key:** `nr_vault`
- **Component map + key interfaces + CLI command list:** `docs/ARCHITECTURE.md`

## Commands
> Source: `Makefile` (primary) and `composer.json` scripts

| Task | Command | Notes |
|------|---------|-------|
| Start env | `make up` | DDEV + install TYPO3 v14 |
| Stop env | `make down` | |
| Shell | `make shell` | Container shell |
| Lint (syntax) | `make lint` | `php -l` across sources |
| CS check | `make cgl` | php-cs-fixer --dry-run |
| CS fix | `make fix` | alias of `make cgl-fix` |
| PHPStan | `make phpstan` | Static analysis. Locally use `.Build/bin/phpstan analyse --configuration=Build/phpstan.no-plugins.neon` — the plugin config dies on `Unexpected item 'parameters › ergebnis'` even with a fully populated `.Build`, because the ergebnis ruleset resolves only through the shared typo3-ci-workflows config on CI |
| Rector (dry-run) | `make rector` | |
| Unit tests | `make test-unit` | `composer ci:test:php:unit` |
| Functional tests | `make test-functional` | `composer ci:test:php:functional` |
| All tests | `make test` | unit + functional |
| Mutation tests | `make test-mutation` | Infection |
| All CI | `make ci` | cgl + phpstan + unit + fuzz (no lint/rector/functional) |
| Docs render | `make docs` | |

**Test execution ALWAYS goes through `Build/Scripts/runTests.sh`** (or the composer wrappers around it, e.g. `composer test:unit` / `test:functional`) — the TYPO3 core-style containerized runner with its own ephemeral containers. NEVER run tests inside DDEV (`ddev exec phpunit`); DDEV is the dev *environment*, not the test runner. Single file: `Build/Scripts/runTests.sh -s unit Tests/Unit/Path/ToTest.php`.

Direct composer (without make): `composer ci` — unit + fuzz + phpstan + arch (phpat) + doc-cli drift + evidence + cgl; `composer ci:test:php:functional` — functional suite; `composer ci:cgl` — fix code style.

## Workflow
1. **Before coding**: Read nearest `AGENTS.md` + inspect its Golden Samples (`Classes/AGENTS.md`, `Tests/AGENTS.md`, …).
2. **After each change**: Run the smallest relevant check (`make lint` → `make phpstan` → single test).
3. **Before committing**: `make ci` when changes affect >2 files or touch shared code.
4. **Before claiming done**: Run verification and **paste output as evidence** — never say "should work now" / "tested" / "all green" without showing output.
5. **Response style**: answer first, skip preamble, match length to task; no sycophantic openers.

## File Map
```
Classes/         → PHP sources (see Classes/AGENTS.md + docs/ARCHITECTURE.md for the component map)
Configuration/   → TYPO3 config (TCA, Backend routes, Services.yaml)
Documentation/   → reStructuredText docs + ADRs (Documentation/Developer/Adr/)
Resources/       → Templates (Fluid), JS/CSS, XLIFF language files
Tests/           → Unit + Functional + Fuzz + Architecture + E2E (Playwright)
Build/           → runTests.sh, phpunit.xml, FunctionalTests.xml, verify-harness.sh
docs/            → Agent-facing docs: ARCHITECTURE.md, exec-plans/
.ddev/           → DDEV environment (mock-oauth sidecar, phpunit extras)
.github/         → workflows, CODEOWNERS, renovate, labeler
```

## Heuristics
| When | Do |
|------|-----|
| Adding class | PSR-4 under `Classes/`, namespace `Netresearch\NrVault\*` |
| New command | `Classes/Command/` + register in `Configuration/Services.yaml` |
| AJAX route | Add to `Configuration/Backend/AjaxRoutes.php` + controller in `Classes/Controller/` |
| New backend submodule | Follow the 4-step completeness recipe in `Classes/AGENTS.md` (module registration, overview card, docs + screenshot, coverage). Not done = incomplete feature. |
| Touching secrets | Audit log every read/write via `AuditLogServiceInterface::log()`; invariants in `Classes/AGENTS.md` |
| Running locally | `make up` then `make shell` |
| Committing | Subject-style enforced by `captainhook.json`: capitalized, imperative mood, length-limited, no trailing period (NOT lowercase `feat:`/`fix:` prefixes). Sign off with `git commit -s`. See CONTRIBUTING.md |
| Merging PRs | Merge commit (not squash, not rebase) — preserves GPG signatures |

## Pre-push gate gotchas (cost real CI round-trips)

- **php-cs-fixer's cache masks violations**: a cached-clean file reports `files:[]` locally while fresh-checkout CI fails Code Style. Pre-push check with `--using-cache=no`; CI's fixer version may also be newer than local.
- **`no_unused_imports` strips an import added before its first usage** (import in one edit, usage in a later one, fixer run between) — CI then dies with `Class … not found`. After appending test methods, re-check their imports.
- **Cross-worktree Rector/fixer runs produce false positives**: `main`'s `.Build/bin/rector` resolves classes via main's autoloader, not the branch's — signature changes misfire `RemoveExtraParametersRector`, and rules needing a new interface method fire only in CI. Judge each finding: real, or cross-worktree artifact?
- **`RemoveDefaultArgumentValueRector` strips load-bearing trailing args** that equal the default (`verifyHashChain(null, null, 0)` → `verifyHashChain()`); keep them with a named argument (`verifyHashChain(minEpoch: 0)`), which the rule leaves alone.
- **Opengrep vs Rector on `unlink`**: Rector's first-class-callable rewrite turns cleanup loops into `array_map(unlink(...), …)`, which Opengrep flags. Sidestep both — use `GeneralUtility::rmdir($path, true)` for tempdir cleanup.
- **A `.Build` copied from a sibling worktree can predate a dev dependency**: the unit suite then dies with `Interface "TYPO3\CMS\Dashboard\Widgets\…" not found`-style errors that look like code breakage. Run `./Build/Scripts/runTests.sh -s composerUpdate` in the new worktree before trusting any red. (Observed: a copied `.Build` lacked `typo3/cms-dashboard`; 12 widget tests errored on pristine `main`.)
- **CaptainHook cannot install its hooks in a git worktree** — composer install ends with `CaptainHook could not install yer git hooks! (invalid .git path)`. Harmless for the containerized test runner, but it means NO pre-commit/commit-msg checks run locally in that worktree: the subject-style and cgl gates you rely on elsewhere are silently absent, so run the checks by hand before pushing.
- **`make ci` does not include Rector** (cgl + phpstan + unit + fuzz only), and CI's Rector dry-run is a required gate. `SimplifyQuoteEscapeRector` flags every `\'` escape in a single-quoted string — an assertion message with an apostrophe costs a full CI round trip. When adding or editing PHP files, run `make rector` before pushing. (Cost two round trips in one day, 2026-08-18.)

## Security Requirements
This extension handles sensitive data. Non-negotiable rules:

1. **Never log secrets** — use `[REDACTED]` placeholders in logs & exceptions.
2. **Constant-time comparisons** — `hash_equals()` for secret comparison.
3. **Memory clearing** — `sodium_memzero()` after processing plaintext secrets.
4. **No plaintext storage** — all secrets via envelope encryption (master key wraps per-secret DEK).
5. **Audit every access** — reads/writes/rotations/deletes all create audit log entries.
6. **Access control** — respect backend user groups & ownership via `AccessControlServiceInterface`.
7. **Tamper-evident audit log** — HMAC hash chain plus an in-DB tip anchor (ADR-034); verify on schedule (`vault:audit-verify` / `AuditVerifyTask`, `vault:audit --verify` interactively). A mutation and its audit entry are all-or-nothing — a write that cannot be audited must not land, and that includes the MM ACL tiers written alongside it.
8. **One admin-bypass seam** — every "admins may do anything" decision goes through the private `AccessControlService::adminBypassActive()`. Never inline `isAdmin()`/`isSystemMaintainer()` in a caller, and never route a grant lookup through `BackendUserAuthentication::check()` (core short-circuits it to `true` for admins). The hardened profile can disable the bypass (`disableAdminOverride`); a half-disabled override is worse than none.

## Boundaries

### Always Do
- Use `declare(strict_types=1);`, `final` classes by default, `readonly` properties, constructor promotion.
- Dependency injection via `Configuration/Services.yaml` — not `GeneralUtility::makeInstance()`.
- Run `make fix && make phpstan && make test` before pushing.
- Use atomic commits (one logical change per commit); preserve GPG signatures.
- Force-push only with `--force-with-lease`. Follow PSR-12 + TYPO3 CGL.

### Ask First
- Adding new dependencies (composer / npm). Modifying CI/CD configuration.
- Changing public API signatures of `*Interface.php`. Rotating / regenerating cryptographic keys in fixtures.

### Never Do
- Commit secrets, credentials, or real master keys (test fixtures only — synthetic values; `.gitleaks.toml` tunes the `gitleaks` job in `.github/workflows/checks.yml`, so a new fixture that trips a rule fails CI).
- Commit `composer.lock` (extension, not application).
- Push directly to `main` — open a PR. Merge a PR before all review threads are resolved.
- Squash or rebase-merge (loses GPG signatures — use merge commits).
- Use `secrets: inherit` in reusable GitHub Actions workflows (pass secrets explicitly).
- Modify `.Build/`, `vendor/`, `Documentation-GENERATED-temp/`, `.php-cs-fixer.cache`.
- Use `$GLOBALS['TYPO3_DB']` (deprecated) — use Doctrine QueryBuilder.

## Index of scoped AGENTS.md
MUST read when working in these directories:
- `./Classes/AGENTS.md` — PHP sources, crypto, services, hooks, audit invariants
- `./Configuration/AGENTS.md` — TCA, Services.yaml, routes
- `./Documentation/AGENTS.md` — RST docs + ADRs
- `./Resources/AGENTS.md` — Fluid templates, JS/CSS, XLIFF
- `./Tests/AGENTS.md` — PHPUnit unit + functional + fuzz
- `./Tests/E2E/AGENTS.md` — Playwright E2E
- `./.ddev/AGENTS.md` — DDEV environment
- `./.github/workflows/AGENTS.md` — CI workflows

> **Agents**: When you read or edit files in a listed directory, load its AGENTS.md first.

## Repository Settings
- **Default branch:** `main` · **Merge strategy:** merge commit (GPG signature preservation)
- **Signed commits:** required (GPG/SSH)
- **DCO:** required (`Signed-off-by:` trailer on every commit — use `git commit -s`). Enforced at the PR gate; the local commit-msg hook does NOT check it.

## When Stuck
1. `docs/ARCHITECTURE.md` — component map, dependency rules, key interfaces, CLI commands
2. TYPO3 v14 docs: <https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/>
3. Review ADRs in `Documentation/Developer/Adr/`
4. Run `make phpstan` for type hints; check audit logs (`vault:audit`) for access issues

---
*© Netresearch DTT GmbH — GPL-2.0-or-later*
