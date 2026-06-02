<!-- FOR AI AGENTS - Human readability is a side effect, not a goal -->
<!-- Managed by agent: keep sections and order; edit content, not structure -->
<!-- Last updated: 2026-04-20 | Last verified: 2026-04-20 -->

# AGENTS.md — nr-vault

> Secure secrets management for TYPO3 (envelope encryption, access control, tamper-evident audit log).

**Precedence:** the **closest `AGENTS.md`** to the files you're changing wins. Root holds global defaults only. Explicit user prompts override files.

## Project Overview

- **Stack:** PHP 8.2+, TYPO3 ^13.4 || ^14.3, libsodium (XChaCha20-Poly1305 / AES-256-GCM envelope encryption)
- **Environment:** DDEV for local development
- **License:** GPL-2.0-or-later
- **Namespace:** `Netresearch\NrVault\` (PSR-4 from `Classes/`)
- **Extension key:** `nr_vault`

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
| PHPStan | `make phpstan` | Static analysis. In a fresh git worktree use `.Build/bin/phpstan analyse --configuration=Build/phpstan.no-plugins.neon` (the plugin config errors before `.Build/vendor` is populated) |
| Rector (dry-run) | `make rector` | |
| Unit tests | `make test-unit` | `composer ci:test:php:unit` |
| Functional tests | `make test-functional` | `composer ci:test:php:functional` |
| All tests | `make test` | unit + functional |
| Mutation tests | `make test-mutation` | Infection |
| All CI | `make ci` | cgl + phpstan + unit + fuzz (no lint/rector/functional) |
| Docs render | `make docs` | |

Direct composer (without make):
- `composer ci` — unit + fuzz + phpstan + cgl
- `composer ci:test:php:functional` — functional suite
- `composer ci:cgl` — fix code style

## Response Style
- Answer first, elaborate only if needed. No sycophantic openers.
- For yes/no or status questions, lead with the answer.
- Skip preamble. Match response length to task complexity.

## Workflow
1. **Before coding**: Read nearest `AGENTS.md` + inspect Golden Samples.
2. **After each change**: Run the smallest relevant check (`make lint` → `make phpstan` → single test).
3. **Before committing**: `make ci` when changes affect >2 files or touch shared code.
4. **Before claiming done**: Run verification and **paste output as evidence** — never say "should work now" / "tested" / "all green" without showing output.

## File Map
```
Classes/         → PHP sources (Adapter, Audit, Command, Controller, Crypto, Domain, Hook, Http, Service, Task, Upgrades, Utility)
Configuration/   → TYPO3 config (TCA, Backend routes, Services.yaml)
Documentation/   → reStructuredText docs + ADRs
Resources/       → Templates (Fluid), JS/CSS, XLIFF language files
Tests/           → Unit + Functional + E2E (Playwright)
Build/           → phpunit.xml, FunctionalTests.xml
.ddev/           → DDEV environment (mock-oauth sidecar, phpunit extras)
.github/         → workflows, CODEOWNERS, renovate, labeler
```

## Golden Samples
| For | Reference |
|-----|-----------|
| Domain service | `Classes/Service/VaultService.php` |
| Crypto boundary | `Classes/Crypto/EncryptionService.php` |
| Controller (backend module) | `Classes/Controller/SecretsController.php` |
| AJAX controller | `Classes/Controller/AjaxController.php` |
| TYPO3 hook | `Classes/Hook/FlexFormVaultHook.php` |
| Audit writer | `Classes/Audit/AuditLogService.php` |
| Upgrade wizard | `Classes/Upgrades/AuditHmacMigrationWizard.php` |
| Functional test | `Tests/Functional/Crypto/MasterKeyRotationTest.php` |

## Heuristics
| When | Do |
|------|-----|
| Adding class | PSR-4 under `Classes/`, namespace `Netresearch\NrVault\*` |
| New command | `Classes/Command/` + register in `Configuration/Services.yaml` |
| AJAX route | Add to `Configuration/Backend/AjaxRoutes.php` + controller in `Classes/Controller/` |
| New backend submodule | (1) register in `Configuration/Backend/Modules.php` (with its dedicated labels XLF); (2) add a card to the `submodules` list in `OverviewController::indexAction` (with localized title/description in `locallang_mod.xlf`); (3) add a `Documentation/Usage/Index.rst` section + a `Documentation/Images/*.png` screenshot; (4) exclude the controller in `Build/phpunit.xml` coverage (backend module render is E2E-covered) **or** unit-test its extractable logic. Not done = incomplete feature. |
| Touching secrets | Audit log every read/write via `AuditLogServiceInterface::log()` |
| Running locally | `make up` then `make shell` |
| Committing | Subject-style enforced by `captainhook.json`: capitalized, imperative mood, length-limited, no trailing period (NOT lowercase `feat:`/`fix:` prefixes). Sign off with `git commit -s`. See CONTRIBUTING.md |
| Merging PRs | Merge commit (not squash, not rebase) — preserves GPG signatures |

## Security Requirements
This extension handles sensitive data. Non-negotiable rules:

1. **Never log secrets** — use `[REDACTED]` placeholders in logs & exceptions.
2. **Constant-time comparisons** — `hash_equals()` for secret comparison.
3. **Memory clearing** — `sodium_memzero()` after processing plaintext secrets.
4. **No plaintext storage** — all secrets via envelope encryption (master key wraps per-secret DEK).
5. **Audit every access** — reads/writes/rotations/deletes all create audit log entries.
6. **Access control** — respect backend user groups & ownership via `AccessControlServiceInterface`.
7. **Tamper-evident audit log** — HMAC hash chain; verify on schedule (see `VaultAuditCommand`).

## Key Interfaces
> Authoritative source: the `*Interface.php` files. This is a cheat-sheet — read the PHP for full docblocks.

```php
// Core vault operations — Classes/Service/VaultServiceInterface.php
VaultServiceInterface::store(string $identifier, string $secret, array $options = []): void
VaultServiceInterface::retrieve(string $identifier): ?string
VaultServiceInterface::exists(string $identifier): bool
VaultServiceInterface::delete(string $identifier, string $reason = ''): void
VaultServiceInterface::rotate(string $identifier, string $newSecret, string $reason = ''): void
VaultServiceInterface::list(?string $pattern = null): array
VaultServiceInterface::getMetadata(string $identifier): SecretDetails
VaultServiceInterface::clearCache(): void
VaultServiceInterface::http(): VaultHttpClientInterface

// Encryption — Classes/Crypto/EncryptionServiceInterface.php
EncryptionServiceInterface::encrypt(string $plaintext, string $identifier): EncryptedData
EncryptionServiceInterface::decrypt(
    string $encryptedValue, string $encryptedDek,
    string $dekNonce, string $valueNonce, string $identifier
): string
EncryptionServiceInterface::generateDek(): string
EncryptionServiceInterface::calculateChecksum(string $plaintext): string

// Master key — Classes/Crypto/MasterKeyProviderInterface.php
MasterKeyProviderInterface::getMasterKey(): string

// Audit logging — Classes/Audit/AuditLogServiceInterface.php
AuditLogServiceInterface::log(
    string $secretIdentifier, string $action, bool $success,
    ?string $errorMessage = null, ?string $reason = null,
    ?string $hashBefore = null, ?string $hashAfter = null,
    ?AuditContextInterface $context = null,
): void
AuditLogServiceInterface::query(?AuditLogFilter $filter = null, int $limit = 100, int $offset = 0): array
AuditLogServiceInterface::verifyHashChain(?int $fromUid = null, ?int $toUid = null): HashChainVerificationResult
```

## CLI Commands (TYPO3 `vendor/bin/typo3`)
> All 13 registered `vault:*` commands. Full options/examples in
> `Documentation/Developer/Commands.rst`.
```
vault:init                 # Initialize the vault (generate master key, verify configuration)
vault:store                # Store a secret in the vault
vault:retrieve             # Retrieve a secret from the vault
vault:list                 # List all secrets in the vault
vault:rotate               # Rotate (replace) a secret value
vault:delete               # Delete a secret from the vault
vault:scan                 # Scan database content for exposed secrets
vault:migrate-field        # Migrate a database field value into the vault
vault:audit                # View / verify audit log entries
vault:audit-migrate-hmac   # Migrate audit log hash chain from SHA-256 to HMAC-SHA256
vault:rotate-master-key    # Re-encrypt all secrets with a new master key
vault:cleanup-orphans      # Clean up orphaned vault entries (scheduled task wrapper)
vault:seed-demo            # Seed demo secrets + audit history (development only)
```

## Boundaries

### Always Do
- Use `declare(strict_types=1);`, `final` classes by default, `readonly` properties, constructor promotion.
- Dependency injection via `Configuration/Services.yaml` — not `GeneralUtility::makeInstance()`.
- Run `make fix && make phpstan && make test` before pushing.
- Use atomic commits (one logical change per commit); preserve GPG signatures.
- Force-push only with `--force-with-lease`.
- Follow PSR-12 + TYPO3 CGL.

### Ask First
- Adding new dependencies (composer / npm).
- Modifying CI/CD configuration.
- Changing public API signatures of `*Interface.php`.
- Rotating / regenerating cryptographic keys in fixtures.

### Never Do
- Commit secrets, credentials, or real master keys (test fixtures only — allowlisted in `.gitleaks.toml`).
- Commit `composer.lock` (extension, not application).
- Push directly to `main` — open a PR.
- Merge a PR before all review threads are resolved.
- Squash or rebase-merge (loses GPG signatures — use merge commits).
- Use `secrets: inherit` in reusable GitHub Actions workflows (pass secrets explicitly).
- Modify `.Build/`, `vendor/`, `Documentation-GENERATED-temp/`, `.php-cs-fixer.cache`.
- Use `$GLOBALS['TYPO3_DB']` (deprecated) — use Doctrine QueryBuilder.

## Index of scoped AGENTS.md
MUST read when working in these directories:
- `./Classes/AGENTS.md` — PHP sources, crypto, services, hooks
- `./Configuration/AGENTS.md` — TCA, Services.yaml, routes
- `./Documentation/AGENTS.md` — RST docs + ADRs
- `./Resources/AGENTS.md` — Fluid templates, JS/CSS, XLIFF
- `./Tests/AGENTS.md` — PHPUnit unit + functional + fuzz
- `./Tests/E2E/AGENTS.md` — Playwright E2E
- `./.ddev/AGENTS.md` — DDEV environment
- `./.github/workflows/AGENTS.md` — CI workflows

> **Agents**: When you read or edit files in a listed directory, load its AGENTS.md first.

## Repository Settings
- **Default branch:** `main`
- **Merge strategy:** merge commit (required for GPG signature preservation)
- **Signed commits:** required (GPG/SSH)
- **DCO:** required (`Signed-off-by:` trailer on every commit — use `git commit -s`). Enforced at the PR gate; the local commit-msg hook does NOT check it.

## When Stuck
1. TYPO3 v14 docs: <https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/>
2. Review ADRs in `Documentation/Developer/Adr/`
3. Run `make phpstan` for type hints
4. Check audit logs (`vault:audit`) for access issues
5. Root AGENTS.md for project-wide conventions

---
*© Netresearch DTT GmbH — GPL-2.0-or-later*
