<!-- Managed by agent: keep sections and order; edit content, not structure -->
<!-- Last updated: 2026-08-02 | Last verified: 2026-08-02 -->

# AGENTS.md — Classes

## Overview
PHP sources for the nr-vault TYPO3 extension. PSR-4 namespace `Netresearch\NrVault\` rooted here.
Strict types, final classes, readonly properties, constructor promotion. DI via `Configuration/Services.yaml`.

## Key Files
| File | Purpose |
|------|---------|
| `Classes/Service/VaultService.php` | Core secret CRUD + rotation; binds vault adapters |
| `Classes/Service/VaultServiceInterface.php` | Public contract for store/retrieve/rotate/delete |
| `Classes/Crypto/EncryptionService.php` | libsodium envelope-encryption (plaintext ↔ ciphertext) |
| `Classes/Crypto/FileMasterKeyProvider.php` | Reads master key from filesystem (config-driven) |
| `Classes/Crypto/EnvironmentMasterKeyProvider.php` | Reads master key from env var |
| `Classes/Crypto/Typo3MasterKeyProvider.php` | Uses TYPO3 encryptionKey as fallback |
| `Classes/Audit/AuditLogService.php` | Tamper-evident audit log (HMAC hash chain); fans out to external sinks after the chain write |
| `Classes/Audit/Sink/AuditSinkRegistry.php` | Fan-out to external sinks; contains + counts per-sink failures |
| `Classes/Audit/Anchor/ChainTipAnchorService.php` | Publishes + verifies external chain-tip anchors (detects a full table reset) |
| `Classes/Audit/AuditChainAnchorStore.php` | In-DB chain tip in `sys_registry` (`tx_nrvault_audit_anchor`, ADR-034) |
| `Classes/Security/AccessControlService.php` | Per-secret tiers + operation permissions; sole admin-bypass seam |
| `Classes/Security/VaultPermission.php` | The operation enum every `isGranted()` call names |
| `Classes/Security/FrontendPlaceholderPolicy.php` | Frontend placeholder allow-set (ADR-035) |
| `Classes/Controller/SecretsController.php` | Backend module: list/create/rotate UI |
| `Classes/Controller/AjaxController.php` | AJAX reveal/copy endpoints |
| `Classes/Hook/FlexFormVaultHook.php` | Rewrites vault placeholders in FlexForms |
| `Classes/Hook/DataHandlerHook.php` | DataHandler integration for vault fields; fail-closed record copy/delete |
| `Classes/Hook/SecretTcaHook.php` | `tx_nrvault_secret` datamap guard; compensating rollback incl. MM ACL tiers |
| `Classes/Command/VaultMigrateFieldCommand.php` | `vault:migrate-field` CLI |
| `Classes/Command/VaultRotateMasterKeyCommand.php` | `vault:rotate-master-key` CLI |
| `Classes/Upgrades/AuditHmacMigrationWizard.php` | Install-tool migration to HMAC chain |

## Golden Samples
| Pattern | Reference |
|---------|-----------|
| Service with DI + interface | `Classes/Service/VaultService.php` |
| Crypto boundary (libsodium) | `Classes/Crypto/EncryptionService.php` |
| TYPO3 hook integration | `Classes/Hook/FlexFormVaultHook.php` |
| AJAX controller | `Classes/Controller/AjaxController.php` |
| Symfony Console command | `Classes/Command/VaultMigrateFieldCommand.php` |
| Upgrade wizard | `Classes/Upgrades/AuditHmacMigrationWizard.php` |
| Interface-first API | `Classes/Service/VaultServiceInterface.php` |

## Setup
- `make up` — DDEV + TYPO3 v14 install
- `make shell` — container shell
- PHP `^8.2`, TYPO3 `^13.4 || ^14.3`

## Directory Structure
```
Classes/
├── Adapter/       # Vault backend adapters (LocalEncryptionAdapter, external)
├── Audit/         # AuditLogService, HashChainVerificationResult, AuditIntegrityReport
│   ├── Anchor/     # External chain-tip anchoring (ChainTipAnchorService, AnchorFileReader)
│   └── Sink/       # External audit sinks (syslog, NDJSON file, webhook) + registry
│                   #   + per-sink delivery state (SinkDeliveryStateRepository)
├── Command/       # Symfony Console commands (vault:*)
├── Configuration/ # ExtensionConfiguration wrapper
├── Controller/    # Backend module + AJAX controllers
├── Crypto/        # Encryption services + master-key providers
├── Domain/
│   ├── Dto/        # Filter + detail DTOs
│   ├── Model/      # Secret
│   └── Repository/ # SecretRepository
├── Event/         # PSR-14 events (SecretAccessed/Created/Rotated, BreakGlass*, …)
├── EventListener/ # TypoScriptVaultListener
├── Exception/     # OAuthException, AuditWriteException + domain exceptions
├── Form/          # FormEngine render types for vault fields
├── Hook/          # FlexFormVaultHook, DataHandlerHook, SecretTcaHook
├── Http/          # VaultHttpClient, OAuth token manager
├── Secret/        # Shared secret-pattern catalogue + redactor
├── Security/      # AccessControlService + VaultPermission, TechnicalActorContext,
│                  #   BreakGlassService, FrontendPlaceholderPolicy
├── Seeder/        # Demo data for vault:seed-demo (development only)
├── Service/       # VaultService, SecretDetectionService, VaultHealthService
│   └── Doctor/     # vault:doctor readiness checks (one class per control group)
├── TCA/           # VaultFieldHelper (TCA-time helpers)
├── Task/          # Scheduler tasks (OrphanCleanup, AuditAnchor, AuditVerify)
├── Upgrades/      # Install-tool upgrade wizards
├── Utility/       # IdentifierValidator, VaultFieldResolver
└── Widgets/       # Dashboard widgets (admin-only)
```

## Build/Tests
| Task | Command |
|------|---------|
| Lint | `make lint` |
| CS check | `make cgl` |
| CS fix | `make fix` |
| PHPStan | `make phpstan` |
| Rector (dry-run) | `make rector` |
| Unit tests | `make test-unit` |
| Functional tests | `make test-functional` |
| Mutation tests | `make test-mutation` |
| All CI | `make ci` |

## Code Style
- **PSR-12** + TYPO3 CGL (`.php-cs-fixer.dist.php`)
- `declare(strict_types=1);` on every file
- `final` classes by default; extend only where necessary
- `readonly` properties + constructor promotion
- No `@author` tags in docblocks
- DI via `Services.yaml` — avoid `GeneralUtility::makeInstance()`
- Doctrine QueryBuilder only — never `$GLOBALS['TYPO3_DB']`, never raw SQL
- Prefer `*Interface.php` seams at public boundaries (services, adapters, providers)

## Security
This directory contains the crypto + audit core. Review bar is high:
- **libsodium only** — no `openssl_*` fallbacks
- **Constant-time equality** — `hash_equals()`
- **Memory scrub** — `sodium_memzero()` once plaintext is consumed
- **No secrets in logs/exceptions** — pass `[REDACTED]` to context
- **Audit every access** — `AuditLogServiceInterface::log()` before returning plaintext
- **Identifier validation** — use `IdentifierValidator` (no path traversal, no control chars)
- **Access control** — per-secret tiers via `AccessControlServiceInterface::canRead/canWrite/canDelete/canCreate`; privileged *operations* (create, rotate, delete, manage_policy) additionally go through `isGranted(VaultPermission::…)`. Both before the mutation, never after
- **Mutation and audit are atomic** — if the audit write fails, compensate the mutation (`VaultService::compensateAuditFailure()`, `SecretTcaHook`'s MM-relation restore). A change that persists unaudited is a control failure, not a degraded success

## Checklist
- [ ] `make ci` passes (lint + cs + phpstan + rector + tests)
- [ ] New public methods have interfaces + tests
- [ ] Audit log entry for any new secret operation
- [ ] TCA changes accompanied by `ext_tables.sql` update
- [ ] No new `GeneralUtility::makeInstance()` (use DI)
- [ ] PHPStan level untouched (check `phpstan.neon`)
- [ ] `ext_emconf.php` version bumped if publishable

## Examples
Look at real code — prefer Golden Samples above. No template snippets; copy from existing files.

## When Stuck
- Root AGENTS.md for project-wide rules
- ADRs: `Documentation/Developer/Adr/ADR-*.rst`
- TYPO3 v14 docs: <https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/>
- Invoke skill: `typo3-conformance` for extension standards
- Invoke skill: `php-modernization` for PHP 8.2+ patterns
