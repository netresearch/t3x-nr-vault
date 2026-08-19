<!-- Managed by agent: keep sections and order; edit content, not structure -->
<!-- Last updated: 2026-08-19 | Last verified: 2026-08-19 -->

# Architecture — nr-vault

Agent-facing component map. Human-facing documentation lives in `Documentation/` (rendered to docs.typo3.org); design decisions live in `Documentation/Developer/Adr/`. Nothing here duplicates those — this file locates code and states the enforced boundaries.

## System Overview

nr-vault is a TYPO3 extension (key `nr_vault`, namespace `Netresearch\NrVault\`) providing secrets management inside a TYPO3 instance: envelope encryption via libsodium (a master key wraps a per-secret DEK), per-secret and per-operation access control, and a tamper-evident audit log (HMAC hash chain with an in-DB chain-tip anchor, ADR-034). Consumers reach it through the PHP API (`VaultServiceInterface`), 17 `vault:*` CLI commands, a backend module, TCA/FlexForm field integration, and placeholder resolution in TypoScript/site config.

## Components

| Component | Location | Responsibility |
|-----------|----------|----------------|
| Vault service | `Classes/Service/VaultService.php` | Core secret CRUD + rotation; binds vault adapters; compensates mutations on failed audit writes |
| Crypto | `Classes/Crypto/` | `EncryptionService` (libsodium envelope), master-key providers (file / env / TYPO3 encryptionKey) behind `MasterKeyProviderInterface` |
| Access control | `Classes/Security/AccessControlService.php` | Per-secret tiers + operation permissions (`VaultPermission` enum); sole admin-bypass seam |
| Technical actor | `Classes/Security/TechnicalActorContext.php` | Headless `runAs()` for CLI/scheduler/API actors without a live session |
| Break-glass | `Classes/Security/BreakGlassService.php` | Time-boxed restore of the admin override |
| Audit log | `Classes/Audit/AuditLogService.php` | HMAC hash-chain writer/verifier; fans out to external sinks (`Classes/Audit/Sink/`) after the chain write |
| Audit anchor | `Classes/Audit/AuditChainAnchorStore.php`, `Classes/Audit/Anchor/` | In-DB chain tip in `sys_registry` (ADR-034) + external chain-tip anchoring |
| Persistence | `Classes/Domain/Repository/SecretRepository.php` | Doctrine QueryBuilder access to `tx_nrvault_secret` |
| Adapters | `Classes/Adapter/` | Vault backend adapters behind `VaultAdapterInterface` (local encryption, external) |
| HTTP client | `Classes/Http/` | `VaultHttpClient` + OAuth token manager for secure outbound calls (ADR-010, ADR-027) |
| Backend UI | `Classes/Controller/`, `Resources/` | Backend module (Overview/Secrets/Audit/Migration) + AJAX endpoints (reveal, verify-chain) |
| TYPO3 integration | `Classes/Hook/`, `Classes/Form/`, `Classes/TCA/`, `Classes/EventListener/` | DataHandler/FlexForm/TCA hooks, FormEngine render types, TypoScript placeholder listener |
| CLI | `Classes/Command/` | 17 `vault:*` Symfony Console commands (list below) |
| Scheduler | `Classes/Task/` | OrphanCleanup, AuditAnchor, AuditVerify tasks |
| Doctor | `Classes/Service/Doctor/` | `vault:doctor` readiness checks, one class per control group |
| Events | `Classes/Event/` | PSR-14 events (SecretAccessed/Created/Rotated, BreakGlass*, …) |
| Config wrapper | `Classes/Configuration/` | ExtensionConfiguration accessor (settings documented in `Documentation/Configuration/Index.rst`) |

## Dependency Rules

Enforced by phpat via `Tests/Architecture/ArchitectureTest.php` (`composer ci:test:php:arch`; config `phpat.neon`). The test is authoritative — the summary below mirrors its 25 rules:

- **Immutability/finality**: events, `AuditLogEntry`, OAuth value objects, and `VaultHttpClient` must be readonly; exceptions, enums, and Crypto/Security implementations must be final.
- **Interface seams**: `*Service` classes and adapters must implement their interface (`VaultAdapterInterface` for adapters).
- **Layering**: services must not depend on controllers or commands; hooks and commands must not depend on controllers; commands must not depend on the repository; controllers must not depend on Crypto; Domain must not depend on infrastructure; Configuration must not depend on services; event listeners must not depend on presentation; utilities must not depend on services.
- **Isolation locks**: Crypto is isolated; Security must not depend on Http; only `SecureHttpClientFactory` may instantiate a Guzzle `Client` (ADR-028); the audit anchor never uses TYPO3's core `Registry`; shared test infrastructure must not leak into production code.

## Data Flow

Write path: caller (controller / CLI / hook / API) → `VaultServiceInterface::store()/rotate()/delete()/setEnabled()` → `AccessControlService` gate (`isGranted()` + `canWrite()`/`canDelete()`) → `EncryptionService` envelope encryption → `SecretRepository` persist → `AuditLogService::log()` (HMAC chain + sinks). Mutation and audit entry are all-or-nothing: a failed audit write triggers compensation (`VaultService::compensateAuditFailure()`, `SecretTcaHook` MM-relation restore, ADR-036).

Read path: `retrieve()`/`retrieveForFrontend()` → access-control gate → decrypt (DEK unwrapped with the master key, request-lifetime key cache per ADR-020) → audit read entry (configurable, ADR-019) → plaintext to the caller; `sodium_memzero()` after processing.

## Key Interfaces (cheat-sheet)

Authoritative source: the `*Interface.php` files — read the PHP for full docblocks.

```php
// Core vault operations — Classes/Service/VaultServiceInterface.php
VaultServiceInterface::store(string $identifier, string $secret, array $options = []): void
VaultServiceInterface::retrieve(string $identifier): ?string
VaultServiceInterface::retrieveForFrontend(string $identifier): ?string
VaultServiceInterface::exists(string $identifier): bool
VaultServiceInterface::delete(string $identifier, string $reason = ''): void
// Runs delete()'s permission gates WITHOUT deleting, so a record delete spanning
// several vault fields can fail closed before the first (unrestorable) deletion.
// An absent secret passes.
VaultServiceInterface::assertDeletable(string $identifier): void
VaultServiceInterface::rotate(string $identifier, string $newSecret, string $reason = ''): void
// The single write path for a secret's availability. Disabling withdraws it from
// every read path at once (TCA `disabled` enable column), so it is gated by
// canWrite() AND secret.manage_policy, audited as `metadata_update`, and
// compensated on a failed audit write. Absolute, not a toggle: setting the
// current state is a no-op. A disabled secret stays administrable — it can be
// re-enabled, rotated, deleted, and its metadata read.
VaultServiceInterface::setEnabled(string $identifier, bool $enabled, string $reason = ''): void
// `$includeDisabled` widens the listing to secrets that are out of service;
// off by default, passed by the management surfaces only. Each SecretMetadata
// reports its state in `$enabled`.
VaultServiceInterface::list(?string $pattern = null, bool $includeDisabled = false): array
VaultServiceInterface::getMetadata(string $identifier): SecretDetails
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
// Static: wipes the request-lifetime key cache (ADR-020). Long-running processes
// (workers, scheduler tasks) must call it to bound key residency.
MasterKeyProviderInterface::clearCachedKey(): void

// Operation permissions — Classes/Security/AccessControlServiceInterface.php
// Every privileged operation resolves through isGranted(); the VaultPermission
// enum (Classes/Security/VaultPermission.php) is the single list of operations
// (secret.create, secret.rotate, secret.delete, secret.manage_policy, …).
// A technical actor has no live session, so its grants are read straight from
// the `tx_nrvault:<permission>` custom options on its be_groups rows — never
// from BackendUserAuthentication::check(). Fail-closed: no groups, no grant.
AccessControlServiceInterface::isGranted(VaultPermission $permission): bool
AccessControlServiceInterface::canRead(Secret $secret): bool
AccessControlServiceInterface::canWrite(Secret $secret): bool
AccessControlServiceInterface::canDelete(Secret $secret): bool
AccessControlServiceInterface::canCreate(): bool

// Technical actor (headless runAs) — Classes/Security/TechnicalActorContextInterface.php
TechnicalActorContextInterface::runAs(int $beUserUid, callable $fn): mixed
TechnicalActorContextInterface::getCurrentActor(): ?TechnicalActor

// Break-glass (time-boxed restore of the admin override) — Classes/Security/BreakGlassServiceInterface.php
BreakGlassServiceInterface::activate(string $reason, int $minutes = 15): BreakGlassSession
BreakGlassServiceInterface::deactivate(string $reason): void
// Read-only seam consumed by AccessControlService — Classes/Security/BreakGlassStateInterface.php
BreakGlassStateInterface::getActiveSession(): ?BreakGlassSession
BreakGlassStateInterface::isActive(): bool

// Audit logging — Classes/Audit/AuditLogServiceInterface.php
AuditLogServiceInterface::log(
    string $secretIdentifier, string $action, bool $success,
    ?string $errorMessage = null, ?string $reason = null,
    ?string $hashBefore = null, ?string $hashAfter = null,
    ?AuditContextInterface $context = null,
): void
AuditLogServiceInterface::query(?AuditLogFilter $filter = null, int $limit = 100, int $offset = 0): array
AuditLogServiceInterface::count(?AuditLogFilter $filter = null): int
AuditLogServiceInterface::export(?AuditLogFilter $filter = null): array
AuditLogServiceInterface::verifyHashChain(
    ?int $fromUid = null, ?int $toUid = null, ?int $minEpoch = null,
): HashChainVerificationResult
AuditLogServiceInterface::getLatestHash(): ?string

// In-DB chain-tip anchor (ADR-034) — Classes/Audit/AuditChainAnchorStoreInterface.php
// Persists the tip in sys_registry under `tx_nrvault_audit_anchor`, so a full
// truncation of the audit table is still detected. `auditAnchorRequired` decides
// whether a missing anchor is a warning or a critical finding.
```

## CLI Commands (TYPO3 `vendor/bin/typo3`)

All 17 registered `vault:*` commands (`Classes/Command/`). Full options/examples in `Documentation/Developer/Commands.rst`.

```
vault:init                 # Initialize the vault (generate master key, verify configuration)
vault:store                # Store a secret in the vault
vault:retrieve             # Retrieve a secret from the vault
vault:list                 # List all secrets in the vault
vault:rotate               # Rotate (replace) a secret value
vault:delete               # Delete a secret from the vault
vault:scan                 # Scan database content for exposed secrets
vault:migrate-field        # Migrate a database field value into the vault
vault:audit                # View / export audit entries; --verify checks the hash chain and the in-DB anchor, --reset-anchor clears the anchor after a legitimate wipe
vault:audit-anchor         # Publish the audit chain tip to the external audit sinks (scheduled task wrapper)
vault:audit-verify         # Verify the hash chain AND the external chain-tip anchor (scheduled task wrapper)
vault:audit-migrate-hmac   # Migrate audit log hash chain from SHA-256 to HMAC-SHA256
vault:rotate-master-key    # Re-encrypt all secrets with a new master key
vault:cleanup-orphans      # Clean up orphaned vault entries (scheduled task wrapper)
vault:break-glass          # Open/close/inspect a time-boxed break-glass window (restores the admin override)
vault:doctor               # Check the configuration for deployment/audit readiness (exit 0 clean / 1 warnings / 2 critical)
vault:seed-demo            # Seed demo secrets + audit history (development only)
```

## CI

`.github/workflows/ci.yml` is a thin caller of `netresearch/typo3-ci-workflows/.github/workflows/ci.yml@main` with matrix PHP 8.2/8.3/8.4/8.5 × TYPO3 ^13.4/^14.3, functional tests and coverage upload enabled. `checks.yml` (security/quality jobs) is drift-locked across all netresearch TYPO3 extensions; the mutation ratchet for `Classes/Crypto|Security|Audit` lives in `security-gates.yml`. See `.github/workflows/AGENTS.md`.

## Key Decisions

37 ADRs in `Documentation/Developer/Adr/` (index: `Documentation/Developer/Adr/Index.rst`). Load-bearing for agents: ADR-002 (envelope encryption), ADR-003 (master-key management), ADR-005 (access control), ADR-006/ADR-023/ADR-024 (audit logging + HMAC chain + forensic fields), ADR-020 (master-key request-lifetime caching), ADR-028 (phpat HTTP-client lock), ADR-029 (technical actor context), ADR-034 (audit chain-tip anchor), ADR-035 (frontend placeholder allow-set), ADR-036 (mutation/audit atomicity).
