# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **VaultService::store() now requires authorization.** Previously any
  backend user with write rights on a host table carrying a vault field
  could create or overwrite arbitrary vault identifiers, bypassing the
  per-secret ACL. `store()` now distinguishes new vs. update and calls
  `canCreate()` / `canWrite($existing)`; denied paths emit an
  `access_denied` audit entry and throw `AccessDeniedException`. Non-admin
  backend actors that attempt to set or change `owner_uid` are silently
  coerced to the default (existing owner on update, current actor on
  create). CLI / scheduler / API actors retain full control.
- **`#[SensitiveParameter]` rolled out across the crypto / DTO / audit
  boundaries** (0 → 35 occurrences). Plaintext secrets, master keys,
  DEKs, OAuth tokens, refresh tokens and vault tokens no longer surface
  in stack traces, error handlers, monolog payloads, or `var_dump()`.
  Applied to `EncryptionService(Interface)`, `MasterKeyProviderInterface`
  and all three providers, `VaultService(Interface)::store/rotate`,
  `AuditLogServiceInterface::log` `$hashBefore`/`$hashAfter`,
  `PendingSecret::$value`, `FlexFormPendingSecret::$value`,
  `VaultServerConfig::$token`, and the private `encryptWithKey` /
  `decryptWithKey` locals.
- **SSRF defence-in-depth in `SecureHttpClientFactory::isHostAllowed()`.**
  Regardless of `allowed_hosts` configuration, IP literals and
  DNS-resolved hostnames pointing into private / RFC1918 / RFC6598 CGNAT
  / loopback / link-local / cloud-metadata (169.254.169.254) /
  multicast / class-E / IPv6 ULA / IPv6 link-local / IPv6 multicast /
  NAT64 / discard ranges are rejected. The check normalises
  `host:port`, `[ipv6]:port`, bare `::1` (which `parse_url` misparses),
  bracketed `[2001:db8::1]`, trailing dots, mixed case, and whitespace.
  LITERAL allowlist entries can opt back in for on-prem deployments
  (e.g. `'10.0.0.42'`); wildcards (`*.example.com`) cannot — a wildcard
  owner could otherwise pivot via DNS rebinding. The check resolves
  hostnames at filter time; full DNS-rebind protection via
  `CURLOPT_RESOLVE` pinning is a follow-up.
- **Master-key rotation is now audit-logged.**
  `VaultRotateMasterKeyCommand` emits `master_key_rotate_start` before
  the re-encryption loop and `master_key_rotate_end` (success or
  failure) afterwards, both with a sanitised reason — error messages
  are scrubbed of libsodium internals before persistence.
- **`auditReads` filesystem-only override.**
  `$TYPO3_CONF_VARS[SYS][nrVault][auditReads]`, if set, takes
  precedence over the BE-toggleable extension configuration. Pin the
  value in `LocalConfiguration.php` / `additional.php` on production so
  a compromised admin cannot silence read logging via the BE Settings
  module.
- **`Typo3MasterKeyProvider` entropy gate.** The default master-key
  provider now rejects TYPO3 `encryptionKey` values shorter than 32
  characters (would otherwise produce a weak HKDF output). Add a
  request-lifetime static cache (ADR-020) so HKDF runs once per
  request instead of on every crypto operation.
- **`FileMasterKeyProvider` chmod race closed.** `storeMasterKey()`
  wraps the `file_put_contents()` call in `umask(0o077)` so the file
  is created `0600`, then `chmod 0400` tightens further — no more
  world-readable window under permissive umasks.

### Changed
- **`MasterKeyProviderInterface::storeMasterKey()`,
  `EncryptionServiceInterface::encrypt/decrypt/reEncryptDek/
  calculateChecksum()`, `VaultServiceInterface::store/rotate()`, and
  `AuditLogServiceInterface::log()` now annotate sensitive parameters
  with `#[SensitiveParameter]`.** This is a signature change visible to
  downstream implementers: PHP does not enforce the attribute on
  implementations, but implementers should mirror it on their overrides
  to keep the protection.
- **`AccessControlServiceInterface` gains
  `isCurrentActorAdmin(): bool`.** New method delegating BE-admin check
  to the service instead of `$GLOBALS['BE_USER']` lookup. Returns
  `false` for CLI / scheduler / API actor types — callers that need
  to bypass admin gates must handle actor type explicitly.
- **Pre-commit hook moves PHPStan from pre-push to pre-commit.** Type
  errors are now caught at commit time on top of the existing
  `php-cs-fixer` + lint actions. Pre-push retains unit-test execution.
  Note: captainhook's installer does not currently support worktree
  gitdirs (`git clone --bare` + `worktree add`); operators in worktrees
  need to run `vendor/bin/captainhook install -g <gitdir>` manually.

## [0.5.0] - 2026-04-22

### Added
- **OAuth fallback**: `OAuthTokenManager::fetchTokenWithFallback()` falls
  back to `client_credentials` when a stored `refresh_token` is
  rejected with HTTP 400/401 + `invalid_grant` / `invalid_token`.
  5xx / 429 / `invalid_client` errors re-throw so outages are not
  masked. Both the failed refresh and the fallback are audit-logged.
- **Internationalization**: Translate all backend module templates to
  use XLF translation keys
- **Help Page**: Add help page with docheader tab menu to backend module
- **Security**: HMAC-SHA256 keyed audit hash chain (ADR-023)
- **CLI**: `vault:audit-migrate-hmac` command for migrating legacy
  SHA-256 audit entries

### Security
- **AccessControlService** now denies vault access to backend users
  whose `disable` flag is set, even when a stale session somehow
  reaches the vault layer. Any non-zero integer / numeric-string
  value is treated as disabled (matches TYPO3 DataHandler semantics).
- **AccessControlService** filters stale group IDs from user sessions
  against the live `be_groups` table before intersecting with a
  secret's `allowedGroups`. A deleted group whose UID still lingers in
  a session no longer grants access. Lookup is cached per request.
- **AuditLogService::verifyHashChain()** detects UID gaps in the
  stored chain — an attacker who deletes entry N **and** patches
  entry N+1's `previous_hash` can no longer hide the deletion. New
  `missingUids` / `missingUidCount` fields on the verification result.

### Changed
- **Test coverage driver**: PCOV → Xdebug. PCOV only emits line
  coverage; Xdebug adds branch and path coverage, which Infection
  mutation testing and audit-flow analysis both need. ~2× CI runtime
  cost accepted for the signal quality.
- **Testing pyramid overhaul**: unit tests 1298 → 1705 (assertions
  3045 → 6949), fuzz tests 1 file → 10 files (1514 methods,
  2255 assertions), functional tests 12 files → 24 files, E2E specs
  8 → 14 including a new `Tests/E2E/security/` bundle (XSS, audit
  tamper, CSRF, cookie attributes, full CRUD lifecycle). See
  `Tests/E2E/USER_PATHWAY_COVERAGE.md` for the full pathway audit
  matrix.
- **Infection mutation testing** enabled end-to-end after years of
  being blocked by PHPUnit 12's `failOnWarning=true`. First measured
  baseline MSI: 72.35 % (thresholds set to 72 / 72 with a documented
  ratchet plan toward 85 / 95 by Q4). See
  `Documentation/Developer/mutation-baseline.md`.
- **CI**: reusable workflows pinned to commit SHAs (no more floating
  `@main`), concurrency block cancels stale PR runs, on-demand
  mutation testing via the `run-mutation` PR label.
- **Dev dependencies** consolidated via
  `netresearch/typo3-ci-workflows` meta-package: 14 direct
  require-dev entries reduced to 4 (`mikey179/vfsstream`,
  `netresearch/typo3-ci-workflows`, `roave/security-advisories`,
  `typo3/cms-scheduler`). The meta-package also brings
  `phpstan/phpstan-deprecation-rules`, `saschaegerer/phpstan-typo3`,
  `nikic/php-fuzzer`, `overtrue/phplint`, and `dg/bypass-finals` that
  we did not previously have.
- **Test infrastructure**: extract `AbstractVaultFunctionalTestCase`,
  `TcaSchemaMockTrait`, `BackendUserMockTrait`,
  `SecretFixtureBuilder`, and a project `Tests/Unit/TestCase.php` base
  class. 100 tests migrated. Architecture check script enforces the
  base on new unit tests.
- **PHPStan**: add strict-rules + deprecation-rules + phpunit +
  saschaegerer/phpstan-typo3 extensions (via meta-package auto-
  installer). Baseline refreshed.
- **runTests.sh**: dual `SIGINT`/`SIGTERM`/`EXIT` trap, collision-
  resistant container suffix, Alpine base bumped 3.8 → 3.20, new
  `unitCoveragePath` suite.
- **Performance**: Fix N+1 queries in `VaultService::list()`
- **Performance**: Optimize frontend rendering and database operations
- **Refactoring**: Extract duplicated `generateUuid` and
  `looksLikeVaultIdentifier` methods

### Fixed
- **CLI**: `vault:migrate-field --uid-field=''` now fails fast with a
  clear error instead of emitting an "Undefined array key" warning
  mid-batch.
- **OAuthException** now carries `httpStatus` and `oauthError`
  (parsed from the RFC 6749 §5.2 error body) so callers can
  distinguish refresh-token rejection from server outage.
- **Symfony 7.4**: migrate `Application::add()` → `addCommand()`
  across command tests (eliminates a deprecation warning).
- **DOM-XSS**: eliminate `innerHTML` sinks in frontend JS and
  insecure test randomness
- **Security**: Address critical and high-severity security findings
- **Accessibility**: Improve frontend accessibility and error handling
- **Secret Reveal**: Fix `SecretReveal.js` GET to POST and
  `EnvironmentMasterKeyProvider` copy-on-write bug
- **Gitleaks**: Allowlist test fixtures and docs in gitleaks config

## [0.4.6] - 2026-03-07

### Added
- **Help Page**: Add help page with docheader tab menu to backend module

## [0.4.5] - 2026-03-07

### Fixed
- **TCA Element**: Implement AJAX reveal and copy for vault secret TCA element

## [0.4.4] - 2026-03-06

### Fixed
- **VaultSecretElement**: Fix missing label, broken form submission, and silent errors
- **CI**: Add `merge_group` trigger to CI workflow
- **README**: Correct broken badges

### Changed
- **Repo Hygiene**: Clean up files that should be gitignored

## [0.4.3] - 2026-03-02

### Fixed
- **TYPO3 v13**: Add Overview submodule for v13 module overview compatibility

## [0.4.2] - 2026-03-01

### Fixed
- **TYPO3 v13**: Use integer values for `f:be.infobox` state for v13 compatibility

## [0.4.1] - 2026-03-01

### Fixed
- **TYPO3 v13**: Use standard TYPO3 XLF label keys for backend modules
- **TYPO3 v13**: Use `tools` parent module for v13 compatibility
- **Documentation**: Fix documentation issues found by analysis

### Changed
- **CI**: Consolidate caller workflows into 4 grouped files

## [0.4.0] - 2026-02-28

### Added
- **Compatibility**: Widen support to PHP 8.2+ and TYPO3 v13.4+
- **CI**: Enable coverage uploads to Codecov
- **CI**: Expand test matrix to PHP 8.2-8.5 and TYPO3 v13.4/v14
- **CodeQL**: Add CodeQL security scanning for actions and JavaScript

### Changed
- **CI**: Migrate to centralized reusable workflows
- **CI**: Harmonize composer script naming to `ci:test:php:*` convention
- **Build**: Move build configs (`phpunit.xml`, `phpstan-baseline.neon`) into `Build/`
- **Licensing**: Add SPDX copyright and license headers to all PHP files
- **OpenSSF**: Improve Scorecard compliance

### Fixed
- **PHP 8.2**: Remove `#[Override]`, typed class constants, and `array_any()` for PHP 8.2 compatibility
- **TYPO3 v13**: Replace TYPO3 v14-only APIs with v13-compatible equivalents
- **TYPO3 v13**: Use `LLL:EXT:` module labels for v13 compatibility
- **PHP 8.5**: Fix MockObject property declarations for PHP 8.5 compatibility
- **i18n**: Localize user-facing hardcoded strings in controllers
- **CI**: Fix SLSA provenance generation and Renovate auto-merge configuration

## [0.3.1] - 2026-01-26

### Added
- **Documentation**: Add Secure Outbound HTTP Client PRD and ADRs
- **CI**: Add dedicated fuzzing workflow for OpenSSF Scorecard

### Changed
- **Code of Conduct**: Update to Contributor Covenant v3.0 and standardize contact methods

### Fixed
- **Security**: Fix scorecard workflow permissions for branch protection check
- **CI**: Use `workflow_run` trigger for SLSA provenance generation
- **OpenSSF**: Improve Scorecard token-permissions and pinned-dependencies

## [0.3.0] - 2026-01-12

### Added
- **CI**: Add TER upload to release workflow
- **Testing**: Enhance `runTests.sh` with mock OAuth, E2E DDEV support, and parallel tests
- **Testing**: Add coverage and E2E test suites to `runTests.sh`
- **Testing**: Support `MOCK_OAUTH_URL` env var in OAuth integration tests
- **Playwright**: Update to Playwright 1.57.0 with parallel execution

### Changed
- **Type Safety**: Replace shaped arrays with typed DTOs throughout codebase
- **Performance**: Enable opcache CLI and JIT for faster test execution
- **Performance**: Enable parallel execution for php-cs-fixer
- **Build**: Simplify Makefile with comprehensive test commands

### Fixed
- **PHPStan**: Add type guards and annotations for PHPStan level 10
- **Tests**: Update functional tests for DTO property access
- **PHPUnit 12**: Add `AllowMockObjectsWithoutExpectations` for PHPUnit 12
- **Codecov**: Improve integration with verification step

## [0.2.0] - 2026-01-09

### Added
- **Documentation**: Document all master key options in Installation
- **Documentation**: Add backend module screenshots
- **CI**: Add SLSA provenance workflow and badge
- **CI**: Add PR quality gates for Code-Review scorecard
- **Badges**: Add Contributor Covenant badge

### Changed
- **Type Safety**: Replace array returns with typed DTOs
- **Documentation**: Improve introduction with compelling value proposition

### Fixed
- **CI**: Remove duplicate Scorecard job from `security.yml`
- **DDEV**: Resolve `network_mode` conflict in mock-oauth-router

## [0.1.1] - 2026-01-08

### Added
- **Testing**: Add comprehensive unit tests to reach 80% coverage
- **Testing**: Add OAuth2 integration tests with mock server
- **Testing**: Add XChaCha20 encryption tests for algorithm coverage
- **Testing**: Add functional tests for repositories and services
- **CI**: Add OpenSSF Scorecard workflow
- **CI**: Add auto-merge workflow for dependency PRs
- **Badges**: Add OpenSSF Scorecard, Best Practices, and Codecov badges

### Changed
- **Supply Chain**: Update cosign to use bundle format for signing
- **OpenSSF**: Improve Scorecard compliance
- **Documentation**: Clarify external vault adapters are planned, not implemented

### Fixed
- **Tests**: Use SQLite-compatible SQL syntax in functional tests
- **Tests**: Resolve test failures and add interfaces for final class mocking

## [0.1.0] - 2026-01-05

### Added
- **Core Vault Service**: Secure secrets storage with CRUD operations
- **Envelope Encryption**: AES-256-GCM encryption with per-secret Data Encryption Keys (DEK)
- **Master Key Management**: Support for file-based, environment variable, and derived master keys
- **Access Control**: Backend user and group-based permission system
- **Context-based Scoping**: Organize secrets by context (e.g., "payment", "email")
- **Audit Logging**: Tamper-evident hash chain for all secret operations
- **CLI Commands**: Command-line tools for secret management and key rotation
- **Backend Module**: TYPO3 backend interface for secret management
- **TCA Integration**: Custom `vaultSecret` renderType for TCA fields
- **FlexForm Support**: Vault secrets in FlexForm configurations
- **Vault HTTP Client**: Make authenticated API calls without exposing secrets
- **OAuth 2.0 Support**: Token management with automatic refresh
- **Secret Versioning**: Track secret changes with version history
- **Expiration Support**: Optional expiration dates for secrets
- **Memory Safety**: Automatic wiping of sensitive data with `sodium_memzero()`

### Security
- Envelope encryption prevents master key exposure during normal operations
- Per-secret DEKs limit blast radius of key compromise
- Integrity verification with checksums on encrypted data
- Secure random nonce generation for each encryption operation
- Backend user group-based access control
- Audit trail with tamper-evident hash chain

### Technical
- PHP 8.2+ required
- TYPO3 v13.4 / v14 compatible
- PER Coding Style (latest)
- PHPStan level 10 (maximum)
- PHPat architecture tests
- Mutation testing with Infection
- Readonly classes and properties throughout
- Constructor property promotion
- Modern PHP 8.x patterns (match, named arguments, attributes)

[Unreleased]: https://github.com/netresearch/t3x-nr-vault/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/netresearch/t3x-nr-vault/compare/v0.4.6...v0.5.0
[0.4.6]: https://github.com/netresearch/t3x-nr-vault/compare/v0.4.5...v0.4.6
[0.4.5]: https://github.com/netresearch/t3x-nr-vault/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/netresearch/t3x-nr-vault/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/netresearch/t3x-nr-vault/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/netresearch/t3x-nr-vault/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/netresearch/t3x-nr-vault/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/netresearch/t3x-nr-vault/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/netresearch/t3x-nr-vault/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/netresearch/t3x-nr-vault/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/netresearch/t3x-nr-vault/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/netresearch/t3x-nr-vault/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/netresearch/t3x-nr-vault/releases/tag/v0.1.0
