<!-- Managed by agent: keep sections and order; edit content, not structure -->
<!-- Last updated: 2026-04-21 | Last verified: 2026-04-21 -->

# AGENTS.md — Tests

## Overview
Unit, Functional, Fuzz, and Architecture tests for nr-vault.
Invoke skill **`typo3-testing`** for deeper guidance on fixtures, mocking, and CI setup.

## Setup
- Local: `make up` to start DDEV, then `make test-unit` / `make test-functional`.
- CI-only config at `Build/phpunit.xml` (unit + fuzz) and `Build/FunctionalTests.xml` (functional).
- Functional tests need DB — run inside DDEV (`ddev exec ...`).

## Key Files
| File | Purpose |
|------|---------|
| `Tests/Unit/Service/VaultServiceTest.php` | Core vault service unit tests |
| `Tests/Unit/Crypto/FileMasterKeyProviderTest.php` | Master-key provider (file) |
| `Tests/Unit/Crypto/EnvironmentMasterKeyProviderTest.php` | Master-key provider (env) |
| `Tests/Unit/Audit/AuditLogServiceTest.php` | Audit log writer + HMAC chain |
| `Tests/Unit/Hook/FlexFormVaultHookTest.php` | FlexForm hook behavior |
| `Tests/Unit/Utility/IdentifierValidatorTest.php` | Identifier validation edge cases |
| `Tests/Functional/Crypto/MasterKeyRotationTest.php` | Full rotation end-to-end |
| `Tests/Functional/Controller/AjaxControllerTest.php` | AJAX reveal flow |
| `Tests/Functional/Controller/Fixtures/be_users.csv` | Test BE users |
| `Tests/Fuzz/` | Fuzz suite — identifiers, payloads |
| `Tests/Architecture/` | PHPat dependency rules |
| `Tests/E2E/` | Playwright browser tests (own scoped AGENTS.md) |

## Golden Samples
| Pattern | Reference |
|---------|-----------|
| Unit test with dataProvider | `Tests/Unit/Utility/IdentifierValidatorTest.php` |
| Unit test of crypto | `Tests/Unit/Crypto/FileMasterKeyProviderTest.php` |
| Functional with DB fixtures | `Tests/Functional/Controller/AjaxControllerTest.php` |
| Functional crypto integration | `Tests/Functional/Crypto/MasterKeyRotationTest.php` |
| Hook test with DataHandler | `Tests/Unit/Hook/FlexFormVaultHookTest.php` |

## Build/Tests
| Type | Command |
|------|---------|
| Unit only | `make test-unit` (or `composer ci:test:php:unit`) |
| Functional only | `make test-functional` (or `composer ci:test:php:functional`) |
| Fuzz | `composer ci:test:php:fuzz` |
| All CI (unit+fuzz+phpstan+cgl) | `composer ci` |
| Mutation (Infection) | `make test-mutation` |
| Single file | `ddev exec vendor/bin/phpunit -c Build/phpunit.xml Tests/Unit/Path/ToTest.php` |
| Coverage | `ddev exec vendor/bin/phpunit -c Build/phpunit.xml --coverage-html .Build/coverage` |
| Test-base convention check | `php Tests/scripts/check-test-base-class.php` |
| Regenerate legacy allow-list | `php Tests/scripts/check-test-base-class.php --update-allowlist` |

## Directory Structure
```
Tests/
├── Architecture/      # PHPat boundary rules
├── E2E/               # Playwright (see E2E/AGENTS.md)
├── Functional/        # DB-backed integration
│   ├── Controller/
│   │   └── Fixtures/  # CSV fixtures
│   └── Crypto/
├── Fuzz/              # Property / input fuzzing
└── Unit/              # Fast isolated tests (100+ files)
    ├── Adapter/  Audit/  Command/  Configuration/  Controller/
    ├── Crypto/  Domain/  EventListener/  Hook/  Http/
    ├── Service/  Task/  Upgrades/  Utility/
```

## Code Style
- **Unit tests MUST extend `\Netresearch\NrVault\Tests\Unit\TestCase`**
  (the project base; composes `TcaSchemaMockTrait` + `BackendUserMockTrait`).
  Direct extension of `UnitTestCase` or `PHPUnit\Framework\TestCase` is gated by
  `Tests/scripts/check-test-base-class.php` — existing files are allow-listed
  as tech debt and migrated in a separate PR.
- **Functional tests that need the master-key lifecycle MUST extend
  `\Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase`**
  (handles key generation, `$GLOBALS` wiring, tearDown zeroing, UUID v7
  helper). Pure "no-secret" functional tests may extend
  `FunctionalTestCase` directly.
- Test class name: `<SourceClass>Test`; methods use the `#[Test]` PHPUnit attribute (`PHPUnit\Framework\Attributes\Test`) or a `test` prefix — never the legacy `@test` docblock annotation.
- Use `#[DataProvider]` (native PHPUnit 10 attribute) for parameterized cases.
- One assertion concept per test; split by behaviour, not by line count.
- No real HTTP / filesystem calls — mock adapters (`VaultAdapterInterface`).
- Functional fixtures: `Tests/.../Fixtures/*.csv`, loaded via `$this->importCSVDataSet()`.

## Security
- **Never commit real secrets** — fixtures use clearly synthetic values. `.gitleaks.toml` allowlists only a narrow set of specific paths (see the `[allowlist] paths` list) for known synthetic tokens; new files are scanned by default.
- **Master keys in tests** are generated per-test (`sodium_crypto_secretbox_keygen()`), never hard-coded.
- **Do not** test against production vault backends.
- **Audit logs** in tests must still verify HMAC chain integrity when the code path produces entries.

## Checklist
- [ ] `composer ci` passes (unit + fuzz + phpstan + cs)
- [ ] `make test-functional` passes
- [ ] New src file has a matching `Tests/Unit/...Test.php`
- [ ] Public API change has a functional test exercising it
- [ ] No hardcoded secrets — generate at runtime or use placeholders
- [ ] Fixtures are minimal (smallest CSV that reproduces the case)
- [ ] Mutation score not regressed on touched files (spot-check with `make test-mutation`)

## Examples
```php
// Unit test with DataProvider attribute, project base class
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

final class IdentifierValidatorTest extends TestCase
{
    #[DataProvider('invalidIdentifierProvider')]
    public function testRejectsInvalidIdentifier(string $input, string $reason): void
    {
        $this->expectExceptionMessage($reason);
        (new IdentifierValidator())->validate($input);
    }

    public static function invalidIdentifierProvider(): iterable
    {
        yield 'path-traversal' => ['../etc/passwd', 'control'];
        yield 'null-byte' => ["a\0b", 'control'];
    }
}
```

```php
// Functional test — extend the project abstract base
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;

final class AuditLogServiceTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users.csv';
    // backendUserUid defaults to 1; masterKeyPath is wired automatically.
}
```

## Shared Test Infrastructure
| Helper | Purpose |
|--------|---------|
| `Tests/Functional/AbstractVaultFunctionalTestCase.php` | Master-key lifecycle + UUID v7 helper (deduplicates ~17 functional tests) |
| `Tests/Unit/TestCase.php` | Project base composing the two mock traits below |
| `Tests/Unit/Traits/TcaSchemaMockTrait.php` | `mockTcaSchemaForTable()` (was duplicated 4x) |
| `Tests/Unit/Traits/BackendUserMockTrait.php` | `createMockBackendUser()` (was duplicated 3x) |
| `Tests/Unit/Traits/EnvironmentSandboxTrait.php` | Throwaway project layout + initialised `Environment` for tests that resolve paths via `getVarPath()` / check the `getPublicPath()` boundary (audit file sink, extension-config path defaults) |
| `Tests/Unit/Traits/ErrorSuppressionTrait.php` | `withoutPhpDiagnostics()` — run one call with PHP diagnostics silenced, for code that handles a native failure by checking the return value (`fopen`/`mkdir` returning false) instead of using `@`, where the genuine warning would otherwise trip `failOnWarning` |
| `Tests/Unit/Fixtures/SecretFixtureBuilder.php` | Fluent builder for `SecretDetails` / `SecretMetadata` / `Secret` DTOs (replaces ~6 hand-rolled factory methods) |
| `Tests/Unit/Fixtures/FailingStreamWrapper.php` | Stream wrapper that stats as a healthy writable file but fails at a chosen point (`fopen` refused/throwing, `flock` refused, short write) — the audit-sink write layers a real filesystem cannot reach |
| `Tests/Unit/Fixtures/AuditChainLockHost.php` | Host exposing `AuditChainLockTrait`'s private lock primitives so the raw-vs-savepoint lock protocol can be tested without a consumer's write path |
| `Tests/scripts/check-test-base-class.php` | Architecture check enforcing the project base on new unit tests |

## When Stuck
- Invoke skill: `typo3-testing`
- TYPO3 TestingFramework docs: <https://docs.typo3.org/other/typo3/testing-framework/main/en-us/>
- Check existing tests in the same directory for patterns
- Root AGENTS.md for project-wide conventions
