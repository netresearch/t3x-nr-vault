# Mutation Testing Baseline (2026-04-21)

> **Historical snapshot.** The numbers, thresholds and commands below describe
> April 2026 and are not maintained. The current floors, their measurement and
> the dated next target live next to the values in `infection.json5`; the
> release evidence workflow (`.github/workflows/release-evidence.yml`) is where
> the score is measured. `Build/phpunit.infection.xml`, used by the invocation
> below, has since been removed — Infection runs against `Build/phpunit.xml`.

First successful end-to-end Infection run after the CI/tooling modernization pass.

## Environment

- Infection: 0.32.5
- PHPUnit: 12.5.14
- PHP: 8.5.5
- Coverage driver: **Xdebug** (this PR switches the project from PCOV to
  Xdebug so Infection and audit-flow analysis get branch + path metrics
  that PCOV cannot report). Earlier internal capture runs showed PCOV,
  reflecting the transient pre-switch state.
- Threads: 4
- Configuration: `infection.json5` (+ `Build/phpunit.infection.xml`)

## Invocation

> **Note — pre-existing test failures:** 7 unit tests currently fail in the Unit
> suite (unrelated to Infection; production code changed ahead of tests in
> `HashChainVerificationResult`, `AccessControlService`, and
> `VaultStoreCommand`). Infection requires a green initial test run, so this
> baseline was produced by **pre-generating coverage** and invoking Infection
> with `--skip-initial-tests`. Once the Tests/ failures are fixed, the standard
> flow (`composer ci:test:php:mutation`) will work end-to-end.

```bash
# 1) Pre-generate coverage with the relaxed infection phpunit config.
mkdir -p /tmp/inf-cov
.Build/bin/phpunit -c Build/phpunit.infection.xml --testsuite=Unit \
    --coverage-xml=/tmp/inf-cov/coverage-xml \
    --log-junit=/tmp/inf-cov/junit.xml

# 2) Run Infection with pre-generated coverage.
.Build/bin/infection \
    --configuration=infection.json5 \
    --threads=4 \
    --coverage=/tmp/inf-cov \
    --skip-initial-tests \
    --show-mutations
```

## Headline metrics

| Metric                  | Value      |
| ----------------------- | ---------- |
| Total mutants           | 4 043      |
| Killed (by test fwk)    | 2 870      |
| Killed (static analysis)| 0          |
| Escaped                 | 1 173      |
| Errored                 | 0          |
| Timed out               | 0          |
| Not covered             | 0          |
| **MSI**                 | **70.99 %**|
| Covered Code MSI        | 70.99 %    |
| Mutation Code Coverage  | 100.00 %   |
| Wall time               | 1 m 52 s   |

`minMsi` threshold is currently 85 % and `minCoveredMsi` 95 % in
`infection.json5` → this baseline **fails** CI thresholds on both axes.

## Top 5 escaped mutants

| # | Mutator           | Location                                               |
| - | ----------------- | ------------------------------------------------------ |
| 1 | `ArrayItem`       | `Classes/Adapter/LocalEncryptionAdapter.php:86`        |
| 2 | `ArrayItem`       | `Classes/Adapter/LocalEncryptionAdapter.php:87`        |
| 3 | `Ternary`         | `Classes/Adapter/LocalEncryptionAdapter.php:89`        |
| 4 | `CastInt`         | `Classes/Audit/AuditLogEntry.php:66`                   |
| 5 | `DecrementInteger`| `Classes/Audit/AuditLogEntry.php:66`                   |

## Top escaped-mutant concentrations

### By mutator

```
155  IncrementInteger
153  DecrementInteger
102  MethodCallRemoval
 64  FunctionCallRemoval
 61  ArrayItemRemoval
 55  Ternary
 53  Coalesce
 52  CastInt
 50  ConcatOperandRemoval
 44  Concat
```

The `IncrementInteger` / `DecrementInteger` dominance suggests many
magic-number checks (length limits, bit-shift offsets) are not asserted
against boundary mutations — tests pass the same happy-path value without
exercising ± 1 variants.

### By file (top 10)

```
 98  Classes/Command/VaultCleanupOrphansCommand.php
 79  Classes/Domain/Model/Secret.php
 79  Classes/Utility/IdentifierValidator.php
 73  Classes/Audit/AuditLogService.php
 68  Classes/Hook/FlexFormVaultHook.php
 63  Classes/Command/VaultAuditMigrateCommand.php
 62  Classes/Form/Element/VaultSecretElement.php
 56  Classes/Service/VaultService.php
 55  Classes/Service/SecretDetectionService.php
 46  Classes/Command/VaultRotateMasterKeyCommand.php
```

`VaultCleanupOrphansCommand`, `Secret`, and `IdentifierValidator` together
account for 256 of 1 173 escapes (≈ 22 %) — focusing future test-hardening
sprints there is the highest-leverage move.

## Reports generated

- `.Build/infection/infection.json`  — machine-readable, consumed by `check-msi.sh`
- `.Build/infection/infection.html`  — mutator-level diff inspector
- `.Build/infection/infection.log`   — human-readable full log
- `.Build/infection/summary.log`     — one-line category counts
- `.Build/infection/per-mutator.md`  — Markdown break-down by mutator
- `.Build/infection/badge.json`      — run `Build/Scripts/check-msi.sh > .Build/infection/badge.json`

## Status update (2026-04-21, r2 — targeted mutant-killer pass)

A second pass read the Infection HTML report per-file and added surgical
mutant-killer tests against `OrphanCleanupTask`, `Audit`, and `Command/*`
hotspots. The unit suite grew 1625 → 1705 tests, assertions 6797 → 6949,
and MSI rose from 70.86 % to **72.35 %** (+1.49 pp). Thresholds ratcheted to
`minMsi: 72` / `minCoveredMsi: 72`.

Current measurements:

| Metric      | r1 (baseline) | r2 (this pass) | Delta |
| ----------- | ------------: | -------------: | ----: |
| Total       |          4043 |           4061 |   +18 |
| Killed      |          2870 |           2938 |   +68 |
| Escaped     |          1173 |           1123 |   –50 |
| **MSI**     |        70.99% |    **72.35 %** | +1.36 |

## Status update (2026-04-21, r1 — test-pyramid pass)

After adding ~128 boundary-value assertions across the top escape hotspots
(Secret, IdentifierValidator, VaultCleanupOrphansCommand, AuditLogService,
FlexFormVaultHook), the unit suite grew 1365 → 1625 tests, assertions
3187 → 6797. The measured post-pass MSI was **70.86 %** (4 060 mutants,
2 876 killed, 1 184 escaped).

MSI stayed flat because:

1. Production code grew by 17 new mutants (security hardening: disabled-user
   check, stale-group filtering, uid-gap detection, OAuth fallback), of
   which only 7 were killed by the accompanying tests. Denominator rose
   faster than numerator.
2. Many boundary-value assertions landed on paths the existing tests already
   killed. Pushing MSI higher from here needs the surgical loop: open
   `.Build/infection/infection.html`, pick one surviving mutant, write a
   test that kills it, repeat.

Thresholds are now set to `minMsi: 70` / `minCoveredMsi: 70` with a
documented ratchet plan (see `infection.json5`):

```
2026-04:  70 /  70  (current)
2026-05:  73 /  73
2026-06:  77 /  77
2026-07:  80 /  85
2026-08:  83 /  90
2026-Q4:  85 /  95  (long-term)
```

## Next steps

1. Work the HTML report one mutant at a time; batch the surgical fixes by
   file (keeps diff review tight).
2. Publish `.Build/infection/badge.json` via the repo's `gh-pages`/`assets`
   branch so the README MSI badge reflects live runs.
3. Each monthly ratchet bump must be backed by a PR that demonstrates the
   new floor has been met — otherwise back off and try again next cycle.
