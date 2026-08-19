<!-- Managed by agent: keep sections and order; edit content, not structure -->
<!-- Last updated: 2026-08-02 | Last verified: 2026-08-02 -->

# AGENTS.md — .github/workflows

## Overview
GitHub Actions workflows for nr-vault. CI, releases, auto-merge, and community automation.

## Key Files
| File | Purpose |
|------|---------|
| `ci.yml` | Extension-specific test matrix — a thin call into `typo3-ci-workflows/ci.yml` |
| `checks.yml` | Security + quality jobs (security, gitleaks, zizmor, codeql, scorecard, fuzz, license-check, dependency-review, pr-quality, labeler). **Byte-identical and drift-enforced across every netresearch typo3-extension — never add a repo-specific job here** |
| `security-gates.yml` | Mutation ratchet over `Classes/Crypto`, `Classes/Security`, `Classes/Audit`, `Classes/Http` (`infection-security.json5`). Standalone precisely because `checks.yml` is drift-locked |
| `check-template-drift.yml` | Verifies this repo still matches the `typo3-extension` template |
| `docs.yml` | Renders `Documentation/` on PRs touching it |
| `release.yml` | Tag-triggered TER publish + GitHub release assets |
| `release-evidence.yml` | Publishes the security release-evidence bundle for a tag |
| `republish.yml` | Manual re-run of a publish target (ter / docs / packagist) for an existing tag |
| `auto-merge-deps.yml` | Auto-merge dependency PRs when CI green (Renovate/Dependabot) |
| `community.yml` | Community health: labeler, stale bot, welcome |
| `../labeler.yml` | PR auto-labeling rules |
| `../dependabot.yml` | Dependabot ecosystems |
| `../zizmor.yml` | zizmor audit configuration |
| `../CODEOWNERS` | Code ownership |
| `../../renovate.json` | Renovate configuration (repository root, not `.github/`) |

## Golden Samples
| Pattern | Reference |
|---------|-----------|
| TYPO3 extension matrix test | `.github/workflows/ci.yml` |
| TER release pipeline | `.github/workflows/release.yml` |
| Auto-merge with CI gate | `.github/workflows/auto-merge-deps.yml` |

## Setup
- Workflows run on GitHub-hosted runners (`ubuntu-latest`).
- Local validation: `actionlint` (via pre-commit or `gh act`).

## Build/Tests
| Task | Command |
|------|---------|
| Lint workflows | `actionlint .github/workflows/*.yml` |
| Local workflow run | `act -j <job>` (requires Docker) |
| Workflow status | `gh run list --limit 5` |
| Re-run failed run | `gh run rerun <run-id>` |
| Inspect annotations | `gh api repos/$REPO/check-runs/$ID/annotations` |

## Directory Structure
```
.github/
├── workflows/
│   ├── ci.yml
│   ├── checks.yml            # drift-locked, shared across all typo3-extensions
│   ├── check-template-drift.yml
│   ├── security-gates.yml
│   ├── docs.yml
│   ├── release.yml
│   ├── release-evidence.yml
│   ├── republish.yml
│   ├── auto-merge-deps.yml
│   └── community.yml
├── ISSUE_TEMPLATE/
├── PULL_REQUEST_TEMPLATE.md
├── labeler.yml
├── dependabot.yml
├── zizmor.yml
├── template.yaml            # template identity for the drift check
└── CODEOWNERS
```

## Code Style
- **Pin every third-party action to a full commit SHA** (not tags). Keep `# vX.Y.Z` comment next to the SHA. **`netresearch/*` reusable workflows stay on `@main`** so upstream fixes propagate — do not SHA-pin those.
- **Minimal permissions** on every workflow — declare `permissions: contents: read` by default, widen per-job only where needed.
- **Reusable workflows** live under `.github/workflows/reusable-*.yml` or are centrally hosted.
- **Naming**:
  - Workflow file: `<purpose>.yml`
  - Workflow name: Title Case (`CI`, `Release`)
  - Job id: `kebab-case`
  - Step name: Sentence case
  - Secret: `SCREAMING_SNAKE`
- **Caching**: `actions/setup-php` + `actions/cache` for composer, cache by `composer.json`.
- **Concurrency**: add `concurrency: { group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true }` on CI.

## Security
- **Never use `permissions: write-all`** — declare minimal per-job.
- **Never use `secrets: inherit`** when calling reusable workflows — pass secrets explicitly by name:
  ```yaml
  secrets:
    TER_TOKEN: ${{ secrets.TER_TOKEN }}
  ```
- **Pin third-party actions to commit SHAs** (not tags) — mitigates tag-hijack supply-chain attacks.
- **Secret scanning is enforced** — the `gitleaks` job in `checks.yml` runs on every PR against the root `.gitleaks.toml`; `zizmor` audits these workflow files themselves (config in `.github/zizmor.yml`).
- **Mask dynamic values** with `::add-mask::` before logging.
- **Environment protection** for release/deploy — require reviewers.
- **OIDC** over long-lived credentials where possible.
- **Reviewdog / actionlint**: set `fail_level: error` so warnings block merges.

## Checklist
- [ ] `actionlint` clean
- [ ] Third-party actions pinned to full SHA with version comment (`netresearch/*` reusables stay `@main`)
- [ ] `checks.yml` untouched — repo-specific jobs go elsewhere or the drift check fails
- [ ] `permissions:` block explicit and minimal
- [ ] No `secrets: inherit` — explicit per-secret
- [ ] Cache key uses lockfile/composer.json hash
- [ ] Concurrency group set for long-running workflows
- [ ] CI annotations checked: `gh api repos/OWNER/REPO/check-runs/$ID/annotations`

## Examples
```yaml
# Pinned action with comment
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

# Minimal permissions + concurrency
name: CI
on: [push, pull_request]
permissions:
  contents: read
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: shivammathur/setup-php@c541c155eee45413f5b09a52248675b1a2575231 # v2.31.1
        with:
          php-version: '8.2'
          coverage: none
      - run: composer install --prefer-dist --no-progress
      - run: composer ci
```

## When Stuck
- Actions docs: <https://docs.github.com/en/actions>
- Workflow syntax: <https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions>
- Existing workflows in this repo are the best reference.
- Invoke skill: `github-project` for ruleset / merge-queue / branch protection
- Invoke skill: `git-workflow` for release orchestration
