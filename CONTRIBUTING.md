# Contributing to nr-vault

Thank you for your interest in contributing to nr-vault! This document provides guidelines and information for contributors.

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributions from everyone.

## Getting Started

### Prerequisites

- PHP 8.2 or higher
- Composer 2.x
- TYPO3 v13.4 or v14
- Docker and DDEV (recommended for local development)

### Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/netresearch/t3x-nr-vault.git
   cd t3x-nr-vault
   ```

2. Install dependencies:
   ```bash
   composer install
   ```

3. Start the development environment (if using DDEV):
   ```bash
   ddev start
   ddev composer install
   ```

## Development Workflow

### Branch Naming

Use descriptive branch names with prefixes:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `test/` - Test additions or fixes

### Commit Messages

The local `commit-msg` hook (CaptainHook, see `captainhook.json`)
enforces a **subject-style** policy, not Conventional-Commit type
prefixes. Each subject line must:

- be capitalized,
- use the imperative mood ("Add", not "Added"/"Adds"),
- stay within the length limit,
- not be empty,
- not end with a period.

```
Add secret rotation support
Fix memory leak in encryption service
Update installation instructions
Add unit tests for VaultService
```

> Note: lowercase Conventional-Commit prefixes (`feat:`, `fix:`) are
> **rejected** by the imperative-mood / capitalize-subject rules. Write
> the subject as an imperative sentence instead.

#### Sign-off (DCO)

Every commit must carry a `Signed-off-by:` trailer (Developer
Certificate of Origin). Add it with `git commit -s`. This is **required
and enforced at the pull-request gate**; the local commit-msg hook does
not currently check for it, so always pass `-s`.

### Code Style

This project follows PER-CS 2.0 coding standards. Run the fixer before committing:

```bash
composer ci:cgl
```

Check for code style issues (dry-run, no changes written):

```bash
composer ci:test:php:cgl
```

### Static Analysis

We use PHPStan at the maximum level (10). Run analysis:

```bash
composer ci:test:php:phpstan
```

> **Git worktree note:** in a fresh git worktree (before
> `phpstan/extension-installer` has populated `.Build/vendor/...`),
> `composer ci:test:php:phpstan` can fail with a cryptic include error.
> If that happens, run PHPStan with the plugin-free config:
>
> ```bash
> .Build/bin/phpstan analyse --configuration=Build/phpstan.no-plugins.neon
> ```

### Testing

Run the full CI suite (unit + fuzz + phpstan + architecture + code style):

```bash
composer ci
```

Run specific test suites:

```bash
# Unit tests
composer ci:test:php:unit

# Functional tests
composer ci:test:php:functional

# Unit + functional together
composer test:all
```

## Pull Request Process

1. **Fork and branch**: Create a feature branch from `main`

2. **Make changes**: Implement your changes following the coding standards

3. **Test**: Ensure all tests pass and add new tests for your changes

4. **Commit**: Use the subject-style commit messages described above, signed off with `git commit -s`

5. **Push**: Push your branch to your fork

6. **Open PR**: Create a pull request with:
   - Clear description of changes
   - Link to any related issues
   - Screenshots for UI changes

### PR Requirements

- [ ] All tests pass
- [ ] PHPStan reports no errors
- [ ] Code style is correct
- [ ] Documentation is updated (if applicable)
- [ ] CHANGELOG.md is updated
- [ ] For security-critical paths: two approvals and a threat-model delta (see below)

## Security-Critical Changes

This extension stores other people's credentials. A defect in the paths below
is not a bug report next week, it is a disclosure. Changes to them carry two
extra requirements on top of the normal PR process.

### Which paths

| Path | Why |
|------|-----|
| `Classes/Crypto/` | Envelope encryption, key wrapping, master-key providers |
| `Classes/Security/` | Access control, permissions, technical-actor context |
| `Classes/Audit/` | Tamper-evident audit log and its hash chain |
| `infection-security.json5`, `.github/workflows/security-gates.yml` | The mutation ratchet that guards the above |
| `.github/workflows/release-evidence.yml`, `Build/Scripts/collect-evidence.php` | The release evidence bundle |
| `SECURITY.md` | The published security policy and its SLAs |

A change counts as security-critical if it touches any of these, **or** if it
changes how a secret, key, or audit record is produced, stored, transported, or
compared anywhere else in the codebase.

### Rule 1 — two-person review

A security-critical PR needs **two approving reviews**, and the author may not
be one of them. One approver must be a code owner for the touched path (see
`.github/CODEOWNERS`). Green CI is not a substitute: the mutation ratchet and
the invariant tests catch regressions in behaviour we already thought of, and
the second reviewer is there for the ones we did not.

If a second qualified reviewer genuinely is not available, do not quietly
self-merge. Say so explicitly in the PR — what you could not get reviewed and
why — so the deviation is on the record and can be revisited. An undocumented
single-approval merge on a crypto path is treated as a process incident, not a
shortcut.

### Rule 2 — threat-model delta

Every security-critical PR must state, in its description, what the change does
to the threat model. Three lines are enough when the answer is "nothing new":

```markdown
## Threat-model delta

- New or changed trust boundary: none — the DEK never leaves EncryptionService.
- New attacker capability required: none.
- Invariant added/removed: adds "a wrapped DEK is rejected when its identifier
  does not match" (covered by MasterKeyRotationAbortTest).
```

Answer these explicitly:

1. **Trust boundaries** — does data cross a new boundary (process, host,
   network, database, log sink, external provider)?
2. **Attacker capability** — what would an attacker now need, and did that get
   cheaper? Call out anything that weakens a constant-time comparison, widens a
   grant, or lengthens a plaintext's lifetime in memory.
3. **Invariants** — which security invariant does this add, change, or remove,
   and which test pins it? A removed invariant needs its own justification.

"No change to the threat model" is a valid answer. Silence is not — a reviewer
cannot tell the two apart, and the delta is what the release evidence bundle
and any future audit are read against.

### Release evidence

Tagged releases publish a security evidence bundle — test results per suite,
coverage overall and for the security directories, the mutation score for the
whole codebase and for the security-critical scope, the dependency audit, the
reference `vault:doctor` posture, and pointers to the signed release artifacts.
It is assembled by `Build/Scripts/collect-evidence.php` and published by
`.github/workflows/release-evidence.yml`.

Every entry in the bundle carries a status of `pass`, `warn`, `fail` or
`absent`. `absent` means the producing step did not run in that build; it is
recorded rather than omitted, precisely so a gap cannot be mistaken for a pass.

Two rules follow from that:

- **Do not describe a release as verified while any bundle entry is `fail`, and
  do not describe an `absent` entry as verified at all.** Fix the gap, or state
  plainly in the release notes what was not measured.
- **A release does not ship with unresolved High or Critical findings** — from
  the bundle, from CodeQL or Opengrep, or from `composer audit`. See the
  emergency-release rules in
  [SECURITY.md](SECURITY.md#emergency-releases) for the one narrow exception
  (a documented, mitigated finding published in the advisory) and how it is
  handled.

Build a bundle locally with `composer ci:evidence`; verify the collector itself
with `composer ci:test:evidence` (also part of `composer ci`). See
[SECURITY.md](SECURITY.md#release-evidence) for how to fetch and verify a
published bundle, and `Documentation/Developer/Index.rst` for the manifest
schema.

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

- TYPO3 version
- PHP version
- Steps to reproduce
- Expected behavior
- Actual behavior
- Error messages (if any)

### Feature Requests

For feature requests, please describe:

- The problem you're trying to solve
- Your proposed solution
- Alternative solutions considered

## Security Vulnerabilities

**DO NOT** create public issues for security vulnerabilities.

Use GitHub's private security reporting feature:
**[Report a vulnerability](https://github.com/netresearch/t3x-nr-vault/security/advisories/new)**

See [SECURITY.md](SECURITY.md) for details.

## Documentation

- Update documentation for any user-facing changes
- Use RST format in `Documentation/` directory
- Keep README.md synchronized with documentation

## License

By contributing, you agree that your contributions will be licensed under the GPL-2.0-or-later license.

## Questions?

If you have questions about contributing, please [open a discussion](https://github.com/netresearch/t3x-nr-vault/discussions) on GitHub.

---

Thank you for contributing to nr-vault!
