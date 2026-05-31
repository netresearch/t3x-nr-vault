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
