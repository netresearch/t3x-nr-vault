<!-- Managed by agent: keep sections and order; edit content, not structure -->
<!-- Last updated: 2026-08-19 | Last verified: 2026-08-19 -->

# AGENTS.md — .ddev

## Overview
DDEV local development environment for nr-vault. Hosts TYPO3 + MariaDB + OAuth mock for auth-flow tests.
Invoke skill **`typo3-ddev`** for setup and multi-version testing patterns.

## Key Files
| File | Purpose |
|------|---------|
| `.ddev/config.yaml` | Main DDEV configuration (PHP/Node versions, webserver) |
| `.ddev/docker-compose.mock-oauth.yaml` | Mock OAuth sidecar for OAuthTokenManager tests |
| `.ddev/commands/host/` | Host-side custom commands |
| `.ddev/commands/web/` | Container-side custom commands |

## Golden Samples
| Pattern | Reference |
|---------|-----------|
| Sidecar service override | `.ddev/docker-compose.mock-oauth.yaml` |
| Standard TYPO3 v14 config | `.ddev/config.yaml` |

## Setup
| Task | Command |
|------|---------|
| Start env | `make up` (runs `ddev start` + TYPO3 install) |
| Stop env | `make down` |
| Shell into web container | `make shell` (or `ddev ssh`) |
| Composer in container | `ddev composer <cmd>` |
| Describe URLs/credentials | `ddev describe` |

## Build/Tests
| Task | Command |
|------|---------|
| Run tests | NOT in DDEV — use `make test-unit` / `make test-functional` (containerized `Build/Scripts/runTests.sh`, own ephemeral containers) |
| Run single test | `Build/Scripts/runTests.sh -s unit Tests/Unit/Path/ToTest.php` |
| DB export | `ddev export-db --file=dump.sql.gz` |
| DB import | `ddev import-db --file=dump.sql.gz` |

## Directory Structure
```
.ddev/
├── config.yaml                        # PHP/node versions, webserver
├── docker-compose.mock-oauth.yaml     # Mock OAuth server sidecar
└── commands/
    ├── host/                          # Host-side commands
    └── web/                           # In-container commands
```

## Code Style
- Keep `config.yaml` minimal; put extras in `docker-compose.*.yaml` overrides.
- Custom commands start with `## Description: …` header.
- Mark DDEV-managed files with `#ddev-generated` comment.
- Pin addon versions for reproducibility.

## Security
- **Never** commit `.ddev/.env` with secrets — include only sample/placeholder values.
- Mock OAuth server must return deterministic, obviously-fake tokens — never reuse prod token shapes.
- Do not expose the DDEV Mailhog/router to public networks; DDEV binds loopback by default — keep it that way.

## Checklist
- [ ] `ddev start` works after changes
- [ ] `make up` → `make test-unit` → `make test-functional` all pass
- [ ] Custom commands carry `## Description:` header
- [ ] No hardcoded paths or credentials in `config.yaml`
- [ ] Overrides live in `docker-compose.*.yaml`, not `config.yaml`
- [ ] Works on macOS, Linux, WSL2

## Examples
### Enable mock-oauth sidecar
```bash
ddev start   # picks up docker-compose.mock-oauth.yaml automatically
ddev describe mock-oauth   # show URL
```

### Multi-version PHP testing
```yaml
# .ddev/config.override.yaml (developer-local, not committed)
php_version: "8.3"
```

## When Stuck
- `ddev describe` — URLs, credentials, add-on status
- `ddev logs` — web/db/custom containers
- DDEV docs: <https://ddev.readthedocs.io>
- Invoke skill: `typo3-ddev`
