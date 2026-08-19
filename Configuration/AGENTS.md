<!-- Managed by agent: keep sections and order; edit content, not structure -->
<!-- Last updated: 2026-08-19 | Last verified: 2026-08-19 -->

# AGENTS.md — Configuration

## Overview
TYPO3 configuration for nr-vault: TCA, DI (`Services.yaml`), backend modules, AJAX routes, icons, JS modules, site sets.

## Key Files
| File | Purpose |
|------|---------|
| `Configuration/Services.yaml` | DI definitions (services, factories, public aliases) |
| `Configuration/Backend/Modules.php` | Backend module + submodule registration |
| `Configuration/Backend/AjaxRoutes.php` | AJAX endpoints (reveal, verify-chain, etc.) |
| `Configuration/Icons.php` | Icon registry (SVG, bitmap) |
| `Configuration/JavaScriptModules.php` | ES module (`@netresearch/nr-vault/...`) registration |
| `Configuration/TCA/tx_nrvault_secret.php` | Secret table TCA |
| `Configuration/TCA/Overrides/*.php` | TCA overrides for core tables |
| `Configuration/Sets/NrVault/config.yaml` | Site set metadata |
| `Configuration/Sets/NrVault/settings.yaml` | Default settings |

## Golden Samples
| Pattern | Reference |
|---------|-----------|
| Interface alias | See `Services.yaml` — `VaultServiceInterface → VaultService` |
| Factory-provided service | `MasterKeyProviderInterface` factory entry |
| CLI command registration | `Classes/Command/*` + `console.command` tag in `Services.yaml` |
| Backend module route | `Configuration/Backend/Modules.php` |
| AJAX route | `Configuration/Backend/AjaxRoutes.php` |

## Setup
No separate setup — configuration is loaded by TYPO3 at bootstrap. After editing:
- Flush caches: `ddev exec vendor/bin/typo3 cache:flush`
- Reload DI container via backend Install Tool or `cache:flush`

## Build/Tests
| Task | Command |
|------|---------|
| Validate YAML | `make lint` covers PHP only — use `ddev exec yq eval Configuration/Services.yaml` |
| Validate DI wiring | `make test-functional` — DI container boots during kernel setup |
| PHPStan on TCA/config | `make phpstan` |
| TCA schema check | `ddev exec vendor/bin/typo3 extension:setup` rebuilds schema |

## Code Style
- **Services.yaml**: two-space indent; leading underscore for defaults (`_defaults:`); explicit `public: true` only where needed (controllers, commands, listeners).
- **TCA**: return a single array literal; no side effects; use `LLL:EXT:nr_vault/Resources/Private/Language/locallang_db.xlf:…` for labels.
- **Backend modules**: use `LLL:EXT:nr_vault/Resources/Private/Language/Modules/<name>.xlf` label paths (one XLIFF per module); POST-only routes declare `methods: ['POST']`.
- **AJAX routes**: name them `vault_<action>`; controller returns `JsonResponse`.
- **Do not** use `$GLOBALS['TYPO3_CONF_VARS']` edits inside `Configuration/` — keep them in `ext_localconf.php`.

## Security
- **No secrets in YAML/PHP config** — master-key material comes from providers (env/file/TYPO3 encryptionKey).
- **Modules + AJAX routes are `'access' => 'user'` on purpose** — authorization is asserted per action in the controller via `AccessControlServiceInterface::isGranted(VaultPermission)` (`ModuleAccessGuard` for modules, a 403 envelope for AJAX). Do NOT "harden" these back to `'admin'`: that silently makes the granular per-group permissions unusable for non-admins. Any new module route or AJAX endpoint MUST add its own `isGranted()` check.
- **TCA**: every column exposing vault data must set `'displayCond'` or guard access via hooks — secrets must not render unredacted in list views.
- **DI boundary**: avoid making internal classes `public: true`; only controllers, CLI commands, event listeners, and interfaces consumed via DI need it.

## Checklist
- [ ] `Services.yaml` validates via functional test bootstrap
- [ ] New service has interface + alias in `Services.yaml`
- [ ] New CLI command tagged `console.command`
- [ ] New backend module route paired with controller + template + XLIFF label
- [ ] New TCA column: matching `ext_tables.sql` + `locallang_db.xlf` entry
- [ ] `make phpstan` clean
- [ ] AJAX route registered with appropriate HTTP method

## Examples
### Interface alias
```yaml
Netresearch\NrVault\Service\VaultServiceInterface:
  alias: Netresearch\NrVault\Service\VaultService
  public: true
```

### Factory-provided service
```yaml
Netresearch\NrVault\Crypto\MasterKeyProviderInterface:
  factory: ['@Netresearch\NrVault\Crypto\MasterKeyProviderFactory', 'create']
  public: true
```

### Backend module route
```php
// Configuration/Backend/Modules.php
return [
    'admin_vault_secrets' => [
        // 'tools' works on v13 natively and is an alias for 'admin' on v14.
        'parent' => 'tools',
        // 'user': the controller asserts the operation permission per action.
        'access' => 'user',
        'workspaces' => 'live',
        'path' => '/module/admin/vault/secrets',
        'labels' => 'LLL:EXT:nr_vault/Resources/Private/Language/Modules/secrets.xlf',
        'iconIdentifier' => 'module-vault-secrets',
        'routes' => [
            // Route target is <Controller>::<action>Action — one action per route.
            // Only Migration flows use a single dispatch method (handleRequest).
            '_default' => ['target' => SecretsController::class . '::listAction'],
            'create'   => ['target' => SecretsController::class . '::createAction'],
            'toggle'   => ['target' => SecretsController::class . '::toggleAction', 'methods' => ['POST']],
        ],
    ],
];
```

### AJAX route
```php
// Configuration/Backend/AjaxRoutes.php
return [
    'vault_reveal' => [
        'path' => '/vault/reveal',
        'target' => AjaxController::class . '::revealAction',
        'methods' => ['POST'],
    ],
];
```

## When Stuck
- TYPO3 DI docs: <https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/ApiOverview/DependencyInjection/>
- TCA reference: <https://docs.typo3.org/m/typo3/reference-tca/main/en-us/>
- Backend module howto: <https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/ApiOverview/BackendRouting/BackendModules/>
- Invoke skill: `typo3-typoscript-ref` for TypoScript-adjacent patterns
