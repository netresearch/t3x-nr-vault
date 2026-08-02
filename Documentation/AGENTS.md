<!-- Managed by agent: keep sections and order; edit content, not structure -->
<!-- Last updated: 2026-08-02 | Last verified: 2026-08-02 -->

# AGENTS.md — Documentation

## Overview
RST documentation for <https://docs.typo3.org> + Architecture Decision Records.
Invoke skill **`typo3-docs`** for deeper guidance (rendering, directives, screenshots).

## Key Files
| File | Purpose |
|------|---------|
| `Documentation/Index.rst` | Main entry point; version table, toctree |
| `Documentation/guides.xml` | Render metadata (replaces old Settings.cfg) |
| `Documentation/Introduction/Index.rst` | Product intro |
| `Documentation/Installation/Index.rst` | Install + environment prep |
| `Documentation/Usage/Index.rst` | TCA / FlexForm / TypoScript / site-config usage |
| `Documentation/Usage/ExtensionSettings.rst` | Admin tooling reference |
| `Documentation/Usage/ApiEndpointExample.rst` | Worked example of the vault HTTP client |
| `Documentation/Configuration/Index.rst` | Every extension setting as a `confval` — the anchor other pages link to |
| `Documentation/Security/Index.rst` | Encryption, access control, audit logging + subsection toctree |
| `Documentation/Security/ThreatModel.rst` | Assets, actors, trust boundaries, STRIDE-lite, attack scenarios |
| `Documentation/Security/SecurityProfiles.rst` | standard vs hardened; migration checklist |
| `Documentation/Security/TrustBoundaries.rst` | The five process boundaries + frontend/page-cache caveats |
| `Documentation/Security/Cryptography.rst` | Envelope scheme, HKDF uses, algorithm agility, memory policy |
| `Documentation/Security/AuditEvidence.rst` | What the chain proves; epochs, anchoring, sinks, export |
| `Documentation/Security/KnownLimitations.rst` | Honest boundaries — load-bearing, read before deploying |
| `Documentation/Operations/Index.rst` | Operations toctree + start-here matrix |
| `Documentation/Operations/HardenedDeployment.rst` | Step-by-step hardened rollout + smoke test |
| `Documentation/Operations/KeyCustody.rst` | Per-provider key custody, rotation story, permissions |
| `Documentation/Operations/BackupAndRestore.rst` | DB/key separation, restore verification, wrong-key symptoms |
| `Documentation/Operations/KeyRotation.rst` | `vault:rotate-master-key` flow + transit key distinction |
| `Documentation/Operations/MonitoringAndAlerting.rst` | Scheduler tasks, events, SIEM wiring, what to page on |
| `Documentation/Operations/IncidentResponse.rst` | Exposure / tampering / break-glass runbooks |
| `Documentation/Operations/Decommissioning.rst` | Disposal, key destruction, retention vs deletion |
| `Documentation/Auditor/Index.rst` | Auditor toctree + first three checks |
| `Documentation/Auditor/TargetOfEvaluation.rst` | Scope, trust assumptions, what nr-vault is not |
| `Documentation/Auditor/ControlMapping.rst` | Controls → BSI IT-Grundschutz / OWASP ASVS + declared gaps |
| `Documentation/Auditor/EvidenceCollection.rst` | Read-only evidence commands + artefact package |
| `Documentation/Auditor/VerificationProcedures.rst` | Reproducible procedures (some STAGING-ONLY) |
| `Documentation/Troubleshooting/Index.rst` | Common issues + diagnostics |
| `Documentation/Developer/Index.rst` | Developer toctree |
| `Documentation/Developer/Api.rst` | PHP API surface for integrators |
| `Documentation/Developer/Commands.rst` | `vault:*` CLI reference |
| `Documentation/Developer/TcaIntegration.rst` | `vaultSecret` field type, record copy/delete semantics |
| `Documentation/Developer/TechnicalActorContext.rst` | Headless `runAs()` scopes |
| `Documentation/Developer/SecureOutbound.rst` | Vault HTTP client + OAuth |
| `Documentation/Developer/Adr/Index.rst` | ADR index |
| `Documentation/Developer/Adr/ADR-006-AuditLogging.rst` | Audit log design |
| `Documentation/Developer/Adr/ADR-018-FlexFormSecretLifecycle.rst` | FlexForm integration |
| `Documentation/Developer/Adr/ADR-023-AuditHashChainHmac.rst` | Tamper-evident audit chain |
| `Documentation/Developer/Adr/ADR-034-AuditChainTipAnchor.rst` | In-DB chain-tip anchor |
| `Documentation/Developer/Adr/ADR-035-FrontendPlaceholderAllowSet.rst` | Frontend placeholder allow-set |
| `Documentation/Sitemap.rst` | Page index |

## Golden Samples
| Pattern | Reference |
|---------|-----------|
| Top-level section | `Documentation/Introduction/Index.rst` |
| ADR structure | `Documentation/Developer/Adr/ADR-023-AuditHashChainHmac.rst` |
| CLI reference page | `Documentation/Developer/Commands.rst` |
| Troubleshooting entry | `Documentation/Troubleshooting/Index.rst` |

## Setup
- Docker required for local rendering.
- PNG images live in `Documentation/Images/` (subfolders mirror page paths).

## Build/Tests
| Task | Command |
|------|---------|
| Render (Make target) | `make docs` |
| Render (direct) | `docker run --rm --pull always -v "$(pwd)":/project -t ghcr.io/typo3-documentation/render-guides:latest --config=Documentation` |
| Preview output | Open `Documentation-GENERATED-temp/Index.html` |
| Clean output | `rm -rf Documentation-GENERATED-temp/` |

## Code Style
- RST, not Markdown.
- Headings: `=` H1, `-` H2, `~` H3, `^` H4.
- **One sentence per line** — diffs stay readable.
- Line width ~80 chars where natural.
- Admonitions: `.. note::`, `.. warning::`, `.. tip::`.
- Tables: `.. t3-field-list-table::` or grid tables.
- Cross-reference with `:ref:` and explicit labels. **Extension settings are `confval` entries — link them with `:confval:`name <ext-nrvault-camelCaseName>`, never `:ref:`**: `:ref:` lowercases its target, so it can never match a camelCase `confval` `:name:` and the render fails with "could not be resolved".
- Code blocks: `.. code-block:: php|bash|yaml|rst`.

## Security
Docs in `Documentation/Security/` are load-bearing — any crypto/access-control claim **must** match source behaviour. When the behaviour changes, update the docs in the same PR.

- Do not publish sample master keys, DEKs, or real audit entries.
- Redact org-specific paths in examples.
- Link to ADRs for design decisions, not source comments.

## Checklist
- [ ] `make docs` renders without warnings
- [ ] All `:ref:` targets resolve
- [ ] Screenshots exist for any new UI; `:alt:` present; `:zoom: lightbox`
- [ ] Images are PNG, viewport ≥ 1440×900
- [ ] ADRs updated for non-trivial behaviour changes
- [ ] New CLI commands documented in `Documentation/Developer/Commands.rst`

## Examples
### Screenshot figure
```rst
.. figure:: /Images/Configuration/ExtensionSettings.png
   :alt: Vault extension configuration — master key providers
   :zoom: lightbox
   :class: with-border with-shadow

   Configure master-key provider under Admin Tools → Settings.
```

### ADR skeleton
```rst
:navigation-title: ADR-NNN Title
..  include:: /Includes.rst.txt

==============================
ADR-NNN: Concise decision line
==============================

Context
=======
…
Decision
========
…
Consequences
============
…
```

## When Stuck
- Invoke skill: `typo3-docs`
- RST reference: <https://docs.typo3.org/m/typo3/docs-how-to-document/main/en-us/>
- Render output log: `Documentation-GENERATED-temp/`
