# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.16.0] - 2026-09-05

### Added

- **A cancellable secure outbound send** (#302). `VaultHttpClient` now also
  implements `CancellableHttpClientInterface`, whose `sendCancellable($request,
  $signal)` polls a caller-supplied `CancellationSignalInterface` and tears the
  socket down when it turns true. Until now a consumer whose own work was
  cancelled still waited out the timeout — up to about 45 seconds for the caller
  that asked for this
  ([netresearch/t3x-nr-llm#774](https://github.com/netresearch/t3x-nr-llm/issues/774))
  — because PSR-18 returns a response and never a handle, and because Guzzle's
  synchronous branch settles its promise before it exists, which makes
  `cancel()` a no-op there.

  The new interface is separate from `VaultHttpClientInterface` and purely
  additive, so consumers feature-detect (`$client instanceof
  CancellableHttpClientInterface && $client->supportsCancellation()`) instead of
  raising a version floor. Nothing existing changes shape.

  The invariant is that **nothing hands a caller a client that already carries a
  vault secret**, and `VaultHttpClient` is the only place nr-vault attaches a
  secret to a *caller's* request. No send a caller can drive puts a vault secret
  on the wire without the four protections that are statements in the sending
  method rather than middleware — the scheme allowlist, the host allowlist, the
  credential injection and the audit write. (nr-vault sends two credentials of
  its own elsewhere, on paths that are not a caller's request: the transit
  master-key provider's `X-Vault-Token` header and the OAuth token leg's
  `client_secret`. Both are listed in ADR-037.) Every public method of
  `VaultHttpClient` returns a configured clone, a PSR-7 response or a bool — no
  client, no handler, no promise — and `sendCancellable()` accepts no
  per-request option surface (a caller-supplied `stream => true` or `curl` array
  would silently drop the `CURLOPT_RESOLVE` DNS pin). Both are asserted by
  `VaultHttpClientCancellableTest::theCredentialBearingClientExportsNoTransportAndNoPromise()`.
  Building a hardened transport *without* vault
  credentials stays a supported public case: `SecureHttpClientFactory::create()`
  and the new `createCancellable()` return one, carrying the SSRF middleware and
  the DNS pin and nothing else.

  A PSR-18 client injected into `VaultHttpClient`'s constructor is never replaced
  by a cancellable transport — it may carry that caller's own middleware or
  proxy. `supportsCancellation()` reports false for such an instance and the call
  completes blocking on their client. The one exception is `withTimeout()`, which
  has to bake the override into a client and therefore rebuilds one from the
  factory; the clone it returns reports `supportsCancellation()` true
  (`anInjectedGuzzleClientIsNeverSwappedForACancellableTransport()`,
  `withTimeoutRebuildsACallerSuppliedClientAndTurnsCancellationOn()`). A client
  obtained from `VaultServiceInterface::http()` supports cancellation wherever
  `curl_multi_*` is available, and degrades to a blocking send where it is not —
  feature-detect with `supportsCancellation()` rather than assuming either.

  `allow_redirects => false` is re-pinned per request on the async path. Guzzle
  pins it for every PSR-18 send but sets nothing on an async one, so on an
  install that configured
  `$GLOBALS['TYPO3_CONF_VARS']['HTTP']['allow_redirects']` this path alone would
  have started following redirects — past a DNS pin computed for the original
  host.

  The timeout stays authoritative: a transport this client builds carries the
  same deadline as its blocking client, so cancellation is an early exit and
  never an extension
  (`VaultHttpClientCancellableTest::theTransportTheClientResolvesForItselfCarriesTheRememberedTimeout()`).

- **Two new audit actions for abandoned calls**, each meaning exactly one thing.
  Every call leaves exactly one row from this client — `sendCancellable()` and
  `sendRequest()` alike — so the log is complete with respect to *calls* and not
  merely with respect to egress: a call that was already cancelled when it began
  gets a row too. ADR-037 maps every outcome to the test that asserts its row.

  `http_call_cancelled` (badge: `warning`) is written **only** when the
  cancellation signal stopped an in-flight request, i.e. after the credential was
  retrieved, injected and handed to the transport. Because it means nothing else,
  "which calls were abandoned after their credential went out?" is a query on one
  action value, with no message parsing
  (`theTwoCancellationOutcomesAreToldApartByTheirAction()`). It is a separate action rather than a
  failed `http_call` because status `0` there already means both "connection
  refused" and "SSRF middleware rejected".

  `http_call_cancelled_before_send` (badge: `info`) is written when the signal
  was already set on entry: no secret was read and nothing egressed. Its own
  action rather than a distinguishing message, so an auditor can *exclude* those
  rows by query.

  Everything that failed rather than was cancelled stays `http_call` with
  `success = false` — a transport that could not be built, a transport error, the
  defensive wall-clock bound, a settlement that is not an HTTP response, and a
  throw from the caller's signal or the ticker. Nobody asked for those; filing them under the cancellation
  action would put a second meaning back on it. The fixed-literal `error_message`
  rendered under the badge identifies the situation within an action.

  The audit write for a cancellable transfer happens in a `finally` that opens on
  the first statement after the credential was injected: Guzzle's option handling
  inside `sendAsync()`, the caller's signal and the ticker can all throw, and
  none of them may be the one outbound call that leaves no trace.

- **The OAuth token round trip is audited and cancellable** (#303). The
  outbound POST that carries the `client_secret` used to leave no trace:
  `VaultHttpClient` built its `OAuthTokenManager` without the audit service,
  and the blocking token send ran before the cancellable transfer, out of the
  signal's reach. Now every attempted round trip — completed, refused by the
  `allowed_hosts` gate, failed in transport, or cancelled — writes exactly one
  row under the new `oauth_token_request` action, carrying the endpoint, the
  real HTTP status and a fixed literal (or redacted upstream message) naming
  the outcome. The row is crash-safe like the manager's other audit writes: an
  audit outage is reported loudly but never costs the caller a token the OAuth
  server already issued.

  On `sendCancellable()`, the signal now reaches the token leg exactly when
  the call's own transfer runs cancellable: an already-cancelled call reads no
  credential from the vault, a cancellation before the send never serialises
  the `client_secret`, and an in-flight token POST is torn down through a
  cancellable transport with the same hardening as the blocking client. On the
  degraded blocking path the token leg blocks like everything else, so the two
  legs never disagree on abortability. `getAccessToken()` gains an optional
  trailing `$cancellationSignal` parameter; every existing call keeps
  compiling.

- **An api-surface snapshot test** (#306). `Tests/Unit/Api/api-surface.txt`
  freezes the rendered public surface — every interface, enum (backing
  values included) and exception class under `Classes/`, the `Domain/Dto`
  value objects, plus every own-namespace type their signatures mention,
  constructors included. A change to any frozen signature now has to be an
  explicit commit with a visible snapshot diff rather than a side effect;
  the failure message classifies the diff as additive (regenerate) or
  breaking (a decision, per AGENTS.md's "Ask First" rule for interface
  signatures). Ported from nr-llm, which has carried the same guard since
  ADR-127, with one deliberate divergence — backed-enum values are rendered,
  proposed upstream as t3x-nr-llm#815.

### Changed

- **The security mutation ratchet now also covers `Classes/Http`** (#307). The
  gate (`infection-security.json5`, enforced by the `Security gates` workflow)
  previously measured only `Classes/Crypto`, `Classes/Security` and
  `Classes/Audit`, so it said nothing about the outbound credential path. The
  release-evidence manifest reports the four-directory scope accordingly. The
  floor was re-baselined 86 → 82 from the first four-directory CI measurement
  (MSI 83.84 %); raising it back above 86 by hardening the Http suites is
  tracked in #328.


- **Agent documentation synced and put under CI verification** (#325). Root
  `AGENTS.md` shrank from 296 to 144 lines: the Key-Interfaces cheat-sheet, the
  `vault:*` CLI list, the component map and the phpat dependency rules now live
  in the new agent-facing `docs/ARCHITECTURE.md`; the audit-log invariants and
  the backend-submodule completeness recipe moved into `Classes/AGENTS.md`.
  Drifted claims were corrected (`composer ci` scope, `make ci` scope in the
  `Classes/` checklist, stale `ddev exec phpunit` instructions in `Tests/` and
  `.ddev/` that contradicted the `runTests.sh` mandate), and
  `Documentation/CLAUDE.md` was added as a regular file (the docs renderer
  rejects symlinks). A new `harness-verify` workflow runs
  `Build/Scripts/verify-harness.sh` on every PR so this class of drift fails CI.

- **One DNS lookup per outbound request instead of two** (#304). The
  caller-side `isHostAllowed()` gate and the `ssrf-dns-pin` middleware each
  ran their own `dns_get_record()`; a short-lived memo (5 s, per host) inside
  `SecureHttpClientFactory` now lets the middleware reuse the gate's answer.
  The sharing is bounded by issue #304's security constraint: it only applies
  where every memoised IP is still range-checked and then pinned via
  `CURLOPT_RESOLVE`, so a memoised answer can never admit an address a fresh
  one would have rejected — a rebind inside the TTL just means curl connects
  to the address that was actually vetted. Where no pin takes effect — no
  ext-curl, or a `stream => true` transfer, which Guzzle routes to the
  StreamHandler that ignores the curl options — the middleware's own resolve
  IS the rebind defence and keeps resolving fresh, decided per hop. (The
  `isHostAllowed()` gate itself may share answers within the TTL in every
  mode; its check was always advisory relative to connect time, and the
  middleware re-validates.) Failed resolutions are never memoised; every
  failure-path behaviour is unchanged.


- **`guzzlehttp/guzzle` is now a declared direct dependency** (`^7.10`).
  Production code already imported `GuzzleHttp\Client`, `HandlerStack` and
  `RequestException` while the manifest named only the PSR interfaces and relied
  on `typo3/cms-core` to pull Guzzle in transitively. The cancellable transport
  reaches deeper still — `CurlMultiHandler`, `Proxy`, `StreamHandler`, promise
  cancel semantics — and a Guzzle major arriving through a third path would
  break it with no warning in our own manifest.

### Fixed

- **A refused scheme, a host outside `allowed_hosts`, and a credential that
  could not be obtained left no audit row.** All three are thrown by
  `VaultHttpClient` before the send, and all three used to escape without a
  trace — on `sendRequest()` as much as on the new cancellable path. They are
  exactly the calls an operator goes looking for: somebody tried `file://`, or a
  host nobody approved. Each now writes one `http_call` row with
  `success = false`, status `0`, the attempted method/host/path, and a fixed
  literal saying which gate refused it (`Request refused before any secret was
  read: …`, `Credential injection failed; nothing was sent: …`). No new audit
  action: that tuple already means "a refused outbound call" here — the SSRF
  middleware rejection lands in it too.

  The exceptions are unchanged, byte for byte: same class, same code, same
  message, pinned by characterization tests written before the rows existed. A
  consumer that catches `VaultException` sees no difference.

- **A blocking send that threw something other than a PSR-18
  `ClientExceptionInterface` left no audit row.** `Client::applyOptions()` raises
  `InvalidArgumentException` outside `Client::transfer()`'s try/catch on the
  synchronous path as well, so a bad option set escaped `VaultHttpClient`'s
  catch — credential already injected, nothing in the log. The send-and-audit
  helper now writes its row from a `finally`, which covers plain `sendRequest()`
  and the degraded branch of `sendCancellable()` alike, under `http_call` with
  the fixed literal `Blocking send aborted by an unexpected error after the
  credential was injected: …`. Success and transport-failure rows are unchanged.

## [0.15.0] - 2026-08-10

One feature, aimed at a gap that only shows up in unattended deployments: there
was no way to write a secret from a pipeline without switching on
`allowCliAccess`, which grants the operation to every process holding a shell in
that container and attributes the write to nobody.

### Added

- **A named actor for unattended writes** (#298). `vault:store --as-provisioner`
  performs the store inside `TechnicalActorContext::runAs()` as the backend user
  named by the new `provisioningBeUserUid` option. The actor needs **no admin
  flag** — a group carrying `tx_nrvault:secret.create` is enough, because a
  technical actor's grants are read from its groups' custom permission options.
  The grant is therefore one operation on one identity, and every write it makes
  is attributable in the audit log.

  The UID comes from configuration and never from the command line. A flag that
  accepted a UID as an argument would be a general impersonation primitive,
  strictly worse than the switch it replaces.

  Fail-closed at both ends: a non-numeric, negative or absent value reads as *no
  provisioning actor* rather than uid 0, which names the unauthenticated CLI
  placeholder the option exists to avoid; and the flag without a configured
  actor is an error, not a silent fallback to the unattributed write the caller
  explicitly asked not to make.

  `ext_conf_template.txt` already recommended *"prefer a named technical actor
  (TechnicalActorContext::runAs())"* over `allowCliAccess`. Until now no command
  could enter such a scope, so the advice had nothing behind it.

### Fixed

- The closure handed to `runAs()` captured the plaintext **by value**, so
  `sodium_memzero()` separated the copy-on-write pair instead of wiping both and
  the secret survived in memory in the copy the command believed it had cleared.
  Caught in review before release, so no shipped version is affected.

### Changed

- CI actions updated: `step-security/harden-runner` to v2.20.1,
  `actions/attest-build-provenance` to v4.2.2.


## [0.14.0] - 2026-08-06

Fifty-eight merged pull requests since 0.13.0, most of them a hardening
programme carried out in four rounds of adversarial review: a technically
enforced security profile, ten grantable operation permissions in place of the
admin-only model, a tamper-evidence anchor inside and outside the database, and
a readiness command an operator or a pipeline can gate on. Several changes are
breaking, and several close paths that produced *successful-looking* audit
entries for operations that were never authorised — in an extension whose
promise is auditability, that is the part to read first. Start with **Changed**
and end with **Migration**, which collects everything you actually have to do.

### Added

- **Security profiles** (#236). `securityProfile` (`standard` | `hardened`,
  default `standard`) is a technically enforced policy, not a documentation
  label. Under `hardened`, `masterKeyProvider = typo3` is a configuration error
  — vault secrets must not be protected by the same key TYPO3 uses for
  everything else — and provider selection stops auto-detecting: the configured
  provider is returned even when it is unavailable, so `getMasterKey()` fails
  loudly instead of silently degrading down the old `typo3 → env → file` chain.
  An unknown profile value throws rather than falling back to `standard`,
  because a typo must never be able to weaken the effective policy.
  `VaultHealthService` and `vault:rotate-master-key` resolve through the same
  factory, so a misconfiguration surfaces in the system status and blocks
  rotation instead of being discovered at decryption time.
- **Ten grantable operation permissions** (#238) replace the coarse admin-only
  model: `secret.use`, `secret.reveal`, `secret.create`, `secret.rotate`,
  `secret.delete`, `secret.manage_policy`, `audit.view`, `audit.export`,
  `master_key.rotate`, `vault.configure`. They are carried as TYPO3 custom
  permission options (`be_groups.custom_options`, namespace `tx_nrvault`) and
  granted per group in the Backend Users module, and they compose with — never
  replace — the per-secret owner/group ACL tiers: both must hold. The split that
  matters operationally is **use ≠ reveal**: `secret.use` gates every
  interactive plaintext read, while displaying a secret additionally needs
  `secret.reveal`, so an application or a technical actor can consume a
  credential no human is allowed to look at. Audit viewing is separated from
  secret access entirely (`audit.view` / `audit.export`), and the "admins may do
  anything" override lives in exactly one seam so it can be switched off as a
  whole (see break-glass, below).
- **The admin override can be switched off, with an audited break-glass window
  as the way back in** (#241). `disableAdminOverride` (hardened profile only;
  inert under `standard` as a lockout guard) removes the admin and
  system-maintainer bypass from *both* layers — the operation permissions and
  the per-secret read/write/delete tiers — and can be pinned out of admin reach
  in `config/system/additional.php` via
  `$GLOBALS['TYPO3_CONF_VARS']['SYS']['nrVault']['disableAdminOverride']`.
  `vault:break-glass --activate --reason "…" [--minutes N]` (1–60, default 15)
  opens a time-boxed window; the audit row is written **before** the power is
  granted, so an open window without evidence is impossible, and a logged failed
  opening is harmless. While a window is open the vault backend modules carry a
  danger banner, `--status` is machine-readable, and PSR-14
  `BreakGlassActivatedEvent` / `BreakGlassDeactivatedEvent` fire for SIEM
  pickup. A `runAs()` technical actor may not open one — break-glass is not an
  authentication boundary.
- **HashiCorp Vault Transit master key provider** (#239). The 32-byte master key
  is generated once, wrapped by Transit, and only the `vault:v1:…` ciphertext is
  stored locally (`0600`, atomic write); every unwrap is a live, centrally
  audited Vault call, so revoking the token or its policy locks the vault out
  immediately and a stolen database plus webroot is useless on its own. Token
  auth only — `approle` and `kubernetes` are rejected rather than silently
  downgraded. New settings `hashicorp.transitMount`, `hashicorp.transitKeyName`,
  `hashicorp.transitWrappedKeyPath`, `hashicorp.tokenEnvVar`. The trust model is
  documented honestly: Transit protects custody, rotation and central
  auditability; it does not stop a fully compromised PHP process from calling
  `decrypt` with the token it legitimately holds.
- **The audit log can be anchored outside the database** (#240).
  `AuditSinkInterface` plus three sinks — syslog (RFC 5424 structured data,
  control characters stripped against log forging), an append-only NDJSON file
  (`0600`, `LOCK_EX`, refuses any path inside the public web root, resolved
  against the nearest existing ancestor so `..` and symlinks cannot bypass it)
  and an SSRF-guarded HTTP webhook. Fan-out happens after commit and after the
  advisory lock is released, so a slow sink can never serialize vault operations
  behind the lock and a sink failure never rolls back the audited operation.
  `vault:audit-anchor` publishes `{sequence, chainTip, timestamp, hmacEpoch}`
  through every enabled sink and the reader takes the **highest** anchored
  sequence, so appending a low anchor cannot weaken the baseline;
  `vault:audit-verify` then checks the chain *and* compares it against that
  anchor, reporting a table that was truncated and re-seeded with a
  valid-but-different chain as `TABLE_RESET`. Machine-readable reason codes
  (`HASH_MISMATCH`, `UID_GAP`, `TABLE_RESET`, `EPOCH_DOWNGRADE`, `SINK_FAILURE`,
  `NO_EXTERNAL_SINK`, `BREAK_GLASS`), scheduler tasks for both commands, and a
  PSR-14 `AuditIntegrityAlertEvent` forwarded through the sinks. Seven new
  settings under "Audit Sinks", all off by default.
- **`vault:doctor`** (#244) — one readiness check across the whole security
  posture, with exit codes a pipeline can gate on: **0** clean, **1** warnings,
  **2** any critical. One class per control (provider explicitness, availability
  and key-file permissions; profile consistency; break-glass window; audit
  reads, retention, chain, external sink and anchor; CLI exposure; secret expiry
  and rotation hygiene; production context and HTTPS; version sanity), each
  declaring which profiles it applies to, each producing a typed `Finding` with
  id, severity, risk, remediation and a documentation link. A crashing check is
  contained as a `check.crashed` critical finding rather than taking the run
  down with it. `--profile=hardened` asks "would this installation pass as
  hardened?" without changing any configuration, which is what makes it usable
  as a deployment gate. The backend overview shows a profile badge and "N/M
  controls passed" to any vault user; the detailed findings are gated behind
  `vault.configure`.
- **Audit sinks are now checked by delivery, not by configuration** (#255).
  "Enabled" used to mean a switch plus a syntactically valid URL, and the only
  telemetry was a per-process failure counter — so a freshly started
  `vault:doctor` always saw zero failures and reported a collector that had been
  unreachable for days as healthy. Per-sink delivery state (last success, last
  failure, consecutive failures, lifetime failures, last error) is now persisted
  in `sys_registry`, written fail-safe on every dispatch outcome and throttled
  to one healthy write per minute per sink, so the bookkeeping can never fail or
  slow the audited operation. New `audit.sink_state.<sink>` findings grade
  consecutive failures and a last success older than
  `auditSinkStaleDeliveryHours` (new setting, default 24) as a warning under
  `standard` and **critical** under `hardened`. `vault:doctor --active-probes`
  goes further and pushes the current chain tip through every enabled sink end
  to end — a refused probe is critical in **both** profiles. Probes never run
  implicitly: not from the passive checks, not from the backend status panel.
  The anchor is re-publishable evidence by design, so a probe pollutes nothing
  and even refreshes the external anchor.
- **Four further doctor controls**, each closing a case where the runtime was
  correct and the readiness report was not. `audit.hmac_epoch` (#260, graded
  further in #268 and #277): critical at epoch 0 — one setting that
  simultaneously drops row hashes to keyless SHA-256, makes the chain-level
  downgrade guard vacuous and disables the in-DB anchor, silently overriding
  `auditAnchorRequired`; warning at epochs 1–2, where 13 and 5 columns
  respectively sit outside the signed payload (at epoch 1 `success` itself is
  forgeable, so a recorded denial can be flipped into a recorded grant without
  touching a signed byte); pass only at ≥ 3. The check now reads the **stored**
  minimum epoch from the oldest row rather than grading the configuration alone,
  and reports it as `details.storedMinEpoch` for CI. `audit.db_anchor` (#260)
  loads the `sys_registry` anchor directly, which no check did before at any
  epoch. `cli.frontend_placeholder_legacy` (#268) reports the
  `frontendPlaceholderLegacyCli` opt-in — emitted from both return paths of the
  CLI check, because the obvious placement would have skipped it on exactly the
  default installations where the bypass is fully live. And
  `cli.allowed_operations` (#277) stops calling `secret.manage_policy` and
  `audit.view` harmless: the first governs the permissions themselves, so a
  shell can widen its own per-secret reach; the second maps out the credential
  topology and is where that shell's own activity is recorded.
- **A secret's availability is a vault operation with a name** (#278).
  `VaultServiceInterface::setEnabled(string $identifier, bool $enabled, string
  $reason = ''): void` — absolute, not a toggle, so two concurrent disables
  converge instead of cancelling out and leaving two audit entries claiming
  opposite outcomes. It resolves the secret through a disabled-visible lookup,
  asserts `canWrite()` **and** `secret.manage_policy`, no-ops when the state
  already matches (the gates run first, so a *refused* no-op is still audited),
  and reverts on `AuditWriteException` exactly as the other compensating paths
  do, including the CRITICAL escalation when the revert itself fails. It is
  audited as `metadata_update`, matching what the FormEngine path already writes
  for the same column, so "who disabled this secret" has one answer regardless
  of the write path. `list()` and the repository filters gained
  `$includeDisabled` (default `false`) so the management surfaces can see what
  the read paths no longer return.
- `vault:audit --verify` reports the anchor state on a `Tip anchor:` line, and
  the backend verification view shows it too. `vault:audit-verify` additionally
  reports the `Stored HMAC epochs` distribution in text and JSON (#277) — the
  count is free, since `verifyHashChain()` already walks every row.
- `vault:audit --reset-anchor` clears the anchor after a wipe or purge you
  performed deliberately, writes the reset into the chain so it cannot be done
  invisibly, and re-arms the anchor on that entry. New audit action
  `audit_anchor_reset`.
- `auditAnchorRequired` extension setting (default off). A missing anchor
  becomes an error, and ordinary audit writes stop arming an anchor that is not
  there — whatever the log currently contains, an emptied one included — so
  deleting the anchor and truncating or wiping the log can no longer be
  laundered back to a valid verdict by ordinary traffic. Enable it after the
  first audit write following the upgrade; while it is on, `vault:audit
  --reset-anchor` is the only way to arm the anchor.
- **Security, operations and auditor documentation** (#243) — 17 new pages that
  turn the implemented hardening into an auditable, reproducible state.
  `Documentation/Security/` gains a threat model, the profile comparison, the
  trust boundaries, the cryptography chapter, what the audit chain does and does
  not prove, and a prominent `KnownLimitations` page.
  `Documentation/Operations/` covers hardened deployment, key custody, backup
  and restore, key rotation, monitoring and alerting, incident response and
  decommissioning. `Documentation/Auditor/` states the target of evaluation,
  maps controls to BSI IT-Grundschutz and OWASP ASVS **with a declared-gaps
  table** so an assessment credits no absent control, and gives reproducible
  evidence and verification procedures (the staging-only ones marked as such).
  The language is deliberately unmarketed throughout — *tamper-evident*, not
  tamper-proof; *minimized exposure*, not secure deletion.
- **ADR-036** (#272) records the rule four hardening rounds had been
  implementing without writing down: a mutation and its audit entry commit
  together, and a change that cannot be audited must not persist. It exists
  because two of its mechanics are non-obvious enough that a future refactor
  would plausibly break them silently — why the ACL MM relations need a snapshot
  captured in `processDatamap_preProcessFieldArray()` (DataHandler writes them
  during `checkValue()`, before any audit hook runs, and the row's
  `allowed_groups` column holds only a relation *count*, so restoring the column
  restores nothing), and why the create path is asymmetric (for a `NEW` record
  the MM writes are deferred past the hook, so a reverted creation deletes the
  row before its relations exist and leaves orphans to purge). It also states
  where the guarantee stops rather than leaving the boundary implied.
- **A release evidence bundle** (#245). `Build/Scripts/collect-evidence.php`
  assembles whatever exists at release time — test results, line and
  security-directory coverage, whole-codebase and security-scoped mutation
  summaries, PHPStan level, `composer audit`, `vault:doctor --format=json` —
  into a flat, stable `evidence-manifest.json` plus a human-readable
  `EVIDENCE.md`. An absent producer is `absent` and exit 0; only a
  present-but-malformed artifact is an error.
  `.github/workflows/release-evidence.yml` runs it on a tag and publishes the
  bundle as a run artifact with a build-provenance attestation over the tarball,
  verifiable with `gh attestation verify`. `CONTRIBUTING.md` now requires
  two-person review for `Classes/Crypto|Security|Audit` (the author cannot
  approve; one approver must be a code owner) plus a threat-model delta, and
  `SECURITY.md` carries a 7-day Critical/High patch SLA, down from 30.
- **Quality gates that block rather than inform.** Codecov is blocking at 90%
  patch coverage for `Classes/Crypto|Security|Audit` and 80% by default, with
  the ignore list mirroring the PHPUnit excludes so the reported number is the
  one the suite actually measures (#242, #258). A security-scoped mutation gate
  ships as `infection-security.json5` with a raise-only ratchet, now at **MSI
  86** after a pass that killed 273 escaped mutants by pinning previously
  unasserted semantics across the audit, crypto and security trees — test-only,
  no production code touched (#242, #257). The gate treats its own inputs as
  security-critical, so a pull request lowering the ratchet is measured rather
  than waved through. Alongside: PHPStan now analyses the whole `Tests` tree
  instead of `Tests/Architecture` only (#233), the CLI documentation guard
  checks each command's **option lists** against the real `addOption()` calls
  and not merely the shell examples (#273), sixteen previously untested classes
  reached full line coverage (#258), and the envelope fuzz probe spans two full
  base64 block periods and reports every observed length when it fails (#256).

### Changed

- **The request-scoped plaintext cache is gone, and
  `VaultServiceInterface::clearCache()` with it (breaking)** (#250). See
  **Security** for what the cache did; what changes for integrators is that the
  method no longer exists — there is nothing left to clear — and the
  `cacheEnabled` extension setting,
  `ExtensionConfiguration(Interface)::isCacheEnabled()` and the
  `ext_conf_template.txt` entry are removed too. The saved work was a single-row
  `SELECT` plus one decrypt; an actor-keyed cache was considered and rejected,
  because permission state, break-glass windows and expiry all change within a
  request and a cache that has to track them is a second authorization
  implementation.
- **`allowCliAccess` no longer grants every operation (breaking)** (#254). With
  the switch on — which deployment automation genuinely requires — a shell on
  the host implicitly held `secret.reveal`, `secret.delete`, `audit.export`,
  `master_key.rotate` and `vault.configure`, because `isGranted()` returned the
  trust switch regardless of which permission was asked for. The new
  `cliAllowedOperations` setting defaults to
  `secret.use,secret.create,secret.rotate`, and both CLI branches now require
  the trust switch **and** the allowlist. Everything else needs an explicit
  opt-in, so `vault:retrieve`, `vault:delete`, the scheduled orphan cleanup,
  `vault:audit --export` and `vault:rotate-master-key` stop working on
  installations that relied on the blanket grant. Under the hardened profile,
  unattributed CLI access is now a **critical** doctor finding rather than a
  warning.
- **The frontend placeholder allow-set applies on the CLI too (breaking)**
  (#262). ADR-035 scoped `%vault()%` resolution to published identifiers in web
  requests, but the CLI branch returned early with a blanket `true`. That looked
  defensible while plain unauthenticated CLI still failed closed on the
  `allowCliAccess = 0` default — except `scheduler:run` authenticates the
  `_cli_` **admin** user, so the admin bypass grants vault reads regardless of
  that switch. For editor-authored content rendered by a scheduled job — a
  newsletter, a static export, a search indexer — the allow-set was therefore
  the only remaining gate, and it was the one being skipped. The CLI is now
  strict like everything else. `frontendPlaceholderLegacyCli` (default `0`)
  restores the previous behaviour byte for byte; it is CLI-scoped so it cannot
  weaken a web request, read per call rather than memoised, fails closed on
  unreadable configuration, and honours the `$TYPO3_CONF_VARS` pin.
  Installations whose scheduler jobs resolve unpublished `frontend_accessible`
  identifiers must publish those identifiers or set the flag.
- **Every audit CLI entry point now asserts an operation permission (breaking)**
  (#274). `vault:audit`, `vault:audit-verify` and `vault:audit-anchor` gated
  nothing at all, while the same capabilities were gated in the backend module
  all along: anyone who could invoke them could read the audit log — who touched
  which secret when, which maps out the credential topology — carry an unchained
  copy of it off with `--export`, clear the tamper-evidence tip anchor, or
  re-attest a truncated chain to the external sinks. The permission now follows
  the operation's effect, so the same operation answers to the same permission
  through every entry point:

  | Operation | Permission | Entry points |
  |---|---|---|
  | Read audit entries | `audit.view` | audit module, `vault:audit` |
  | Verify the chain | `audit.view` | audit module, `vault:audit --verify`, `vault:audit-verify`, `AuditVerifyTask` |
  | Export to a file | `audit.export` | audit module, `vault:audit --export` |
  | Publish the chain tip | `vault.configure` | `vault:audit-anchor`, `AuditAnchorTask` |
  | Reset the tip anchor | `vault.configure` | `vault:audit --reset-anchor` |

  Verification is a read of the chain — it recomputes and compares, it mutates
  nothing — so it shares `audit.view` with the listing rather than taking the
  administrative permission. Anchoring and resetting the anchor do mutate tamper
  evidence: an actor who truncates the log and then anchors makes the external
  sink attest the truncated chain, which is the laundering the anchor exists to
  prevent. A refusal exits 1 before any query, file write, chain read or anchor
  change happens, and writes no `access_denied` entry — the same shape as every
  other operation-permission gate (`vault:retrieve`, `vault:rotate-master-key`,
  the backend modules), and for `--verify` and `--reset-anchor` the deciding
  argument is recursion: a denial entry would append a row and advance the tip
  anchor, mutating the very state the operator is about to inspect. In
  `--format=json` a refused `vault:audit-verify` reports `valid: false`, so a
  monitor never reads it as a clean chain. `OrphanCleanupTask` is deliberately
  *not* gated at task level: its effect already answers to `secret.delete` one
  layer deeper.
- **`undelete`, `copy` and `move` are refused for `tx_nrvault_secret`
  (breaking)** (#276). Each is marked handled so core never reaches its cmdmap
  branch, writes an `access_denied` audit entry and emits a DataHandler error
  naming the reason. `localize`, `copyToLanguage`, `inlineLocalizeSynchronize`,
  `discard` and `version` are deliberately left alone — each was verified inert
  for this schema, and a gate with nothing behind it is noise. **Administrators
  are refused too**, and that is a product rule rather than a permission tier:
  an exemption would make "the vault cannot restore it" mean "unless an
  administrator says otherwise", and would write a restore into the HMAC chain
  that the vault never performed. An operator who must resurrect a row still has
  the database, where the change is visible as what it is. The user-facing
  wording follows: the confirm dialogs, the TCA field clear and `vault:delete`
  now all say *"The vault cannot restore it. The encrypted record is retained in
  the database until it is removed there."*, replacing a documentation passage
  that called the soft delete "auditable and reversible".
- **The `ext_emconf.php` TYPO3 constraint is capped at `14.3.99` (breaking for
  anyone installing via the Extension Manager against a future 14.x)** (#271).
  The previous `13.4.0-14.99.99` claimed compatibility with 14.4 through 14.99,
  which do not exist as supported releases — v14.3 *is* the LTS. This does not
  reopen the 0.7.0 decision to keep a coarse range: that reasoning was about the
  **gap** a single continuous range cannot express (the unsupported 14.0–14.2
  sprint releases, still spanned), not about the ceiling. `composer.json`
  remains authoritative for a Composer-based installation.
- **Six interfaces gained members, which is breaking for third-party
  implementations** (#259, #263, #278, #280, #281). Each addition exists because
  a caller needed a narrower or a wider operation than the interface could
  express; none changes an existing signature's meaning, and the two optional
  parameters default to today's behaviour so existing callers and test doubles
  bind unchanged.

  | Interface | Addition | Why |
  |---|---|---|
  | `VaultServiceInterface` | `assertDeletable(string $identifier): void` | runs `delete()`'s gates without deleting, so a record spanning several vault fields fails closed before the first irreversible deletion |
  | `VaultServiceInterface` | `setEnabled(string $identifier, bool $enabled, string $reason = ''): void` | the single audited write path for a secret's availability |
  | `VaultServiceInterface` | `list(?string $pattern = null, bool $includeDisabled = false): array` | lets the management surfaces see secrets the read paths no longer return |
  | `SecretRepositoryInterface` | `findByIdentifierIncludingDisabled()`, `findByUidIncludingDisabled()` | lift `HiddenRestriction` **by name** for administrative lookups; `removeAll()` was rejected because it would also discard `DeletedRestriction` and resurrect soft-deleted rows |
  | `SecretRepositoryInterface` | `setHidden(int $uid, bool $hidden): void`, `setMetadata(int $uid, array $metadata): void` | column-scoped writes, so a metadata or availability change stops rewriting the whole row |
  | `SecretRepositoryInterface`, `VaultAdapterInterface` | `save()` and `store()` gain `bool $persistGroupRelations = true` | lets the FormEngine completion path keep MM rows and their count columns consistent instead of zeroing the tiers |
  | `VaultDoctorServiceInterface` | `run()` gains `bool $activeProbes = false` | required by `--active-probes` |

- **The backend modules and AJAX routes moved from `admin` to `user`** (#238),
  and every controller action asserts its own operation instead: the overview
  filters its submodule cards by permission and the templates render only the
  actions the user holds. Non-admin editors working with vault-backed FormEngine
  or FlexForm fields therefore need `secret.use`, which they did not need
  before. `vault:rotate-master-key` now needs `allowCliAccess = 1` like every
  other secret command — the `_cli_` user is never logged in, so group grants
  cannot apply to it — and, since #254, `master_key.rotate` in
  `cliAllowedOperations` as well.
- **Technical actors resolve their grants from their backend groups** (#251).
  They were previously hard-coded to an implicit `secret.use`, which central
  enforcement would have turned into "no `runAs()` worker can ever mutate
  anything". The other operation permissions are now read straight from the
  `tx_nrvault:<permission>` custom options on the actor's `be_groups` rows —
  never through `BackendUserAuthentication::check()`, which core short-circuits
  to `true` for admins — and fail closed: no groups, no grant. `secret.use`
  stays implicit.
- **A truncated audit log now verifies as INVALID.** This also blocks
  `vault:rotate-master-key` and both HMAC re-seal paths, which already refuse to
  run on any other chain error — re-sealing a truncated chain would launder it.
  Use `vault:audit --reset-anchor` for a truncation you performed on purpose.
  Installations upgrade into a populated chain with no anchor row; that is a
  warning, not an error, and the anchor arms itself on the next audit write.
- **Frontend `%vault()%` resolution is restricted to frontend requests and to
  any web request whose type cannot be established** — eID among them, where
  `$GLOBALS['TYPO3_REQUEST']` does not exist. CLI and backend requests were
  unchanged by ADR-035 and are now covered separately (see the CLI entry above);
  a backend request is recognised by the request the content object renderer
  carries, never by what an earlier request left in the superglobal, and a
  renderer built without a request of its own is restricted wherever it runs.
  Log volume on the rejection path is bounded by a latch that is per request and
  only engages in a frontend or unknown web context: 100 injected placeholders
  naming a withheld secret used to produce 100 warnings and 100 `AccessDenied`
  audit rows, and now produce at most one record and no rows. The latch cannot
  carry into the next request and never engages on the CLI, so a long-running
  `scheduler:run` or Messenger consumer keeps every warning it emitted.
- **Detection trade-off.** Because a rejected identifier is refused before the
  vault is touched, it no longer produces the `AccessDenied` audit row it used
  to. Outside Development a rejection is written nowhere, so probing for a
  site's published identifiers leaves no trace; the signal is the literal
  `%vault(...)%` surviving in the output. This is deliberate — any per-rejection
  record is a write an anonymous visitor can drive — and is recorded as a
  residual in ADR-035.
- **The documentation was audited against the shipped code and roughly seventy
  drift items corrected** (#266, #267, #246, #264). The corrections worth naming
  are the ones that ran the wrong way: the auditor documentation claimed a
  secret-scanning control *does not exist* when it runs on every pull request,
  while both `AGENTS.md` files claimed a gitleaks scan that did not run at all —
  a false control claim in a secrets extension changes behaviour, because a
  contributor adding fixtures relaxes their own care trusting a scan that never
  happens. Verification procedure 6c expected a `TRUNCATE` to leave a valid
  chain, which the ADR-034 anchor now correctly reports as invalid. ADR-034
  prescribed the one `entry_namespace` value the code deliberately avoids,
  ADR-005's code sample taught the inlined `isAdmin()` pattern the codebase
  forbids, `vault:store` and `vault:retrieve` documented options that do not
  exist, and `TcaIntegration.rst`'s resolver examples were fatal errors. Three
  passages claimed multi-field copy and delete are *atomic*, where the real
  guarantee is preflight plus best-effort compensation with three named
  residuals; the code was honest about this in its own log messages, only the
  prose said "never".
- **Dependencies and CI**, grouped: `actions/upload-artifact` to v7 (#247), the
  zizmor policy first added locally and then removed once the shared reusable
  started serving it centrally (#253, #265), the labeler moved into its own
  `pull_request_target` workflow so fork pull requests stop failing with
  `Resource not accessible by integration` (#275), and the unit tests moved off
  `expectExceptionMessage()`, which PHPUnit 13.2 deprecated — via a trait
  routing to `expectExceptionMessageMatches()` with a `preg_quote`d needle,
  because the official replacement landed in 13.2.0 and four of eight matrix
  cells resolve PHPUnit below that (#279).

### Fixed

- **Master-key rotation skipped disabled secrets** (#286). The rotation
  inventory, the pre-flight smoke test and the per-secret loop all used the
  hidden-restricted repository lookups, so a disabled secret's DEK stayed
  wrapped under the old master key — the very key the command's next-steps
  output tells the operator to destroy. Re-enabling the secret later would
  surface a permanently undecryptable ciphertext; with only disabled secrets
  in the vault the command even reported "No secrets found" and exited
  successfully. All three lookups now use the disabled-visible repository
  paths, and a functional test rotates a vault holding an active and a
  disabled secret and proves both plaintexts survive the key switch.
- **`reseal()` skipped its anti-truncation guard on the master-key rotation
  path** (#283). The guard refuses to re-sign a shortened chain, but it can
  only check a stored anchor it has authenticated — and it authenticated under
  the key it was about to sign with. Rotation is the one path that passes a
  different key, so the old-key MAC never verified, the guard was skipped, and
  `reseal()` minted a fresh anchor over whatever the tip was at that moment.
  The command's pre-flight chain verification kept this theoretical (the rows
  would have to disappear inside the rotate transaction), which is why it was
  tracked as a follow-up rather than an advisory. `reseal()` now falls back to
  the provider's current key to authenticate the stored anchor, putting the
  rotation path behind the same guard as the two migration paths.
- **A rotated secret read as never rotated** (#281). `store()` carried
  `version`, `crdate` and `cruser_id` forward from the existing record but not
  `last_rotated_at`, `read_count` or `last_read_at`, so all three fell back to
  their `0` constructor defaults and were written on **every** update — from the
  module's edit form, `vault:store`, `vault:migrate-field`, the FormEngine
  completion path and any programmatic call alike. `rotate()` was never
  affected. This is not cosmetic: those are the columns the module's Reads and
  Last read display, that rotation-age reporting consults, that the
  orphan-cleanup heuristics act on, and that an audit reads. The whole suite was
  green while the bug was live, which is itself part of the finding.
- **`updateMetadata()` wrote the whole row** (#281), carrying the same
  concurrency exposure `setEnabled()` was fixed for, while its own docblock
  promised a write "without changing the secret value". It is narrowed rather
  than removed — there is no production caller, but it is declared on
  `VaultAdapterInterface`, the documented extension point for third-party
  adapters (ADR-007), so deleting it would be a public-API break for a defect
  that is fixable in place. The merge stays in the adapter; the new
  `setMetadata()` primitive writes the metadata column and `tstamp` and nothing
  else.
- **Two fail-open lookups on the FormEngine write path** (#280).
  `isUpdateAuthorized()` and `enforcePrivilegedColumnPolicy()` both treated
  "record not found" as "allowed". A null lookup is not hypothetical: core reads
  its datamap target with the delete clause **off** and skips only on an empty
  record, so a soft-deleted tombstone has a pid, is processed by core, and was
  waved straight through by the vault. Both now refuse. They report differently,
  because only one of them has an identifier — a tombstone gets an
  `access_denied` entry under its own identifier plus a DataHandler error, an
  absent record gets the error alone, so nothing enters the tamper-evident chain
  anonymously. `enforcePrivilegedColumnPolicy()` returns a bool and the caller
  nulls `$fieldArray` rather than dropping the privileged columns: the read that
  failed is the same read that would supply the stored values to compare
  against, so dropping columns is not fail-closed there.
- **Disabling a secret was a one-way door** (#278). A disabled secret vanished
  from every repository query, so the row left the list, the re-enable button —
  rendered per listed row — became unreachable, `editAction` threw
  `SecretNotFoundException`, and a fresh `store()` classified as a creation and
  collided with the unique key as a raw database error. Administrative
  operations (`delete()`, `assertDeletable()`, `rotate()`, `store()`,
  `getMetadata()`) now use the disabled-visible lookup, and
  `buildSecretEntity()` carries `hidden` forward — without which routing
  `store()` through the wider lookup would have silently re-enabled a disabled
  secret on any value write. `findByIdentifier()` itself is untouched, so the
  read path is unchanged. The list template's "Disabled" badge, row class and
  active/disabled filter had been dead against a hardcoded `'hidden' => false`
  and a comment claiming secrets have no hidden state; both are gone.
- **`LocalEncryptionAdapter::delete()` did nothing at all for a disabled
  secret** (#278) — a silent no-op, because it went through the
  restriction-honouring lookup.
- **An update replaced unsubmitted options with defaults** (#252), wiping
  description, context, `allowed_groups`, `write_groups`, expiry, scope and
  frontend availability that DataHandler had just persisted; a plain
  programmatic `store('id', $value)` silently reset policy fields whose *change*
  is gated by `secret.manage_policy`. Updates preserve unsubmitted fields now.
  In the same area, a FormEngine create was classified as an update because the
  row exists before `store()` is called, so it was gated by `secret.rotate` and
  audited as `update`; creation is now classified by the **value** — a record
  without an encrypted value is a creation in progress.
- **`Secret` parsed the `allowed_groups` / `write_groups` count columns as a
  list of group uids** when the MM load came back empty (#261), so a count of 3
  would have read as "group 3 is allowed". The fallback had no legitimate
  producer and is gone; the write side emits the relation count consistently.
- **`EncryptionService::resolveAlgorithm()` accepted any `encryption_version >=
  2`** and opened it under version-2 rules (#242) — forward compatibility by
  accident, so an envelope claiming version 99 decrypted "successfully".
  Unimplemented versions are refused loudly; versions 1 and 2 are unchanged.
- **`wipeCredentials()` raised instead of being idempotent** (#258).
  `sodium_memzero()` nulls the zval after zeroing, so a second call threw
  `SodiumException` — on a failure path, where it replaced the real error with
  its own. A guard flag makes repeat calls the no-ops the docblock always
  promised.
- The TypoScript examples in `Documentation/Usage/Index.rst` showed `TEXT`
  objects whose only property was `value`. `TEXT` removes `value` from its
  configuration before rendering, so such an object never calls `stdWrap()` and
  the placeholder never resolved. The examples now carry the `stdWrap.`
  sub-array that makes them work.

### Security

- **The plaintext read cache bypassed every control on the read path** (#250,
  High). `VaultService` held a request-scoped plaintext cache consulted *before*
  the record load, the per-secret `canRead()` tier, the interactive `secret.use`
  gate, the expiry check and the read audit entry — and `VaultService` is a
  shared singleton. In a long-running worker the concrete failure is three
  steps: technical actor A reads secret X and the plaintext lands in the cache;
  the `runAs()` scope switches to actor B; actor B retrieves the same identifier
  and gets the plaintext back with no authorization, no expiry check and **no
  audit row**. The cache key carried neither actor nor context nor permission
  state, and the cache was only reliably emptied in the destructor. It is
  removed entirely; see **Changed** for the API consequence.
- **The operation permissions could be bypassed through the paths that matter
  most** (#251, High). Only the module controllers checked them.
  `VaultService::store()`, `rotate()` and `delete()` checked the per-secret
  tiers alone, and `tx_nrvault_secret` is an ordinary visible TCA table — so a
  backend user with generic table rights could create, rotate or delete secrets
  through a direct FormEngine or DataHandler request without ever meeting
  `secret.create`, `secret.rotate` or `secret.delete`, and change policy columns
  without `secret.manage_policy`. Enforcement now sits at the business boundary
  with audited denials: `store()` requires `secret.create` for a new identifier
  and `secret.rotate` for an existing one, plus `secret.manage_policy` when the
  call actually changes owner, group tiers or frontend availability — compared
  on the **effective** values after the existing coercions, not on what was
  submitted. `SecretTcaHook` carries the same gates for the two FormEngine paths
  that do not pass through the service.
- **FormEngine mutations were fail-open on audit errors** (#252, High for audit
  purposes). The delete success entry was written *before* core deleted the
  record and a failing audit write was swallowed outright (`catch (Throwable)
  {}`); a metadata update kept its database change when the audit write failed,
  on a "don't fail the save" rationale. The auditor documentation's claims —
  every mutation logged, delete and store compensate a failed audit write —
  simply did not hold for the DataHandler path. The honest failure contract came
  first: `AuditLogService::log()` now wraps *any* chain-write failure in
  `AuditWriteException`, where previously only the advisory-lock timeout was
  wrapped, so a genuine INSERT failure bypassed every compensating rollback that
  catches that type. On top of it, the `tx_nrvault_secret` delete command runs
  through `VaultService::delete()` and core's `deleteAction` is skipped in every
  outcome; metadata changes revert their captured pre-change values when the
  audit write fails; and a failed vault delete now **cancels** the record delete
  on foreign tables instead of proceeding and orphaning the secret behind an
  apparently successful removal.
- **The rollback restored the row but not the ACL relations** (#261, High).
  `SecretRepository` loads effective groups from the MM tables, and the
  audit-failure rollback only restored the `tx_nrvault_secret` row — so an ACL
  widening whose audit write failed persisted unaudited, while the restored
  count column actively contradicted the MM state. Both tiers are now
  snapshotted in `processDatamap_preProcessFieldArray()`, which is the only
  viable moment because DataHandler's `writeMM()` runs inside `checkValue()`,
  before the audit hook exists to fail. A tier that legitimately had no groups
  is restored to empty, and if a tier cannot be repaired the DataHandler log
  says **NOT revertible** instead of falsely reporting success. For
  `status='new'` the MM writes are deferred past the hook, so the revert used to
  leave orphaned rows against the deleted uid; a new
  `processDatamap_afterAllOperations()` pass purges them.
- **A refused create left a squatted row and a false success entry in the HMAC
  chain** (#263). The hook classified creates by outcome — "was a value stored"
  — so "no value submitted" and "value submitted but refused" were
  indistinguishable, and a create by a user lacking `secret.create` fell into
  the value-less branch: the row survived with `owner_uid` forced to the denied
  user, the identifier was reserved against later legitimate creators, and a
  `create success=1` entry went into the tamper-evident chain next to the
  truthful `access_denied` one. Classification is now explicit
  (`RecordCreationOutcome::classify()` → `ValueLess` / `Stored` / `Rejected`), a
  rejected create deletes the fresh row and joins the MM purge, and **no success
  entry is written** — the `access_denied` entry is the record.
- **Value-less creates bypassed `secret.create` entirely** (#270). Both create
  gates live inside `VaultService::store()`, and the value-less path is by
  definition the one where `store()` is never called; `secret_input` is optional
  in the TCA, so a backend user with `tables_modify` but without `secret.create`
  could deliberately leave the value empty, create a vault record, become its
  owner, reserve the identifier, and produce a successful `create` entry in the
  chain for an operation they were not permitted to perform. No race, no
  misconfiguration. The gate now sits in `processDatamap_preProcessFieldArray()`
  and refuses **before the row exists**, using core's documented abort contract
  (`$fieldArray = null` → `if (!is_array($incomingFieldArray)) { continue 2; }`,
  present in v12.4, v13.4 and v14.3), so nothing is inserted and nothing needs
  compensating.
- **Every non-privileged update to an existing secret went through with no
  per-secret ACL check** (#269, High), and the hook then audited it as a
  *successful* `metadata_update` attributed to the editor — the log asserting
  that a change was authorised when it was not. Two concrete abuses followed.
  Backdating `expires_at` takes a foreign secret out of service for every
  consumer, and setting it to `0` revives a retired one. Writing `metadata` is
  worse: `OrphanCleanupTask` reads table and uid straight out of that column and
  `recordExists()` answered **false for a table that does not exist**, which the
  caller reads as "source record gone, retire the secret" — so a crafted payload
  on a secret past the retention cutoff made the scheduler delete it, with the
  task as the recorded actor. That is destruction, not denial of service. The
  hook now resolves the `Secret` and requires `canWrite()` before anything is
  written, refusing the whole record; `expires_at` and `metadata` join the
  privileged column set; orphan cleanup fails closed, so only a successful
  lookup against an existing table returning no row may answer "gone"; and
  `SecretsController::toggleAction`, which gated the operation permission alone
  and let any holder hide or unhide any secret, checks `canWrite()` too.
  Reachability was narrower than "any editor" — vault-created secrets live at
  `pid 0`, which core refuses to non-admins before the hook runs, so the defect
  needed a secret row on a real page — and the control gap and the false audit
  entry are real regardless.
- **Record copy and delete were not fail-closed across multiple vault fields**
  (#259). A failed per-field clone was only logged, so the copied record kept
  the DataHandler-duplicated **source identifier** and silently aliased the
  source's secret: rotating the copy mutated the source, deleting the copy
  destroyed it. A unit test had pinned that as expected behaviour. Deletes ran
  sequentially with no break, so a mid-sequence failure still deleted the
  remaining fields and left the record pointing at dead secrets — and
  `SecretNotFoundException` counted as failure, which made a record referencing
  a missing secret **permanently undeletable** through the backend,
  self-reinforcing with the copy bug. Copy now compensates every already-cloned
  secret and blanks all vault fields of the copy on any failure; delete
  pre-flights every field through the new non-mutating `assertDeletable()`,
  which shares `delete()`'s private gate so the two cannot drift, and a missing
  secret counts as success. The residual is stated rather than implied: this is
  preflight plus best-effort compensation, not atomicity (#267).
- **`undelete` restored a soft-deleted secret with no vault check of any kind**
  (#276) — no ACL, no operation permission, no audit entry. The vault delete
  writes only `deleted = 1`, so ciphertext, DEK, `frontend_accessible`, `hidden`
  and both MM ACL tiers survive intact, and restoring the row brings all of it
  back; a previously frontend-accessible secret is immediately resolvable again.
  The prerequisites were an authenticated **non-admin** with `tables_modify`,
  workspace 0 and one uid — zero vault permissions — because core's
  `undeleteRecord()` gates page permissions behind `if ($recordPid > 0)`,
  skipped entirely at `pid 0`, and `SimpleDataHandlerController` passes `cmd`
  through with no allow-list. Core does write `sys_log` and `sys_history`, so
  the restore was invisible specifically to the chain auditors are pointed at.
  `copy` and `move` are refused alongside it: a copied secret is always
  value-less while carrying the original's identifier, and `findByIdentifier()`
  has no `ORDER BY`, so the empty clone can win the lookup and break an intact
  secret; `move` is the only command that takes a secret off root level into the
  page tree, where `deleteSpecificPage()` removes records by pid through a path
  that reaches neither the vault ACL nor the audit log.
- **Truncating the audit log is no longer invisible** (ADR-034, #234). The hash
  chain only ever checked rows that were still present, so `DELETE FROM
  tx_nrvault_audit_log WHERE uid > N` — or a full `TRUNCATE` — left a
  self-consistent chain that every tamper-evidence control reported as valid.
  nr_vault now records one signed assertion outside that table, in the core
  table `sys_registry`: "row `uid = A` still exists and its `entry_hash` is
  still `H`", authenticated with a key derived from the master key under its own
  HKDF context. Tail truncation, deletion of the last row, a full wipe, and a
  wipe followed by refilling the same UIDs are all reported as an invalid chain
  now. There is no database schema change. What an attacker without the master
  key cannot do is forge the assertion, so the one-statement invisible
  truncation becomes a two-target attack whose second target can only be
  destroyed — and destruction changes the reported verdict.
- **Frontend `%vault()%` placeholders are now scoped to published identifiers**
  (ADR-035, #235). `TypoScriptVaultListener` runs on the output of every
  `stdWrap()` call, so an editor-written `tt_content` field (`stdWrap.field =
  bodytext`) or a reflected request parameter (`data = GP:q`) was a resolution
  site for any secret flagged `frontend_accessible` — the plaintext landed in
  output shared through the page cache. In a frontend request the extension now
  resolves an identifier only when it was published through a source an editor
  cannot write: the TypoScript setup array, the site configuration or settings,
  `plugin.tx_nrvault.frontendResolvableIdentifiers`, or
  `FrontendPlaceholderPolicyInterface::allowIdentifier()`. The check runs before
  the vault is touched, so a rejected identifier reaches neither the vault nor
  the audit log.
- **Nine findings from a security scan of the extension** (#232). Secrets
  entered into a `vaultSecret` **FlexForm** field were stored in cleartext
  (HIGH): the hook resolved the data structure with an empty table name, an
  empty field name and the submitted array where the record row belongs, which
  throws on both v13 and v14 — and the exception was swallowed, so the editor's
  plaintext fell through to DataHandler and into the record XML with no vault
  ACL and no audit entry. Frontend authorization was inferred from the *absence*
  of `$GLOBALS['BE_USER']`, which TYPO3 populates for any visitor carrying a
  backend session, so an editor could put a placeholder for a secret they cannot
  read into a published page, have an admin review it in the frontend, and the
  decrypted value went into the shared page cache and out to anonymous visitors.
  The SSRF DNS-pinning middleware returned "allowed, nothing to pin" for
  canonical IP literals, trusting a caller-side check that redirect hops never
  pass, so a `302` to `169.254.169.254` reached cloud metadata. An unbounded
  `X-Request-Id` went into a `varchar(100)` column while the HMAC covered the
  untruncated value, which either aborted the audit write or left a row
  permanently disagreeing with its own hash. Both CSV exports emitted the
  proprietary `fputcsv` escape, letting an attacker-controlled field close its
  own cell and synthesize a formula cell past the sanitizer; both now emit
  strict RFC 4180. And vault exception text reached editors through the flash
  message and `DataHandler::log()`, giving an existence oracle for secrets
  outside their ACL — failures now report a generic message plus a correlation
  reference, with the cause logged server-side, while the TSconfig `edit` /
  `readOnly` field permissions are re-checked on the write path instead of only
  rendered as a `readonly` attribute.
- **The plaintext exposure window in the browser is bounded, and the reveal
  endpoint is uncacheable** (#237). A shared reveal lifecycle auto-hides after
  30 seconds with a visible countdown and wipes immediately on
  `visibilitychange` and `pagehide`; the reveal modal wipes its input on every
  close path, including ESC and backdrop. `AjaxController::revealAction` sends
  `Cache-Control: no-store` on success **and** error. Under the hardened profile
  copy-to-clipboard is disabled outright, because the clipboard outlives the
  dialog and cannot be reliably cleared from JavaScript. The guarantee is
  documented for what it is — a bounded exposure window, not memory clearing,
  since JavaScript strings cannot be zeroized. An orphaned `SecretReveal.js`,
  whose DOM ids appeared in no template, PHP file, configuration or test, was
  deleted rather than hardened.

### Migration

Everything below is something an operator has to do; nothing here happens by
itself.

- **Grant the operation permissions before upgrading, not after.** Backend users
  need the matching `tx_nrvault:<permission>` custom option on one of their
  groups (Backend Users module). The one that bites quietly: non-admin editors
  who work with vault-backed FormEngine or FlexForm fields now need
  `secret.use`. Admins are unaffected unless you also set
  `disableAdminOverride`.
- **Re-check every CLI workflow against `cliAllowedOperations`.** The default is
  `secret.use,secret.create,secret.rotate`. Anything that reveals
  (`vault:retrieve`), deletes (`vault:delete`, the scheduled orphan cleanup),
  exports (`vault:audit --export`), rotates the master key, reads or verifies
  the audit log (`vault:audit`, `vault:audit-verify`), or publishes the tip
  anchor (`vault:audit-anchor`) needs `allowCliAccess = 1` **and** the operation
  added to that list. Prefer a named technical actor via
  `TechnicalActorContext::runAs()`: grants then come from its provisioned groups
  and the audit trail names the identity that read, exported or anchored, rather
  than recording an unattributable shell.
- **Scheduled operation is unaffected on a default installation** —
  `scheduler:run` authenticates the `_cli_` administrator, who passes through
  the admin bypass. Under `disableAdminOverride` that bypass is gone by design,
  so the identity running the scheduler needs a group carrying
  `tx_nrvault:audit.view` (verify) and `tx_nrvault:vault.configure` (anchor);
  without it both tasks fail loudly rather than skipping quietly. That is the
  intended trade: a red scheduler entry is recoverable, an anchoring run that
  did not happen but looks like one that did is exactly what the anchor exists
  to rule out.
- **Publish any frontend identifier that is not already in TypoScript or site
  configuration.** Every documented TypoScript and site-configuration form keeps
  working: writing `lib.apiKey.value = %vault(my_api_key)%` publishes
  `my_api_key`. An identifier used *only* in a Fluid template file, a `userFunc`
  or a DataProcessor is not in the setup array — publish it once per site with
  `plugin.tx_nrvault.frontendResolvableIdentifiers = my_api_key`. A rejected
  placeholder is left literal in the output, and the Development context emits
  one `notice` per request naming it.
- **In an eID handler, call `allowIdentifier()` with the PSR-7 request as its
  second argument**:
  `GeneralUtility::makeInstance(FrontendPlaceholderPolicyInterface::class)->allowIdentifier('my_api_key',
  $request)`. The policy is a shared service that outlives a request, so the
  grant is stored against that request object in a `WeakMap` — unreachable from
  any later request, which in a worker SAPI (FrankenPHP, RoadRunner) is what
  stops one request's grant from authorising the next one's anonymous,
  page-cached render. Pass the request you are handling and `setRequest()` the
  same object on the content object renderer you render with; the grant is
  matched by object identity. `$GLOBALS['TYPO3_REQUEST']` is never used for it.
  A renderer carrying a different request, or none, resolves nothing.
- **Check your scheduled render jobs before upgrading if any of them resolve
  placeholders.** A newsletter, static export or indexing job that renders
  editor-authored content now enforces the same allow-set as a frontend request.
  Publish the identifiers it needs, or set `frontendPlaceholderLegacyCli = 1` to
  restore the old CLI behaviour — and expect `vault:doctor` to report that flag
  as a warning under `standard` and a critical under `hardened`, because no
  workflow needs it that publishing the identifier would not also serve.
- **Drop any `VaultServiceInterface::clearCache()` call and any `cacheEnabled`
  configuration.** Both are gone. Reads are no longer cached at all, so a
  consumer that read the same identifier in a tight loop now performs one
  `SELECT` and one decrypt per read — and produces one audit row per read, which
  is the point.
- **Third-party implementations of `VaultServiceInterface`,
  `SecretRepositoryInterface`, `VaultAdapterInterface` or
  `VaultDoctorServiceInterface` need the new members** listed in the interface
  table under **Changed**. The two new parameters are optional and default to
  today's behaviour, so only the new methods are a hard break.
- **`undelete` is no longer available for `tx_nrvault_secret`, for anyone,
  administrators included.** If you rely on restoring soft-deleted secrets, that
  path is now the database — where the change is visible as what it is. Update
  any runbook that promised the delete was reversible.
- **Enable `auditAnchorRequired` after the first audit write following the
  upgrade**, not before: installations arrive with a populated chain and no
  anchor row, which is a warning while the flag is off and an error once it is
  on. While it is on, `vault:audit --reset-anchor` is the only way to arm the
  anchor, and it writes the reset into the chain so the operation cannot be
  performed invisibly.
- **If you configure the webhook audit sink against an on-premises RFC 1918
  collector, add an explicit `HTTP.allowed_hosts` entry.** The sink uses the
  SSRF-guarded client and the refusal is loud — logged, counted and raised as a
  finding — but it is a refusal.
- **Run `vault:doctor --profile=hardened` before switching a profile, and
  `vault:doctor --active-probes` after configuring sinks.** The first tells you
  what would fail without changing any configuration; the second is the only
  check that proves records actually arrive rather than that a URL parses. Exit
  codes are stable (0 clean, 1 warnings, 2 critical), so both are usable as
  pipeline gates.
- **If `auditHmacEpoch` is below 3, raise it and run the migration — in that
  order matters less than doing both.** Raising the setting without running
  `vault:audit-migrate-hmac` leaves older rows signed at the lower epoch and is
  the silent case doctor now reports as a warning; at epoch 1 the `success`
  column itself is outside the signed payload, so a recorded denial can be
  flipped to a recorded grant without touching a signed byte. Epoch 0 is
  critical: it drops row hashes to keyless SHA-256, makes the downgrade guard
  vacuous, and disables the in-DB anchor even when `auditAnchorRequired` is set.

## [0.13.0] - 2026-07-30

### Added

- **Shared secret-shape catalogue** (`Netresearch\\NrVault\\Secret`, ADR-031).
  The knowledge of what a secret looks like was maintained in four places — this
  extension's plaintext scanner and three separate redactors in nr-llm — and the
  copies had drifted apart in both directions. `SecretPatternLibrary` merges
  them, carrying an anchored form per shape for whole-value classification and an
  inline form for masking a secret embedded in free text. `SecretRedactor` is the
  consumer-facing API. Consuming extensions can read the catalogue statically or
  resolve `SecretRedactorInterface` from the container.
- **Portable envelope codec** (`EnvelopeCodecInterface`, ADR-032). `seal()` /
  `open()` / `isSealed()` / `rewrap()` protect a payload a consumer keeps in ONE
  column, so it no longer has to invent framing around
  `EncryptionServiceInterface`'s seven-argument, column-per-field shape. The
  sealed form is `nrv1:` + base64 JSON.
- **Consumer-owned envelope rotation** (`ForeignEnvelopeRotatorInterface`,
  ADR-033). A consuming extension tags an implementation
  `nrvault.foreign_envelope_rotator`; `vault:rotate-master-key` then re-wraps its
  envelopes inside the same transaction as its own secrets, handing over the keys
  as an `EnvelopeRotationContext` so the consumer never holds key material.

### Fixed

- **Master-key rotation no longer strands a consumer's envelopes.** Rotation
  re-wrapped the data keys in `tx_nrvault_secret` only. A consuming extension's
  wrapped data key lives in its own table, so rotating left those envelopes under
  a key the operator was told to destroy — silently, because the rotation
  succeeded at everything it knew about. Any consumer that seals payloads must
  now register a rotator; the command reports each participant and refuses to run
  when it cannot inventory one, when a consumer's table sits on a different
  database connection, or when a rotator re-wraps fewer envelopes than it
  reported.
- **`MasterKeyRotatedEvent` is dispatched.** It was declared, documented in
  `Api.rst`, and listed as step 3 of the rotation procedure in ADR-003, but was
  never dispatched from anywhere. It now fires after the rotation commits and
  carries the consumer-envelope count alongside the secret count.
- **Credential query parameters with a vendor prefix are redacted.** The
  parameter-name alternation had to match immediately after the `?` or `&`, so
  `client_secret` — the name RFC 6749 §2.3.1 defines — never matched and passed
  through untouched. `password` and the hyphenated `api-key` were missing for the
  same reason.
- **The URL redaction patterns no longer run past the end of the URL.** Bounded
  only at `&` and whitespace, a `?token=…` inside a JSON payload swallowed the
  closing quote and the following key, and a URL carrying a port followed later
  by an unrelated address was read as one userinfo component — losing the port
  and the following field, and fabricating a credentialled URL to a host that was
  never contacted.
- **The plaintext scanner classifies three more shapes.** OpenAI API keys,
  `ghs_` tokens and fine-grained GitHub PATs in a scanned column or configuration
  key are now reported as `Critical` instead of unlabelled.
- Corrected the documented `decrypt()` and `reEncryptDek()` signatures in
  `Api.rst`, which had drifted five parameters behind the interface.

## [0.12.2] - 2026-07-27

### Fixed

- Saving an existing secret record without re-entering the secret no longer
  shows "Audit logging failed: Unknown audit action \"metadata_update\"". The
  DataHandler hook classified such metadata-only saves as `metadata_update`,
  but the `AuditAction` enum had no such case, so the audit write was rejected
  — the save succeeded, yet the audit entry for the metadata change was
  silently never written. The action is now a valid enum case and the change
  is sealed into the tamper-evident audit chain; it also appears as
  "Metadata Update" in the audit-module action filter (#227).

## [0.12.1] - 2026-07-25

### Fixed

- A vault secret (for example a provider API key) is no longer wiped when its
  record is saved without re-entering the secret. Because the stored secret is
  never rendered back into the edit form, an untouched re-save submitted an
  empty value, which the DataHandler hooks treated as "delete" — removing the
  secret from both the record and the vault. Empty saves now keep the existing
  secret; deletion requires an explicit clear (which also repairs the
  previously no-op clear control). Applies to both regular TCA fields and
  FlexForm-embedded vault fields (#223).

## [0.12.0] - 2026-07-23

Security release. Six findings from a full security review, one HIGH and five
MEDIUM. Two carry behaviour changes — read **Changed** and **Removed** before
upgrading.

### Security

- **Vault secrets no longer persisted in cleartext in the site-configuration
  cache** (#216, HIGH). `%vault(id)%` references in `config/sites/*/config.yaml`
  were resolved eagerly when TYPO3 loaded the site configuration, and TYPO3
  writes that resolved array into its on-disk `core` cache — so decrypted
  secrets landed in `var/cache` in cleartext, and the per-principal access check
  ran only once, at cache-warm time. Resolution is now caller-driven at read
  time (see **Removed**).
- **CSV formula injection in audit-log exports** (#218). Attacker-controlled
  audit fields (`User-Agent`, request id, identifiers) were written to CSV
  exports without neutralizing spreadsheet formula leaders (`= + - @`, tab, CR).
  All four export sinks now route cells through a shared neutralizer.
- **Secret leaked into the audit log via transport errors** (#217). A
  query-parameter-placed secret surfaced in the outbound-request exception
  message and was logged verbatim; the URL query is now stripped before the
  message is sealed into the tamper-evident row.
- **Audit hash chain hardened against downgrade forgery** (#221). Chain
  verification accepted a uniform relabel to keyless epoch-0 SHA-256, and the
  HMAC migration re-sealed the chain without verifying it first (laundering
  prior tampering). Verification now enforces a configured-epoch floor, and the
  migration refuses to re-seal a chain that fails verification.
- **Delete access control on `tx_nrvault_secret`** (#220). Deleting a secret
  via DataHandler (FormEngine, list module) enforced no vault ACL; it now
  requires owner / admin / system-maintainer, mirroring `VaultService::delete()`.
- **Secret and master-key files created with `0600` from the start** (#219).
  `vault:retrieve --output` and `vault:init` wrote the file with the process
  umask and only `chmod`-ed afterward, leaving a world/group-readable window.

### Changed

- **Site-configuration `%vault()%` references resolve at read time, not
  automatically on load** (#216). Consumers that relied on transparent
  resolution — reading `$site->getConfiguration()[…]` and receiving a decrypted
  value — must now call
  `SiteConfigurationVaultProcessor::processConfiguration($config, $site)` at the
  point of use. See ADR-030.
- **`AuditLogServiceInterface`**: `verifyHashChain()` gains an optional
  `?int $minEpoch = null` parameter and a new `verifyChainForReseal()` method
  (#221). External implementers of the interface must implement the new method.
- **`vault:retrieve` / `vault:init` abort on a failed `chmod`** (#219) instead
  of silently continuing.
- **A vault-ACL-denied delete preserves the record** (#220) and records an
  `access_denied` audit entry, instead of being soft-deleted.

### Removed

- **`SiteConfigurationVaultListener`** — the event listener that eagerly
  resolved site-configuration vault references on load (#216). See **Security**
  above for why, and **Changed** for the read-time replacement.

## [0.11.2] - 2026-07-21

### Fixed

- **Copy-mode translation TypeError also fixed for FlexForm vault fields**
  (#207, #210). The 0.11.1 fix covered only `DataHandlerHook`; the same
  `bool`-typed `$pasteUpdate` parameter remained on
  `FlexFormVaultHook::processCmdmap_postProcess` and threw the identical
  `TypeError` when translating records with FlexForm vault fields in copy
  mode. The parameter now accepts `bool|array` — the last remaining
  `bool`-typed `$pasteUpdate` in the extension.

## [0.11.1] - 2026-07-21

### Fixed

- **`DataHandlerHook` TypeError when translating content in copy mode** (#207,
  #208). TYPO3 core reassigns the `$pasteUpdate` hook argument from its `false`
  default to an array on the localize / copy-to-language path, so the `bool`
  type on `processCmdmap_preProcess()` and `processCmdmap_postProcess()` raised
  a `TypeError` before the command guard ran, breaking content-element
  translation via the `records/localize` AJAX endpoint. The parameter now
  accepts `bool|array`, matching core's runtime contract.

## [0.11.0] - 2026-07-17

### Added

- **`TechnicalActorContext::runAs()`** (#202, #205). Headless consumers
  (Symfony Messenger workers, scheduler tasks) can evaluate vault access as a
  named technical backend user without mutating `$GLOBALS['BE_USER']`: the
  scoped context is consulted directly by `AccessControlService` with the same
  user semantics an authenticated backend login gets (owner, admin, group ACLs
  with subgroup expansion). Actor validation is fail-closed (deleted, disabled,
  time-restricted and non-rootLevel users are rejected before the scope
  starts), nesting stacks innermost-wins, the identity is always restored on
  scope exit, and audit rows record the actor as `technical`. Ambient behavior
  without an active scope is unchanged.

## [0.10.2] - 2026-07-17

### Security

- **CLI access control reachable from queue workers and scheduler** (#201). The
  TYPO3 CLI bootstrap places an unauthenticated `CommandLineUserAuthentication`
  in `$GLOBALS['BE_USER']`; `AccessControlService` treated it as a backend user,
  which shadowed the configured CLI access rules — making them unreachable from
  Symfony Messenger workers and scheduler runs — and let its default uid 0 match
  `ownerUid=0` secrets, granting read and delete even with CLI access disabled.
  The unauthenticated placeholder is now routed to the CLI access rules;
  authenticated `_cli_` users keep their user-based semantics and web requests
  are unaffected.

## [0.10.1] - 2026-07-03

### Security

- **Legacy numeric IP-literal SSRF bypass closed** (#192). curl's resolver
  accepts `inet_aton()` forms — dword (`2130706433`), octal (`0177.0.0.1`),
  hex (`0x7f.0.0.1`) and partial-dot (`127.1`) — that all reach `127.0.0.1`,
  but PHP's `inet_pton()` / `FILTER_VALIDATE_IP` reject them, so they slipped
  through the dangerous-IP guard as pseudo-hostnames (no DNS record, no pin)
  and curl derived the internal IP itself. Such forms are now rejected both in
  `isHostAllowed()` and in the request-time SSRF middleware unless the operator
  allowlists the exact literal; the canonical dotted-quad / IPv6 form is
  unaffected.

- **Privileged secret ACL columns are now authorization-gated** (#186). On the
  secret FormEngine write path, the `owner_uid`, `allowed_groups`,
  `write_groups`, `frontend_accessible` and `scope_pid` columns of
  `tx_nrvault_secret` carried no `exclude` flag and no admin gate, so a
  non-admin editor could widen a secret's ACL or reassign ownership
  (privilege escalation, CWE-639 / CWE-269). The write path now enforces
  owner/admin authorization on those privileged columns (also closes a minor
  in-memory cleartext exposure, CWE-316).

- **Audit hash-chain tamper-evidence hardened** (#185). Two forgery paths
  reachable by the documented in-scope database attacker (a principal with
  `UPDATE`/`DELETE` on `tx_nrvault_audit_log`) are closed: an epoch-downgrade
  that allowed the tail row to be rewritten under a keyless SHA-256 epoch
  because the `hmac_key_epoch` was not bound into any hashed payload
  (CWE-345 / CWE-757), and an attribution forgery. Both are now detected by
  `verifyHashChain()`.

### Fixed

- **The `vaultSecret` field description no longer renders twice on v14** (#189).
  TYPO3 v14's `AbstractFormElement::renderLabel()` emits the TCA `description`
  itself (via `renderDescription()`), so `VaultSecretElement`'s own copy became
  a duplicate. The element now renders its own description only on v13, where
  the label does not — so it appears exactly once on both v13 and v14.

- **The SSRF middleware no longer fatals without ext-curl** (#192). It
  referenced the curl-only `CURLOPT_RESOLVE` constant unconditionally, so the
  first pinned request on a curl-less install raised `Error: Undefined
  constant "CURLOPT_RESOLVE"` — contradicting `create()`'s documented
  StreamHandler-fallback warning. The pin is now attached only when
  `curl_init()` exists; the dangerous-IP rejections still run.

- **Dual-stack hosts are reachable again from IPv6-less environments** (#190).
  The DNS-rebinding defence pinned each resolved address as a separate
  `CURLOPT_RESOLVE` entry, but curl keeps only the last entry per `host:port`
  — so effectively only the final DNS record (typically the AAAA) was pinned.
  On hosts without IPv6 connectivity every request to a dual-stack host
  (e.g. `api.github.com`) failed with `cURL error 7` and no IPv4 fallback;
  all-IPv4 multi-record hosts silently lost their fallback addresses too.
  All safe resolved addresses now travel comma-joined in a single resolve
  entry (curl's multi-address form, curl ≥ 7.59), restoring curl's native
  cross-family/cross-address connect fallback while keeping the pin: every
  usable address is still one the defence resolved and vetted.

## [0.10.0] - 2026-06-11

### Added

- **Per-instance request timeout on the secure HTTP client.**
  `VaultHttpClientInterface::withTimeout(int $seconds)` is a new immutable
  wither (like `withReason()`): the override is baked into the hardened inner
  Guzzle client via the shared factory, so it applies to every send path —
  plain and authenticated — while `connect_timeout` stays platform-managed.
  Non-positive values keep the platform default. Long-running upstream calls
  (large image generations) no longer die at the instance-wide HTTP timeout.

### Fixed

- **CLI and worker reads are classified as automated again.** The TYPO3 CLI
  bootstrap installs a `CommandLineUserAuthentication` (a
  `BackendUserAuthentication` subclass), so the backend-user-first check in
  `AccessControlService::getCurrentActorType()` stamped every CLI/worker
  access as `backend`. Analytics then counted 0 automated reads and flagged
  busy automation secrets "Automation-stale". CLI detection now runs first,
  and a latent constant-case fatal in the legacy CLI check was removed.

### Changed

- `runTests.sh` defaults to the upper supported PHP bound (8.5) instead of
  8.2; CI pins its matrix explicitly and is unaffected.

## [0.9.0] - 2026-06-10

### Added

- **Per-secret encryption-algorithm marker.** Each secret now records how it
  was encrypted (`encryption_version` 2 + explicit algorithm in the new
  `tx_nrvault_secret.encryption_algorithm` column). Decryption dispatches on
  the stored marker instead of re-deriving the algorithm from the decrypting
  host's CPU capabilities, so the same data decrypts identically on any PHP
  host and future algorithm migrations become possible. Legacy rows (version 1,
  no marker) keep decrypting byte-identically via the old host-derived path;
  value rotation upgrades them to version 2. New secrets default to
  XChaCha20-Poly1305; `aes256gcm` can be pinned via the new
  `encryptionAlgorithm` extension setting (invalid or host-unavailable values
  fail loudly).
- **Audit-chain re-keying during master-key rotation.** The tamper-evident
  audit chain is HMAC-keyed from the master key; `vault:rotate-master-key` now
  re-keys the whole chain inside the same transaction as the DEK
  re-encryption (new `AuditChainRekeyService`, keyset-paginated for bounded
  memory), preserving per-row epochs and refusing to re-key a chain that does
  not verify under the current key. A second-rotation (epoch 2) functional
  test covers consecutive rotations end to end.

### Changed

- `verifyHashChain()` streams rows instead of materialising the whole audit
  log; rotation pre-flight on large installs no longer risks OOM.
- `dek_nonce`/`value_nonce` columns widened varchar(24) → varchar(32): the
  base64 form of a 24-byte XChaCha20 nonce is 32 characters (latent truncation
  bug on the XChaCha20 path).
- `encrypt()`/`decrypt()` no longer `sodium_memzero()` the master key — it is
  the provider's shared request-lifetime cache entry; the provider owns its
  lifecycle. Per-secret key material (DEK, MAC key, plaintext) is still wiped
  on every path, including exception paths.

### Fixed

- Backend column migration built `table__column__{{uid}}` identifiers whose
  literal braces failed validation — every backend-module column migration was
  rejected.
- OAuth token cache key now includes the refresh-token secret identifier and
  the (order-normalised) additional parameters, preventing cross-audience
  token confusion between configurations that differ only in
  audience/resource/tenant.
- OAuth error messages additionally redact JSON-body and quoted-prose echoes
  of `client_secret`, `refresh_token`, and `access_token`.
- `OAuthConfig` rejects unknown grant types and a `refresh_token` grant
  without a refresh-token secret at construction time.
- Secure HTTP client rejects non-object JSON request bodies up front instead
  of silently dropping the payload (or fataling on scalars).
- UUID v7 generation now sets all 14 random bits of the variant field.

## [0.8.0] - 2026-06-09

### Added
- **`prefix` option for `withAuthentication()` Header placement** — prepends an
  auth scheme/prefix to the secret before injection, so non-Bearer
  `Authorization: <scheme> <secret>` schemes can use the audited, memory-scrubbed
  secure HTTP client instead of building the header manually with a plaintext key.
  TYPO3 FAL providers use `Key `, DeepL uses `DeepL-Auth-Key `. The combined
  prefixed value is zeroed alongside the raw secret; the no-prefix path keeps a
  single secret buffer (no extra allocation). The option is threaded through
  `withReason()`; the OAuth builder leaves it unset.

### Documentation
- `Api.rst`: documented the `prefix` option and added a custom-`Authorization`-scheme
  example; corrected the DeepL usage example, which previously documented `Bearer`
  (a scheme DeepL never used).

## [0.7.0] - 2026-06-02

### Changed
- **Require TYPO3 v14.3 LTS instead of v14.0** for the v14 line
  (`typo3/cms-* : ^13.4 || ^14.3`). 14.0/14.1/14.2 were unsupported sprint
  releases; 14.3 is the LTS. The CI matrix, README, and bug-report template
  are aligned to the same constraint. (`ext_emconf.php` keeps its coarse
  `13.4.0-14.99.99` range — a single continuous range cannot express the
  `^13.4 || ^14.3` gap. Because nr-vault requires a composer-based TYPO3
  installation, `composer.json` is the authoritative version constraint.)

### Fixed
- **`SecretRepository::findIdentifiers()` now skips non-string identifier
  rows** instead of coercing them to an empty string. A driver/schema
  anomaly that returned a non-string `identifier` previously injected a
  bogus empty identifier into list views and rotation loops; such rows are
  now dropped (an empty identifier is unreachable for valid data).

### Added
- **CLI documentation drift guard** (`Tests/scripts/check-cli-docs.php`,
  wired into `composer ci` as `ci:test:php:doc-cli`). It verifies every
  documented `vault:*` example across `README.md` and the whole
  `Documentation/` tree against the command classes — unknown commands,
  unknown options, and excess positional arguments fail the build. Backslash
  line-continuations are joined so options on continuation lines are checked,
  and both `#[AsCommand(name: …)]` and positional `#[AsCommand(…)]` forms are
  recognised.
- `.gitattributes` (`export-ignore` dev-only paths for smaller composer/TER
  packages), `.ddev/.gitignore`, and a canonical `.ddev/commands/web/setup`
  entry point.
- **Vault Analytics backend module** — a new "Analytics" submodule under the
  Vault module showing usage KPIs (total / expired / frontend-accessible /
  never-rotated secrets and reads in the selected window) and, most usefully, a
  **redaction-candidates** table that flags secrets which appear unused and may
  be safe to remove. Candidates are graded into delete-candidates (never read,
  not read for a configurable period, or expired) and review-candidates
  (revealed manually but never read by automation; never rotated). A time-window
  selector (30/90/180/365 days) drives the usage signals, and each flagged
  secret links straight to its edit view. Thresholds are configurable under the
  extension's Analytics settings.
- **`vault:seed-demo` command** — populates a development instance with
  realistic, historic demo secrets and a matching audit-log history so the
  Analytics module has lifelike data to show. Idempotent, refuses to run in
  Production, and reseeds with `--force`.

### Documentation
- README CLI reference expanded from 5 to all 12 `vault:*` commands with
  corrected argument signatures (`vault:store --value=…`, `vault:audit
  --since=…`).
- Corrected `vault:*` examples across the documentation that drifted from the
  actual command signatures: `vault:store` value via `--value`/`--metadata`
  (not `--description`/`--context`/`--expires` or a positional), `vault:audit`
  `--since`/`--until` (not `--days`), `vault:migrate-field` positional
  `<table> <field>` (not `--table`/`--field`), `vault:rotate-master-key`
  `--confirm`/`--new-key`, the full `vault:audit` option reference, and
  `tx_vault_secret` → `tx_nrvault_secret`.
- Documented the dev-only ``vault:seed-demo`` command in the CLI reference.

## [0.6.1] - 2026-05-31

### Fixed
- **`SecureHttpClientFactory`'s request-time SSRF middleware now honours
  literal `allowed_hosts` entries.** In 0.6.0 the per-request DNS-rebinding
  middleware rejected every host that resolved into a private/loopback range
  regardless of `allowed_hosts`, so the documented on-prem opt-in ("LITERAL
  allowlist entries can opt back in") only applied to the `isHostAllowed()`
  gate, not to clients built by `create()`. Consumers that reach an
  internal/self-hosted endpoint through a `create()` client — e.g. an LLM
  provider talking to a local Ollama at a private-resolving hostname — were
  silently blocked with no way to opt back in. The middleware now applies the
  same literal-allowlist check as `isHostAllowed()`; an allowlisted host whose
  DNS answer is private is pinned via `CURLOPT_RESOLVE` instead of rejected, so
  rebinding to a *different* address stays blocked. Wildcard `allowed_hosts`
  entries still never bypass the guard.

## [0.6.0] - 2026-05-31

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

[Unreleased]: https://github.com/netresearch/t3x-nr-vault/compare/v0.16.0...HEAD
[0.16.0]: https://github.com/netresearch/t3x-nr-vault/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/netresearch/t3x-nr-vault/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/netresearch/t3x-nr-vault/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/netresearch/t3x-nr-vault/compare/v0.12.2...v0.13.0
[0.12.2]: https://github.com/netresearch/t3x-nr-vault/compare/v0.12.1...v0.12.2
[0.12.1]: https://github.com/netresearch/t3x-nr-vault/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/netresearch/t3x-nr-vault/compare/v0.11.4...v0.12.0
[0.11.0]: https://github.com/netresearch/t3x-nr-vault/compare/v0.10.2...v0.11.0
[0.10.2]: https://github.com/netresearch/t3x-nr-vault/compare/v0.10.1...v0.10.2
[0.10.1]: https://github.com/netresearch/t3x-nr-vault/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/netresearch/t3x-nr-vault/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/netresearch/t3x-nr-vault/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/netresearch/t3x-nr-vault/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/netresearch/t3x-nr-vault/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/netresearch/t3x-nr-vault/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/netresearch/t3x-nr-vault/compare/v0.5.0...v0.6.0
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
