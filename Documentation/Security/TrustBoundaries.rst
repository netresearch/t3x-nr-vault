:navigation-title: Trust boundaries
.. include:: /Includes.rst.txt

.. _security-trust-boundaries:

================
Trust boundaries
================

A control is only meaningful at a boundary. This page names the five
boundaries nr-vault crosses, states what crossing each one costs an attacker,
and — more usefully — what each boundary does **not** stop.

The diagram is in :ref:`security-threat-model-boundaries`.

.. _security-trust-boundaries-anchor:

The PHP process is the trust anchor
===================================

Everything else on this page is relative to one fact: plaintext exists in the
PHP process and nowhere else. The master key is loaded there, cached there for
the duration of one request
(:php:`AbstractMasterKeyProvider::getMasterKey()`, see
:ref:`adr-020-master-key-request-lifetime-caching`), and wiped with
:php:`sodium_memzero()` when the provider's cache slot is cleared. DEKs are
unwrapped there and wiped on every path, including the error paths.

Consequently: **a fully compromised PHP process defeats every control in this
extension.** nr-vault raises the cost of a database compromise, a backup
leak, a misconfigured backend group and an insider with SQL access. It does
not defend the process against itself. See
:ref:`security-known-limitations`.

.. _security-trust-boundaries-browser:

Boundary 1 — browser to PHP process
===================================

**Crossing requires:** a TYPO3 backend session, the CSRF protection built into
``@typo3/core/ajax/ajax-request.js``, a ``POST`` request, and — for a reveal —
**both** ``secret.reveal`` (displaying plaintext to a human) and
``secret.use`` (obtaining the plaintext at all), plus per-secret read access.
The ``vault_reveal`` route is registered ``access => 'user'`` on purpose:
:php:`AjaxController::revealAction()` re-asserts the method and the permission
server-side, so authorization holds even if the route configuration is later
loosened.

**What the boundary protects.** Plaintext leaves the process only in a
response marked ``Cache-Control: no-store`` (and ``Pragma: no-cache``), on
success and error alike, so no browser, proxy or service worker retains it.
Nothing is cached client-side: every reveal re-hits the endpoint, which is
what makes every reveal produce its own audit row.

**What it does not protect.** Once the plaintext is in the browser it is
outside anything PHP can enforce:

*   JavaScript strings cannot be zeroized. ``startRevealLifecycle()`` bounds
    the *exposure window* — 30 seconds, or immediately on
    ``visibilitychange`` (tab hidden) and ``pagehide`` — but the engine may
    retain copies after the field is cleared.
*   The clipboard outlives the dialog and cannot be cleared reliably from
    JavaScript. That is why the hardened profile reports
    ``copyAllowed = false`` and offers no copy button.
*   Screenshots, screen sharing and cameras are outside scope entirely.

.. _security-trust-boundaries-database:

Boundary 2 — PHP process to database
====================================

**Crossing requires:** the database credentials in :file:`settings.php`, or
any other path to SQL execution.

**What the boundary protects.** The database holds ciphertext, wrapped DEKs,
nonces, algorithm markers and the audit chain. It holds **no master key under
any provider** — the ``typo3`` provider derives it from ``encryptionKey`` in
:file:`settings.php`, the others read a file, an environment variable or a
KMS. A read-only database compromise therefore yields nothing directly
usable.

A database *write* compromise is the interesting case, and the audit chain is
designed for exactly it: from epoch 1 the entry hash is an HMAC under a key
derived from the master key, which the database does not contain. An attacker
who can rewrite rows cannot re-sign them.

**What it does not protect.**

*   Metadata is not encrypted. Identifiers, owners, group tiers, timestamps,
    version counters and the full audit trail are readable plaintext. The
    audit log in particular maps out the credential topology — which is why
    reading it is its own permission (``audit.view``) rather than a side
    effect of holding a secret permission.
*   The chain detects tampering; it does not prevent it, and it cannot by
    itself detect a wholesale reset. That needs the external anchor
    (:ref:`security-audit-evidence`).
*   ``value_checksum`` is a keyed change detector over the ciphertext, not an
    integrity control — integrity comes from the AEAD tag.

.. _security-trust-boundaries-filesystem:

Boundary 3 — PHP process to filesystem
======================================

**Crossing requires:** filesystem access as the web-server or CLI user.

**What crosses it.** Depending on configuration: the master-key file
(``file`` provider), the wrapped master key (``transit``), the NDJSON audit
stream and the anchor file (``file`` sink), and — always —
:file:`config/system/settings.php` and :file:`additional.php`.

**What the boundary protects.** Permissions, and only permissions. The
``file`` provider writes its key with the umask tightened to ``0o077`` before
the write, then ``chmod`` to ``0400``, so there is no window in which the
freshly created file is world-readable. The transit provider writes the
wrapped key the same way but at ``0600`` (rotation must be able to overwrite
it) and via write-to-temp-then-rename, because a truncated wrapped key is an
unrecoverable vault rather than a failed write. The NDJSON sink creates files
``0600`` and directories ``0700``, and refuses paths under a public root.

**What it does not protect.** The web-server user can read what the
web-server user can read. A key file readable by the PHP process is readable
by anything running as that process — which is the whole point of
:ref:`security-known-limitations` on the ``typo3`` provider, and the reason
:ref:`operations-key-custody` treats "who else runs as this user" as the
question that matters.

Pinning matters here. Settings that are editable in
:guilabel:`Admin Tools > Settings` can be changed by a compromised
administrator; the same settings pinned in
:file:`config/system/additional.php` require filesystem access to change.
``disableAdminOverride`` is the canonical example
(:ref:`security-disable-admin-override`).

.. _security-trust-boundaries-kms:

Boundary 4 — PHP process to KMS
===============================

Applies to the ``transit`` master-key provider, which ships in the same
release train as this documentation.

**Crossing requires:** network reachability of the Vault address **and** a
valid token, read from the configured environment variable in preference to
the stored setting (the stored one is readable in the Install Tool and
appears in configuration exports).

**What the boundary protects.** Custody, rotation and auditability. Only the
wrapped ciphertext (``vault:v1:…``) sits on the local filesystem; unwrapping
is a live API call. Pulling the token or the policy locks the vault out
immediately, with no key file left behind to recover. Every unwrap is logged
centrally, by a system the TYPO3 administrator does not control. A stolen
database plus a stolen webroot is useless without Vault access.

Path safety is enforced before interpolation: mount segments and the key name
must match ``[A-Za-z0-9._-]+`` and must not be ``.`` or ``..``, so a
configured mount cannot traverse the API path. Token-shaped strings are
redacted from transport error messages before they reach a log.

**What it does not protect.** A live attacker inside the request. The process
holds a token it may legitimately use, so it can call ``decrypt`` and obtain
the master key. **A KMS protects custody, not runtime.** Stated plainly
because it is the most common misreading of what a KMS buys.

Availability also becomes a dependency: an unreachable Vault means an
unreadable vault. ``isAvailable()`` deliberately performs no network call so a
Vault outage does not become a per-request HTTP timeout on hot paths, but the
first real ``getMasterKey()`` will fail.

.. _security-trust-boundaries-siem:

Boundary 5 — PHP process to SIEM
================================

**Crossing requires:** nothing from the attacker's side — this boundary is
one-way and outbound. Its purpose is to put evidence where the database owner
cannot reach it.

**What crosses it.** Audit entries, chain-tip anchors and integrity alerts,
through any enabled sink: local syslog as RFC 5424 structured data at facility
``LOG_LOCAL0``, an append-only NDJSON file, or an HTTP POST to a collector.

**Ordering matters.** Fan-out happens *after* the transaction commits and
*after* the advisory audit lock is released. Two consequences, both
deliberate: a hanging collector cannot serialise every other vault operation
behind the audit lock, and a sink failure is a delivery problem that never
fails or rolls back the audited operation. Failures are contained per sink,
counted, logged, and raised as a ``SINK_FAILURE`` alert.

**What it does not protect.** The window between a write and its delivery. A
sink that has been failing since Tuesday is an availability problem with
integrity consequences, which is why the failure counters exist and why
``SINK_FAILURE`` belongs in your alerting (see
:ref:`operations-monitoring-and-alerting`).

.. _security-trust-boundaries-frontend:

Frontend and page-cache caveats
===============================

The frontend is not a boundary nr-vault defends across — it is a context in
which the vault deliberately refuses to act.

*   **Frontend requests hold no operation permission.** :php:`isGranted()`
    returns ``false`` for any frontend request regardless of what
    :php:`$GLOBALS['BE_USER']` contains, because TYPO3 populates that global
    for any visitor carrying a valid backend session, and frontend output is
    shared with anonymous visitors through the page cache.
*   **Frontend reads are a property of the secret, not of the visitor.** Only
    the secret's own ``frontend_accessible`` flag governs them — and for
    :typoscript:`%vault(id)%` placeholders, additionally the request's
    FrontendPlaceholderPolicy allow-set
    (:ref:`adr-035-frontend-placeholder-allow-set`): being
    ``frontend_accessible`` no longer makes an identifier resolvable from
    editor-authored content.
*   **Anything rendered into a cached page is public.** A secret resolved into
    frontend output is cached alongside it and served to everyone. Vault
    values belong in server-side integrations — HTTP clients, API calls, and
    site configuration resolved at read time
    (:ref:`adr-030-site-config-vault-read-time-resolution`) — not in rendered
    markup.
