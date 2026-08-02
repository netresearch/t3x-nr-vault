:navigation-title: Known limitations
.. include:: /Includes.rst.txt

.. _security-known-limitations:

=================
Known limitations
=================

..  warning::

    Read this page before deploying nr-vault, and read it again before
    telling anyone what the vault guarantees. Every limitation below is a
    property of the design, not a bug awaiting a fix. Several of them cannot
    be fixed inside a TYPO3 extension at all.

Nothing on this page is hedging. A control whose boundary is undocumented
gets trusted past its boundary, and that is how a hardening feature turns
into a liability.

.. _security-known-limitations-process:

A compromised PHP process can request every secret
==================================================

**The limitation.** Arbitrary code execution in the TYPO3 PHP process — an
RCE, a malicious extension, a hostile Composer dependency, a compromised
deployment — defeats every control in this extension. The attacker is inside
the trust anchor: they can call :php:`VaultService::retrieve()`, or load the
master key provider directly, and take whatever the process may legitimately
take.

**Why it cannot be fixed here.** nr-vault runs in that process. A control
implemented in the same address space as its attacker is not a control.

**What actually helps.** Moving decryption out of the process, so that a
compromise yields a request-rate-limited oracle instead of the key. That is a
different architecture, evaluated in :ref:`adr-016-sidecar-option`, and it is
not what this extension is today.

**What still holds.** Attribution. A read performed by compromised code still
writes an audit row, and with a KMS every unwrap is logged by a system the
attacker does not control. Detection after the fact is a genuinely different
thing from prevention — just not a substitute for it.

.. _security-known-limitations-typo3-provider:

The ``typo3`` provider does not separate the vault from TYPO3
=============================================================

**The limitation.** The default provider derives the master key from
:php:`$GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey']` with HKDF-SHA256.
The derivation is sound, but it changes nothing about custody: anyone who can
read :file:`config/system/settings.php` can derive the master key. That
includes every backup of the configuration directory, every developer with a
copy of the production settings, and every process running as the web-server
user.

Its strength also cannot exceed the strength of ``encryptionKey`` itself. The
provider refuses source keys shorter than 32 characters, but a weak-but-long
key still yields a weak master key.

**Consequence for backups.** A dump of the database *plus* the configuration
directory is a complete break. See :ref:`operations-backup-and-restore`.

**What to do.** Use ``file``, ``env`` or ``transit`` for anything holding
production credentials. The hardened profile enforces this: ``typo3`` is
rejected outright with exception code ``1753900002``, and there is no
auto-detection fallback that could quietly put you back on it.

.. _security-known-limitations-js:

Revealed plaintext in the browser cannot be zeroized
====================================================

**The limitation.** JavaScript strings are immutable and garbage-collected.
Setting ``input.value = ''`` removes the value from the DOM; it does not
remove the engine's copies from memory. There is no browser API that would.

**What is actually provided.** A bounded exposure window, not secure
deletion: 30 seconds of visibility, plus an immediate wipe when the tab is
hidden (``visibilitychange``) or the page goes away (``pagehide``). Nothing is
cached client-side, so a revealed value does not survive a modal close, and
the response is marked ``Cache-Control: no-store``.

**The clipboard is worse.** Clipboard contents outlive the dialog, outlive the
page, and cannot be cleared reliably from JavaScript — they may also
synchronise to other devices. That is why the hardened profile disables the
copy button entirely rather than clearing the clipboard on a timer, which
would be theatre.

.. _security-known-limitations-chain:

The hash chain does not prevent a database reset
================================================

**The limitation.** The HMAC chain proves that no row was altered *within* the
stored chain. It cannot prove that the chain is still the same chain. An
attacker with ``DELETE`` rights on ``tx_nrvault_audit_log`` can truncate it and
let the service build a fresh, internally consistent chain from uid 1 — the
chain itself cannot distinguish that from a genuinely young installation.

**What closes the gap, partially.** Two chain-tip anchors, at different
distances from the attacker.

The in-database anchor (:ref:`adr-034-audit-chain-tip-anchor`) records "row
uid=A still exists with entry_hash=H" in ``sys_registry``, MACed under a key
derived from the master key — which is not in the database. Truncating the
audit table alone therefore no longer looks like a young installation: the
anchor still names a row that is gone, and verification reports a violation.

The external anchor is published to a store the database owner does not
control at all, giving verification two facts to check that no database write
can reach: the chain cannot have shrunk, and the row at the anchored sequence
must still hash to the anchored tip.

**What remains.** Detection, not prevention — and each anchor only as far as
its storage is trustworthy. An attacker who also holds ``DELETE`` on
``sys_registry`` can remove the in-database anchor, which then reads as "not
armed" rather than as a violation; :confval:`ext-nrvault-auditAnchorRequired`
is what closes that, turning a missing anchor into a critical finding a
database writer cannot silence. It lives in the extension configuration, so a
database-write attacker cannot reach it — but unlike ``disableAdminOverride``
it accepts no ``$TYPO3_CONF_VARS`` pin, so a compromised administrator can
still clear it from the Settings module. An anchor
file on a host the attacker owns can likewise be truncated, so anchors shipped
off-host through syslog or a webhook are what makes the external property
real. And in every case: **tamper-evident, not tamper-proof.**

.. _security-known-limitations-kms:

A KMS protects custody, not runtime
===================================

**The limitation.** With the ``transit`` provider the master key is unwrapped
by HashiCorp Vault on demand and only the wrapped ciphertext sits locally.
That is a genuine improvement in custody, rotation and auditability. It does
**not** stop a live attacker inside the request: the process holds a token it
may legitimately use, so it can call ``decrypt`` and obtain the master key
exactly as the vault does.

**What it buys, precisely.** Key custody and rotation move into Vault; every
unwrap is centrally audited and revocable, so pulling the token or the policy
locks the vault out immediately with no key file left to recover; and a stolen
database plus a stolen webroot is useless without Vault access.

**What it costs.** Availability. An unreachable Vault is an unreadable vault.

.. _security-known-limitations-backup:

Backups need the database **and** separately stored key material
================================================================

**The limitation.** A database backup alone cannot be restored into a working
vault — the ciphertext is undecryptable without the master key. A backup of
both, stored together, is a single artefact that contains everything.

**Both failure modes are real, and they pull in opposite directions.** Storing
key material with the dump destroys the protection; storing it nowhere
destroys the data. The only correct answer is: back up both, store them
separately, restore both, and verify the restore with a probe decrypt. See
:ref:`operations-backup-and-restore`.

.. _security-known-limitations-key-loss:

Master key loss is data loss
============================

**The limitation.** There is no recovery path, no escrow, no vendor-side
reset. If the master key is lost, every secret in the vault is permanently
unreadable. This is not a limitation to be engineered away — a vault with a
recovery backdoor is a vault with a backdoor.

The ``typo3`` provider makes this easier to trip over than it looks: rotating
TYPO3's ``encryptionKey`` changes the derived master key and orphans every
stored secret. Treat ``encryptionKey`` as vault key material for as long as
that provider is configured.

.. _security-known-limitations-break-glass:

Break-glass restores full admin power
=====================================

**The limitation.** While a break-glass window is open, an administrator has
exactly what they had before the override was disabled: every operation
permission, and read, write and delete on every secret. Break-glass prevents
nothing.

**Its value is evidence and time boxing** — a named actor, a mandatory typed
justification, a hash-chained audit row written *before* the window opens, a
PSR-14 event observers can alert on, a banner every operator sees, and an
expiry between 1 and 60 minutes that nobody has to remember, evaluated at read
time on every access-control decision.

**Two gaps worth naming.** A window that simply expires writes no audit row —
nothing runs at the moment it lapses, so reconstruct the closed interval from
the activation row's ``expiresAt`` context value. And an administrator with
filesystem access can unpin ``disableAdminOverride`` instead of using
break-glass at all; that path is visible in the filesystem, not in the audit
log.

Treat an activation as an incident to review, not as routine maintenance
(:ref:`operations-incident-response`).

.. _security-known-limitations-metadata:

Metadata is not confidential
============================

Identifiers, ownership, group tiers, timestamps, version counters and the
whole audit trail are stored unencrypted. The audit log is the sensitive one:
it maps who holds which credential and when they use it, which is a useful
target in its own right. That is why ``audit.view`` and ``audit.export`` are
separate permissions, and why an export — which leaves the tamper-evident
store behind, with no hash chain, no retention policy and no further access
control — is gated apart from viewing.

.. _security-known-limitations-scope:

Out of scope entirely
=====================

nr-vault makes no claim about, and provides no control over:

*   the operating system, the web server, the PHP runtime and its extensions;
*   the database server, its access control, its backups and its replicas;
*   TYPO3 core authentication, session handling and CSRF (inherited, not
    provided);
*   the browser, the clipboard, screenshots, screen sharing and cameras;
*   the SIEM or log pipeline once evidence has left the process;
*   physical and network security, and the trustworthiness of every other
    installed TYPO3 extension.

:ref:`auditor-target-of-evaluation` states the same boundary in the form an
assessor needs.
