:navigation-title: Target of evaluation
.. include:: /Includes.rst.txt

.. _auditor-target-of-evaluation:

====================
Target of evaluation
====================

What an assessment of nr-vault can and cannot conclude. Read this before
scoping the engagement — several of the controls an auditor would expect to
find are, correctly, somebody else's.

.. _auditor-toe-what:

What nr-vault is
================

A TYPO3 extension (``netresearch/nr-vault``, extension key ``nr_vault``) that
runs **inside the TYPO3 PHP process** and provides:

*   **Envelope encryption at rest** for secret values: a per-secret data
    encryption key, AEAD-encrypted, wrapped by a master key that is never
    stored in the database. :ref:`security-cryptography`.
*   **Master-key custody options**: derived from the TYPO3 encryption key, a
    file, an environment variable, or a KMS.
    :ref:`operations-key-custody`.
*   **Two-gate access control**: ten operation permissions granted per backend
    user group, and per-secret ownership and group tiers. Both must pass.
    :ref:`security-access-control`.
*   **A tamper-evident audit log**: an HMAC hash chain over every access,
    mirrored to external sinks and anchored outside the database.
    :ref:`security-audit-evidence`.
*   **Two enforced security profiles**, ``standard`` and ``hardened``, the
    latter fail-closed. :ref:`security-profiles`.
*   **A bounded reveal path**: server-side permission checks, no-store
    responses, auto-hide, and no clipboard copy under the hardened profile.

.. _auditor-toe-not:

What nr-vault is not
====================

..  warning::

    **nr-vault is not a boundary against code running in the TYPO3 PHP
    process.** A compromised process — RCE, a malicious extension, a hostile
    dependency — can request every secret the process may legitimately
    request. No configuration changes this; see
    :ref:`security-known-limitations-process`.

    An assessment that concludes "secrets are protected against application
    compromise" has mis-scoped the target.

It is also not:

*   **A key management system.** It consumes one (``transit``) but implements
    none. There is no HSM integration, no key hierarchy beyond master key and
    per-secret DEKs, and no escrow.
*   **A secrets *distribution* system.** Values are consumed in-process by
    TYPO3 code. There is no agent, no broker, no lease, no TTL on a delivered
    credential.
*   **A credential rotator.** It stores and versions values; it does not talk
    to the systems those credentials authenticate against. Rotating a
    credential at its origin is an operator action —
    :ref:`operations-incident-response-exposure`.
*   **A defence against the key holder.** Anyone who can read the master key
    can read every secret and recompute the entire audit chain.
*   **Tamper-*proof*.** The audit chain is tamper-*evident*: it detects, it
    does not prevent. :ref:`security-known-limitations-chain`.

.. _auditor-toe-scope:

Scope boundary
==============

..  list-table::
    :header-rows: 1
    :widths: 50 50

    *   -   In scope — assessable in this codebase
        -   Out of scope — assess elsewhere

    *   -   Envelope construction, algorithm selection and markers, nonce
            handling, key lengths
        -   The libsodium build and the PHP runtime that provide the
            primitives

    *   -   HKDF domain separation and derived-key usage
        -   The entropy of the *source* key material (``encryptionKey``, a
            generated key file, a KMS key)

    *   -   Master-key provider selection, fail-closed policy, request-lifetime
            caching and wiping
        -   Filesystem permissions, container secret injection, and the KMS
            itself

    *   -   Operation permissions, the per-secret tiers, and the single
            admin-bypass seam
        -   TYPO3 core authentication, session handling, CSRF, and backend
            user management

    *   -   Audit chain construction, epoch dispatch, verification, anchoring
            and sink fan-out
        -   The SIEM, the log pipeline, and the retention applied there

    *   -   Reveal-path authorization, cache headers, and the client-side
            exposure lifecycle
        -   The browser, the clipboard, screen capture, and the operator's
            physical environment

    *   -   Outbound HTTP hardening for the webhook sink (SSRF and
            DNS-rebinding defences)
        -   Network segmentation and egress filtering

    *   -   Break-glass activation policy, evidence and time boxing
        -   Whether the organisation actually reviews activations

    *   -   Soft-delete semantics and what decommissioning therefore requires
        -   Database backups, replicas, binlogs and storage snapshots

Explicitly out of scope, and not compensated for anywhere in this extension:
the operating system, the web server, the database server and its access
control, TYPO3 core itself, every other installed extension, physical
security, and network security.

.. _auditor-toe-trust:

Trust assumptions
=================

The design assumes, without verifying:

#.  **The PHP process is not hostile.** Everything follows from this. See
    :ref:`security-trust-boundaries-anchor`.
#.  **TYPO3 core authentication is sound.** nr-vault inherits sessions, login
    and CSRF; it adds authorization on top of them and asserts it server-side
    at each entry point.
#.  **Every installed extension is trusted.** ``runAs()`` is explicitly not an
    authentication boundary — any code with DI access can act as any enabled
    backend user, which is the same power :php:`$GLOBALS['BE_USER']` mutation
    already grants. The value added is validation, guaranteed scope
    restoration, and honest audit attribution.
#.  **A CLI shell is trusted.** A shell on the host reaches
    :file:`settings.php`, the key file and the environment. Secret *reads*
    over CLI remain gated on ``allowCliAccess`` (off by default) and, when
    that is on, narrowed further by ``cliAllowedOperations``, but break-glass
    deliberately is not.
#.  **The filesystem enforces its permissions**, and the PHP user is not
    shared with untrusted workloads.
#.  **The database is honest about what it stores.** A database *writer* is
    treated as an adversary — that is what the audit chain is for — but the
    ciphertext read path assumes the driver returns what was stored.

An assessment should verify these assumptions in the *deployment*, since the
extension cannot.

.. _auditor-toe-sidecar:

Future work: the sidecar boundary
=================================

The most significant limitation — a compromised PHP process reaching every
secret — cannot be fixed inside a PHP extension, because the control would run
in the same address space as its attacker.

The architecture that would change the answer is a separate decryption process
with its own credentials and its own rate limiting, so a process compromise
yields a metered oracle rather than the key. That option is recorded and
evaluated in :ref:`adr-016-sidecar-option`.

..  note::

    **It is not implemented.** Do not credit it as a control. It is documented
    here so an assessment can distinguish "not addressed" from "addressed
    elsewhere" — and so a re-assessment after a future release knows what to
    look for.

.. _auditor-toe-versions:

Versions and configuration under evaluation
===========================================

An assessment is only meaningful against a stated configuration, because the
profile changes enforced behaviour. Record at minimum:

*   the extension version, and the TYPO3 and PHP versions;
*   ``securityProfile``, and whether ``disableAdminOverride`` is set **and**
    effective (``vault:break-glass --status`` reports
    ``adminOverrideDisabledEffective``);
*   ``masterKeyProvider``, and whether the key material is pinned outside the
    backend;
*   ``auditHmacEpoch``, and the lowest epoch actually present in the chain;
*   which audit sinks are enabled, and whether anchoring and verification are
    scheduled;
*   ``auditAnchorRequired``, and whether the in-database tip anchor is armed
    (``vault:audit --verify`` reports it) — an install with the anchor
    unarmed cannot detect a full reset of the audit table;
*   ``allowCliAccess``, ``cliAllowedOperations``, and the ``tx_nrvault:*``
    grants per backend group;
*   ``frontendPlaceholderLegacyCli``, which decides whether command-line
    placeholder resolution is bound by the same allow-set as a frontend
    request;
*   ``encryptionAlgorithm``, which records the AEAD used for new secrets —
    empty means XChaCha20-Poly1305;
*   ``auditSinkStaleDeliveryHours``, the window after which an enabled sink's
    last successful delivery counts as stale.

:ref:`auditor-evidence-collection` produces all of this as artefacts.
