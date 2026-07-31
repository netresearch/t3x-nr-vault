:navigation-title: Key custody
.. include:: /Includes.rst.txt

.. _operations-key-custody:

===========
Key custody
===========

Where the master key lives under each provider, who can read it, and how it is
rotated. The one question that decides everything on this page: **who else
runs as the PHP process user?** Anything readable by that user is readable by
the vault's attacker in a process compromise.

Design rationale: :ref:`adr-003-master-key-management`. Request-lifetime
caching: :ref:`adr-020-master-key-request-lifetime-caching`.

.. _operations-key-custody-comparison:

Provider comparison
===================

..  list-table::
    :header-rows: 1
    :widths: 14 22 22 21 21

    *   -   Provider
        -   Key at rest
        -   Who can read it
        -   Rotation
        -   Hardened profile

    *   -   ``typo3``
        -   Nowhere — derived on demand from
            ``SYS/encryptionKey`` with HKDF-SHA256.
        -   Anyone who can read :file:`config/system/settings.php`, plus every
            backup of it.
        -   Only by rotating TYPO3's ``encryptionKey``, which orphans every
            stored secret unless the vault is rotated in the same operation.
        -   **Rejected** (``1753900002``).

    *   -   ``file``
        -   A file outside the web root, ``0400``, path in
            ``masterKeySource``.
        -   The file's owner, and root. Not the database.
        -   ``vault:rotate-master-key`` writes the new key in place.
        -   Permitted.

    *   -   ``env``
        -   An environment variable named by ``masterKeySource``
            (default ``NR_VAULT_MASTER_KEY``).
        -   Anything that can read the process environment: the process
            itself, root, and whatever injected it.
        -   Out of band — the provider cannot persist a value. Set the new
            variable, restart, then rotate.
        -   Permitted.

    *   -   ``transit``
        -   Only the **wrapped** ciphertext (``vault:v1:…``) locally, at
            ``hashicorp.transitWrappedKeyPath``. Unwrapping is a live Vault
            call.
        -   Anyone holding the Vault token *and* the wrapped blob. Neither
            alone suffices.
        -   Two independent rotations — see
            :ref:`operations-key-rotation-transit`.
        -   Permitted; it is the kind of external custody the profile asks
            for.

..  note::

    The ``transit`` provider ships in the same release train as this
    documentation. On a build without it, ``masterKeyProvider`` accepts
    ``typo3``, ``file`` and ``env``; an unknown value is refused with
    exception code ``1703800015``.

.. _operations-key-custody-typo3:

``typo3`` — derived from the TYPO3 encryption key
=================================================

The default, and the only zero-configuration option. HKDF-SHA256 over
``SYS/encryptionKey`` with the domain-separation string
``nr-vault-master-key``, yielding 32 bytes. Source keys shorter than 32
characters are refused outright — they would give HKDF far less than 256 bits
of entropy.

**What it does not do is separate the vault from TYPO3.** The derivation is
sound; the custody is not improved at all. See
:ref:`security-known-limitations-typo3-provider`.

Two operational consequences that catch people out:

*   ``encryptionKey`` is vault key material for as long as this provider is
    configured. Rotating it orphans every secret.
*   The provider defines no destructor, so its request-lifetime cache slot
    survives individual instances. Long-running processes — scheduler daemons,
    messenger workers — must call :php:`Typo3MasterKeyProvider::clearCachedKey()`
    to observe a rotated ``encryptionKey``.

Acceptable for: development, staging, and installations where the secrets are
no more sensitive than the rest of :file:`settings.php`. Not acceptable for a
hardened deployment, and the profile enforces that.

.. _operations-key-custody-file:

``file`` — a key file outside the web root
==========================================

..  code-block:: none
    :caption: Extension configuration

    masterKeyProvider = file
    masterKeySource = /var/lib/typo3-secrets/vault-master.key

The path must be outside the document root. The file is written with the umask
tightened to ``0o077`` *before* the write and then ``chmod`` to ``0400``, so
there is no window in which it is world-readable — an ordering that matters on
hosts with permissive umasks.

..  code-block:: bash
    :caption: Recommended ownership

    # Owned by the user the PHP process runs as; nothing else needs it.
    install -d -m 0700 -o www-data -g www-data /var/lib/typo3-secrets
    chown www-data:www-data /var/lib/typo3-secrets/vault-master.key
    chmod 0400 /var/lib/typo3-secrets/vault-master.key

The provider accepts the file as raw 32 bytes or as base64 (trailing newlines
are tolerated). Anything else is rejected on length rather than padded.

..  warning::

    If ``masterKeySource`` is empty or left at the default, the provider falls
    back to an auto-generated development key under
    :php:`Environment::getVarPath() . '/secrets/vault-master.key'`. That
    location is convenient for development and wrong for production: it lives
    inside the TYPO3 var path, which many deployment and backup routines treat
    as ordinary application state. Always set ``masterKeySource`` explicitly.

**Checklist:** outside the web root; ``0400``; owned by the PHP user; excluded
from application backups and included in a *separate* key backup
(:ref:`operations-backup-and-restore`); on a filesystem whose snapshots you
also control; access-logged if the platform allows it.

.. _operations-key-custody-env:

``env`` — an environment variable
=================================

..  code-block:: none
    :caption: Extension configuration

    masterKeyProvider = env
    masterKeySource = NR_VAULT_MASTER_KEY

The natural fit for containers and any platform with a secret-injection
mechanism (Kubernetes secrets, systemd ``LoadCredential``, a supervisor's
environment file). Raw 32 bytes or base64; the provider zeroes the base64
string once decoded.

**Where environment variables leak.** Process listings on some platforms,
``phpinfo()``, crash dumps, ``/proc/<pid>/environ`` for the same user or root,
child processes, and — commonly — CI logs and container inspection output.
Verify that yours does not, rather than assuming.

The provider cannot persist a value, so ``vault:rotate-master-key`` cannot
write the new key for you: set the variable in the injection mechanism,
restart the process, and rotate with the new value supplied explicitly.

.. _operations-key-custody-transit:

``transit`` — wrapped by HashiCorp Vault
========================================

..  code-block:: none
    :caption: Extension configuration

    masterKeyProvider = transit
    hashicorp.address = https://vault.example.internal:8200
    hashicorp.authMethod = token
    hashicorp.tokenEnvVar = VAULT_TOKEN
    hashicorp.transitMount = transit
    hashicorp.transitKeyName = nr-vault-master
    hashicorp.transitWrappedKeyPath = /var/lib/typo3-secrets/vault-master.wrapped

The master key is generated once, wrapped by Vault's transit engine, and only
the ciphertext is stored locally. Every unwrap is a ``POST`` to
``/v1/{mount}/decrypt/{key}``.

**Custody notes.**

*   **Token, not configuration.** The token is read from
    ``hashicorp.tokenEnvVar`` in preference to ``hashicorp.token``, because a
    token in the extension configuration is readable in the Install Tool and
    lands in configuration exports. Leave ``hashicorp.token`` empty in
    production.
*   **Token auth only.** ``approle`` and ``kubernetes`` are rejected rather
    than silently downgraded to something weaker.
*   **Least-privilege policy.** The token needs ``update`` on
    ``transit/decrypt/<key>``, plus ``update`` on ``transit/encrypt/<key>``
    only for initialisation and rotation. Nothing else. Withhold
    ``transit/keys/*`` so the vault cannot delete or export its own key.
*   **Path safety is enforced.** Mount segments and the key name must match
    ``[A-Za-z0-9._-]+`` and must not be ``.`` or ``..``, so a configured mount
    cannot traverse the API path. A nested mount such as ``platform/transit``
    stays usable.
*   **The wrapped file is written safely.** ``0600`` (rotation must overwrite
    it) via write-to-temp-then-rename, because a half-written wrapped key is
    an unrecoverable vault rather than a failed write.
*   **Errors are redacted.** Token-shaped strings are stripped from transport
    error messages, and non-2xx response bodies are never surfaced — Vault
    echoes the submitted ciphertext on some error paths.

**What it buys and what it does not.** Custody, rotation and central,
revocable audit of every unwrap; a stolen database plus a stolen webroot is
useless. It does **not** protect a live attacker inside the request — see
:ref:`security-known-limitations-kms`. And it makes Vault an availability
dependency: ``isAvailable()`` performs no network call so an outage does not
become a per-request timeout, but the first real key load will fail.

.. _operations-key-custody-hsm:

HSM and cloud KMS
=================

nr-vault has no direct HSM or cloud-KMS integration. The ``transit`` provider
is the supported indirection: HashiCorp Vault can itself be backed by an HSM
or a cloud KMS for its own seal, which puts the vault's master key under that
custody transitively without nr-vault needing a provider per KMS vendor.

Anything else — AWS KMS, Azure Key Vault, GCP KMS directly — would need a new
``MasterKeyProviderInterface`` implementation. The interface is a single
method, and :php:`AbstractMasterKeyProvider` already implements the caching
and wiping contract, so the surface is small; but it does not exist today, and
no configuration setting will produce it.

.. _operations-key-custody-inprocess:

What custody cannot fix
=======================

Regardless of provider, the master key is present in the PHP process for the
duration of a request that touches a secret. It is cached in a static keyed by
provider class, and wiped with :php:`sodium_memzero()` when the slot is
cleared — but while it is there, code running in that process can read it.

Custody decides who can obtain the key *outside* the request. It has no
opinion about the request itself. Everything on this page is about the former.
