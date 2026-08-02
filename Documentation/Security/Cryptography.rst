:navigation-title: Cryptography
.. include:: /Includes.rst.txt

.. _security-cryptography:

============
Cryptography
============

The precise cryptographic contract, for reviewers who need more than
:ref:`security-encryption-architecture`. Every statement here is a property of
:php:`Netresearch\NrVault\Crypto\EncryptionService`,
:php:`EnvelopeCodec` and the master-key providers on this branch.

Design rationale lives in :ref:`adr-002-envelope-encryption` (envelope
scheme), :ref:`adr-032-portable-envelope-codec` (framing) and
:ref:`adr-003-master-key-management` (key custody).

.. _security-cryptography-primitives:

Primitives
==========

libsodium only. There is no ``openssl_*`` fallback path anywhere in the
extension.

..  list-table::
    :header-rows: 1
    :widths: 30 20 50

    *   -   Purpose
        -   Primitive
        -   Notes

    *   -   Value and DEK encryption
        -   XChaCha20-Poly1305 (IETF) or AES-256-GCM
        -   AEAD in both cases. 256-bit keys. The secret identifier is passed
            as associated data, so an envelope cannot be moved to another
            identifier without failing authentication.

    *   -   Key derivation
        -   HKDF-SHA256 (:php:`hash_hkdf()`)
        -   Three distinct, domain-separated uses — see
            :ref:`security-cryptography-hkdf`.

    *   -   Audit chain authentication
        -   HMAC-SHA256
        -   Under a key derived from the master key. See
            :ref:`security-audit-evidence`.

    *   -   Change detection
        -   HMAC-SHA256 over the ciphertext
        -   A change detector, **not** an integrity control. Integrity is the
            AEAD tag's job.

    *   -   Randomness
        -   :php:`random_bytes()`
        -   Every DEK and every nonce. No counters, no derived nonces.

.. _security-cryptography-envelope:

Envelope scheme
===============

Each secret carries its own DEK, wrapped by the master key:

#.  A fresh DEK of the algorithm's key length is generated with
    :php:`random_bytes()`.
#.  Two independent nonces of the algorithm's nonce length are generated,
    one for the DEK envelope and one for the value.
#.  The DEK is encrypted under the **master key**, with the secret identifier
    as associated data.
#.  The value is encrypted under the **DEK**, with the same identifier as
    associated data.
#.  A change-detection token is computed (see
    :ref:`security-cryptography-checksum`).
#.  The DEK, the derived MAC key and the plaintext are wiped with
    :php:`sodium_memzero()`.

Decryption reverses it: unwrap the DEK with the master key, then decrypt the
value with the DEK, then wipe the DEK. A failed AEAD tag surfaces as
``Authentication failed - data may have been tampered with`` rather than as a
garbled plaintext.

The practical consequence is that rotating the master key never touches a
secret value: only the DEK layer is re-wrapped
(:php:`EncryptionService::reEncryptDek()`), which is why
:ref:`operations-key-rotation` is an operation on envelopes rather than a
re-encryption of the vault.

.. _security-cryptography-agility:

Algorithm agility
=================

Which algorithm a given envelope uses is **recorded, not re-derived**. That
distinction is the whole point: an envelope written on a host with hardware
AES must still open on a host without it.

..  list-table::
    :header-rows: 1
    :widths: 20 20 60

    *   -   Version
        -   Constant
        -   Algorithm resolution

    *   -   1
        -   ``ENCRYPTION_VERSION_LEGACY``
        -   No marker exists. Derived from host capabilities plus the
            ``preferXChaCha20`` setting, byte-identical to the behaviour that
            existed before markers, so legacy rows keep decrypting exactly as
            before.

    *   -   2
        -   ``ENCRYPTION_VERSION_CURRENT``
        -   The stored ``encryption_algorithm`` marker is authoritative.

New envelopes are always version 2. The marker values —
``xchacha20poly1305`` and ``aes256gcm`` — are persisted per secret and are
byte-for-byte stable: changing one would make every secret carrying the old
string undecryptable.

**The default for new secrets is XChaCha20-Poly1305**, deliberately. It is
available in every libsodium build (AES-256-GCM requires hardware support),
and its 24-byte nonce makes random-nonce collisions a non-concern — so vault
contents stay portable across hosts with differing CPU capabilities. A site
can pin the other algorithm through the ``encryptionAlgorithm`` setting.

**Unknown or unavailable values fail loudly.** An unrecognised marker on a
version-2 row is a hard error, not a guess; an ``encryptionAlgorithm`` setting
naming an unknown or host-unavailable algorithm refuses to encrypt. For a
vault, refusing to encrypt beats encrypting with an algorithm the operator did
not choose, and refusing to decrypt beats silently trying the wrong primitive.

.. _security-cryptography-hkdf:

HKDF usages
===========

Four derivations, each with its own ``info`` string so no two outputs can
collide even though three of them start from the same master key.

..  list-table::
    :header-rows: 1
    :widths: 26 24 24 26

    *   -   Derivation
        -   Input
        -   ``info``
        -   Output

    *   -   Master key, ``typo3`` provider
        -   ``SYS/encryptionKey``
        -   ``nr-vault-master-key``
        -   32 bytes

    *   -   Audit chain HMAC key
        -   Master key
        -   ``nr-vault-audit-hmac-v1``
        -   32 bytes

    *   -   Chain-tip anchor MAC key
        -   Master key
        -   ``nr-vault-audit-anchor-v1``
        -   32 bytes

    *   -   Per-secret checksum MAC key
        -   That secret's DEK
        -   ``nr-vault-checksum``
        -   32 bytes

The audit derivation is what gives the chain cryptographic separation from
encryption key material: an attacker who somehow obtained the audit HMAC key
could forge chain hashes but not decrypt anything, and vice versa.

.. _security-cryptography-checksum:

The change-detection token
==========================

``value_checksum`` is a **keyed MAC over the ciphertext**, never over the
plaintext, with a MAC key derived per secret from that secret's DEK. Two
properties follow, and both were the reason for the design:

*   The stored checksum is not an offline-computable function of the plaintext,
    so it is no guess-confirmation oracle for someone holding the database.
*   Identical plaintexts in different secrets produce different checksums, so
    the column leaks no equality relation between secrets.

It exists to answer "did this value change?" for the audit trail's
``hash_before`` / ``hash_after`` fields. It is not an integrity control and is
not required to open an envelope.

.. _security-cryptography-key-lengths:

Key and nonce lengths
=====================

..  list-table::
    :header-rows: 1
    :widths: 34 22 44

    *   -   Item
        -   Length
        -   Source

    *   -   Master key
        -   32 bytes
        -   Every provider: derived (``typo3``), read and length-checked
            (``file``, ``env``), or unwrapped and length-checked
            (``transit``). A wrong length is rejected, never padded or
            truncated.

    *   -   DEK
        -   32 bytes
        -   ``random_bytes()`` at the algorithm's key length; both supported
            algorithms use 256-bit keys.

    *   -   Nonce, XChaCha20-Poly1305
        -   24 bytes
        -   ``SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES``

    *   -   Nonce, AES-256-GCM
        -   12 bytes
        -   ``SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES``

    *   -   Audit HMAC key
        -   32 bytes
        -   HKDF-SHA256 from the master key

    *   -   Chain-tip anchor MAC key
        -   32 bytes
        -   HKDF-SHA256 from the master key, under a distinct ``info`` string

Nonces are random per operation and never reused across the DEK envelope and
the value envelope — two independent nonces are drawn for every ``encrypt()``
call, and re-wrapping a DEK during master-key rotation draws a fresh one.

.. _security-cryptography-constant-time:

Constant-time comparison
========================

Every comparison of a secret or an integrity tag uses
:php:`hash_equals()`. The comparisons that matter:

*   audit chain verification — both ``previous_hash`` and ``entry_hash``;
*   chain-tip anchor comparison — the anchored tip against the stored row;
*   the transit provider's check of whether a token copy is safe to wipe.

Plain ``!==`` is never used on that class of value. AEAD tag verification is
libsodium's own, and constant-time by construction.

.. _security-cryptography-memory:

Memory scrubbing policy
=======================

:php:`sodium_memzero()` is called on plaintexts, DEKs and derived MAC keys —
on the success path *and* in ``finally`` blocks, so the error paths reachable
through tampered ciphertext do not leak buffers.

Two deliberate exceptions, both documented at the call sites:

*   **The master key is not wiped by the encryption service.** What
    ``getMasterKey()`` returns is the provider's shared request-lifetime cache
    entry. Wiping the local reference would either be a no-op (PHP's
    ``sodium_memzero()`` skips strings with a refcount above one) or corrupt
    the cached key for every later vault operation in the request. The
    provider owns that lifecycle and wipes its slot in
    :php:`clearCachedKey()`. See
    :ref:`adr-020-master-key-request-lifetime-caching`.
*   **A token that came from configuration is not wiped.** It shares its
    string buffer with the configuration singleton, so zeroing it would NUL
    out the stored setting for the rest of the request. Only env-derived
    copies — freshly allocated by ``getenv()`` — are wiped.

..  note::

    Call this **minimised exposure**, not secure deletion. PHP offers no
    guarantee that a string had no other copy before ``sodium_memzero()``
    reached it, and the process may have been swapped or dumped. The policy
    shortens the window; it does not close it. Sensitive parameters are marked
    :php:`#[SensitiveParameter]` so a stack trace does not print them, and
    logs and exception messages carry ``[REDACTED]`` rather than values.

.. _security-cryptography-agility-policy:

Algorithm agility policy
========================

Adding an algorithm means adding an ``EncryptionAlgorithm`` case with a new
stable string value and bumping nothing else: existing rows keep their marker
and keep decrypting. Removing one is a breaking change that requires
re-encrypting every affected secret first, because the marker is what the
decrypt path dispatches on.

The same applies to the audit chain, where the analogous version marker is
``hmac_key_epoch``: epochs are additive, verification dispatches per row, and
a *downgrade* is treated as an attack (see
:ref:`security-audit-evidence-epochs`).

The envelope framing used for portable, off-table storage
(:php:`EnvelopeCodec`) is deliberately tolerant in one direction only: it
ignores unknown fields when reading, and re-wrapping rewrites just the DEK
layer on top of the body as it was read. Rebuilding the body from known
fields would make rotation lossy for an envelope written by a newer version —
irreversibly, once the old key is gone.
