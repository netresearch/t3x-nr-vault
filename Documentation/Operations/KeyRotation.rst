:navigation-title: Key rotation
.. include:: /Includes.rst.txt

.. _operations-key-rotation:

============
Key rotation
============

Rotating the master key re-wraps every DEK under a new key. Secret *values*
are never re-encrypted and never materialise as plaintext — only the DEK layer
changes (:ref:`security-cryptography-envelope`), which is what makes the
operation affordable at all.

It is also the most powerful operation in the extension: it rewrites every
envelope and rekeys the audit chain in one transaction. It carries its own
permission, ``master_key.rotate``.

..  warning::

    **The command does not install the new key for you.** It re-wraps
    everything under the key you hand it and then tells you to update the
    configuration. Between the commit and that configuration change, secrets
    cannot be decrypted. Plan for that window — see
    :ref:`operations-key-rotation-window`.

.. _operations-key-rotation-when:

When to rotate
==============

*   After any suspected exposure of the key material, or of a host that could
    read it.
*   After personnel with filesystem or KMS access leave.
*   On a schedule — annually is a common policy.
*   When moving between providers, for example off ``typo3`` as part of
    :ref:`security-profiles-migration`.

Rotating the *master key* is not the same as rotating a *secret*. If a single
credential leaked, rotate that credential and use ``vault:rotate``; a master
key rotation changes nothing about a leaked credential value.

.. _operations-key-rotation-command:

The command
===========

..  code-block:: bash

    vendor/bin/typo3 vault:rotate-master-key \
        --old-key=/path/to/old.key \
        --new-key=/path/to/new.key \
        [--dry-run] [--confirm]

..  list-table::
    :header-rows: 1
    :widths: 20 80

    *   -   Option
        -   Meaning

    *   -   ``--old-key``
        -   Path to a **file** containing the old master key. Omitted: the
            currently configured provider's key is used.

    *   -   ``--new-key``
        -   Path to a **file** containing the new master key. Omitted: the
            currently configured provider's key is used — which, with
            ``--old-key`` also omitted, means both are identical and the
            command refuses.

    *   -   ``--dry-run``
        -   Inventory, confirmation and the old-key smoke test run; the
            re-encryption does not. No changes are made.

    *   -   ``--confirm``
        -   Required for an actual run. Without it (and without
            ``--dry-run``) the command aborts rather than asking.

Both keys are read from files, not from the command line, so they do not land
in shell history or a process listing. Both copies are wiped with
:php:`sodium_memzero()` when the command returns.

.. _operations-key-rotation-preflight:

Preflight
=========

The command performs these checks itself, in this order, and each one aborts:

#.  **Permission.** ``master_key.rotate`` must be granted. On CLI without a
    backend user that means ``allowCliAccess = 1`` **and** ``master_key.rotate``
    listed in :confval:`ext-nrvault-cliAllowedOperations`, which excludes it by
    default; as a backend user it means the admin override or an explicit group
    grant.
#.  **Keys must differ.** Compared with :php:`hash_equals()`. Identical keys
    are refused as *"Nothing to rotate."*
#.  **Inventory.** Vault secrets are counted, and so are consumer-owned
    foreign envelopes registered by other extensions
    (:ref:`adr-033-foreign-envelope-rotation`) — a vault with no secrets of
    its own may still be the key authority for thousands of them. If both
    counts are zero the command stops with a warning.
#.  **Confirmation.** ``--confirm`` for a real run.
#.  **Old-key smoke test.** One real secret is re-encrypted to prove the
    supplied old key is actually the one that wrapped the envelopes. This is
    the check that turns "wrong key" from a half-rotated vault into a clean
    abort.

    ..  note::

        With no vault secrets of its own the smoke test cannot run, and the
        command says so. A wrong key then surfaces as a failure of the
        consumer-envelope pass, which rolls the rotation back — a lost early
        warning, not a lost safety net.

Your own preflight, before running any of it:

*   [ ] **A verified backup of the database and of the current key material.**
      If the rotation fails in a way the transaction cannot undo, this is the
      only way back. See :ref:`operations-backup-and-restore`.
*   [ ] **The new key exists, is 32 bytes, and is stored where the provider
      will read it after the switch.**
*   [ ] **The audit chain verifies now.** Rotating over an already-broken
      chain destroys your ability to tell the two problems apart:

      ..  code-block:: bash

          vendor/bin/typo3 vault:audit-verify

*   [ ] **A maintenance window.** Vault reads fail between the commit and the
      configuration switch.
*   [ ] **``vault:doctor`` is clean**, so a pre-existing misconfiguration does
      not surface mid-rotation.

.. _operations-key-rotation-dryrun:

Dry run
=======

Always run this first:

..  code-block:: bash

    vendor/bin/typo3 vault:rotate-master-key \
        --old-key=/path/to/old.key --new-key=/path/to/new.key --dry-run

The dry run is genuinely useful rather than cosmetic, because the old-key
smoke test happens **before** the short-circuit: a dry run that succeeds has
proved that the old key opens a real envelope. It reports the number of
secrets and foreign envelopes that would be re-wrapped and makes no changes.

A dry run that fails the smoke test means the old key is wrong. Fix that
before going further; do not proceed with ``--confirm`` hoping the real run
behaves differently.

.. _operations-key-rotation-execution:

What the real run does
======================

Everything below happens inside **one database transaction**, and any failure
rolls back secrets, audit events and the chain rewrite together.

#.  A ``master_key_rotate_start`` audit row is written under the pseudo
    identifier ``__master_key__``.
#.  Every secret's DEK is unwrapped with the old key and re-wrapped with the
    new one, with a fresh nonce. Values, value nonces and the
    version/algorithm markers are untouched.
#.  Registered foreign envelopes are re-wrapped the same way.
#.  The audit advisory lock is taken for the remainder of the transaction, so
    no concurrent writer can chain onto a tip hash that is about to be
    rewritten.
#.  The ``audit_chain_rekey`` and successful ``master_key_rotate_end`` rows
    are appended — still sealed with the old, provider-derived HMAC key.
#.  **The whole audit chain is rewritten** under the HMAC key derived from the
    new master key, including the two rows just appended, so the committed
    chain verifies under the new key from first row to last with no old-keyed
    tail.
#.  Commit, then :php:`MasterKeyRotatedEvent` is dispatched.

Two properties of the rekey worth knowing:

*   **Per-row epochs are preserved.** Re-keying changes the key, never the
    payload format. An epoch-2 row stays epoch 2.
*   **An all-epoch-0 chain passes through untouched.** Keyless SHA-256 hashes
    do not depend on the master key, so rows are only updated when their
    hashes actually change.

.. _operations-key-rotation-window:

The configuration switch — and the window
=========================================

On success the command prints its next steps, and they are not advisory:

#.  **Update the configuration to use the new master key immediately.** Until
    then, secrets cannot be decrypted *and* audit-chain verification runs
    against the old key. Depending on the provider: replace the key file
    (``file``), re-inject the environment variable and restart (``env``), or
    re-wrap the new key with the KMS (``transit``).
#.  **Securely archive or destroy the old key.** Archive it if you may still
    need to open an older backup; destroy it if you may not. Do not leave it
    where the vault could pick it up again.
#.  **Test retrieval and verify the chain** — see below.
#.  **Re-seal any rows written in the gap.** Audit rows written between the
    rotation commit and the configuration switch are sealed with the old
    HMAC key while the rest of the chain is under the new one. Re-seal them
    with ``vault:audit-migrate-hmac``.

That fourth step is the reason to keep the window short and to make it a
maintenance window: every audited operation during the gap adds a row that
will need re-sealing.

.. _operations-key-rotation-verification:

Verification
============

..  code-block:: bash

    # 1. The provider resolves and the configuration is coherent.
    vendor/bin/typo3 vault:doctor --format=json

    # 2. Plaintext comes back — the real proof. On the CLI this needs
    #    allowCliAccess = 1 AND secret.reveal in cliAllowedOperations;
    #    a reveal in the backend module proves the same decrypt path.
    vendor/bin/typo3 vault:retrieve <a-known-identifier>

    # 3. The chain verifies under the new key, end to end.
    vendor/bin/typo3 vault:audit-verify

    # 4. Anchor the new tip; the old anchor's baseline is now stale.
    vendor/bin/typo3 vault:audit-anchor

    # 5. The in-database anchor is re-sealed by the rotation itself. Confirm
    #    it reads "Tip anchor: ok" — a re-key that left it UNREADABLE means
    #    the re-seal did not complete, and that is a finding, not a nuisance.
    #    Needs vault.configure: on the CLI that is allowCliAccess = 1 AND
    #    vault.configure in cliAllowedOperations, or a named technical actor.
    vendor/bin/typo3 vault:audit --verify

Probe at least two secrets, and pick them from different encryption versions
if the installation has both — see
:ref:`operations-backup-and-restore-verification` for why.

..  note::

    Re-anchoring after a rotation is not optional. The rewritten chain has new
    hashes throughout, so an anchor taken before the rotation will now report
    ``TABLE_RESET`` against it. Publish a fresh anchor, and keep the old one
    with your rotation record so the finding is explainable rather than
    alarming.

.. _operations-key-rotation-failure:

If it fails
===========

*   **Aborted during preflight** — nothing changed. Fix and retry.
*   **Rolled back** — the transaction reverted secrets, the appended events
    and the chain rewrite together. A ``master_key_rotate_end`` row with
    ``success = 0`` and the reason *"Unexpected error during rotation;
    transaction rolled back"* records the attempt. The old key is still the
    right one; do **not** switch the configuration.
*   **Committed but the configuration was never switched** — secrets stay
    undecryptable and verification uses the wrong key. Complete the switch;
    this is a half-finished rotation, not a failed one.
*   **Committed, configuration switched, and reads still fail** — the key you
    installed is not the ``--new-key`` you rotated to. Install the correct
    one. Do not rotate again to "fix" it: a second rotation from the wrong old
    key will fail its smoke test, which is the safety net working.

..  warning::

    Never run ``vault:init`` to recover from a failed rotation. It generates a
    fresh master key, and a fresh key over a rotated vault makes every secret
    unreadable — the command's own ``--force`` warning says as much.

.. _operations-key-rotation-transit:

Transit key rotation is a different operation
=============================================

With the ``transit`` provider there are **two independent rotations**, and
confusing them is a common mistake.

..  list-table::
    :header-rows: 1
    :widths: 26 74

    *   -   Operation
        -   Effect

    *   -   ``vault:rotate-master-key``
        -   Changes the nr-vault **master key**: every DEK is re-wrapped and
            the audit chain is rekeyed. Installing the new key afterwards means
            wrapping it with Vault and replacing the local blob — the command
            does not do that for you. This is what the rest of this page
            describes.

    *   -   ``vault write -f transit/keys/<name>/rotate``
        -   Rotates the **Vault transit key**. New ciphertexts are wrapped
            under the new transit key version; existing ciphertexts stay
            decryptable under their recorded version. **The nr-vault master
            key does not change**, so no DEK is re-wrapped, the audit chain is
            untouched, and no secret is affected.

So: rotating the transit key is a KMS hygiene operation with no vault
downtime and no re-encryption. Rotating the master key is the operation that
touches every envelope. Do the first freely; schedule the second.

To re-wrap the existing master key under the newest transit key version
without changing the master key itself, use Vault's ``rewrap`` endpoint on the
stored ciphertext and replace the local blob — again with no effect on any
secret. Keep the file mode at ``0600`` and write it atomically, as the
provider itself does.
