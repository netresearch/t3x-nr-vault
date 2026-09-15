:navigation-title: Backup and restore
.. include:: /Includes.rst.txt

.. _operations-backup-and-restore:

==================
Backup and restore
==================

..  warning::

    A database backup alone cannot be restored into a working vault, and a
    backup of the database together with the key material is a single artefact
    containing everything. Both failure modes are real and they pull in
    opposite directions. **Back up both, store them separately, restore both,
    and verify the restore with a probe decrypt.**

.. _operations-backup-and-restore-what:

What has to be backed up
========================

..  list-table::
    :header-rows: 1
    :widths: 26 30 44

    *   -   Artefact
        -   Where
        -   Notes

    *   -   Secrets and audit chain
        -   ``tx_nrvault_secret``,
            ``tx_nrvault_audit_log``
        -   Ordinary database backup. Ciphertext, wrapped DEKs, nonces,
            algorithm markers, and the full chain including
            ``previous_hash`` / ``entry_hash`` / ``hmac_key_epoch``.

    *   -   Per-secret ACL tiers
        -   ``tx_nrvault_secret_begroups_mm``,
            ``tx_nrvault_secret_writegroups_mm``
        -   **Easily missed, and silent when it is.** The read tier and the
            write tier of every secret live in these two MM tables, not on
            the secret row — ``allowed_groups`` and ``write_groups`` there
            are counts. Restore the secret table without them and every
            secret comes back, the chain verifies, and each member of a
            once-allowed group is refused with ``AccessDeniedException …
            insufficient permissions``.

    *   -   Permission grants
        -   ``be_groups`` (``custom_options``)
        -   The ``tx_nrvault:*`` grants live here. Restoring secrets without
            them leaves nobody able to operate the vault.

    *   -   Registry state
        -   ``sys_registry``, namespaces ``tx_nrvault_audit_anchor`` and
            ``tx_nrvault``
        -   The in-database audit chain-tip anchor
            (:ref:`ADR-034 <adr-034-audit-chain-tip-anchor>`), the
            break-glass session and the per-sink delivery state. Expect to
            re-arm the anchor rather than restore it — see step 7.

    *   -   Scheduler task rows
        -   ``tx_scheduler_task``
        -   The *Vault Audit Integrity Verification*, *Vault Audit Anchor*
            and orphan-cleanup registrations, including the nr-vault columns
            ``nr_vault_retention_days`` and ``nr_vault_table_filter``.
            Without them the restored vault runs unverified and unanchored
            until somebody notices.

    *   -   Master key material
        -   Depends on the provider — see below.
        -   **Separate store, separate credentials, separate retention.**

    *   -   Extension configuration
        -   ``LocalConfiguration.php`` /
            :file:`config/system/settings.php`,
            :file:`additional.php`
        -   The provider choice, the profile, the epoch floor and any pinned
            values. A restore with a different ``auditHmacEpoch`` will report
            an epoch-floor finding.

    *   -   External audit evidence
        -   Anchor file, syslog archive, SIEM retention
        -   Not restorable *into* the vault, but required to prove the
            restored chain is the chain that was backed up.

Key material per provider
-------------------------

..  list-table::
    :header-rows: 1
    :widths: 16 84

    *   -   Provider
        -   What to back up, separately from the database

    *   -   ``typo3``
        -   ``SYS/encryptionKey`` from :file:`config/system/settings.php`.
            **This is the trap.** Most backup jobs already include the config
            directory alongside the database dump, which puts the key and the
            ciphertext in one artefact and negates the encryption. Either
            exclude the config directory from the database backup stream and
            store it separately, or move off this provider.

    *   -   ``file``
        -   The key file named by ``masterKeySource``. Not covered by a
            document-root backup if it lives where it should.

    *   -   ``env``
        -   The value of the variable named by ``masterKeySource``, from
            wherever it is injected. It is not on disk, so nothing backs it up
            implicitly — which means nothing warns you either.

    *   -   ``transit``
        -   The wrapped blob at ``hashicorp.transitWrappedKeyPath``
            **and** the Vault transit key itself (Vault's own backup, or an
            exportable key if your policy allows it). The wrapped blob alone
            is useless if the transit key is gone.

..  note::

    The audit chain is bound to the master key from epoch 1 onwards: the HMAC
    key is derived from it. A restore with the wrong master key therefore
    breaks chain verification as well as decryption — one more reason the two
    artefacts have to travel together in time, even while they are stored
    apart.

.. _operations-backup-and-restore-procedure:

Restore procedure
=================

#.  **Restore the database — the whole table set, in one pass.**

    ..  code-block:: none
        :caption: Every table a restore needs

        tx_nrvault_secret
        tx_nrvault_secret_begroups_mm      <- read tier, easily forgotten
        tx_nrvault_secret_writegroups_mm   <- write tier, easily forgotten
        tx_nrvault_audit_log
        be_groups                          <- the tx_nrvault:* grants
        tx_scheduler_task                  <- verification + anchor schedules
        sys_registry                       <- namespaces tx_nrvault_audit_anchor
                                              and tx_nrvault

    Restore the two MM tables **together with** ``tx_nrvault_secret``: an MM
    row points at a secret uid, so importing them against a secret table
    that was reloaded with different uids silently re-points the tiers. A
    dump that includes the uid column, restored in one transaction, keeps
    them aligned.

#.  **Restore the configuration**, including the provider setting, the
    security profile, ``auditHmacEpoch`` and any pinned values in
    :file:`additional.php`.

#.  **Restore the key material** to the location the configuration expects,
    with the right ownership and mode — ``0400`` for a ``file`` key, ``0600``
    for a ``transit`` wrapped blob. For ``env``, re-inject the variable and
    restart the process so it is actually in the environment.

#.  **Confirm the provider resolves before touching secrets.**

    ..  code-block:: bash

        vendor/bin/typo3 vault:doctor --format=json

    On a hardened target, gate on the profile explicitly:

    ..  code-block:: bash

        vendor/bin/typo3 vault:doctor --profile=hardened

#.  **Probe-decrypt.** See below. A restore is not verified until a real
    secret has come back as plaintext.

#.  **Check the ACL back, with a non-admin account.** An administrator
    passes the per-secret tiers by the admin bypass, so a reveal as
    administrator proves nothing about them. Log in as a member of a group
    that held a read tier — or run the reveal through a technical actor
    bound to that group — and confirm the secret still opens. This is the
    one step no command performs for you; see the note below.

#.  **Verify the audit chain and compare it against the external anchor.**

    ..  code-block:: bash

        vendor/bin/typo3 vault:audit-verify

#.  **Re-anchor — both anchors.** A point-in-time restore rolls the audit
    table back, so the external baseline is stale *and* the in-database tip
    anchor now names a row the restored table no longer has, which reports as
    ``VIOLATED``.

    ..  code-block:: bash

        # External baseline
        vendor/bin/typo3 vault:audit-anchor

        # In-database anchor. Verify FIRST that the violation is explained by
        # the restore you just performed — clearing the anchor discards the
        # very evidence that would show a truncation, so never run this to
        # make a finding go away.
        vendor/bin/typo3 vault:audit --verify
        vendor/bin/typo3 vault:audit --reset-anchor

    ..  note::

        ``vault:audit-anchor`` and ``--reset-anchor`` assert
        ``vault.configure``; ``--verify`` asserts ``audit.view``. Both
        permissions are excluded by
        :confval:`ext-nrvault-cliAllowedOperations`, so on the CLI these steps
        need ``allowCliAccess = 1`` **and** the operation in the allowlist, or
        a named technical actor. Restoring the allowlist to its previous value
        is part of finishing the restore.

..  warning::

    Do not run a restored production database against a *fresh* master key in
    the hope that the vault will re-key itself. It will not. Envelopes are
    bound to the key that wrapped their DEKs; the only path from one key to
    another is :ref:`operations-key-rotation`, which needs **both** keys.

.. _operations-backup-and-restore-verification:

Restore verification: the probe decrypt
=======================================

Listing secrets proves nothing — the list reads metadata and never touches the
master key. Verification means decrypting.

..  code-block:: bash
    :caption: Minimal probe

    # 1. Metadata is readable (proves the database restore, not the key).
    vendor/bin/typo3 vault:list

    # 2. Plaintext comes back (proves the key restore).
    vendor/bin/typo3 vault:retrieve <a-known-identifier>

..  note::

    ``vault:retrieve`` needs **two** things on the CLI, both off by default:
    ``allowCliAccess = 1``, and ``secret.reveal`` present in
    :confval:`ext-nrvault-cliAllowedOperations`, which excludes it. Enable both
    for the verification and revert afterwards, or — simpler and with nothing
    to revert — perform the probe through a reveal in the backend module
    instead. A reveal exercises exactly the same decrypt path.

Probe **more than one secret**, and pick them deliberately: at least one
written recently (encryption version 2, with an algorithm marker) and, if the
installation has any, one legacy secret (version 1, algorithm derived from host
capabilities). Those two take different branches through
:php:`EncryptionService::resolveAlgorithm()`, and a host that lacks hardware
AES will fail the second while passing the first.

Every probe writes an audit row, which is the intended side effect: the
restore verification leaves its own evidence.

..  warning::

    ``vault:doctor`` does not establish that a restore is COMPLETE, and no
    command in the current release does. Its controls cover the master-key
    provider, the security profile, CLI access and the audit chain; none of
    them reads ``tx_nrvault_secret`` or the two MM tables. A restore that
    brought back no secrets at all, or every secret without its ACL tiers,
    therefore passes ``provider.available`` and
    ``provider.master_key_readable`` exactly like a complete one.

    The audit table is the one exception: a chain shorter than the published
    anchor is reported — as ``TABLE_RESET`` by ``vault:audit-verify``, and by
    the ``audit.anchor`` control where an external anchor exists. Missing
    secrets and missing group tiers have no equivalent.

    Completeness is the operator's own step. Compare row counts against the
    source database — ``tx_nrvault_secret`` and both MM tables — and treat the
    probe decrypt and the non-admin ACL check above as part of the procedure
    rather than as optional extras.

.. _operations-backup-and-restore-symptoms:

Wrong-key symptoms
==================

..  list-table::
    :header-rows: 1
    :widths: 42 58

    *   -   Symptom
        -   Most likely cause

    *   -   ``Authentication failed - data may have been tampered with``
        -   The classic wrong-master-key signature. The AEAD tag on the DEK
            envelope did not verify. The ciphertext is almost certainly fine;
            the key is not the one that wrapped it.

    *   -   A reveal returns *Decryption failed* (HTTP 500) while the list
            renders normally
        -   Same cause seen from the backend module: metadata does not need the
            master key, plaintext does.

    *   -   ``Master key not found at: <path>``, or the same with
            ``(not readable)`` appended, or
            ``Environment variable "…" for master key is not set``
        -   The key material was not restored, or not to the path or variable
            the configuration names, or not with permissions the PHP user has.

    *   -   ``Invalid master key length: expected 32 bytes, got …``
        -   A truncated or re-encoded key file — a text editor added or
            stripped bytes, or a base64 value was decoded twice. The provider
            refuses rather than padding.

    *   -   ``Unknown encryption algorithm marker`` for a version-2 row
        -   The row was written by a newer version, or the marker column was
            not restored faithfully.

    *   -   ``Encryption algorithm "aes256gcm" is not available on this host``
        -   Secrets were encrypted on a host with hardware AES and restored
            onto one without. Not a key problem: restore onto a capable host,
            or re-encrypt onto XChaCha20-Poly1305 there first.

    *   -   Everything decrypts, but ``vault:audit-verify`` reports
            ``HASH_MISMATCH`` on every row from a certain uid onwards
        -   Not a key problem either — see the next section.

..  warning::

    If a probe decrypt fails, **stop**. Do not rotate, do not re-initialise,
    do not run ``vault:init`` against the restored database in the hope of
    repairing it. Generating a new master key over a restored vault destroys
    the only thing that could still open it. Fix the key restore first.

.. _operations-backup-and-restore-chain:

Audit-chain consistency after a restore
=======================================

A restore is one of the few legitimate ways to produce findings that otherwise
mean tampering. Expect and interpret them:

*   **``HASH_MISMATCH`` from a given uid onwards** — the audit table and the
    master key came from different points in time, or the table was restored
    partially. The chain is bound to the key from epoch 1 up.

*   **``UID_GAP``** — rows were lost between the last backup and the restore
    point, or the dump excluded rows. A genuine restore artefact; document it
    with the backup timestamps rather than dismissing it.

*   **``TABLE_RESET``** — the restored chain is shorter than the last published
    anchor, or the row at the anchored sequence hashes differently. **This is
    the expected finding after restoring to an earlier point in time**, and it
    is also exactly what a malicious reset looks like. The only thing that
    distinguishes them is your own record of the restore. Write it down: which
    backup, taken when, restored when, by whom — and keep the pre-restore
    anchor file alongside it.

*   **``EPOCH_DOWNGRADE``** — usually a configuration mismatch: the restored
    ``auditHmacEpoch`` is higher than the epoch the restored rows carry.
    Restore the configuration that matches the data, then migrate forward with
    ``vault:audit-migrate-hmac`` if you want the higher epoch.

*   **``NO_EXTERNAL_SINK``** (hardened only) — sinks were not re-enabled, or the
    anchor file was not restored. Re-enable and re-anchor.

Always re-anchor after a restore, and keep the old anchor file. The old anchor
is what proves the restore happened when you say it did; the new one is what
gives the next verification a usable baseline.
