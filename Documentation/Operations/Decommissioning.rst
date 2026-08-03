:navigation-title: Decommissioning
.. include:: /Includes.rst.txt

.. _operations-decommissioning:

===============
Decommissioning
===============

Retiring a vault, or an installation that contains one. The order matters, and
one step is irreversible by design.

.. _operations-decommissioning-secrets:

Secret disposal
===============

..  warning::

    **``vault:delete`` is a soft delete.** :php:`SecretRepository::delete()`
    sets ``deleted = 1`` and updates ``tstamp``; the row — with its ciphertext,
    its wrapped DEK and its nonces — stays in ``tx_nrvault_secret``. The same
    is true of ``vault:cleanup-orphans``, which routes through the same
    :php:`VaultService::delete()`.

    There is no hard-delete path in the extension. Do not read "deleted" as
    "gone".

That is the right default for a live system: it keeps the operation auditable,
and the row is unreadable to anyone without the master key anyway. It does
**not** make the delete reversible. The vault has no restore operation, and
the backend refuses TYPO3's ``undelete`` command on ``tx_nrvault_secret`` — a
restore would hand back the ciphertext, the wrapped DEK, ``frontend_accessible``
and both ACL tiers with no vault check at all, and nothing in the audit chain
would say it happened. Recovering a deleted secret means acting on the database
directly, deliberately and visibly. See
:ref:`usage-record-operations-refused`.

The soft delete is the wrong assumption when decommissioning. For actual
disposal you have two options, and they compose:

**Crypto-erasure (recommended).** Destroy the master key and every secret in
the vault becomes permanently unreadable in one step — including soft-deleted
rows, including rows in every backup already taken. This is the only measure
that reaches copies you no longer control. See
:ref:`operations-decommissioning-keys`.

**Row removal (for completeness).** Drop or truncate the tables at the
database level once the audit-retention obligations below are satisfied:

..  code-block:: sql
    :caption: Only after the evidence export is complete and verified

    -- Secrets, including soft-deleted rows, and their two ACL relation
    -- tables. Dropping only the secret table leaves the MM rows behind.
    DROP TABLE tx_nrvault_secret;
    DROP TABLE tx_nrvault_secret_begroups_mm;
    DROP TABLE tx_nrvault_secret_writegroups_mm;
    -- Audit chain. Check your retention obligations FIRST.
    DROP TABLE tx_nrvault_audit_log;

    -- Vault state also lives in the core registry: the chain tip anchor,
    -- and the break-glass session plus per-sink delivery state.
    DELETE FROM sys_registry WHERE entry_namespace = 'tx_nrvault_audit_anchor';
    DELETE FROM sys_registry WHERE entry_namespace = 'tx_nrvault';

..  note::

    Row removal on its own is weaker than it looks: database backups,
    replicas, binlogs, filesystem snapshots and storage-level copies keep the
    ciphertext for as long as their own retention allows. Crypto-erasure is
    what makes those copies worthless. Do both if the policy demands it; do
    crypto-erasure if you can only do one.

.. _operations-decommissioning-rotate-out:

Rotate credentials out, do not just delete them
===============================================

A secret in the vault is a *copy* of a credential that also exists in the
system it authenticates against. Deleting the vault copy does not revoke
anything.

Before disposal, for every secret still in use: rotate the credential at its
origin — the API provider, the SMTP relay, the OAuth client, the deploy key —
so that the value the vault held stops working. Then dispose of the vault
copy. In that order: a rotation performed after the vault is gone has to be
done without the ability to read what is being replaced.

.. _operations-decommissioning-evidence:

Final evidence export
=====================

Do this **before** anything destructive. Once the master key is gone, the
audit chain can no longer be verified — the HMAC key was derived from it — so
a verification run after key destruction proves nothing.

#.  **Verify the chain while the key still exists**, and keep the output:

    ..  code-block:: bash

        vendor/bin/typo3 vault:audit-verify > decommission-verify.txt

#.  **Publish a final anchor**, so the tip is witnessed externally at the
    moment of decommissioning:

    ..  code-block:: bash

        vendor/bin/typo3 vault:audit-anchor

    ..  note::

        Both commands assert an operation permission (breaking change; they
        previously asserted none): ``vault:audit-verify`` needs ``audit.view``,
        ``vault:audit-anchor`` needs ``vault.configure``, and the export in the
        next step needs ``audit.export``. All three are excluded from the
        :confval:`ext-nrvault-cliAllowedOperations` default, so from a shell
        they need ``allowCliAccess = 1`` **and** the operation in that
        allowlist — or, better for an evidence run, a named technical actor, so
        the record names who collected the evidence. Sort the grant out before
        the decommissioning window: after the master key is destroyed there is
        no second chance at this output.

#.  **Export the audit log** in full, over the entire retained period, with
    the hash columns included — ``uid``, ``previous_hash``, ``entry_hash``,
    ``hmac_key_epoch``. Without them the export is a log, not evidence.

#.  **Collect the external evidence** from where it actually lives: the anchor
    file, the syslog archive, the SIEM's retained records. This is the half
    the installation cannot fabricate, and after decommissioning it is the
    only half left.

#.  **Record the decommissioning itself** — date, operator, which artefacts
    were exported, which tables were dropped, when and how the key was
    destroyed. A ``TABLE_RESET`` finding against the final anchor is
    indistinguishable from a malicious reset without this record.

:ref:`auditor-evidence-collection` lists the artefacts in the form an assessor
expects.

.. _operations-decommissioning-retention:

Retention obligations versus deletion
=====================================

These pull in opposite directions and nr-vault cannot resolve the conflict for
you — it can only make sure you notice it.

*   **The secrets are the deletion obligation.** Credentials have no reason to
    outlive the system that used them, and a retained ciphertext is a retained
    risk for as long as any copy of the key might exist.

*   **The audit log is the retention obligation.** It is the record of who
    accessed which credential and when — frequently the artefact an audit
    regime requires to be kept, and often for years. It contains no secret
    values.

**They are separable, and separating them is the answer.** Destroy the key and
drop ``tx_nrvault_secret``; keep the exported audit evidence for as long as
policy requires. The exported chain remains internally verifiable — each row's
``previous_hash`` still links to its predecessor — but note honestly what is
lost: **without the master key, HMAC recomputation is no longer possible**, so
from epoch 1 upwards the export becomes a *sequence* whose links can be
inspected rather than a chain whose authenticity can be re-proved. That is why
the verification output from step 1 above matters: it is the last point at
which authenticity was demonstrable, and it must be captured then, not later.

..  note::

    ``tx_nrvault_audit_log`` also holds personal data — ``actor_username``,
    ``ip_address``, ``user_agent``. A deletion request under data-protection
    law collides with the tamper-evident design: editing or removing a row
    breaks the chain by construction, which is the entire point.
    :ref:`adr-017-audit-metadata-retention` is where that trade-off is
    recorded; resolve it as a policy decision before decommissioning, not
    during.

.. _operations-decommissioning-keys:

Key destruction
===============

Irreversible. There is no escrow and no vendor-side reset — see
:ref:`security-known-limitations-key-loss`.

..  list-table::
    :header-rows: 1
    :widths: 16 84

    *   -   Provider
        -   How to destroy the key

    *   -   ``typo3``
        -   Rotate or remove ``SYS/encryptionKey`` in
            :file:`config/system/settings.php`, and destroy every backup of
            that file. **Harder than it sounds** — the config directory is
            usually in more backups than anyone expects, and ``encryptionKey``
            is also used by TYPO3 core for unrelated purposes, so removing it
            has effects beyond the vault.

    *   -   ``file``
        -   Delete the key file and every copy, including the separate key
            backup. On a copy-on-write filesystem or a storage layer with
            snapshots, deletion is not erasure — destroy the snapshots too.

    *   -   ``env``
        -   Remove the variable from the injection mechanism and restart. Then
            check where it was *also* recorded: CI secret stores, deployment
            manifests, container inspection output, shell history.

    *   -   ``transit``
        -   **The cleanest case.** Delete the transit key in HashiCorp Vault
            (or revoke every policy granting ``decrypt`` on it) and the
            locally stored wrapped blob becomes undecryptable immediately —
            including in every backup that contains it. Then delete the
            wrapped file as well.

#.  Confirm the evidence export is complete and stored elsewhere.
#.  Confirm no other installation shares the key material. A key file copied
    to a staging system is still a live key.
#.  Destroy the key.
#.  Verify destruction by attempting a read: a probe decrypt must now fail
    with ``Master key not found at: …`` or
    ``Authentication failed - data may have been tampered with``. A successful
    read means a copy survived somewhere — find it.
#.  Drop the tables, if row removal is also required.

.. _operations-decommissioning-cleanup:

Installation cleanup
====================

*   **Remove the sinks** last, not first: they are what records the
    decommissioning steps. Turn off ``auditSinkWebhookEnabled`` and friends
    only after the final anchor has been published.
*   **Unschedule the tasks** — the audit anchor and audit verify scheduler
    tasks, and orphan cleanup — or they will start failing loudly against a
    vault that no longer exists.
*   **Revoke the grants.** Remove the ``tx_nrvault:*`` custom options from
    ``be_groups``, so a later reinstall does not silently inherit a permission
    model nobody reviewed.
*   **Unpin the settings.** Remove the
    :php:`$GLOBALS['TYPO3_CONF_VARS']['SYS']['nrVault']` entries from
    :file:`config/system/additional.php`, and the extension configuration
    block itself from :file:`config/system/settings.php` — the pins are only
    the part that lives in ``additional.php``.
*   **Remove the extension**, and remember that removing it does not remove
    its tables.
*   **Clean up the KMS side** if ``transit`` was used: revoke the token, remove
    the policy, delete the transit key.
