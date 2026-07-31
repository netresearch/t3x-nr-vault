.. include:: /Includes.rst.txt

.. _operations:

==========
Operations
==========

Running nr-vault in production: deploying the hardened profile, holding key
material, backing it up, rotating it, watching the audit pipeline, responding
to incidents, and shutting the vault down again.

These pages assume the concepts from :ref:`security`. Per-setting reference is
in :ref:`configuration`; per-command reference in
:ref:`developer-commands`.

.. toctree::
   :maxdepth: 2

   HardenedDeployment
   KeyCustody
   BackupAndRestore
   KeyRotation
   MonitoringAndAlerting
   IncidentResponse
   Decommissioning

.. _operations-start-here:

Start here
==========

..  list-table::
    :header-rows: 1
    :widths: 34 66

    *   -   If you are …
        -   Read

    *   -   deploying a vault that holds production credentials
        -   :ref:`operations-hardened-deployment`, then
            :ref:`operations-key-custody`

    *   -   converting an existing standard installation
        -   :ref:`security-profiles-migration` — the order matters, because
            the key has to move before the profile does

    *   -   setting up backups
        -   :ref:`operations-backup-and-restore`. The database alone is not a
            backup, and the database plus the key in one artefact is not a
            protection

    *   -   wiring monitoring
        -   :ref:`operations-monitoring-and-alerting`. Anchoring and
            verification are two different jobs and you need both

    *   -   handling an incident
        -   :ref:`operations-incident-response` — read the runbook before
            executing step 1; several useful actions destroy evidence

    *   -   retiring the installation
        -   :ref:`operations-decommissioning`. Note that ``vault:delete`` is a
            soft delete

.. _operations-non-negotiables:

The four things that actually matter
====================================

Everything else on these pages is detail around these.

#.  **The master key is not in the database — keep it that way in backups
    too.** A dump taken together with the key material is a single artefact
    containing everything. This is easiest to get wrong with the ``typo3``
    provider, where the key lives in :file:`config/system/settings.php`.

#.  **Master key loss is data loss.** There is no escrow and no reset. Back it
    up separately, and verify the backup by restoring it somewhere and
    decrypting something.

#.  **The audit chain needs an external anchor to be worth anything against a
    database writer.** The chain detects row edits; only an anchor published
    outside the database detects a wholesale reset — and only if it is stored
    somewhere the attacker cannot truncate.

#.  **A scheduled check whose failures nobody receives is not a control.**
    Schedule anchoring and verification, then wire the alerts, then break the
    delivery on purpose once to confirm the alert arrives.
