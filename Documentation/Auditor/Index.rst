.. include:: /Includes.rst.txt

.. _auditor:

=======
Auditor
=======

Material for a security assessment, a certification audit, or an internal
review of an nr-vault deployment: what is in scope, which controls exist and
where they are implemented, which artefacts to collect, and how to demonstrate
that a control works rather than merely that it is configured.

.. toctree::
   :maxdepth: 2

   TargetOfEvaluation
   ControlMapping
   EvidenceCollection
   VerificationProcedures

.. _auditor-how-to-use:

How to use this section
=======================

..  list-table::
    :header-rows: 1
    :widths: 34 66

    *   -   Page
        -   Purpose

    *   -   :ref:`auditor-target-of-evaluation`
        -   Scope the engagement. **Read this first** — it states what nr-vault
            is not, and which controls an assessor would expect to find that
            are correctly somebody else's.

    *   -   :ref:`auditor-control-mapping`
        -   Implemented controls mapped to BSI IT-Grundschutz modules and OWASP
            ASVS chapters, with an implementation pointer and an evidence
            source per row. Includes a list of **declared gaps**.

    *   -   :ref:`auditor-evidence-collection`
        -   The read-only commands to run and the artefacts to keep. Safe on
            production.

    *   -   :ref:`auditor-verification-procedures`
        -   Reproducible procedures with expected results. Several are marked
            **STAGING-ONLY** because they deliberately misconfigure the vault
            or manipulate the audit table.

.. _auditor-reading-order:

The three things worth checking first
=====================================

If time is short, these three findings are the ones that most often change the
conclusion:

#.  **Is the hardened profile actually enforced, or just configured?**
    ``vault:break-glass --status`` reports
    ``adminOverrideDisabledEffective``. A raw ``disableAdminOverride = 1`` with
    an effective ``no`` means the profile is ``standard`` and the flag is
    inert — a common and consequential mismatch.
    (:ref:`auditor-verify-admin-override`)

#.  **Does independent evidence exist?** ``vault:audit-verify`` reporting
    ``NO_EXTERNAL_SINK``, or an anchor file stored only on the host whose
    database it protects, means a full audit-table reset would be
    undetectable — regardless of how sound the hash chain is.
    (:ref:`auditor-evidence-chain`)

#.  **Which master-key provider is in use?** With ``typo3``, anyone who can
    read :file:`config/system/settings.php` can derive the master key, and most
    backup jobs already include that file alongside the database dump.
    (:ref:`security-known-limitations-typo3-provider`)

.. _auditor-honesty:

On claims
=========

The documentation for this extension deliberately avoids "tamper-proof",
"military-grade" and "secure deletion". The corresponding accurate terms are
**tamper-evident** (detection, not prevention), **authenticated encryption with
256-bit keys**, and **minimised exposure** (a shortened window, not cleared
memory).

If an assessment encounters a stronger claim about nr-vault — in a proposal, a
datasheet, or a conversation — :ref:`security-known-limitations` is the page
that contradicts it, and it is maintained as part of the codebase rather than
as marketing copy.
