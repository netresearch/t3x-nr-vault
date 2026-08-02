:navigation-title: Security profiles
.. include:: /Includes.rst.txt

.. _security-profiles:

=================
Security profiles
=================

nr-vault has two operating profiles. A profile is **one internally consistent
policy, not a bag of independent toggles** — which is why some settings are
inert outside the profile they belong to, and why the profile is enforced in
code (provider selection, access control, audit anchoring) rather than in
prose.

..  code-block:: none
    :caption: Extension configuration

    securityProfile = standard   # or: hardened

An unknown value is refused with exception code ``1753900001`` and the message
*"Refusing to fall back to a weaker profile."* There is no permissive default
for a typo.

.. _security-profiles-standard:

Standard
========

Secure defaults with zero-configuration TYPO3 integration. Envelope
encryption, the full permission model, the tamper-evident audit chain and
the reveal lifecycle are all active — this is not a "off" setting.

What it deliberately allows: the ``typo3`` master-key provider, provider
auto-detection when the configured provider is unavailable, copy-to-clipboard
on reveal, the unconditional administrator override, and external audit sinks
as opt-in.

Choose it when TYPO3 administrators are already trusted with production
credentials, and the vault's job is to stop plaintext sitting in database
columns and configuration files.

.. _security-profiles-hardened:

Hardened
========

Fail-closed and audit-ready. The premise is different: "TYPO3 administrator"
and "may read production credentials" are separate roles, and every plaintext
access must be attributable to a *granted permission* rather than to a role.

A misconfigured hardened vault stops. It never silently continues on weaker
key material — that is the contract, and choosing the profile is the explicit
statement that it has been read.

.. _security-profiles-differences:

Exact technical differences
===========================

..  list-table::
    :header-rows: 1
    :widths: 20 40 40

    *   -   Aspect
        -   ``standard``
        -   ``hardened``

    *   -   Master-key provider policy
        -   ``typo3``, ``file`` and ``env`` all permitted.
        -   ``typo3`` is **rejected** with exception code ``1753900002``. An
            explicit external provider is required.

    *   -   Provider fallback
        -   :php:`getAvailableProvider()` auto-detects: configured provider
            first, then ``typo3``, then ``env``, then ``file``.
            :php:`ConfigurationException` is swallowed to reach the fallback
            chain.
        -   **No auto-detection and no fallback.** The explicitly configured
            provider is returned even when it is unavailable — its
            ``getMasterKey()`` then fails loudly — and configuration errors
            propagate.

    *   -   Copy to clipboard on reveal
        -   Allowed; the reveal response reports
            ``copyAllowed = true``.
        -   Disabled; the response reports ``copyAllowed = false`` and no copy
            button is offered. The clipboard outlives the dialog and cannot be
            cleared reliably.

    *   -   Administrator override
        -   Always active. ``disableAdminOverride`` is **inert** — a lockout
            guard, see below.
        -   ``disableAdminOverride = 1`` withdraws the bypass everywhere at
            once. Full power is then reachable only inside a break-glass
            window.

    *   -   External audit sink
        -   Opt-in. No sink is no finding.
        -   Required. No enabled and usable sink, or no readable chain-tip
            anchor, is reported as ``NO_EXTERNAL_SINK`` by
            ``vault:audit-verify``.

    *   -   Deployment gate
        -   ``vault:doctor`` is advisory.
        -   ``vault:doctor --profile=hardened`` asserts the hardened policy and
            is meant to gate the deploy — see
            :ref:`operations-hardened-deployment`.

Unchanged between the profiles: the cryptography, the ten operation
permissions, the per-secret ownership and group tiers, the audit chain and its
epochs, ``allowCliAccess`` (off by default in both), the reveal auto-hide and
wipe-on-leave lifecycle, and ``Cache-Control: no-store`` on reveal responses.
Hardening does not turn controls on that were previously off; it removes
escape hatches.

.. _security-profiles-lockout-guard:

Why ``disableAdminOverride`` is inert in the standard profile
=============================================================

It looks like an inconsistency and is a deliberate guard. Setting that flag
alone, without the rest of the hardened policy — an explicit external
provider, no fallback to the TYPO3 encryption key — is far more likely to be a
misunderstanding than a decision, and its failure mode is locking every
administrator out of the vault.

So the bypass seam checks the flag *and* the profile: not privileged → no
bypass; flag off → bypass, without even resolving the profile (which throws on
an unknown value, and must stay off the hot path of every existing
installation); profile ``standard`` → bypass anyway; hardened **and** flag set
→ bypass only inside an open break-glass window.

The mismatch is visible rather than silent. ``vault:break-glass --status``
reports ``adminOverrideDisabledEffective`` alongside the raw setting, and
``vault:doctor`` pairs the two.

.. _security-profiles-migration:

Migrating from standard to hardened
===================================

Do this in the order below. Steps 1 to 3 are prerequisites; switching the
profile before them is what produces an unreadable vault.

..  tip::

    **Plan the migration from a real finding list, not from guesswork.** Run
    this on the un-migrated system first:

    ..  code-block:: bash

        vendor/bin/typo3 vault:doctor --profile=hardened

    ``--profile`` changes the question the command asks, never the
    configuration: on a standard installation it answers *"would this pass if
    we hardened it?"* and writes nothing. Every step below then corresponds to
    a finding you can see up front, instead of flipping the switch on
    production to discover what breaks.

#.  **Move off the ``typo3`` provider.** Choose ``file``, ``env`` or
    ``transit`` (:ref:`operations-key-custody`), then rotate the master key
    onto it with ``vault:rotate-master-key``. Verify that secrets still
    decrypt *before* touching the profile — under ``hardened`` there is no
    fallback that would mask a mistake.

#.  **Back up the new key material separately from the database**, and
    verify the backup. See :ref:`operations-backup-and-restore`.

#.  **Grant the operation permissions your groups actually need.** With the
    override withdrawn, administrators hold exactly what their groups were
    granted. Editors working with vault-backed fields need ``secret.use``;
    whoever operates the vault needs the administrative permissions
    explicitly. See :ref:`security-operation-permissions`.

#.  **Enable at least one external audit sink** and schedule anchoring and
    verification (:ref:`operations-monitoring-and-alerting`). Without this,
    hardened verification reports ``NO_EXTERNAL_SINK``.

#.  **Set the profile.**

    ..  code-block:: none
        :caption: Extension configuration

        securityProfile = hardened

#.  **Withdraw the admin override, and pin it.** Set
    ``disableAdminOverride = 1``, then pin the value where the backend cannot
    reach it:

    ..  code-block:: php
        :caption: config/system/additional.php

        $GLOBALS['TYPO3_CONF_VARS']['SYS']['nrVault']['disableAdminOverride'] = true;

#.  **Confirm break-glass works before you need it.** Open and close a window
    once, on purpose, and check that both rows appear in the audit log:

    ..  code-block:: bash

        vendor/bin/typo3 vault:break-glass --status
        vendor/bin/typo3 vault:break-glass --activate --reason="Verify break-glass path after hardening" --minutes=1
        vendor/bin/typo3 vault:break-glass --deactivate --reason="Verification complete"

#.  **Gate the deployment.** ``vault:doctor --profile=hardened`` must pass.

#.  **Smoke test the surfaces that changed:** a reveal (no copy button, value
    disappears after 30 seconds), a non-admin editor loading a form with a
    vault-backed field, and an unprivileged administrator confirming they no
    longer reach secrets they do not own.

..  warning::

    Rolling back from hardened to standard re-enables the administrator
    override and the copy button, and makes ``disableAdminOverride`` inert
    again. It does **not** re-enable the ``typo3`` provider as a source for
    secrets already re-encrypted under the new master key — those envelopes
    are bound to that key. Rolling the profile back is not the same as
    rolling the key back.
