:navigation-title: Evidence collection
.. include:: /Includes.rst.txt

.. _auditor-evidence-collection:

===================
Evidence collection
===================

The commands to run and the artefacts to keep. Everything here is read-only and
safe on a production system; the destructive checks live in
:ref:`auditor-verification-procedures`.

Run every command from the TYPO3 project root. Redirect output to a file — the
artefact is the evidence, not the terminal.

..  note::

    Two of these commands need a permission that a CLI operator only holds when
    ``allowCliAccess = 1`` (``vault:retrieve`` and ``vault:rotate-master-key``).
    Everything in this section works without it. If a read-only command reports
    access denied, that is itself a finding worth recording — with an
    ``access_denied`` audit row to match.

.. _auditor-evidence-configuration:

Configuration and posture
=========================

..  code-block:: bash
    :caption: Machine-readable posture snapshot

    vendor/bin/typo3 vault:doctor --format=json > evidence/doctor.json

    # And, if the installation claims to be hardened, the policy assertion:
    vendor/bin/typo3 vault:doctor --profile=hardened --format=json \
        > evidence/doctor-hardened.json; echo "exit=$?" >> evidence/doctor-hardened.json

Exit code is the verdict: ``0`` every control passed, ``1`` warnings only,
``2`` at least one critical finding. Record it — a JSON body without the exit
code loses half the signal. Severity is **worst-wins**, so a long list of
passes can never average a critical finding away.

Two behaviours that matter when this runs as a pipeline gate: an unusable
``--profile`` value and an internal crash **both** exit ``2``, deliberately
coinciding with "critical" so a gate that could not actually check something is
never readable as "checked and fine".

..  note::

    **``--profile`` changes the question, never the configuration.**
    ``--profile=hardened`` on a standard installation answers *"would this pass
    if we hardened it?"* and writes nothing. For an assessment that is the more
    useful run: it produces the real finding list for the un-migrated system
    without anyone flipping a switch on production. Short forms are ``-p`` and
    ``-f``; ``--format`` defaults to ``text``.

The JSON body carries ``profile``, ``configuredProfile``,
``profileOverridden``, ``auditReady``, ``highestSeverity``, ``exitCode``, a
``summary`` object (``total``, ``pass``, ``warning``, ``critical``) and a
``findings`` array.

**``findings`` lists every control, including the ones that passed** — 23
controls in total (22 always emitted, plus ``cli.access_groups`` only when
``allowCliAccess`` is on). Each entry carries a stable dotted ``id`` plus
``severity`` (``pass`` | ``warning`` | ``critical``), ``summary``, ``risk``,
``remediation``, ``docsUrl`` and ``details``; for a pass, ``risk`` and
``remediation`` are empty strings rather than absent. The ``id`` is what lets
you diff two runs months apart instead of re-reading prose.

..  warning::

    **Check for ``error`` before ``findings``.** On a rejected ``--profile``
    value, or a run that could not start at all, the payload is
    ``{error, exitCode}`` *instead* — there is no ``findings`` key. A parser
    that reads ``findings`` unconditionally will crash on exactly the runs
    where something was wrong.

..  important::

    **``vault:doctor`` is a gate, not the authoritative verifier.** It runs in
    a pipeline and on a backend page load, so two of its audit controls are
    deliberately bounded:

    *   ``audit.hash_chain`` verifies only the **newest 1000 entries**;
    *   ``audit.anchor`` checks only that the chain has **not shrunk** below
        the anchored sequence. It does **not** re-compare the anchored row's
        tip hash, and it does **not** check the anchor's age.

    ``vault:audit-verify`` remains the authoritative full-range verifier — it
    walks the whole chain and performs the tip-hash comparison. For an
    assessment, run both and keep both artefacts; do not accept a green
    ``vault:doctor`` as evidence that the full chain verifies.

..  note::

    **A default standard installation has zero criticals by design**, so read
    a green run in context. Nine controls change severity with the target
    profile; two of them shift from *pass* to *critical*:
    ``audit.external_sink`` and a missing ``audit.anchor`` are passes under
    ``standard`` (sinks and anchoring are opt-in there, matching
    ``NO_EXTERNAL_SINK``'s documented semantics) and criticals under
    ``hardened``. ``provider.configured`` and ``audit.reads_logged`` go from
    warning to critical. This is why the ``--profile=hardened`` run is the
    informative one even on a standard installation.

Finding ids worth citing directly in an assessment:

..  list-table::
    :header-rows: 1
    :widths: 34 66

    *   -   Area
        -   Ids

    *   -   Profile and administrative override
        -   ``profile.valid``, ``profile.admin_override``

    *   -   Master-key custody
        -   ``provider.known``, ``provider.configured``,
            ``provider.available``, ``provider.master_key_readable``,
            ``provider.key_permissions``

    *   -   Audit evidence
        -   ``audit.hash_chain``, ``audit.anchor``,
            ``audit.external_sink``, ``audit.sink_delivery``,
            ``audit.reads_logged``, ``audit.retention``

    *   -   CLI exposure
        -   ``cli.access``, ``cli.access_groups``

    *   -   Emergency access
        -   ``breakglass.window_open``

    *   -   Secret hygiene
        -   ``secrets.never_rotated``, ``secrets.expired``,
            ``secrets.dead``

    *   -   Platform
        -   ``version.extension``, ``version.typo3_supported``,
            ``environment.production_context``,
            ``environment.backend_lock_ssl``

    *   -   Check failed to run
        -   ``check.crashed`` — treat as unknown, never as a pass

..  code-block:: bash
    :caption: Administrative override state

    vendor/bin/typo3 vault:break-glass --status > evidence/break-glass-status.txt

The important field is ``adminOverrideDisabledEffective`` (``yes`` / ``no``),
reported alongside the raw ``disableAdminOverride`` setting. A raw ``1`` with an
effective ``no`` means the flag is inert because the profile is ``standard`` — a
finding, and a common one.

Also capture, by inspection rather than by command:

*   the extension configuration (``securityProfile``, ``masterKeyProvider``,
    ``masterKeySource``, ``auditHmacEpoch``, ``allowCliAccess``,
    ``auditReads``, the ``auditSink*`` block);
*   :file:`config/system/additional.php` — which values are **pinned** out of
    the backend's reach;
*   :php:`$GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts']`, if a webhook
    sink is configured;
*   the ``tx_nrvault:*`` grants per backend user group
    (:guilabel:`Backend Users > Groups`, :guilabel:`Custom module options`) —
    the authorization model as actually deployed;
*   file ownership and mode of the master-key file or wrapped blob, and of the
    NDJSON audit and anchor files.

.. _auditor-evidence-chain:

Audit chain integrity
=====================

..  code-block:: bash
    :caption: Chain plus anchor comparison — the primary integrity artefact

    vendor/bin/typo3 vault:audit-verify --format=json > evidence/audit-verify.json
    echo "exit=$?" >> evidence/audit-verify.json

This is the one command that checks **both** halves: the internal hash chain
*and* the comparison against the last published chain-tip anchor. Findings
carry the stable reason codes from
:ref:`security-audit-evidence-reasons`.

..  code-block:: bash
    :caption: Chain-only verification

    vendor/bin/typo3 vault:audit --verify > evidence/audit-chain.txt

``vault:audit --verify`` verifies the chain without the anchor comparison.
Useful for isolating a finding: a chain that verifies here but fails
``vault:audit-verify`` points at the anchor, not at the rows.

..  note::

    ``vault:audit-verify --tamper-only`` suppresses ``NO_EXTERNAL_SINK`` and
    ``SINK_FAILURE``. For an assessment, run **without** it — those two codes
    are exactly the ones that tell you whether independent evidence exists at
    all.

Anchor inspection
-----------------

The anchor file is NDJSON, one record per line. Read it directly; do not take
the application's word for it:

..  code-block:: bash
    :caption: The anchor with the highest sequence is the effective baseline

    jq -c 'select(.type=="anchor") | .anchor' < /var/log/typo3/nr-vault-anchors.ndjson \
        | tail -20 > evidence/anchors-recent.json

    # The effective baseline — the reader takes the MAXIMUM sequence, not the last line.
    jq -s 'map(select(.type=="anchor") | .anchor) | max_by(.sequence)' \
        < /var/log/typo3/nr-vault-anchors.ndjson > evidence/anchor-effective.json

Each anchor carries ``sequence``, ``chainTip``, ``timestamp`` and
``hmacEpoch``. Three things to check **by inspecting the file yourself** —
none of these is covered by a ``vault:doctor`` control:

#.  **Freshness.** Compare the newest ``timestamp`` against the configured
    anchoring interval. A stale anchor means the detection baseline is old even
    though nothing reported an error. **No automated control checks anchor
    age** — ``audit.anchor`` covers presence and shrinkage only — so the blind
    window is the anchoring *interval*, and confirming it is a manual step.
#.  **Continuity.** Sequences should rise across the file. A long flat stretch
    means anchoring was not running.
#.  **Epoch.** ``hmacEpoch`` should equal the configured ``auditHmacEpoch``. A
    lower value in recent anchors means the protection level was reduced.

..  warning::

    An anchor file stored only on the host whose database it protects is weak
    evidence: whoever can truncate the audit table can usually truncate the
    file. **Prefer the off-host copy** — the syslog archive or the SIEM — and
    record which source you used. This distinction decides what the anchor
    actually proves.

.. _auditor-evidence-export:

Audit log export
================

..  code-block:: bash
    :caption: Period export, with the hash columns

    vendor/bin/typo3 vault:audit \
        --since="2026-01-01" --until="2026-06-30" \
        --format=json --limit=100000 \
        --export=evidence/audit-2026-H1.json

..  code-block:: bash
    :caption: Useful narrower slices

    # One secret's full history.
    vendor/bin/typo3 vault:audit --identifier=<identifier> --format=json \
        --export=evidence/audit-secret.json

    # Every denial in the period — reconnaissance and broken integrations.
    vendor/bin/typo3 vault:audit --action=access_denied --format=json \
        --export=evidence/audit-denials.json

    # Break-glass activations and closures.
    vendor/bin/typo3 vault:audit --identifier=__break_glass__ --format=json \
        --export=evidence/audit-break-glass.json

    # Master-key lifecycle.
    vendor/bin/typo3 vault:audit --identifier=__master_key__ --format=json \
        --export=evidence/audit-master-key.json

``--format`` accepts ``table``, ``json`` and ``csv``; ``--limit`` defaults to
``50``, so raise it explicitly for an export or you will silently truncate the
evidence. Other filters: ``--action``, ``--actor``, ``--success``.

..  warning::

    **Export the hash columns.** ``uid``, ``previous_hash``, ``entry_hash`` and
    ``hmac_key_epoch`` are what make the export evidence rather than a log.
    Without them nobody can re-check the links later.

    And note the honest limit: an export has **no hash chain of its own, no
    retention policy and no further access control**. It is why
    ``audit.export`` is a separate permission from ``audit.view``, and it means
    the export must itself be handled as sensitive material. It also contains
    personal data (``actor_username``, ``ip_address``, ``user_agent``).

..  note::

    Pair every export with the ``vault:audit-verify`` output from the **same
    session**. Authenticity is demonstrable only while the master key is
    available; the verification run is the artefact that records the moment it
    was demonstrated. See
    :ref:`operations-decommissioning-retention` for why this matters at
    end of life.

.. _auditor-evidence-scan:

Plaintext exposure elsewhere
============================

..  code-block:: bash

    vendor/bin/typo3 vault:scan > evidence/secret-scan.txt

Scans database content for values that look like unprotected secrets. It
evidences a different question from everything above: not "is the vault
sound?" but "is the vault actually being used?" A hardened vault next to
API tokens sitting in a content field is a finding about the deployment, not
about the extension.

.. _auditor-evidence-ci:

Development and release evidence
================================

Verified against this repository's workflows. Do not assume a typical setup —
the list below is what is actually declared here.

..  list-table::
    :header-rows: 1
    :widths: 30 34 36

    *   -   Evidence
        -   Where
        -   What it shows

    *   -   Compatibility test matrix
        -   :file:`.github/workflows/ci.yml`
        -   PHP 8.2, 8.3, 8.4, 8.5 × TYPO3 ``^13.4`` and ``^14.3``; unit and
            functional tests; coverage uploaded

    *   -   Security scanning
        -   :file:`.github/workflows/checks.yml` → shared
            ``security.yml``
        -   Consumes the in-repo :file:`semgrep.yml` rules and
            :file:`.gitleaks.toml` allowlist

    *   -   Static application security testing
        -   ``checks.yml`` → ``codeql.yml``
        -   CodeQL results in the repository's security tab

    *   -   Fuzz testing
        -   ``checks.yml`` → ``fuzz.yml``
        -   Fuzz suite on every push, pull request, merge group and weekly
            schedule

    *   -   Dependency review
        -   ``checks.yml`` → ``dependency-review.yml``
        -   Runs on pull requests

    *   -   Licence compliance
        -   ``checks.yml`` → ``license-check.yml``
        -   Dependency licences checked in CI

    *   -   OpenSSF Scorecard
        -   ``checks.yml`` → ``scorecard.yml``
        -   Weekly and on default-branch pushes; supply-chain posture score

    *   -   Release provenance attestations
        -   :file:`.github/workflows/release.yml`
        -   Tag-triggered release requesting ``id-token: write`` and
            ``attestations: write``; verify the published attestation with
            ``gh attestation verify``

    *   -   Static analysis and code style
        -   :file:`phpstan.neon`,
            :file:`.php-cs-fixer.dist.php`,
            :file:`phpat.neon`,
            :file:`rector.php`
        -   PHPStan level and baseline; architecture rules pinning the HTTP
            client (:ref:`adr-028-phpat-http-client-lock`)

    *   -   Mutation testing
        -   :file:`infection.json5`,
            :file:`Documentation/Developer/mutation-baseline.md`
        -   Infection configuration and the recorded baseline. Run locally with
            ``make test-mutation``

    *   -   Coverage and quality gates
        -   :file:`codecov.yml`,
            :file:`.sonarcloud.properties`
        -   Codecov thresholds; SonarCloud project configuration

    *   -   SBOMs, signatures, checksums
        -   Shared reusable
            ``release-typo3-extension.yml``, job ``build-and-sign``
        -   SPDX + CycloneDX SBOMs, Sigstore bundles and ``checksums.txt``
            attached to every tagged release — see below

    *   -   Vulnerability disclosure policy
        -   :file:`SECURITY.md`
        -   Private reporting through GitHub security advisories

..  important::

    **Supply-chain controls are one level up — follow the delegation, do not
    infer from the call site.** This repository's :file:`release.yml` contains
    no SBOM, signing or checksum steps of its own. They live in the shared
    reusable ``netresearch/typo3-ci-workflows/.github/workflows/release-typo3-extension.yml``,
    job ``build-and-sign``, which produces for every tagged release:

    *   ``<prefix>-<version>.sbom.spdx.json`` and ``.sbom.cdx.json`` —
        SPDX and CycloneDX, via ``anchore/sbom-action`` (gated on
        ``include-sbom``, default ``true``);
    *   ``<file>.sigstore.json`` for **every** file in ``dist/`` — keyless
        Sigstore signing via ``sigstore/cosign-installer`` and
        ``cosign sign-blob --bundle`` (gated on ``sign-artifacts``, default
        ``true``);
    *   ``checksums.txt`` — ``sha256sum`` over the whole ``dist/`` directory;
    *   a build-provenance attestation over the ``.zip`` and ``.tar.gz`` via
        ``actions/attest-build-provenance`` — **ungated**.

    nr-vault's call site passes only ``archive-prefix``, ``package-name`` and
    ``extension-key``, so it opts out of neither gate and both defaults hold.

    Record **which** source you verified this against and at which revision:
    the reusable is referenced at ``@main``, so its content can change without
    any commit in this repository.

..  code-block:: bash
    :caption: Verifying a published release

    gh release download v<version> -R netresearch/t3x-nr-vault -D release-assets
    cd release-assets

    # Integrity.
    sha256sum -c checksums.txt

    # Signature (keyless — identity and issuer must match the release workflow).
    cosign verify-blob \
        --bundle nr-vault-<version>.zip.sigstore.json \
        --certificate-identity-regexp 'https://github\.com/netresearch/.+' \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        nr-vault-<version>.zip

    # Build provenance.
    gh attestation verify nr-vault-<version>.zip -R netresearch/t3x-nr-vault

Third-party actions in that release path are pinned to full commit SHAs.
Netresearch-owned reusables are deliberately referenced at ``@main`` so
upstream fixes propagate; an assessment should record that as policy rather
than flag it as an oversight, and should pin the *observed revision* in its own
evidence instead.

.. _auditor-evidence-package:

Assembling the evidence package
===============================

..  code-block:: text
    :caption: A complete package

    evidence/
    ├── doctor.json                  # posture + exit code
    ├── doctor-hardened.json         # policy assertion + exit code
    ├── break-glass-status.txt       # adminOverrideDisabledEffective
    ├── audit-verify.json            # chain + anchor, with reason codes
    ├── audit-chain.txt              # chain only
    ├── anchor-effective.json        # highest-sequence anchor
    ├── anchors-recent.json          # recent anchor history
    ├── audit-<period>.json          # entry sequence WITH hash columns
    ├── audit-denials.json
    ├── audit-break-glass.json
    ├── audit-master-key.json
    ├── secret-scan.txt
    ├── config-snapshot.txt          # settings, pins, allowed_hosts, grants
    ├── file-permissions.txt         # key file, NDJSON files
    └── ci/
        ├── workflow-runs.txt        # run URLs for ci.yml / checks.yml / release.yml
        ├── scorecard.json           # OpenSSF Scorecard result
        ├── coverage.txt             # Codecov / SonarCloud summary
        ├── sbom.spdx.json           # SBOM as published with the release
        ├── sbom.cdx.json
        ├── checksums-verify.txt     # sha256sum -c output
        ├── cosign-verify.txt        # cosign verify-blob output
        └── attestation-verify.txt   # gh attestation verify output

Record for the package as a whole: **when** it was collected, **from which
environment**, **by whom**, under **which extension, TYPO3 and PHP versions**,
and — for the anchor — **from which storage** the copy came. An evidence
package without that provenance cannot be re-checked, which is the only thing
it was collected for.
