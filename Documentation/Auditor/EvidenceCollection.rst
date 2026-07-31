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

Exit code is the verdict: ``0`` pass, ``1`` warnings, ``2`` critical. Record
it — a JSON body without the exit code loses half the signal. Each finding
carries a stable identifier, which is what lets you compare two runs months
apart rather than re-reading prose.

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
``hmacEpoch``. Three things to check:

#.  **Freshness.** Compare the newest ``timestamp`` against the configured
    anchoring interval. A stale anchor means the detection baseline is old even
    though nothing reported an error.
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

    *   -   Vulnerability disclosure policy
        -   :file:`SECURITY.md`
        -   Private reporting through GitHub security advisories

..  note::

    **What is not declared in this repository:** SBOM generation and artefact
    signing (cosign/sigstore) do not appear in these workflow files. The
    release job delegates to a shared reusable workflow
    (``netresearch/typo3-ci-workflows``) and requests attestation permissions;
    anything beyond build provenance has to be verified **in that reusable
    workflow**, not inferred from the call site. Record what you verified and
    where.

    Several jobs also reference reusable workflows at ``@main`` rather than a
    pinned commit SHA. For organisation-owned reusables that is the deliberate
    policy — it lets upstream fixes propagate — but an assessment should note
    it explicitly rather than treat it as an oversight.

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
    └── ci/                          # workflow run URLs, attestation verification,
                                     # Scorecard result, coverage report

Record for the package as a whole: **when** it was collected, **from which
environment**, **by whom**, under **which extension, TYPO3 and PHP versions**,
and — for the anchor — **from which storage** the copy came. An evidence
package without that provenance cannot be re-checked, which is the only thing
it was collected for.
