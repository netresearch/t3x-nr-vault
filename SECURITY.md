# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x     | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities in nr-vault seriously. If you discover a security issue, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Use GitHub's private security reporting feature:

**[Report a vulnerability](https://github.com/netresearch/t3x-nr-vault/security/advisories/new)**

Include the following information:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

Our response targets, measured from the moment your report reaches us:

| Stage | Target |
|-------|--------|
| Acknowledgement of your report | 48 hours |
| Triage and severity rating (CVSS v3.1) | 3 days |
| **Fix released — Critical or High** | **7 days** |
| Fix released — Medium | 30 days |
| Fix released — Low | next scheduled release |
| Advisory published | with the fix, or earlier if the issue is already public |

The 7-day patch SLA for Critical and High severity is the commitment that
matters most: this extension holds live credentials, so a working exploit is a
credential-disclosure risk in every installation that runs the affected version.

If we are going to miss a target, we tell you before it expires and say why —
you will not be left guessing. A fix that needs longer than its SLA (for
example a change that cannot be made without breaking decryption of existing
secrets) gets a written mitigation you can apply in the meantime.

We follow coordinated disclosure: we ask for up to 90 days before public
disclosure, and we publish sooner when a fix is out or the issue is already
known publicly. You decide whether to be credited.

### Emergency Releases

Meeting the 7-day Critical/High SLA sometimes means shipping outside the normal
release cadence. An emergency release changes the *schedule*, never the gates.

What is fast-tracked:

- **Scope.** The patch fixes the vulnerability and nothing else. No refactors,
  no dependency bumps, no unrelated bug fixes riding along — a minimal diff is
  what makes same-day review trustworthy.
- **Branching.** The fix is cut from the affected release tag, not from `main`,
  so installations can take the patch without also taking unreleased work. It is
  then forward-merged into `main`.
- **Review latency.** Reviewers are paged rather than waited on. The
  two-person review requirement for security-critical paths
  (see [CONTRIBUTING.md](CONTRIBUTING.md#security-critical-changes)) still
  applies — it is not waived under time pressure, because a rushed crypto change
  is exactly the change that most needs a second pair of eyes.
- **Disclosure.** The advisory is drafted in parallel with the fix and published
  with the release.

What is **not** skipped, in any circumstance:

- the full CI matrix (PHP 8.2-8.5 x TYPO3 13.4/14.3) must be green;
- the security invariant tests and the mutation ratchet on
  `Classes/Crypto`, `Classes/Security`, `Classes/Audit` and `Classes/Http`
  must hold;
- the release evidence bundle is generated and read before announcing.

**A release does not ship with unresolved High or Critical findings.** That
covers the reported vulnerability itself and anything of High/Critical severity
surfaced by CodeQL, Opengrep, `composer audit`, or the evidence bundle at the
release commit. If such a finding cannot be fixed in time, the release is held,
or it ships with the finding documented in the advisory and a mitigation
readers can apply — never silently.

If an emergency release later proves incomplete, we treat the follow-up as a new
report against the same SLA clock rather than as a continuation of the old one.

### After an External Security Audit

When this extension undergoes an external audit, we commit to a **retest**: once
the audit findings are remediated, the auditors (or, if they are unavailable, an
independent reviewer who did not write the fixes) verify the remediations against
the released version, and we publish which findings were retested and confirmed
closed.

Two things follow from that commitment:

- every audit finding is fixed with a regression test that pins the invariant it
  violated, so the retest has something durable to verify and a later refactor
  cannot quietly reintroduce it;
- the retest outcome is published alongside the audit report, including any
  finding accepted as a risk rather than fixed, with the reasoning.

An audit whose findings are remediated but never retested is not a completed
audit, and we will not describe it as one.

### Security Considerations

This extension handles sensitive data (API keys, credentials, secrets). Key security features:

- **Envelope Encryption**: AES-256-GCM with per-secret Data Encryption Keys
- **Master Key Protection**: Stored outside database (file, env, or derived)
- **Access Control**: Backend user group-based permissions
- **Audit Logging**: Tamper-evident hash chain for all operations
- **Memory Safety**: Sensitive data wiped with `sodium_memzero()`

### Security Best Practices

When using nr-vault:

1. **Master Key Storage**
   - Store master key outside webroot
   - Use file permissions 0400
   - Never commit to version control
   - Backup separately from database

2. **Access Control**
   - Restrict CLI access unless needed
   - Use context-based permission scoping
   - Review audit logs regularly

3. **Operations**
   - Rotate master key annually
   - Rotate secrets after personnel changes
   - Monitor for `access_denied` events
   - Schedule the audit hash-chain verification task (see below)

## Audit Log Immutability — Trust Model

The audit log (`tx_nrvault_audit_log`) is **tamper-evident, not
tamper-proof**. Every entry is bound into an HMAC-SHA256 hash chain
(see ADR-023 / ADR-024), so any in-place edit, row deletion, or
front-truncation is *detected* by `verifyHashChain()` — but nothing at
the application layer *prevents* a database principal with `UPDATE` /
`DELETE` rights from modifying the table. The chain surfaces the
tampering; it does not stop it.

For a defense-in-depth posture, add a preventive control at the
database layer and verify the chain on a schedule.

### Recommended: INSERT-only database grant

Run the application with a DB user that can only `INSERT` and `SELECT`
on the audit table. The two-step writer (INSERT row, then a single
`UPDATE` to set `entry_hash` on the just-inserted row) needs `UPDATE`,
so either grant a column-scoped `UPDATE(entry_hash)` or use the trigger
recipe below.

```sql
-- MySQL / MariaDB: dedicated low-privilege role for the app connection
REVOKE ALL PRIVILEGES ON your_db.tx_nrvault_audit_log FROM 'typo3_app'@'%';
GRANT SELECT, INSERT ON your_db.tx_nrvault_audit_log TO 'typo3_app'@'%';
-- entry_hash is written by a follow-up UPDATE on the new row:
GRANT UPDATE (entry_hash) ON your_db.tx_nrvault_audit_log TO 'typo3_app'@'%';
```

### Alternative: reject UPDATE/DELETE via triggers

If column-scoped grants are impractical, block destructive statements
with triggers. Allow only the `entry_hash` write that immediately
follows the INSERT, and forbid all `DELETE`s.

```sql
-- MySQL / MariaDB
DELIMITER //
CREATE TRIGGER tx_nrvault_audit_no_delete
BEFORE DELETE ON tx_nrvault_audit_log
FOR EACH ROW
  SIGNAL SQLSTATE '45000'
  SET MESSAGE_TEXT = 'Audit log is append-only; DELETE is forbidden';

CREATE TRIGGER tx_nrvault_audit_seal
BEFORE UPDATE ON tx_nrvault_audit_log
FOR EACH ROW
BEGIN
  -- Permit only the post-insert entry_hash write; reject any other change.
  IF (OLD.entry_hash <> '' AND OLD.entry_hash IS NOT NULL)
     OR NOT (NEW.uid <=> OLD.uid
         AND NEW.secret_identifier <=> OLD.secret_identifier
         AND NEW.action <=> OLD.action
         AND NEW.success <=> OLD.success
         AND NEW.previous_hash <=> OLD.previous_hash) THEN
    SIGNAL SQLSTATE '45000'
      SET MESSAGE_TEXT = 'Audit log rows are immutable after sealing';
  END IF;
END//
DELIMITER ;
```

> PostgreSQL: implement the same policy with a `BEFORE UPDATE OR DELETE`
> trigger that `RAISE EXCEPTION`s, or with `REVOKE UPDATE, DELETE`.

### Schedule hash-chain verification

Run `verifyHashChain()` regularly so tampering is caught quickly. Add
the *Vault: Verify audit hash chain* scheduler task (or call
`vendor/bin/typo3 vault:audit` on a cron) and alert on any reported
mismatch or UID gap. Persist the current chain tip
(`getLatestHash()` + max UID) to an out-of-band store (syslog/SIEM) so
a full-table wipe-and-reseed is also detectable.

## Release Evidence

Every tagged release publishes a **security evidence bundle**: a record of what
was actually verified at the tagged commit, so you do not have to take the
release notes on faith. It is generated by
`.github/workflows/release-evidence.yml` and contains

- test results per suite (unit, fuzz, functional), with per-suite counts,
- line coverage overall and separately for `Classes/Crypto`,
  `Classes/Security`, `Classes/Audit` and `Classes/Http`,
- the mutation score for the whole codebase and, separately, for those same
  four security-critical directories,
- the dependency audit (`composer audit`),
- the PHPStan level the release was analysed at,
- the `vault:doctor` reference posture from a clean installation of that exact
  commit — diff it against your own `vault:doctor` output,
- the release identity (tag, commit, extension version) and pointers plus
  verification commands for the signed release artifacts.

Every entry carries one of four statuses:

| Status | Meaning |
|--------|---------|
| `pass` | measured, and it met the threshold |
| `warn` | measured, but inconclusive — or the producer exists and did not run |
| `fail` | measured, and it did not meet the threshold |
| `absent` | not measured in this build at all |

`absent` is the important one. A check that did not run is reported as absent,
never quietly omitted, so a gap in the evidence can never be mistaken for a
clean result. Read the statuses rather than assuming a published bundle means
everything passed.

The workflow run itself is annotated with a one-word roll-up derived from those
statuses, so you can judge a release without opening the bundle:

| Roll-up | Means |
|---------|-------|
| `PASS` | every check passed with a report behind it |
| `DEGRADED` | nothing failed, but at least one check warned or was absent — the release is verified only as far as the bundle shows |
| `FAIL` | at least one check failed, or a producing job did not complete |

The bundle is published in all three cases. A `FAIL` roll-up marks the run red
rather than suppressing the evidence.

### Fetching a bundle

The bundle is attached to its workflow run rather than to the GitHub release,
because releases are immutable once published and are not edited afterwards.

```bash
# List the evidence run for a tag and download the bundle
gh run list --workflow release-evidence.yml --limit 10
gh run download <run-id> --name release-evidence-v1.2.3
tar -xzf release-evidence-1.2.3.tar.gz
```

Read `EVIDENCE.md` first. `evidence-manifest.json` is the same data in
machine-readable form (`schemaVersion 1`), and `artifacts/` holds verbatim
copies of the raw JUnit, coverage, mutation, audit and doctor reports the
summary was derived from, each listed in the manifest with its SHA-256 so you
can confirm the summary matches its inputs.

### Verifying a bundle

The bundle is covered by a build-provenance attestation, which stays verifiable
after the run artifact expires:

```bash
gh attestation verify release-evidence-1.2.3.tar.gz --repo netresearch/t3x-nr-vault
```

Release artifacts themselves (SBOMs in SPDX and CycloneDX, `checksums.txt`,
Sigstore bundles) are attached to the GitHub release:

```bash
sha256sum -c checksums.txt

cosign verify-blob \
  --bundle nr-vault-1.2.3.zip.sigstore.json \
  --certificate-identity-regexp "https://github.com/netresearch/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  nr-vault-1.2.3.zip

gh attestation verify nr-vault-1.2.3.zip --repo netresearch/t3x-nr-vault
```

A failed signature or checksum means the file you hold is not the file we
published. Do not install it, and report it through the channel above.

## Security Audit

This extension has not yet undergone a formal security audit. If you are interested in sponsoring a security audit, please [open a discussion](https://github.com/netresearch/t3x-nr-vault/discussions) or reach out through the [GitHub project](https://github.com/netresearch/t3x-nr-vault).

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report valid vulnerabilities (unless they prefer to remain anonymous).
