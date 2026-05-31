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

1. **Acknowledgment**: We will acknowledge receipt within 48 hours
2. **Assessment**: We will assess the vulnerability within 7 days
3. **Resolution**: Critical vulnerabilities will be patched within 30 days
4. **Disclosure**: We follow responsible disclosure practices

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

## Security Audit

This extension has not yet undergone a formal security audit. If you are interested in sponsoring a security audit, please [open a discussion](https://github.com/netresearch/t3x-nr-vault/discussions) or reach out through the [GitHub project](https://github.com/netresearch/t3x-nr-vault).

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report valid vulnerabilities (unless they prefer to remain anonymous).
