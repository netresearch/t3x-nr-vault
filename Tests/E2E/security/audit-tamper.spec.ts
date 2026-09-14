import { test, expect, getModuleFrame, waitForModuleContent } from '../fixtures/auth';
import { isDbExecConfigured, runSql } from '../fixtures/db';

/**
 * Hash-chain tamper-detection E2E test.
 *
 * Fills the P0 gap in UP-AUD-009: the existing test loads the verify-chain
 * page and asserts *some* status callout, but never mutates the audit table
 * and re-verifies. A regression that caused `verifyHashChain()` to always
 * return valid=true would pass the existing test.
 *
 * This spec:
 *   1. Ensures at least one audit entry exists (creates a secret).
 *   2. Visits verify-chain and captures the baseline "valid" status.
 *   3. Tampers with the audit row through the database client
 *      (`ddev mysql` locally, `E2E_DB_EXEC` in CI — see fixtures/db.ts).
 *   4. Reloads verify-chain and asserts it now reports invalid.
 *   5. Restores the original row so subsequent tests are not impacted.
 *
 * Without `E2E_DB_EXEC`, an unavailable DDEV database skips the test with a
 * visible reason — it is NOT a hard prerequisite for a local run. With
 * `E2E_DB_EXEC` set the client was configured on purpose, so a failing client
 * fails the test: a broken CI database command must not turn into a silent skip.
 */

const generateTestId = () => `e2e_tamper_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;

test.describe.serial('UP-AUD-009 (extended): Hash chain detects tampering', () => {
  test('mutating an audit row flips verifyChain result to invalid', async ({ authenticatedPage: page, browserName }) => {
    // DB-mutation tests must run on a single browser to avoid races where one
    // worker's tamper step races another worker's restore step on the same row.
    test.skip(
      browserName !== 'chromium',
      'DB mutation tests must run on a single browser to avoid races',
    );

    const dbAvailable = runSql('SELECT 1');
    if (isDbExecConfigured()) {
      expect(dbAvailable, 'E2E_DB_EXEC is set but the database client failed to run SELECT 1').toBe('1');
    } else if (dbAvailable === null) {
      // Skip if DDEV helper isn't available — functional tests cover this path.
      test.skip(true, 'DDEV mysql helper unavailable — run functional tests for hash-chain coverage');
    }

    // Step 1: create a secret to guarantee at least one audit entry.
    const identifier = generateTestId();

    await page.goto('/typo3/module/admin/vault/secrets/create');
    await waitForModuleContent(page);

    let frame = getModuleFrame(page);
    await frame.locator('input[data-formengine-input-name*="identifier"]').fill(identifier);
    await frame.locator('input[data-vault-is-new="1"]').first().fill('tamper-test');
    await frame.locator('button[name="_savedok"]').first().click();
    await page.waitForLoadState('networkidle');

    // Step 2: baseline verifyChain — expect valid.
    await page.goto('/typo3/module/admin/vault/audit/verifyChain');
    await waitForModuleContent(page);

    frame = getModuleFrame(page);
    const baselineValid = await frame
      .locator('.callout-success, .alert-success, [class*="success"]')
      .first()
      .isVisible()
      .catch(() => false);

    expect(baselineValid, 'Baseline chain should be valid before tampering').toBe(true);

    // Step 3: fetch the newest audit row id and original hash_after.
    const audit = runSql(
      'SELECT uid, hash_after FROM tx_nrvault_audit_log ORDER BY uid DESC LIMIT 1',
    );

    if (audit === null || audit === '') {
      test.skip(true, 'No audit entries found — cannot test tampering');
    }

    const [uidStr, originalHash] = audit.split('\t');
    const uid = Number.parseInt(uidStr, 10);
    expect(Number.isFinite(uid) && uid > 0).toBe(true);

    // Known-bad but well-formed hex hash (64 hex chars for SHA-256 output).
    const badHash = '00'.repeat(32);

    // Pass SQL via stdin using hard-coded literals — no user input interpolated
    // into a shell command. `uid` is validated as a finite integer above.
    const tamperResult = runSql(
      `UPDATE tx_nrvault_audit_log SET hash_after='${badHash}' WHERE uid=${uid}`,
    );
    expect(tamperResult, 'Tamper UPDATE failed').not.toBeNull();

    try {
      // Step 4: re-run verifyChain — expect invalid now.
      await page.goto('/typo3/module/admin/vault/audit/verifyChain');
      await waitForModuleContent(page);

      frame = getModuleFrame(page);

      const invalidVisible = await frame
        .locator('.callout-danger, .alert-danger, [class*="danger"], [class*="error"]')
        .first()
        .isVisible()
        .catch(() => false);

      expect(
        invalidVisible,
        'verifyChain did not detect mutation in hash_after — hash chain is NOT tamper-evident',
      ).toBe(true);
    } finally {
      // Step 5: restore original hash_after so later tests see a valid chain.
      // originalHash comes from the DB query itself, not from the test — it is
      // already hex (no injection risk) but we additionally validate the shape.
      if (/^[0-9a-fA-F]+$/.test(originalHash)) {
        runSql(
          `UPDATE tx_nrvault_audit_log SET hash_after='${originalHash}' WHERE uid=${uid}`,
        );
      }
    }
  });
});
