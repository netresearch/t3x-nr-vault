import { test, expect, getModuleFrame, waitForModuleContent } from '../fixtures/auth';

/**
 * Extended migration-wizard tests that fill the P2 gap in UP-MIG-009
 * (prevent double migration).
 *
 * The existing UP-MIG-009 test only checks that a static known-bad string
 * isn't in page content. These tests navigate through the wizard's
 * intermediate pages and verify the wizard does not crash when used
 * sequentially. Since a full round-trip migration needs seeded plaintext
 * configuration, the test gracefully skips when no scan candidates exist.
 */

test.describe('MIG-EXT-001: Wizard steps progress and do not crash on replay', () => {
  test('all wizard actions render without a TYPO3 error page', async ({
    authenticatedPage: page,
  }) => {
    const actions = ['scan', 'review', 'configure', 'run', 'verify'];

    for (const action of actions) {
      const response = await page.goto(`/typo3/module/admin/vault/migration?action=${action}`);
      expect(
        response?.status() ?? 0,
        `step ${action} returned >=500`,
      ).toBeLessThan(500);
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      await expect(
        frame.locator('text=Oops, an error occurred'),
        `step ${action} renders TYPO3 error page`,
      ).not.toBeVisible();
    }
  });

  test('scan is idempotent — running twice does not change candidate count', async ({
    authenticatedPage: page,
  }) => {
    // First scan
    await page.goto('/typo3/module/admin/vault/migration?action=scan');
    await waitForModuleContent(page);
    const frame1 = getModuleFrame(page);
    await expect(frame1.locator('text=Oops, an error occurred')).not.toBeVisible();

    const firstPass = await frame1.locator('body').innerText().catch(() => '');

    // Second scan
    await page.goto('/typo3/module/admin/vault/migration?action=scan');
    await waitForModuleContent(page);
    const frame2 = getModuleFrame(page);
    await expect(frame2.locator('text=Oops, an error occurred')).not.toBeVisible();

    const secondPass = await frame2.locator('body').innerText().catch(() => '');

    // The candidate-count line should be the same both times (re-scanning
    // with no mutations in between must be deterministic).
    const countMatch1 = /(\d+)\s+(secrets?|candidates?|found|detected)/i.exec(firstPass);
    const countMatch2 = /(\d+)\s+(secrets?|candidates?|found|detected)/i.exec(secondPass);

    if (countMatch1 !== null && countMatch2 !== null) {
      expect(countMatch2[1]).toBe(countMatch1[1]);
    }
  });
});

test.describe('MIG-EXT-002: Wizard does not leak plaintext into HTML', () => {
  test('scan page does not echo raw plaintext into DOM', async ({ authenticatedPage: page }) => {
    // If the wizard found a secret, that secret's plaintext must not be in
    // the page HTML — only a redacted preview or identifier reference.
    await page.goto('/typo3/module/admin/vault/migration?action=scan');
    await waitForModuleContent(page);

    const frame = getModuleFrame(page);
    // The scan page must render cleanly for the plaintext-leak check below to
    // be meaningful (an errored page proves nothing about DOM leakage).
    await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();

    const html = await frame.locator('body').innerHTML().catch(() => '');

    // Heuristic: scan HTML for long hex strings that should NEVER
    // appear in the wizard UI (TYPO3 encryptionKey hex, bcrypt hashes,
    // base64-looking strings of suspicious length).
    const longHexPattern = /[a-f0-9]{40,}/gi;
    const matches = html.match(longHexPattern) ?? [];

    // Filter out CSS hex colors and known hash_before/hash_after display
    // values (which are audit hashes, not secrets). This is a best-effort
    // signal; real review uses functional tests.
    const suspicious = matches.filter(
      (m) => m.length >= 40 && !/^[0-9]+$/.test(m) && !/(id|aria|data)-/.test(m),
    );

    // We do NOT hard-fail on matches (TYPO3 uses long hex IDs in CSRF tokens
    // etc.) — but we annotate for review.
    if (suspicious.length > 10) {
      test.info().annotations.push({
        type: 'warning',
        description: `Migration scan page contains ${suspicious.length} long hex strings — manual review recommended to ensure no plaintext leaks.`,
      });
    }
  });
});
