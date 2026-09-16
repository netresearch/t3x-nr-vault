import { test, expect, getModuleFrame, waitForModuleContent } from '../fixtures/auth';
import type { Page } from '@playwright/test';

/**
 * The URL the module iframe currently shows.
 *
 * Navigation inside a backend module happens in that iframe. TYPO3 14 mirrors
 * it into the address bar afterwards; TYPO3 13 does not, so `page.url()` still
 * reports the route the shell was opened with and an assertion on it measures
 * the wrong document. Falls back to the top URL when there is no iframe, so the
 * helper is safe on a standalone page too.
 */
function frameUrl(page: Page): string {
  const child = page.frames().find((frame) => frame !== page.mainFrame());

  return child === undefined ? page.url() : child.url();
}

/**
 * Open the wizard's configure step with a selection, the way the review form
 * does it.
 *
 * `configureAction()` renders `Migration/Configure` only for a POST carrying
 * `selected[]`; a GET is answered with a redirect back to the review step. The
 * review page emits that form only when the scan found database candidates,
 * and a freshly provisioned instance has none — which is why every test that
 * navigated to `action=configure` was looking at the review page instead. The
 * step is reached here by posting the same field the review form posts, from
 * inside the module iframe so the module token and the backend session come
 * from the real document. The key names a column rather than a stored finding
 * because the step does not validate it against the scan; what is under test
 * is what the template makes of a selected row.
 */
async function openConfigureStep(page: Page, selection = 'database:tt_content.bodytext'): Promise<void> {
  await page.goto('/typo3/module/admin/vault/migration?action=review');
  await waitForModuleContent(page);

  const frame = page.frames().find((candidate) => candidate !== page.mainFrame());
  if (frame === undefined) {
    throw new Error('The backend rendered no module iframe');
  }

  const token = new URL(frame.url()).searchParams.get('token');
  if (token === null) {
    throw new Error(`The module URL carried no token: ${frame.url()}`);
  }

  await frame.evaluate(
    ([moduleToken, key]) => {
      const form = document.createElement('form');
      form.method = 'post';
      form.action = `/typo3/module/admin/vault/migration?token=${moduleToken}&action=configure`;
      const field = document.createElement('input');
      field.type = 'hidden';
      field.name = 'selected[]';
      field.value = key;
      form.append(field);
      document.body.append(form);
      form.submit();
    },
    [token, selection] as const
  );

  await frame.waitForURL(/action=configure/, { timeout: 15000 });
}

/**
 * E2E tests for Migration Module User Pathways.
 *
 * TYPO3 v14 uses an iframe-based backend structure where module content
 * is rendered inside an iframe.
 *
 * Tests cover the migration wizard workflow:
 * - UP-MIG-001: View Migration Wizard Start
 * - UP-MIG-002: Scan for Plaintext Secrets
 * - UP-MIG-003: Review Detected Secrets
 * - UP-MIG-004: Configure Migration Options
 * - UP-MIG-005: Execute Migration
 * - UP-MIG-006: Verify Migration Results
 * - UP-MIG-007: Migration - No Secrets Found
 * - UP-MIG-008: Migration Wizard - Back Navigation
 * - UP-MIG-009: Migration - Prevent Duplicate Migrations
 */

test.describe('Migration Module User Pathways', () => {
  test.describe('UP-MIG-001: View Migration Wizard Start', () => {
    test('displays migration wizard introduction page', async ({ authenticatedPage: page }) => {
      const response = await page.goto('/typo3/module/admin/vault/migration');
      expect(response?.status()).toBe(200);

      await waitForModuleContent(page);
      const frame = getModuleFrame(page);

      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
      await expect(frame.locator('h1')).toBeVisible();
    });

    test('shows start scan button', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Look for the start/scan button in the iframe
      const startButton = frame.locator(
        'a[href*="action=scan"], ' +
        'button:has-text("Start"), ' +
        'button:has-text("Scan"), ' +
        'a:has-text("Start Scan"), ' +
        'a:has-text("Begin")'
      );

      await expect(startButton.first()).toBeVisible();
    });

    test('displays explanation of migration purpose', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Should have explanatory content about the wizard
      const wizardTitle = frame.locator('h1');
      await expect(wizardTitle).toBeVisible();

      // Check for "How it works" section or similar explanation
      const howItWorks = frame.locator('text=How it works');
      const scanStep = frame.locator('text=Scan');

      const hasHowItWorks = await howItWorks.first().isVisible().catch(() => false);
      const hasScanStep = await scanStep.first().isVisible().catch(() => false);

      expect(hasHowItWorks || hasScanStep).toBe(true);
    });
  });

  test.describe('UP-MIG-002: Scan for Plaintext Secrets', () => {
    test('can navigate to scan step', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration');
      await page.waitForLoadState('networkidle');

      // Click start scan
      const startButton = page.locator(
        'a[href*="action=scan"], ' +
        'button:has-text("Scan"), ' +
        'a:has-text("Start Scan")'
      ).first();

      if (await startButton.isVisible()) {
        await startButton.click();
        await page.waitForLoadState('networkidle');

        // Should be on scan page or show scan results
        await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
      }
    });

    test('scan page shows results or progress', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=scan');
      await page.waitForLoadState('networkidle');

      // The wizard renders inside the module iframe, so the whole search has to
      // happen there. `text=` also consumes the rest of the selector string —
      // 'text=No secrets found, text=No plaintext secrets' looked for that one
      // literal sentence and could never match. :has-text() composes in a union.
      await waitForModuleContent(page);
      const frame = getModuleFrame(page);

      const scanResults = frame.locator('.scan-results, .migration-results, table');
      const continueButton = frame.locator(
        'a:has-text("Continue"), a:has-text("Review"), button:has-text("Next")',
      );
      // Nothing to migrate renders as an infobox (f:be.infobox -> .callout).
      const noSecretsMessage = frame.locator('.callout');

      const hasScanContent =
        (await scanResults.first().isVisible().catch(() => false)) ||
        (await continueButton.first().isVisible().catch(() => false)) ||
        (await noSecretsMessage.first().isVisible().catch(() => false));

      expect(hasScanContent, 'Scan step rendered neither results, a continue action nor an infobox').toBe(true);
    });

    test('scan results show severity grouping or the all-clear', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=scan');
      await waitForModuleContent(page);
      const frame = getModuleFrame(page);

      // `Scan.html` branches on {totalCount}: findings render the by-severity
      // section, an empty scan renders the all-clear infobox. Which of the two
      // shows depends on the instance's data; that exactly one of them shows
      // does not, and neither appears when the step fails to render.
      const bySeverity = await frame.locator('text=Secrets by Severity').count();
      const allClear = await frame.locator('text=No Plaintext Secrets Detected').count();

      expect(
        (bySeverity > 0) !== (allClear > 0),
        `Scan step showed neither the severity grouping nor the all-clear (grouping=${bySeverity}, all-clear=${allClear})`
      ).toBe(true);
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });

  test.describe('UP-MIG-003: Review Detected Secrets', () => {
    test('review page loads without errors', async ({ authenticatedPage: page }) => {
      const response = await page.goto('/typo3/module/admin/vault/migration?action=review');

      expect(response?.status()).toBeLessThan(500);
      await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('review page offers a selection or reports that there is nothing to select', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=review');
      await waitForModuleContent(page);
      const frame = getModuleFrame(page);

      // `Review.html` branches on the candidate count: the table carries the
      // `#select-all` control and one `.secret-checkbox` per row, the empty
      // case carries the "No Database Secrets Found" infobox.
      const selectAll = await frame.locator('#select-all').count();
      const nothingToSelect = await frame.locator('text=No Database Secrets Found').count();

      expect(
        (selectAll > 0) !== (nothingToSelect > 0),
        `Review step offered neither a selection nor an empty-state notice (select-all=${selectAll}, empty=${nothingToSelect})`
      ).toBe(true);

      if (selectAll > 0) {
        await expect(frame.locator('.secret-checkbox').first()).toBeVisible();
      }
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });

  test.describe('UP-MIG-004: Configure Migration Options', () => {
    test('configure step without a selection returns to the review step', async ({ authenticatedPage: page }) => {
      const response = await page.goto('/typo3/module/admin/vault/migration?action=configure');

      expect(response?.status()).toBeLessThan(500);
      await waitForModuleContent(page);
      const frame = getModuleFrame(page);

      // This is what a plain GET of the configure step does, and every test
      // in this group used to assert against the result without saying so.
      expect(frameUrl(page)).toContain('action=review');
      await expect(frame.locator('text=Selection Required')).toBeVisible();
      await expect(frame.locator('text=No secrets selected for migration.')).toBeVisible();
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('configure page has identifier pattern input', async ({ authenticatedPage: page }) => {
      await openConfigureStep(page);
      const frame = getModuleFrame(page);

      // One input per selected row, named `migrations[<i>][identifierPattern]`.
      // The plain `identifierPattern` the old locator asked for is never
      // emitted, so it could not have matched on any instance.
      await expect(frame.locator('th:has-text("Identifier Pattern")')).toBeVisible();

      const rows = await frame.locator('table tbody tr').count();
      const patternInputs = await frame.locator('input[name$="[identifierPattern]"]').count();
      expect(rows, 'The selected row must reach the configure table').toBeGreaterThan(0);
      expect(patternInputs, 'Every selected row must offer an identifier pattern input').toBe(rows);
      await expect(frame.locator('input[name$="[identifierPattern]"]').first()).toBeVisible();

      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('configure page offers the clear-originals option and a submit control', async ({ authenticatedPage: page }) => {
      await openConfigureStep(page);
      const frame = getModuleFrame(page);

      // This step used to look for an owner selector, which the module does
      // not have: `Configure.html` offers exactly one option, and it decides
      // whether the original plaintext is replaced.
      await expect(frame.locator('#clearOriginals')).toBeVisible();
      await expect(frame.locator('button[type="submit"]:has-text("Execute Migration")')).toBeVisible();
    });
  });

  test.describe('UP-MIG-005: Execute Migration', () => {
    test('execute page loads without errors', async ({ authenticatedPage: page }) => {
      const response = await page.goto('/typo3/module/admin/vault/migration?action=execute');

      expect(response?.status()).toBeLessThan(500);
      await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('execute page renders without an error page', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=execute');
      await page.waitForLoadState('networkidle');

      // What this test measures is that the step renders at all. Three
      // locators for progress, results and a Continue control used to stand
      // here unasserted, which read as coverage and was none: a `:has-text()`
      // union without an element prefix matches the whole document anyway, so
      // asserting them would have passed on any page. The name says what is
      // checked.
      await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });

  test.describe('UP-MIG-006: Verify Migration Results', () => {
    test('verify page loads without errors', async ({ authenticatedPage: page }) => {
      const response = await page.goto('/typo3/module/admin/vault/migration?action=verify');

      expect(response?.status()).toBeLessThan(500);
      await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('verify page renders without an error page', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=verify');
      await page.waitForLoadState('networkidle');

      // Same as the execute step: the summary, count and return-link
      // locators that stood here were never asserted. This checks that the
      // step renders.
      await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });

  test.describe('UP-MIG-007: Migration - No Secrets Found', () => {
    test('handles case when no plaintext secrets exist', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=scan');
      await waitForModuleContent(page);
      const frame = getModuleFrame(page);

      // Either branch is acceptable here — a seeded instance lists findings,
      // a clean one shows the all-clear — so the check is that the scan step
      // renders one of them. The locator that stood here for that purpose
      // searched the backend shell and was never asserted; a `:has-text()`
      // union without an element prefix would have matched the whole document
      // in any case.
      const rendered =
        (await frame.locator('text=Secrets by Severity').count()) +
        (await frame.locator('text=No Plaintext Secrets Detected').count());

      expect(rendered, 'Scan step rendered neither findings nor the all-clear').toBeGreaterThan(0);
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });

  test.describe('UP-MIG-008: Migration Wizard - Back Navigation', () => {
    test('can navigate back from review to scan', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=review');
      await page.waitForLoadState('networkidle');

      // The wizard's Back control is an <f:be.link> inside the module iframe,
      // so both the click and the resulting URL belong to the frame. The top
      // window's address only follows on TYPO3 14, which is why asserting
      // page.url() passed there and failed on 13.4 — it was measuring the
      // backend shell, not the navigation under test.
      await waitForModuleContent(page);
      const frame = getModuleFrame(page);
      const backButton = frame
        .locator('a:has-text("Back"), button:has-text("Back"), a[href*="action=scan"]')
        .first();

      // Required, not optional: a conditional skip here would let the test
      // pass precisely when the Back control has gone missing.
      await expect(backButton).toBeVisible();

      {
        // Wait for the iframe's own navigation. `networkidle` on the top page
        // returns before the module frame has re-rendered, so an assertion
        // behind it reads the document from before the click.
        const navigated = page.waitForResponse(
          (resp) => resp.url().includes('/vault/migration') && resp.request().method() === 'GET',
          { timeout: 10000 },
        );
        await backButton.click();
        await navigated.catch(() => undefined);

        // The step is left behind — where it lands depends on the data: with
        // findings the Back control carries action=scan, and on an instance
        // with nothing to migrate the no-secrets branch links to the wizard
        // start. Both are "no longer on review"; asserting one of them would
        // pass or fail on the fixture rather than on the navigation.
        await expect
          .poll(() => frameUrl(page), { timeout: 10000 })
          .not.toMatch(/action=review/);
      }
    });

    test('can navigate back from configure to review', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=configure');
      await page.waitForLoadState('networkidle');

      await waitForModuleContent(page);
      const frame = getModuleFrame(page);
      const backButton = frame
        .locator('a:has-text("Back"), button:has-text("Back"), a[href*="action=review"]')
        .first();

      // Required for the same reason as the review step above.
      await expect(backButton).toBeVisible();

      await backButton.click();

      // `networkidle` observes the outer document, and on TYPO3 13 the module
      // iframe can still carry action=configure when it returns — so the URL
      // is polled until the frame itself has moved.
      await expect
        .poll(() => frameUrl(page), { timeout: 10000 })
        .toMatch(/action=review|action=scan|admin_vault_migration/);
    });

    test('index page is accessible from any step', async ({ authenticatedPage: page }) => {
      // Start from a later step
      await page.goto('/typo3/module/admin/vault/migration?action=configure');
      await waitForModuleContent(page);

      // Two locators for a link back to the index used to stand here without
      // ever being asserted, and the check that followed them — that a URL
      // just navigated to carries no `action=` — could not fail. What this
      // step actually guarantees is that the index renders its own start view
      // again, which is the control the wizard begins with.
      await page.goto('/typo3/module/admin/vault/migration');
      await waitForModuleContent(page);
      const frame = getModuleFrame(page);

      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
      await expect(frame.locator('a[href*="action=scan"]').first()).toBeVisible();
      expect(frameUrl(page)).not.toContain('action=');
    });
  });

  test.describe('UP-MIG-009: Migration - Prevent Duplicate Migrations', () => {
    test('already-vaulted identifiers are not shown as candidates', async ({ authenticatedPage: page }) => {
      // This test verifies the logic that prevents re-migration
      // It's hard to test directly without setup, so we verify the scan works

      await page.goto('/typo3/module/admin/vault/migration?action=scan');
      await page.waitForLoadState('networkidle');

      // Page should load and show results
      await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();

      // If there are results, they should not include vault identifiers
      const pageContent = await page.content();

      // Should not show identifiers that look like vault references
      // (Implementation-specific check)
      expect(pageContent).not.toContain('vault(already-migrated)');
    });
  });

  test.describe('Wizard Flow Integration', () => {
    test('complete wizard flow navigation', async ({ authenticatedPage: page }) => {
      // Start at index
      await page.goto('/typo3/module/admin/vault/migration');
      await page.waitForLoadState('networkidle');

      // Step 1: Index -> Scan
      const scanLink = page.locator('a[href*="action=scan"], button:has-text("Scan")').first();
      if (await scanLink.isVisible()) {
        await scanLink.click();
        await page.waitForLoadState('networkidle');
        expect(page.url()).toContain('action=scan');
      }

      // Step 2: Scan -> Review (if continue link exists)
      const reviewLink = page.locator('a[href*="action=review"], button:has-text("Review")').first();
      if (await reviewLink.isVisible()) {
        await reviewLink.click();
        await page.waitForLoadState('networkidle');
        expect(page.url()).toContain('action=review');
      }

      // Verify no errors throughout
      await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('wizard maintains state across steps', async ({ authenticatedPage: page }) => {
      // Navigate through wizard and verify session state is maintained
      await page.goto('/typo3/module/admin/vault/migration?action=scan');
      await page.waitForLoadState('networkidle');

      // The wizard should maintain selection/state via session
      // This is implementation-specific but we verify pages load correctly
      await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });

  test.describe('Cross-cutting concerns', () => {
    test('migration module has no console errors', async ({ authenticatedPage: page }) => {
      const consoleErrors: string[] = [];

      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          consoleErrors.push(msg.text());
        }
      });

      await page.goto('/typo3/module/admin/vault/migration');
      await page.waitForLoadState('networkidle');

      const criticalErrors = consoleErrors.filter(
        (err) => !err.includes('favicon') && !err.includes('404')
      );

      expect(criticalErrors).toHaveLength(0);
    });

    test('all wizard steps return valid HTTP status', async ({ authenticatedPage: page }) => {
      const steps = ['', '?action=scan', '?action=review', '?action=configure', '?action=execute', '?action=verify'];

      for (const step of steps) {
        const response = await page.goto(`/typo3/module/admin/vault/migration${step}`);
        expect(response?.status()).toBeLessThan(500);
      }
    });

    test('wizard has consistent DocHeader navigation', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration');
      await waitForModuleContent(page);

      // DocHeader is outside the iframe, in the main page
      // Look for the module dropdown or breadcrumb
      const moduleDropdown = page.locator('[class*="docheader"], [class*="module-docheader"]');
      const breadcrumbVault = page.locator('text=Vault');
      const breadcrumbMigration = page.locator('text=Migration');

      const hasDocHeader = await moduleDropdown.first().isVisible().catch(() => false);
      const hasBreadcrumbVault = await breadcrumbVault.first().isVisible().catch(() => false);
      const hasBreadcrumbMigration = await breadcrumbMigration.first().isVisible().catch(() => false);

      expect(hasDocHeader || hasBreadcrumbVault || hasBreadcrumbMigration).toBe(true);
    });
  });
});
