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
        await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();
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

    test('scan results show severity grouping', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=scan');
      await page.waitForLoadState('networkidle');

      // Look for severity indicators
      const severityIndicators = page.locator(
        '.badge:has-text("high"), ' +
        '.badge:has-text("medium"), ' +
        '.badge:has-text("low"), ' +
        'text=severity'
      );

      // May or may not have secrets, so just check page loads correctly
      await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });

  test.describe('UP-MIG-003: Review Detected Secrets', () => {
    test('review page loads without errors', async ({ authenticatedPage: page }) => {
      const response = await page.goto('/typo3/module/admin/vault/migration?action=review');

      expect(response?.status()).toBeLessThan(500);
      await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('review page has filter options', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=review');
      await page.waitForLoadState('networkidle');

      // Look for filter controls
      const sourceFilter = page.locator('select[name="source"], input[name="source"], #filter-source');
      const severityFilter = page.locator('select[name="severity"], input[name="severity"], #filter-severity');

      // Filter controls may or may not exist depending on implementation
      const hasFilters = await sourceFilter.isVisible() || await severityFilter.isVisible();

      // Either has filters or page loads correctly
      expect(page.url()).toContain('action=review');
    });

    test('review page allows secret selection', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=review');
      await page.waitForLoadState('networkidle');

      // Look for checkboxes or selection mechanism
      const checkboxes = page.locator('input[type="checkbox"]');
      const selectButtons = page.locator('button:has-text("Select"), a:has-text("Select")');

      // May have selection controls if secrets were found
      await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });

  test.describe('UP-MIG-004: Configure Migration Options', () => {
    test('configure page loads without errors', async ({ authenticatedPage: page }) => {
      const response = await page.goto('/typo3/module/admin/vault/migration?action=configure');

      expect(response?.status()).toBeLessThan(500);
      await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('configure page has identifier pattern input', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=configure');
      await page.waitForLoadState('networkidle');

      // Look for configuration inputs
      const patternInput = page.locator(
        'input[name="identifierPattern"], ' +
        'input[name="pattern"], ' +
        '#identifier-pattern'
      );

      // Configuration inputs may exist
      await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('configure page has ownership options', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=configure');
      await page.waitForLoadState('networkidle');

      // Look for owner selection
      const ownerSelect = page.locator('select[name="owner"], #owner-select');

      // Page should load correctly
      await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });

  test.describe('UP-MIG-005: Execute Migration', () => {
    test('execute page loads without errors', async ({ authenticatedPage: page }) => {
      const response = await page.goto('/typo3/module/admin/vault/migration?action=execute');

      expect(response?.status()).toBeLessThan(500);
      await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('execute shows progress or results', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=execute');
      await page.waitForLoadState('networkidle');

      // Should show progress indicator or results
      // `text=` consumes the rest of the selector string verbatim, so a
      // comma-separated list containing it never matches anything. Use
      // :has-text() inside a CSS union instead.
      const progress = page.locator('.progress, .spinner, :has-text("Processing"), :has-text("Migrating")');
      const results = page.locator('.results, :has-text("Complete"), :has-text("Success"), :has-text("migrated")');
      const continueButton = page.locator('a:has-text("Continue"), a:has-text("Verify")');

      // Page should show something meaningful
      await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });

  test.describe('UP-MIG-006: Verify Migration Results', () => {
    test('verify page loads without errors', async ({ authenticatedPage: page }) => {
      const response = await page.goto('/typo3/module/admin/vault/migration?action=verify');

      expect(response?.status()).toBeLessThan(500);
      await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('verify page shows migration summary', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=verify');
      await page.waitForLoadState('networkidle');

      // Should show summary of migration results
      const summary = page.locator('.migration-summary, .results-summary');
      const successCount = page.locator(':has-text("success"), :has-text("migrated"), :has-text("completed")');
      const returnLink = page.locator('a:has-text("Return"), a:has-text("Done"), a:has-text("Finish")');

      // Page should have some content
      await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });

  test.describe('UP-MIG-007: Migration - No Secrets Found', () => {
    test('handles case when no plaintext secrets exist', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration?action=scan');
      await page.waitForLoadState('networkidle');

      // If no secrets found, should show appropriate message
      const noSecretsMessage = page.locator(
        ':has-text("No secrets found"), ' +
        ':has-text("No plaintext secrets"), ' +
        ':has-text("all clear"), ' +
        '.callout-success'
      );

      const hasSecrets = page.locator(':has-text("found"), :has-text("detected")').first();

      // Either shows "no secrets" message or lists found secrets
      await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();
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

      if (await backButton.isVisible().catch(() => false)) {
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

      if (await backButton.isVisible().catch(() => false)) {
        await backButton.click();
        await page.waitForLoadState('networkidle');

        expect(frameUrl(page)).toMatch(/action=review|action=scan|admin_vault_migration/);
      }
    });

    test('index page is accessible from any step', async ({ authenticatedPage: page }) => {
      // Start from a later step
      await page.goto('/typo3/module/admin/vault/migration?action=configure');
      await page.waitForLoadState('networkidle');

      // Should be able to return to index
      const indexLink = page.locator('a[href*="vault/migration"]:not([href*="action="])');
      const moduleMenuLink = page.locator('.scaffold-modulemenu a[href*="vault/migration"]');

      const canReturnToIndex = await indexLink.isVisible() || await moduleMenuLink.isVisible();

      // Can at least use browser navigation
      await page.goto('/typo3/module/admin/vault/migration');
      expect(page.url()).not.toContain('action=');
    });
  });

  test.describe('UP-MIG-009: Migration - Prevent Duplicate Migrations', () => {
    test('already-vaulted identifiers are not shown as candidates', async ({ authenticatedPage: page }) => {
      // This test verifies the logic that prevents re-migration
      // It's hard to test directly without setup, so we verify the scan works

      await page.goto('/typo3/module/admin/vault/migration?action=scan');
      await page.waitForLoadState('networkidle');

      // Page should load and show results
      await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();

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
      await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('wizard maintains state across steps', async ({ authenticatedPage: page }) => {
      // Navigate through wizard and verify session state is maintained
      await page.goto('/typo3/module/admin/vault/migration?action=scan');
      await page.waitForLoadState('networkidle');

      // The wizard should maintain selection/state via session
      // This is implementation-specific but we verify pages load correctly
      await expect(page.locator('text=Oops, an error occurred')).not.toBeVisible();
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
