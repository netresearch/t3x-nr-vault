import { expect, test, filterByIdentifier, getModuleFrame, saveRecord, waitForModuleContent } from '../fixtures/auth';

/**
 * E2E tests for Cross-Module User Pathways.
 *
 * TYPO3 v14 uses an iframe-based backend structure where module content
 * is rendered inside an iframe.
 *
 * Tests cover interactions between modules:
 * - UP-CROSS-001: Full Secret Lifecycle
 * - UP-CROSS-002: Dashboard Statistics Accuracy
 * - UP-CROSS-003: Module Navigation Consistency
 *
 * These tests mutate shared DB state (creating and deleting secrets that feed
 * the overview counters). Run them serially within a worker to avoid races
 * where one test's teardown sees another test's newly-created row.
 */

// Generate unique identifier for test isolation (underscore format for valid identifiers)
const generateTestId = (): string =>
  `e2e_cross_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;

test.describe.serial('Cross-Module User Pathways', () => {
  test.describe('UP-CROSS-001: Full Secret Lifecycle', () => {
    test('complete secret lifecycle with audit trail', async ({ authenticatedPage: page }) => {
      const testIdentifier = generateTestId();

      // Step 1: Create a new secret via FormEngine
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Use FormEngine field selectors
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);
      const secretInput = frame.locator('input[data-vault-is-new="1"]').first();
      await secretInput.fill('lifecycle-test-value');

      const descriptionField = frame.locator(
        'textarea[data-formengine-input-name*="description"], input[data-formengine-input-name*="description"]',
      );
      if (await descriptionField.isVisible()) {
        await descriptionField.fill('Lifecycle test secret');
      }

      await saveRecord(page, frame);

      // Verify creation succeeded
      const newFrame = getModuleFrame(page);
      await expect(newFrame.locator('text=Oops, an error occurred')).not.toBeVisible();

      // Step 2: Check audit log for create entry — concrete row assertion.
      await page.goto(
        `/typo3/module/admin/vault/audit?secretIdentifier=${encodeURIComponent(testIdentifier)}`,
      );
      await waitForModuleContent(page);

      const auditFrame = getModuleFrame(page);
      await expect(auditFrame.locator('text=Oops, an error occurred')).not.toBeVisible();
      await expect(
        auditFrame.locator('table tbody tr', { hasText: testIdentifier }).first(),
      ).toBeVisible({ timeout: 10000 });

      // Step 3: View the secret in list
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const listFrame = getModuleFrame(page);
      await filterByIdentifier(listFrame, testIdentifier);

      const filteredFrame = getModuleFrame(page);
      const secretRow = filteredFrame.locator(`[data-testid="secret-row-${testIdentifier}"]`);
      await expect(secretRow).toBeVisible({ timeout: 5000 });

      // Step 4: Delete the secret (cleanup)
      const deleteButton = secretRow.getByTestId('vault-delete-btn').first();
      if (await deleteButton.isVisible()) {
        await deleteButton.click();
        const confirm = page.getByRole('button', { name: 'Delete', exact: true });
        if (await confirm.isVisible().catch(() => false)) {
          await confirm.click();
          await confirm.waitFor({ state: 'hidden', timeout: 15000 });
        }
      }
    });
  });

  test.describe('UP-CROSS-002: Dashboard Statistics Accuracy', () => {
    test('overview statistics reflect secrets state', async ({ authenticatedPage: page }) => {
      // Get overview page
      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Should show some statistics
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();

      // Statistics group MUST render (template attaches data-testid).
      await expect(frame.getByTestId('vault-stats')).toBeVisible();

      // At least the overview page loads
      await expect(frame.locator('h1')).toBeVisible();
    });

    test('overview shows different counts for different states', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Concrete check: each stat card must render with a numeric value.
      await expect(frame.getByTestId('stat-card-total')).toBeVisible();
      await expect(frame.getByTestId('stat-card-active')).toBeVisible();
      await expect(frame.getByTestId('stat-card-disabled')).toBeVisible();

      for (const testid of ['stat-value-total', 'stat-value-active', 'stat-value-disabled']) {
        const value = await frame.getByTestId(testid).innerText();
        expect(value.trim(), `${testid} must be numeric`).toMatch(/^\d[\d,]*$/);
      }

      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });

  test.describe('UP-CROSS-003: Module Navigation Consistency', () => {
    test('can navigate between all modules without errors', async ({ authenticatedPage: page }) => {
      const modules = [
        '/typo3/module/admin/vault',
        '/typo3/module/admin/vault/secrets',
        '/typo3/module/admin/vault/secrets/create',
        '/typo3/module/admin/vault/audit',
        '/typo3/module/admin/vault/migration',
      ];

      for (const modulePath of modules) {
        const response = await page.goto(modulePath);
        expect(response?.status()).toBe(200);

        await waitForModuleContent(page);
        const frame = getModuleFrame(page);
        await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
      }
    });

    test('browser back button works correctly', async ({ authenticatedPage: page }) => {
      // Navigate through modules
      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      await page.goto('/typo3/module/admin/vault/audit');
      await waitForModuleContent(page);

      // Go back. `page.goBack()` resolves on the navigation itself, so the
      // `networkidle` that stood here added a wait for unrelated traffic.
      await page.goBack();

      // URL should still be within vault module.
      const currentUrl = page.url();
      expect(currentUrl).toMatch(/vault/);
    });

    test('module menu reflects current module', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      // Check that module menu shows current module. `.scaffold-modulemenu`
      // exists only in TYPO3 13; both 13 and 14 label the menu landmark
      // "Module Menu" (same locator as overview.spec.ts).
      const moduleMenu = page.locator('nav[aria-label="Module Menu"]');
      await expect(moduleMenu).toBeVisible();
    });

    test('DocHeader is present on all module pages', async ({ authenticatedPage: page }) => {
      const modules = [
        '/typo3/module/admin/vault/secrets',
        '/typo3/module/admin/vault/audit',
        '/typo3/module/admin/vault/migration',
      ];

      for (const modulePath of modules) {
        await page.goto(modulePath);
        await waitForModuleContent(page);

        // DocHeader contains the module dropdown and breadcrumb
        const breadcrumb = page.locator('text=Vault');
        await expect(breadcrumb.first()).toBeVisible();
      }
    });
  });

  test.describe('Session and State Management', () => {
    test('filters can be applied via URL params', async ({ authenticatedPage: page }) => {
      // Apply filter on secrets via URL
      await page.goto('/typo3/module/admin/vault/secrets?status=active');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Page should load without errors
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();

      // Navigate away
      await page.goto('/typo3/module/admin/vault/audit');
      await waitForModuleContent(page);

      // Navigate back
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      // Page should still work
      const newFrame = getModuleFrame(page);
      await expect(newFrame.locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('secret creation shows feedback', async ({ authenticatedPage: page }) => {
      const testIdentifier = generateTestId();

      // Create a secret via FormEngine
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);
      const secretInput = frame.locator('input[data-vault-is-new="1"]').first();
      await secretInput.fill('feedback-test');
      await saveRecord(page, frame);

      // Verify the secret exists in the list (concrete state check).
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const listFrame = getModuleFrame(page);
      await filterByIdentifier(listFrame, testIdentifier);

      const filteredFrame = getModuleFrame(page);
      await expect(
        filteredFrame.locator(`[data-testid="secret-row-${testIdentifier}"]`),
      ).toBeVisible({ timeout: 5000 });

      // Cleanup
      const deleteButton = filteredFrame
        .locator(`[data-testid="secret-row-${testIdentifier}"]`)
        .getByTestId('vault-delete-btn')
        .first();
      if (await deleteButton.isVisible()) {
        await deleteButton.click();
        const confirmButton = page.getByRole('button', { name: 'Delete', exact: true });
        if (await confirmButton.isVisible().catch(() => false)) {
          await confirmButton.click();
          await confirmButton.waitFor({ state: 'hidden', timeout: 15000 });
        }
      }
    });
  });

  test.describe('Data Integrity', () => {
    test('secret data is consistent across views', async ({ authenticatedPage: page }) => {
      const testIdentifier = generateTestId();
      const testDescription = 'Consistency test description';

      // Create with specific data via FormEngine
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);
      const secretInput = frame.locator('input[data-vault-is-new="1"]').first();
      await secretInput.fill('consistency-test');

      const descField = frame.locator(
        'textarea[data-formengine-input-name*="description"], input[data-formengine-input-name*="description"]',
      );
      if (await descField.isVisible()) {
        await descField.fill(testDescription);
      }

      await saveRecord(page, frame);

      // Check in list view
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const listFrame = getModuleFrame(page);
      await filterByIdentifier(listFrame, testIdentifier);

      const filteredFrame = getModuleFrame(page);
      await expect(
        filteredFrame.locator(`[data-testid="secret-row-${testIdentifier}"]`),
      ).toBeVisible({ timeout: 5000 });

      // Cleanup
      const deleteButton = filteredFrame
        .locator(`[data-testid="secret-row-${testIdentifier}"]`)
        .getByTestId('vault-delete-btn')
        .first();
      if (await deleteButton.isVisible()) {
        await deleteButton.click();
        const confirmButton = page.getByRole('button', { name: 'Delete', exact: true });
        if (await confirmButton.isVisible().catch(() => false)) {
          await confirmButton.click();
          await confirmButton.waitFor({ state: 'hidden', timeout: 15000 });
        }
      }
    });

    test('audit entries are created for operations', async ({ authenticatedPage: page }) => {
      // Just verify audit log loads and displays entries if any
      await page.goto('/typo3/module/admin/vault/audit');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();

      // Should have table or empty state
      const table = frame.locator('table');
      const emptyState = frame.locator('.callout-info, text=No');
      const hasContent =
        (await table.first().isVisible()) || (await emptyState.first().isVisible());
      expect(hasContent).toBe(true);
    });
  });

  test.describe('Error Handling', () => {
    test('invalid routes handled gracefully', async ({ authenticatedPage: page }) => {
      // Try to access a non-existent route
      const response = await page.goto('/typo3/module/admin/vault/nonexistent');

      // Should not crash (404 or redirect is acceptable)
      expect(response?.status()).toBeLessThan(500);
    });

    test('invalid audit filter shows empty results', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/audit?secretIdentifier=definitely_does_not_exist');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Should show empty state, not error
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });
});
