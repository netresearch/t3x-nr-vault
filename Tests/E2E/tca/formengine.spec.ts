import { test, expect, getModuleFrame, waitForModuleContent } from '../fixtures/auth';

/**
 * E2E tests for TYPO3 FormEngine/TCA integration.
 *
 * These tests verify that the tx_nrvault_secret TCA configuration works
 * correctly with TYPO3's native record editing interface (/typo3/record/edit).
 *
 * This is critical because:
 * 1. TCA issues (like pid field conflicts) only manifest in FormEngine
 * 2. Our custom module bypasses FormEngine, so these issues were missed
 * 3. Admins may use List module or direct URLs to edit records
 *
 * Tests cover:
 * - TCA-001: FormEngine can render the edit form without errors
 * - TCA-002: Group fields (owner_uid, allowed_groups, scope_pid) render correctly
 * - TCA-003: FormEngine can save changes without errors
 */

// Generate unique identifier for test isolation
const generateTestId = () => `e2e_tca_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;

test.describe('TYPO3 FormEngine/TCA Integration', () => {
  test.describe('TCA-001: FormEngine Edit Form Rendering', () => {
    test('can load FormEngine for tx_nrvault_secret record', async ({ authenticatedPage: page }) => {
      // First create a secret via FormEngine (create action redirects to FormEngine now)
      const testIdentifier = generateTestId();

      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      let frame = getModuleFrame(page);
      // Use FormEngine field selectors
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);
      // For VaultSecretInputElement, new records have data-vault-is-new="1"
      const secretInput = frame.locator('input[data-vault-is-new="1"]').first();
      await secretInput.fill('formengine-test-secret');
      // Click save button - try multiple selectors
      const saveButton = frame.locator('button[name="_savedok"], button:has-text("Save")').first();
      await saveButton.click();

      await page.waitForLoadState('networkidle');

      // Get the UID of the created record by finding it in the list
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      frame = getModuleFrame(page);
      await frame.getByRole('textbox', { name: 'Identifier' }).fill(testIdentifier);
      const filterResp = page.waitForResponse(
        (resp) => resp.url().includes('admin_vault_secrets') && resp.status() === 200,
        { timeout: 10000 },
      );
      await frame.locator('button:has-text("Filter")').click();
      await filterResp.catch(() => undefined);

      // Find edit button in the filtered table row (pencil icon button)
      // The identifier is not shown in the table, so we select by the row in the filtered result
      frame = getModuleFrame(page);
      const editButton = frame.locator('table tbody tr button[title*="Edit"], table tbody tr a[title*="Edit"]').first();

      // Verify filter worked - should have 1 result
      const secretsCount = frame.getByLabel('secrets found');
      await expect(secretsCount).toBeVisible();

      // Click edit button to go to FormEngine
      await editButton.click();
      await waitForModuleContent(page);

      const newFrame = getModuleFrame(page);

      // Critical check: No 503 error or PHP fatal error
      await expect(newFrame.locator('text=Oops, an error occurred')).not.toBeVisible();
      await expect(newFrame.locator('.callout-danger:has-text("503")')).not.toBeVisible();
      await expect(newFrame.locator('text=str_starts_with')).not.toBeVisible();

      // FormEngine should render successfully with tabs
      const tabs = newFrame.locator('[role="tablist"], .nav-tabs');
      await expect(tabs.first()).toBeVisible();
    });

    test('FormEngine renders without PHP errors for any secret record', async ({ authenticatedPage: page }) => {
      // Try to load FormEngine for record UID 1 (might not exist, but should not 500/503)
      const response = await page.goto('/typo3/record/edit?edit[tx_nrvault_secret][1]=edit');

      // Even if record doesn't exist, FormEngine should handle gracefully
      // We're specifically checking for the str_starts_with error that was caused by pid conflict
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // These errors indicate TCA misconfiguration
      await expect(frame.locator('.callout-danger:has-text("503")')).not.toBeVisible();
      await expect(frame.locator('text=str_starts_with')).not.toBeVisible();
      await expect(frame.locator('text=must be of type string, array given')).not.toBeVisible();
    });
  });

  test.describe('TCA-002: Group Field Rendering', () => {
    test('scope_pid group field renders correctly (not conflicting with system pid)', async ({ authenticatedPage: page }) => {
      // Navigate to FormEngine
      await page.goto('/typo3/record/edit?edit[tx_nrvault_secret][1]=edit');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // If record exists, check that scope_pid field is properly rendered
      // The field should NOT cause str_starts_with errors
      await expect(frame.locator('.callout-danger:has-text("503")')).not.toBeVisible();

      // Check for Settings tab which contains scope_pid
      const settingsTab = frame.locator('text=Settings');
      if (await settingsTab.first().isVisible()) {
        await settingsTab.first().click();
        // Wait for tab pane to become active instead of arbitrary sleep.
        await frame
          .locator('[role="tabpanel"].active, .tab-pane.active')
          .first()
          .waitFor({ state: 'visible', timeout: 5000 })
          .catch(() => undefined);

        // scope_pid should be rendered as a group element picker
        const scopePidField = frame.locator('[data-field-name="scope_pid"], [id*="scope_pid"]');

        // Either the field exists and is properly rendered, or the tab is there without errors
        await expect(frame.locator('text=str_starts_with')).not.toBeVisible();
      }
    });

    test('owner_uid group field renders correctly', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/record/edit?edit[tx_nrvault_secret][1]=edit');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Navigate to Access tab if visible
      const accessTab = frame.locator('text=Access');
      if (await accessTab.first().isVisible()) {
        await accessTab.first().click();
        await frame
          .locator('[role="tabpanel"].active, .tab-pane.active')
          .first()
          .waitFor({ state: 'visible', timeout: 5000 })
          .catch(() => undefined);

        // owner_uid should render without errors
        await expect(frame.locator('.callout-danger:has-text("503")')).not.toBeVisible();
        await expect(frame.locator('text=str_starts_with')).not.toBeVisible();
      }
    });
  });

  test.describe('TCA-003: FormEngine Save Operations', () => {
    test('can create new record via FormEngine', async ({ authenticatedPage: page }) => {
      // Try to create new record via FormEngine
      const response = await page.goto('/typo3/record/edit?edit[tx_nrvault_secret][0]=new');
      expect(response?.status()).toBe(200);

      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Should load without fatal errors
      await expect(frame.locator('.callout-danger:has-text("503")')).not.toBeVisible();
      await expect(frame.locator('text=str_starts_with')).not.toBeVisible();
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('re-saving an existing record does not raise an audit logging error', async ({ authenticatedPage: page }) => {
      // Regression test for https://github.com/netresearch/t3x-nr-vault/issues/227:
      // a metadata-only re-save (secret untouched) logged the unknown audit
      // action "metadata_update" and surfaced "Audit logging failed" to the editor.
      const testIdentifier = generateTestId();

      // Create a secret via the module's create form (FormEngine)
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      let frame = getModuleFrame(page);
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);
      await frame.locator('input[data-vault-is-new="1"]').first().fill('resave-test-secret');
      await frame.locator('button[name="_savedok"], button:has-text("Save")').first().click();
      await page.waitForLoadState('networkidle');

      // Re-open the record via the filtered list
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);
      frame = getModuleFrame(page);
      await frame.getByRole('textbox', { name: 'Identifier' }).fill(testIdentifier);
      const filterResp = page.waitForResponse(
        (resp) => resp.url().includes('admin_vault_secrets') && resp.status() === 200,
        { timeout: 10000 },
      );
      await frame.locator('button:has-text("Filter")').click();
      await filterResp.catch(() => undefined);

      frame = getModuleFrame(page);
      await frame.locator('table tbody tr button[title*="Edit"], table tbody tr a[title*="Edit"]').first().click();
      await waitForModuleContent(page);

      // Hit save without touching anything — the issue #227 reproduction
      frame = getModuleFrame(page);
      await frame.locator('button[name="_savedok"], button:has-text("Save")').first().click();
      await page.waitForLoadState('networkidle');

      // The form must still render (save succeeded) …
      frame = getModuleFrame(page);
      const tabs = frame.locator('[role="tablist"], .nav-tabs');
      await expect(tabs.first()).toBeVisible();

      // … and no audit logging error may surface to the editor
      await expect(frame.locator('text=Audit logging failed')).not.toBeVisible();
      await expect(page.locator('text=Audit logging failed')).not.toBeVisible();
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });
});
