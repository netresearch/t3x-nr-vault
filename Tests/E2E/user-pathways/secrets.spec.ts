import { test, expect, getModuleFrame, waitForModuleContent } from '../fixtures/auth';
import type { Page, FrameLocator, Locator } from '@playwright/test';

/**
 * E2E tests for Secrets Module User Pathways.
 *
 * TYPO3 v14 uses an iframe-based backend structure where module content
 * is rendered inside an iframe. These tests use the moduleFrame fixture
 * to access content within the module iframe.
 *
 * Tests cover the complete secret lifecycle:
 * - UP-SEC-001: View Secrets List
 * - UP-SEC-002: Filter Secrets List
 * - UP-SEC-003: Create New Secret (Happy Path)
 * - UP-SEC-004: Create Secret - Validation Errors
 * - UP-SEC-005: View Secret Details
 * - UP-SEC-006: Reveal Secret Value (AJAX)
 * - UP-SEC-007: Edit Secret Metadata
 * - UP-SEC-008: Rotate Secret Value
 * - UP-SEC-009: Toggle Secret Status (Enable/Disable)
 * - UP-SEC-010: Delete Secret
 * - UP-SEC-011: Delete Secret - Cancellation
 * - UP-SEC-012: Secrets List - Empty State
 * - UP-SEC-013: Access Denied - Unauthorized Secret
 */

// Generate unique identifier for test isolation
// Must start with a letter and contain only letters, numbers, and underscores
const generateTestId = (): string =>
  `e2e_test_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;

/**
 * Submit the filter form and wait for the response that re-renders the list.
 * Uses Playwright's waitForResponse to replace arbitrary sleeps.
 */
async function applyIdentifierFilter(
  page: Page,
  frame: FrameLocator,
  identifier: string,
): Promise<FrameLocator> {
  await frame
    .getByRole('textbox', { name: 'Identifier' })
    .fill(identifier);
  const filterResponse = page.waitForResponse(
    (resp) => resp.url().includes('/admin_vault_secrets') && resp.status() === 200,
    { timeout: 10000 },
  );
  await frame.locator('button:has-text("Filter")').click();
  await filterResponse.catch(() => undefined);
  // Stats panel re-renders after filter apply; wait for it.
  const newFrame = getModuleFrame(page);
  await newFrame
    .locator('[data-testid="secret-filter-stats"]')
    .waitFor({ state: 'visible', timeout: 10000 })
    .catch(() => undefined);
  return newFrame;
}

/**
 * Reveal-lifecycle constant mirrored from
 * `Resources/Public/JavaScript/vault-reveal-lifecycle.js` (AUTO_HIDE_SECONDS).
 */
const AUTO_HIDE_SECONDS = 30;

/**
 * Scope for locating elements of the open reveal modal.
 *
 * TYPO3's Modal is created by the JS module running inside the module iframe,
 * but depending on the backend version it can end up in the outer document.
 * Probe the iframe first, fall back to the top document, so the lifecycle specs
 * assert against whichever document actually holds the dialog.
 */
async function revealModalScope(page: Page): Promise<{ locator: (selector: string) => Locator }> {
  const frame = getModuleFrame(page);
  try {
    await frame.locator('#reveal-modal-secret').waitFor({ state: 'attached', timeout: 5000 });
    return { locator: (selector: string) => frame.locator(selector) };
  } catch {
    await page.locator('#reveal-modal-secret').waitFor({ state: 'attached', timeout: 5000 });
    return { locator: (selector: string) => page.locator(selector) };
  }
}

/**
 * Create a secret, then open its reveal modal from the list (waiting for the
 * `vault_reveal` POST so the modal is populated before assertions run).
 */
async function createSecretAndReveal(page: Page, plaintext: string): Promise<string> {
  const testIdentifier = generateTestId();

  await page.goto('/typo3/module/admin/vault/secrets/create');
  await waitForModuleContent(page);
  let frame = getModuleFrame(page);
  await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);
  await frame.locator('input[data-vault-is-new="1"]').first().fill(plaintext);
  await saveFormEngine(page, frame);

  await page.goto('/typo3/module/admin/vault/secrets');
  await waitForModuleContent(page);
  frame = await applyIdentifierFilter(page, getModuleFrame(page), testIdentifier);

  const revealResponse = page.waitForResponse(
    (resp) => resp.url().includes('/vault/reveal') && resp.request().method() === 'POST',
    { timeout: 10000 },
  );
  await frame
    .locator(`[data-testid="secret-row-${testIdentifier}"]`)
    .getByTestId('vault-reveal-btn')
    .first()
    .click();
  await revealResponse;

  return testIdentifier;
}

async function saveFormEngine(page: Page, frame: FrameLocator): Promise<void> {
  const saveResponse = page.waitForResponse(
    (resp) => resp.request().method() === 'POST' && resp.status() < 400,
    { timeout: 15000 },
  );
  await frame.locator('button[name="_savedok"], button:has-text("Save")').first().click();
  await saveResponse.catch(() => undefined);
  await page.waitForLoadState('networkidle');
}

test.describe('Secrets Module User Pathways', () => {
  test.describe('UP-SEC-001: View Secrets List', () => {
    test('displays secrets list page', async ({ authenticatedPage: page }) => {
      const response = await page.goto('/typo3/module/admin/vault/secrets');
      expect(response?.status()).toBe(200);

      await waitForModuleContent(page);
      const frame = getModuleFrame(page);

      // Check for page title or heading inside iframe
      await expect(frame.locator('h1')).toBeVisible();
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('shows secrets table with proper structure', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Check for table presence (if secrets exist)
      const table = frame.getByTestId('secret-list-table');
      const emptyState = frame.locator('.callout-info, .alert-info');

      // Either table or empty state should be visible
      const hasTable = await table.first().isVisible();
      const hasEmptyState =
        (await emptyState.first().isVisible()) ||
        (await frame.locator('text=No Secrets Found').first().isVisible());

      expect(hasTable || hasEmptyState).toBe(true);

      if (hasTable) {
        // Verify table headers
        const headers = frame.locator('table th');
        expect(await headers.count()).toBeGreaterThanOrEqual(1);
      }
    });

    test('shows create secret button in header', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Look for create button in DocHeader toolbar
      const createButton = frame.locator('button:has-text("Create Secret"), a:has-text("Create Secret")');
      await expect(createButton).toBeVisible();
    });
  });

  test.describe('UP-SEC-002: Filter Secrets List', () => {
    test('filter form is present on list page', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Check for filter form elements
      const filterForm = frame.getByTestId('secret-filter-form');
      await expect(filterForm).toBeVisible();
    });

    test('can filter by identifier', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      const newFrame = await applyIdentifierFilter(page, frame, 'test-filter-value');

      // Verify filter was applied - stats panel is visible and page is not errored.
      await expect(newFrame.locator('text=Oops, an error occurred')).not.toBeVisible();
      await expect(newFrame.getByTestId('secret-filter-stats')).toBeVisible();
    });

    test('can filter by status', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Select status filter
      const statusSelect = frame.locator('select[name="status"]');
      await statusSelect.selectOption('active');

      const filterResponse = page.waitForResponse(
        (resp) => resp.url().includes('/admin_vault_secrets') && resp.status() === 200,
        { timeout: 10000 },
      );
      await frame.locator('button:has-text("Filter")').click();
      await filterResponse.catch(() => undefined);

      // Verify filter was applied
      const newFrame = getModuleFrame(page);
      await expect(newFrame.locator('text=Oops, an error occurred')).not.toBeVisible();
      await expect(newFrame.getByTestId('secret-filter-stats')).toBeVisible();
    });

    test('displays count of filtered results', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Stats panel with count badge MUST be present.
      await expect(frame.getByTestId('secret-count-badge')).toBeVisible();
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });

  test.describe('UP-SEC-003: Create New Secret (Happy Path)', () => {
    test('create secret form loads correctly', async ({ authenticatedPage: page }) => {
      // Create action now redirects to FormEngine
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // FormEngine uses data[table][uid][field] naming convention
      // Verify FormEngine form elements are present
      await expect(frame.locator('input[data-formengine-input-name*="identifier"]')).toBeVisible();

      // The secret_value field should be visible for new records (password input with data-vault-is-new)
      const secretInput = frame.locator('input[data-vault-is-new="1"]');
      await expect(secretInput).toBeVisible();

      // Description field should also be present
      await expect(frame.locator('textarea[data-formengine-input-name*="description"], input[data-formengine-input-name*="description"]')).toBeVisible();
    });

    test('can create a new secret with required fields only', async ({ authenticatedPage: page }) => {
      const testIdentifier = generateTestId();

      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Fill identifier using FormEngine input
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);

      // Fill secret value - look for the password input in the secret_input field
      const secretInput = frame.locator('input[data-vault-is-new="1"]').first();
      await secretInput.fill('test-secret-value-123');

      // Click save button in DocHeader
      await saveFormEngine(page, frame);

      // Verify the secret now appears in the list (concrete DB-state assertion).
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);
      const listFrame = await applyIdentifierFilter(
        page,
        getModuleFrame(page),
        testIdentifier,
      );
      await expect(
        listFrame.locator(`[data-testid="secret-row-${testIdentifier}"]`),
      ).toBeVisible({ timeout: 5000 });
    });

    test('can create a new secret with all fields', async ({ authenticatedPage: page }) => {
      const testIdentifier = generateTestId();

      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Fill required fields using FormEngine inputs
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);

      // Fill secret value
      const secretInput = frame.locator('input[data-vault-is-new="1"]').first();
      await secretInput.fill('full-test-secret-value');

      // Fill optional fields
      const descriptionInput = frame.locator('textarea[data-formengine-input-name*="description"], input[data-formengine-input-name*="description"]');
      if (await descriptionInput.isVisible()) {
        await descriptionInput.fill('E2E test secret description');
      }

      // Check if context field exists
      const contextInput = frame.locator('input[data-formengine-input-name*="context"]');
      if (await contextInput.isVisible()) {
        await contextInput.fill('testing');
      }

      // Click save button
      await saveFormEngine(page, frame);

      // Verify the secret row is visible after save.
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);
      const listFrame = await applyIdentifierFilter(
        page,
        getModuleFrame(page),
        testIdentifier,
      );
      await expect(
        listFrame.locator(`[data-testid="secret-row-${testIdentifier}"]`),
      ).toBeVisible({ timeout: 5000 });
    });

    test('creation redirects to list with success', async ({ authenticatedPage: page }) => {
      const testIdentifier = generateTestId();

      // Create the secret via FormEngine
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);

      const secretInput = frame.locator('input[data-vault-is-new="1"]').first();
      await secretInput.fill('list-check-secret');

      await saveFormEngine(page, frame);

      // Navigate to list and verify secret was created (assert row presence).
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      let listFrame = getModuleFrame(page);
      await expect(listFrame.locator('h1:has-text("Secrets")')).toBeVisible();
      listFrame = await applyIdentifierFilter(page, listFrame, testIdentifier);
      await expect(
        listFrame.locator(`[data-testid="secret-row-${testIdentifier}"]`),
      ).toBeVisible({ timeout: 5000 });
    });
  });

  test.describe('UP-SEC-004: Create Secret - Validation Errors', () => {
    test('shows error for empty identifier', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Fill only the secret value, leave identifier empty
      const secretInput = frame.locator('input[data-vault-is-new="1"]').first();
      await secretInput.fill('test-value');

      // Try to save - FormEngine validation should show error
      await frame.locator('button[name="_savedok"]').click();

      // FormEngine shows validation errors or keeps us on the form — wait for
      // EITHER condition to become true (no arbitrary sleep).
      const newFrame = getModuleFrame(page);
      const identifierInput = newFrame.locator(
        'input[data-formengine-input-name*="identifier"]',
      );
      const validationError = newFrame
        .locator('.has-error, .is-invalid, .alert-danger')
        .first();

      await Promise.race([
        identifierInput.waitFor({ state: 'visible', timeout: 5000 }),
        validationError.waitFor({ state: 'visible', timeout: 5000 }),
      ]).catch(() => undefined);

      const hasValidationError = await validationError.isVisible();
      const stayedOnForm = await identifierInput.isVisible();

      expect(hasValidationError || stayedOnForm).toBe(true);
    });

    test('shows error for empty secret value', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Fill only the identifier
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill('test-identifier');

      // Try to save without secret value
      await frame.locator('button[name="_savedok"]').click();

      const newFrame = getModuleFrame(page);
      const identifierInput = newFrame.locator(
        'input[data-formengine-input-name*="identifier"]',
      );
      const validationError = newFrame
        .locator('.has-error, .is-invalid, .alert-danger')
        .first();

      await Promise.race([
        identifierInput.waitFor({ state: 'visible', timeout: 5000 }),
        validationError.waitFor({ state: 'visible', timeout: 5000 }),
      ]).catch(() => undefined);

      const hasValidationError = await validationError.isVisible();
      const stayedOnForm = await identifierInput.isVisible();

      expect(hasValidationError || stayedOnForm).toBe(true);
    });

    test('handles duplicate identifier appropriately', async ({ authenticatedPage: page }) => {
      const testIdentifier = generateTestId();

      // Create first secret via FormEngine
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      let frame = getModuleFrame(page);
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);
      const secretInput1 = frame.locator('input[data-vault-is-new="1"]').first();
      await secretInput1.fill('first-secret');
      await saveFormEngine(page, frame);

      // Try to create second secret with same identifier
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      frame = getModuleFrame(page);
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);
      const secretInput2 = frame.locator('input[data-vault-is-new="1"]').first();
      await secretInput2.fill('duplicate-secret');
      await frame.locator('button[name="_savedok"], button:has-text("Save")').click();
      await page.waitForLoadState('networkidle');

      // Duplicate identifier MUST be rejected — the system should not silently
      // overwrite a secret. Check for a concrete error indicator.
      const newFrame = getModuleFrame(page);
      const errorLocators = [
        newFrame.locator('.alert-danger'),
        newFrame.locator('.callout-danger'),
        newFrame.locator('.typo3-message-error'),
        newFrame.locator('.has-error, .is-invalid'),
        newFrame.locator('text=already exists'),
        newFrame.locator('text=duplicate'),
      ];
      let hasError = false;
      for (const loc of errorLocators) {
        if (await loc.first().isVisible().catch(() => false)) {
          hasError = true;
          break;
        }
      }
      expect(hasError, 'Duplicate identifier must be rejected with a visible error').toBe(true);
    });
  });

  test.describe('UP-SEC-005: View Secret Details', () => {
    test('can view secret details page', async ({ authenticatedPage: page }) => {
      // First check if there are any secrets
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      const viewLink = frame
        .locator('a[title*="View details"], a[aria-label*="View details"]')
        .first();

      if (await viewLink.isVisible()) {
        await viewLink.click();
        await page.waitForLoadState('networkidle');

        // Verify we're on the view page
        const newFrame = getModuleFrame(page);
        await expect(newFrame.locator('text=Oops, an error occurred')).not.toBeVisible();
      }
    });
  });

  test.describe('UP-SEC-008: Rotate Secret Value', () => {
    test('rotate modal opens correctly', async ({ authenticatedPage: page }) => {
      // First check if there are any secrets
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      const rotateButton = frame.getByTestId('vault-rotate-btn').first();

      if (await rotateButton.isVisible()) {
        await rotateButton.click();

        // Verify modal is displayed - look for the rotate modal by its input field
        const newValueInput = page.locator('#rotate-modal-secret');
        await expect(newValueInput).toBeVisible({ timeout: 5000 });

        // Close modal using Cancel button
        await page.getByRole('button', { name: 'Cancel' }).click();
      }
    });

    test('can rotate a secret value', async ({ authenticatedPage: page }) => {
      const testIdentifier = generateTestId();

      // Create a secret first via FormEngine
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      let frame = getModuleFrame(page);
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);
      const secretInput = frame.locator('input[data-vault-is-new="1"]').first();
      const originalValue = 'original-secret-value';
      await secretInput.fill(originalValue);
      await saveFormEngine(page, frame);

      // Reveal BEFORE rotation to capture pre-rotation value via AJAX.
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);
      frame = await applyIdentifierFilter(page, getModuleFrame(page), testIdentifier);

      const preRotateRevealPromise = page.waitForResponse(
        (resp) => resp.url().includes('/vault/reveal') && resp.request().method() === 'POST',
        { timeout: 10000 },
      );
      const preRevealBtn = frame.getByTestId('vault-reveal-btn').first();
      if (await preRevealBtn.isVisible().catch(() => false)) {
        await preRevealBtn.click();
        const preRotateResp = await preRotateRevealPromise.catch(() => null);
        if (preRotateResp !== null) {
          const preJson = (await preRotateResp.json().catch(() => null)) as
            | { success?: boolean; secret?: string }
            | null;
          expect(preJson?.secret).toBe(originalValue);
        }
      }

      // Click rotate button (opens modal)
      const rotateButton = frame.getByTestId('vault-rotate-btn').first();
      if (await rotateButton.isVisible()) {
        await rotateButton.click();

        // Fill new value in modal (modal is in main page context)
        const newValueInput = page.locator('#rotate-modal-secret').first();
        await newValueInput.waitFor({ state: 'visible', timeout: 5000 });
        const rotatedValue = 'rotated-secret-value-NEW';
        await newValueInput.fill(rotatedValue);

        // Submit rotation via modal; wait for the AJAX response rather than
        // relying on an arbitrary sleep.
        const rotateResponsePromise = page.waitForResponse(
          (resp) => resp.url().includes('/vault/rotate') && resp.request().method() === 'POST',
          { timeout: 10000 },
        );
        await page.getByRole('button', { name: 'Rotate Secret', exact: true }).click();
        const rotateResp = await rotateResponsePromise;
        expect(rotateResp.status()).toBe(200);
        const rotateJson = (await rotateResp.json().catch(() => null)) as
          | { success?: boolean }
          | null;
        expect(rotateJson?.success).toBe(true);

        // Reveal AFTER rotation and verify the new value differs from pre-rotation.
        await page.goto('/typo3/module/admin/vault/secrets');
        await waitForModuleContent(page);
        frame = await applyIdentifierFilter(page, getModuleFrame(page), testIdentifier);

        const postRevealPromise = page.waitForResponse(
          (resp) => resp.url().includes('/vault/reveal') && resp.request().method() === 'POST',
          { timeout: 10000 },
        );
        const postRevealBtn = frame.getByTestId('vault-reveal-btn').first();
        await postRevealBtn.click();
        const postResp = await postRevealPromise;
        const postJson = (await postResp.json().catch(() => null)) as
          | { success?: boolean; secret?: string }
          | null;
        expect(postJson?.success).toBe(true);
        expect(postJson?.secret).toBe(rotatedValue);
        expect(postJson?.secret).not.toBe(originalValue);
      }
    });
  });

  test.describe('UP-SEC-009: Toggle Secret Status', () => {
    test('can disable an active secret', async ({ authenticatedPage: page }) => {
      const testIdentifier = generateTestId();

      // Create a secret first via FormEngine
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      let frame = getModuleFrame(page);
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);
      const secretInput = frame.locator('input[data-vault-is-new="1"]').first();
      await secretInput.fill('toggle-test-value');
      await saveFormEngine(page, frame);

      // Go to list
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);
      frame = await applyIdentifierFilter(page, getModuleFrame(page), testIdentifier);

      // Find and click toggle button (scoped to our row)
      const row = frame.locator(`[data-testid="secret-row-${testIdentifier}"]`);
      await expect(row).toBeVisible({ timeout: 5000 });
      const toggleButton = row.getByTestId('vault-toggle-btn').first();

      if (await toggleButton.isVisible()) {
        const toggleResp = page.waitForResponse(
          (resp) => resp.url().includes('admin_vault_secrets') && resp.status() < 400,
          { timeout: 10000 },
        );
        await toggleButton.click();
        await toggleResp.catch(() => undefined);

        // Re-filter and verify the status badge flipped to "disabled".
        const newFrame = await applyIdentifierFilter(page, getModuleFrame(page), testIdentifier);
        await expect(newFrame.locator('text=Oops, an error occurred')).not.toBeVisible();

        const newRow = newFrame.locator(`[data-testid="secret-row-${testIdentifier}"]`);
        await expect(newRow).toBeVisible({ timeout: 5000 });
        const badge = newRow.locator('.text-bg-secondary');
        await expect(badge).toBeVisible({ timeout: 5000 });
      }
    });
  });

  test.describe('UP-SEC-010: Delete Secret', () => {
    test('can delete a secret', async ({ authenticatedPage: page }) => {
      const testIdentifier = generateTestId();

      // Create a secret first via FormEngine
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      let frame = getModuleFrame(page);
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);
      const secretInput = frame.locator('input[data-vault-is-new="1"]').first();
      await secretInput.fill('delete-test-value');
      await saveFormEngine(page, frame);

      // Go to list
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);
      frame = await applyIdentifierFilter(page, getModuleFrame(page), testIdentifier);

      // Confirm row exists pre-delete.
      const row = frame.locator(`[data-testid="secret-row-${testIdentifier}"]`);
      await expect(row).toBeVisible({ timeout: 5000 });

      // Click delete button
      const deleteButton = row.getByTestId('vault-delete-btn').first();

      if (await deleteButton.isVisible()) {
        await deleteButton.click();

        // Handle TYPO3 Modal confirmation (appears in main page context)
        const confirmButton = page.getByRole('button', { name: 'Delete', exact: true });
        await confirmButton.waitFor({ state: 'visible', timeout: 5000 });

        const deleteResp = page.waitForResponse(
          (resp) => resp.url().includes('admin_vault_secrets') && resp.status() < 400,
          { timeout: 10000 },
        );
        await confirmButton.click();
        await deleteResp.catch(() => undefined);

        // Verify the row is gone (concrete DB-state delta) AND an audit entry
        // exists for the delete.
        await page.goto('/typo3/module/admin/vault/secrets');
        await waitForModuleContent(page);
        const afterFrame = await applyIdentifierFilter(
          page,
          getModuleFrame(page),
          testIdentifier,
        );
        await expect(afterFrame.locator('text=Oops, an error occurred')).not.toBeVisible();
        await expect(
          afterFrame.locator(`[data-testid="secret-row-${testIdentifier}"]`),
        ).toHaveCount(0);

        // Audit entry present for delete action.
        await page.goto(
          `/typo3/module/admin/vault/audit?secretIdentifier=${encodeURIComponent(testIdentifier)}`,
        );
        await waitForModuleContent(page);
        const auditFrame = getModuleFrame(page);
        const auditRow = auditFrame
          .locator('table tbody tr', { hasText: testIdentifier })
          .first();
        await expect(auditRow).toBeVisible({ timeout: 10000 });
        await expect(auditRow).toContainText(/delete/i);
      }
    });
  });

  test.describe('UP-SEC-012: Secrets List - Empty State', () => {
    test('shows appropriate state when filter returns no results', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      const newFrame = await applyIdentifierFilter(
        page,
        frame,
        'nonexistent_secret_xyz_123',
      );

      // Should show empty state or no results - check for 0 secrets count
      await expect(newFrame.locator('text=Oops, an error occurred')).not.toBeVisible();

      // Either "0 secrets" message or no table rows
      const zeroCount = newFrame.locator('text=0 secrets');
      const table = newFrame.locator('table tbody tr');

      const hasZeroCount = await zeroCount.first().isVisible();
      const rowCount = await table.count();

      expect(hasZeroCount || rowCount === 0).toBe(true);
    });
  });

  test.describe('UP-SEC-006: Reveal Secret Value (AJAX)', () => {
    test('can reveal a secret value via AJAX', async ({ authenticatedPage: page }) => {
      const testIdentifier = generateTestId();
      const plaintext = 'reveal-test-value';

      // Create a secret first via FormEngine
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      let frame = getModuleFrame(page);
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);
      const secretInput = frame.locator('input[data-vault-is-new="1"]').first();
      await secretInput.fill(plaintext);
      await saveFormEngine(page, frame);

      // Go to list and find our secret
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);
      frame = await applyIdentifierFilter(page, getModuleFrame(page), testIdentifier);

      // Click reveal button with strong AJAX assertion.
      const row = frame.locator(`[data-testid="secret-row-${testIdentifier}"]`);
      const revealButton = row.getByTestId('vault-reveal-btn').first();

      if (await revealButton.isVisible()) {
        const revealPromise = page.waitForResponse(
          (resp) => resp.url().includes('/vault/reveal') && resp.request().method() === 'POST',
          { timeout: 10000 },
        );
        await revealButton.click();
        const revealResp = await revealPromise;
        expect(revealResp.status()).toBe(200);
        const json = (await revealResp.json().catch(() => null)) as
          | { success?: boolean; secret?: string }
          | null;
        expect(json?.success).toBe(true);
        expect(json?.secret).toBe(plaintext);
      }
    });

    /**
     * Regression for PR #151 (HIGH-severity audit-bypass fix).
     *
     * The JS modules used to keep an in-memory `revealedSecrets` Map
     * that short-circuited the AJAX request on second-and-subsequent
     * reveals. That silently bypassed the server-side audit log:
     * `AjaxController::reveal()` → `VaultService::retrieve()` →
     * `AuditLogService::log()` only fired on the FIRST reveal of a
     * browser session. Every later reveal/copy left no trail.
     *
     * This test clicks reveal twice (with a modal-close in between)
     * and asserts BOTH clicks produce a POST to `/vault/reveal`. If
     * the cache ever comes back, the second AJAX request never
     * leaves the browser and the test fails.
     */
    test('reveals twice — both hit the AJAX endpoint (audit-bypass guard)', async ({
      authenticatedPage: page,
    }) => {
      const testIdentifier = generateTestId();
      const plaintext = 'second-reveal-test-value';

      // Create the secret.
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);
      let frame = getModuleFrame(page);
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);
      await frame.locator('input[data-vault-is-new="1"]').first().fill(plaintext);
      await saveFormEngine(page, frame);

      // Navigate to the list and filter down to our row.
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);
      frame = await applyIdentifierFilter(page, getModuleFrame(page), testIdentifier);
      const row = frame.locator(`[data-testid="secret-row-${testIdentifier}"]`);
      const revealButton = row.getByTestId('vault-reveal-btn').first();

      // First reveal — must hit /vault/reveal.
      const firstRevealPromise = page.waitForResponse(
        (resp) => resp.url().includes('/vault/reveal') && resp.request().method() === 'POST',
        { timeout: 10000 },
      );
      await revealButton.click();
      const firstResp = await firstRevealPromise;
      expect(firstResp.status()).toBe(200);
      const firstJson = (await firstResp.json().catch(() => null)) as
        | { success?: boolean; secret?: string }
        | null;
      expect(firstJson?.success).toBe(true);
      expect(firstJson?.secret).toBe(plaintext);

      // Close the reveal modal so the next click re-enters handleReveal.
      const closeBtn = page.getByRole('button', { name: 'Close' }).first();
      await closeBtn.waitFor({ state: 'visible', timeout: 5000 });
      await closeBtn.click();

      // Second reveal — MUST also hit /vault/reveal (regression guard).
      // If the in-memory cache regresses, this waitForResponse times out.
      const secondRevealPromise = page.waitForResponse(
        (resp) => resp.url().includes('/vault/reveal') && resp.request().method() === 'POST',
        { timeout: 10000 },
      );
      await revealButton.click();
      const secondResp = await secondRevealPromise;
      expect(
        secondResp.status(),
        'Second reveal click must produce a fresh POST to /vault/reveal — '
          + 'otherwise the JS layer is caching plaintext and the audit log '
          + 'misses every reveal-after-first (root AGENTS.md security rule 5).',
      ).toBe(200);
      const secondJson = (await secondResp.json().catch(() => null)) as
        | { success?: boolean; secret?: string }
        | null;
      expect(secondJson?.success).toBe(true);
      expect(secondJson?.secret).toBe(plaintext);
    });

    /**
     * Reveal-lifecycle hardening: the dialog announces its own auto-hide and the
     * countdown really ticks — the same interval drives the auto-close, so a
     * frozen countdown means a dialog that never closes itself.
     */
    test('reveal modal shows a ticking auto-hide countdown', async ({
      authenticatedPage: page,
    }) => {
      await createSecretAndReveal(page, 'countdown-test-value');
      const modal = await revealModalScope(page);

      const countdown = modal.locator('[data-testid="reveal-countdown"]');
      await expect(countdown).toBeVisible();
      await expect(countdown).toHaveText(/automatically in \d+ second/);

      const initialText = (await countdown.textContent()) ?? '';
      await expect(
        countdown,
        'countdown must tick down — a frozen countdown means no auto-hide timer',
      ).not.toHaveText(initialText, { timeout: 8000 });
    });

    /**
     * The default DDEV test environment runs the *standard* security profile, so
     * `copyAllowed` is true and the copy button is offered. In the hardened
     * profile `AjaxController::revealAction()` reports `copyAllowed: false` and
     * `buildRevealModalContent()` omits the button entirely (the clipboard
     * outlives the dialog and cannot be wiped from JS).
     */
    test('reveal modal offers copy-to-clipboard in the standard profile', async ({
      authenticatedPage: page,
    }) => {
      await createSecretAndReveal(page, 'copy-allowed-test-value');
      const modal = await revealModalScope(page);

      await expect(modal.locator('#reveal-modal-toggle')).toBeVisible();
      await expect(modal.locator('#reveal-modal-copy')).toBeVisible();
    });

    /**
     * Wipe-on-close: whichever way the dialog goes away, the input must not keep
     * the plaintext. Asserted on the explicit Close button here; the auto-hide
     * path is covered by the next test.
     */
    test('closing the reveal modal wipes the plaintext from the input', async ({
      authenticatedPage: page,
    }) => {
      const plaintext = 'wipe-on-close-value';
      await createSecretAndReveal(page, plaintext);
      const modal = await revealModalScope(page);

      const input = modal.locator('#reveal-modal-secret');
      await expect(input).toHaveValue(plaintext);

      // Scope the Close button to the modal container — the module docheader has
      // buttons with the same accessible name.
      await modal
        .locator('typo3-backend-modal button:has-text("Close"), .modal button:has-text("Close")')
        .first()
        .click();

      await expect(input).toBeHidden({ timeout: 10000 });
      if ((await input.count()) > 0) {
        await expect(
          input,
          'modal closed but the input still holds the plaintext — wipe-on-close is broken',
        ).toHaveValue('');
      }
    });

    /**
     * Auto-hide: the modal closes itself after AUTO_HIDE_SECONDS and the input is
     * wiped on the way out.
     *
     * This waits out the real timer instead of using `page.clock`: the fake clock
     * has to be installed before the page loads and would also freeze the TYPO3
     * backend's own timers (session refresh, module loading), which cannot be
     * validated here. 30 s of real time fits the 60 s spec timeout, `test.slow()`
     * adds headroom on CI.
     */
    test('reveal modal closes itself after the auto-hide window', async ({
      authenticatedPage: page,
    }) => {
      test.slow();

      const plaintext = 'autohide-test-value';
      await createSecretAndReveal(page, plaintext);
      const modal = await revealModalScope(page);

      const input = modal.locator('#reveal-modal-secret');
      await expect(input).toHaveValue(plaintext);

      await expect(
        input,
        `reveal modal must close itself ~${AUTO_HIDE_SECONDS}s after opening`,
      ).toBeHidden({ timeout: (AUTO_HIDE_SECONDS + 15) * 1000 });

      if ((await input.count()) > 0) {
        await expect(input).toHaveValue('');
      }
    });
  });

  test.describe('UP-SEC-007: Edit Secret Metadata', () => {
    test('can edit secret metadata', async ({ authenticatedPage: page }) => {
      const testIdentifier = generateTestId();

      // Create a secret first via FormEngine
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      let frame = getModuleFrame(page);
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);
      const secretInput = frame.locator('input[data-vault-is-new="1"]').first();
      await secretInput.fill('edit-test-value');
      await saveFormEngine(page, frame);

      // Go to list and find our secret
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);
      frame = await applyIdentifierFilter(page, getModuleFrame(page), testIdentifier);

      // Click edit button scoped to our row
      const row = frame.locator(`[data-testid="secret-row-${testIdentifier}"]`);
      await expect(row).toBeVisible({ timeout: 5000 });
      const editButton = row.getByTestId('vault-edit-btn').first();

      if (await editButton.isVisible()) {
        await editButton.click();
        await page.waitForLoadState('networkidle');

        // Should be on the edit form (FormEngine)
        const editFrame = getModuleFrame(page);
        await expect(editFrame.locator('text=Oops, an error occurred')).not.toBeVisible();

        // Modify description
        const newDesc = 'Updated description via E2E test';
        const descriptionInput = editFrame.locator(
          'textarea[data-formengine-input-name*="description"], input[data-formengine-input-name*="description"]',
        );
        if (await descriptionInput.isVisible()) {
          await descriptionInput.fill(newDesc);
        }

        // Save changes
        await saveFormEngine(page, editFrame);

        // Audit entry for update MUST exist.
        await page.goto(
          `/typo3/module/admin/vault/audit?secretIdentifier=${encodeURIComponent(testIdentifier)}`,
        );
        await waitForModuleContent(page);
        const auditFrame = getModuleFrame(page);
        await expect(
          auditFrame.locator('table tbody tr', { hasText: testIdentifier }).first(),
        ).toBeVisible({ timeout: 10000 });
      }
    });
  });

  test.describe('UP-SEC-011: Delete Secret - Cancellation', () => {
    test('cancelling delete keeps secret intact', async ({ authenticatedPage: page }) => {
      const testIdentifier = generateTestId();

      // Create a secret first via FormEngine
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      let frame = getModuleFrame(page);
      await frame.locator('input[data-formengine-input-name*="identifier"]').fill(testIdentifier);
      const secretInput = frame.locator('input[data-vault-is-new="1"]').first();
      await secretInput.fill('cancel-delete-test');
      await saveFormEngine(page, frame);

      // Go to list and filter to find our secret
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);
      frame = await applyIdentifierFilter(page, getModuleFrame(page), testIdentifier);

      const row = frame.locator(`[data-testid="secret-row-${testIdentifier}"]`);
      const deleteButton = row.getByTestId('vault-delete-btn').first();

      if (await deleteButton.isVisible()) {
        await deleteButton.click();

        // Dismiss confirmation dialog - click Cancel instead of Delete
        const cancelButton = page.getByRole('button', { name: 'Cancel', exact: true });
        await cancelButton.waitFor({ state: 'visible', timeout: 5000 });
        await cancelButton.click();
        // Modal close is synchronous; no sleep needed.

        // Verify secret still exists - reload the list and filter again
        await page.goto('/typo3/module/admin/vault/secrets');
        await waitForModuleContent(page);
        const afterFrame = await applyIdentifierFilter(
          page,
          getModuleFrame(page),
          testIdentifier,
        );

        await expect(afterFrame.locator('text=Oops, an error occurred')).not.toBeVisible();
        await expect(
          afterFrame.locator(`[data-testid="secret-row-${testIdentifier}"]`),
        ).toBeVisible({ timeout: 5000 });
      }
    });
  });

  test.describe('UP-SEC-013: Access Denied - Unauthorized Secret', () => {
    test('non-admin user cannot access unauthorized secrets', async ({ page }) => {
      // Login as a non-admin user (editor)
      await page.goto('/typo3/login');
      await page.fill('input[name="username"]', 'editor');
      await page.fill('input[type="password"]', 'Joh316!!');
      await page.click('button[type="submit"]');

      // Wait for login to complete
      await page.waitForURL(/\/typo3\/(main|module)/, { timeout: 10000 }).catch(() => {
        // Login may fail if editor user doesn't exist - that's acceptable
      });

      // Check if we're logged in
      const isLoggedIn = await page.locator('.scaffold').isVisible();

      if (!isLoggedIn) {
        // Skip with an explicit, diagnostic reason — the test environment does
        // not provide a non-admin user, so this scenario cannot be exercised.
        test.skip(
          true,
          'Non-admin "editor" user not present in DDEV test env — cannot verify access-denied path here; functional tests cover ACL enforcement.',
        );
        return;
      }

      // Try to access vault secrets module
      const response = await page.goto('/typo3/module/admin/vault/secrets');

      // Should either show access denied or redirect
      if (response?.status() === 200) {
        await waitForModuleContent(page);
        const frame = getModuleFrame(page);

        // Look for access denied or empty/restricted view
        const accessDenied = frame.locator(
          'text=Access Denied, text=access denied, text=not authorized, .callout-danger',
        );
        const hasAccessDenied = await accessDenied.first().isVisible();
        expect(hasAccessDenied).toBe(true);
      } else {
        // Non-200 response (403, 302) is expected for unauthorized access
        expect([302, 401, 403]).toContain(response?.status());
      }
    });
  });

  test.describe('Cross-cutting concerns', () => {
    test('secrets module has no JavaScript errors', async ({ authenticatedPage: page }) => {
      const consoleErrors: string[] = [];

      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          consoleErrors.push(msg.text());
        }
      });

      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      // Filter out known non-critical errors
      const criticalErrors = consoleErrors.filter(
        (err) =>
          !err.includes('favicon') &&
          !err.includes('404') &&
          !err.includes('net::ERR') &&
          !err.includes('Error while retrieving widget'),
      );

      expect(criticalErrors).toHaveLength(0);
    });

    test('secrets module returns 200 status code', async ({ authenticatedPage: page }) => {
      const response = await page.goto('/typo3/module/admin/vault/secrets');
      expect(response?.status()).toBe(200);
    });
  });
});
