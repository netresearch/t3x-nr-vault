import { test, expect, getModuleFrame } from './fixtures/auth';

/**
 * E2E tests for the Vault backend module.
 *
 * Primary goal: Catch runtime errors (500/503) that would affect users.
 * These tests verify the module loads without throwing exceptions.
 */
test.describe('Vault Backend Module', () => {
  test('parent module shows submodule overview', async ({ authenticatedPage: page }) => {
    const response = await page.goto('/typo3/module/admin/vault');

    expect(response?.status()).toBe(200);
    await expect(page).toHaveTitle(/vault/i);
    await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
    await expect(page.locator('text=503')).not.toBeVisible();
  });

  test('secrets submodule list page loads without errors', async ({ authenticatedPage: page }) => {
    const response = await page.goto('/typo3/module/admin/vault/secrets');

    expect(response?.status()).toBe(200);
    await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
  });

  test('create secret page loads without errors', async ({ authenticatedPage: page }) => {
    const response = await page.goto('/typo3/module/admin/vault/secrets/create');

    expect(response?.status()).toBe(200);
    await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
  });

  test('view secret page loads without errors when secret exists', async ({ authenticatedPage: page }) => {
    // First check if there's a secret to view
    await page.goto('/typo3/module/admin/vault/secrets');
    const viewLink = page.locator('a[title="View details"]').first();

    if (await viewLink.isVisible()) {
      await viewLink.click();
      await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
    }
  });

  test('audit submodule page loads without errors', async ({ authenticatedPage: page }) => {
    const response = await page.goto('/typo3/module/admin/vault/audit');

    expect(response?.status()).toBe(200);
    await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
  });

  test('secrets submodule handles empty list gracefully', async ({ authenticatedPage: page }) => {
    const response = await page.goto('/typo3/module/admin/vault/secrets');

    expect(response?.status()).toBe(200);
    await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
  });

  test('audit submodule handles empty log gracefully', async ({ authenticatedPage: page }) => {
    const response = await page.goto('/typo3/module/admin/vault/audit');

    expect(response?.status()).toBe(200);
    await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
  });

  test('export action returns valid response', async ({ authenticatedPage: page }) => {
    const response = await page.goto('/typo3/module/admin/vault/audit/export?format=json');

    expect(response?.status()).toBe(200);
  });

  test('verify chain action does not crash', async ({ authenticatedPage: page }) => {
    const response = await page.goto('/typo3/module/admin/vault/audit/verifyChain');

    expect(response?.status()).toBeLessThan(500);
  });

  test('invalid route returns error gracefully', async ({ authenticatedPage: page }) => {
    const response = await page.goto('/typo3/module/admin/vault/nonexistent');

    expect(response?.status()).toBeLessThan(500);
    await expect(getModuleFrame(page).locator('text=Oops, an error occurred')).not.toBeVisible();
  });
});
