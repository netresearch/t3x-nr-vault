import { test, expect, getModuleFrame, waitForModuleContent } from './fixtures/auth';

test.describe('Vault Analytics', () => {
  test('analytics submodule renders KPIs and candidates table', async ({ authenticatedPage: page }) => {
    const response = await page.goto('/typo3/module/admin/vault/analytics');
    expect(response?.status()).toBe(200);
    await waitForModuleContent(page);

    const frame = getModuleFrame(page);
    await expect(frame.locator('[data-testid="analytics-kpis"]')).toBeVisible();
    await expect(frame.locator('[data-testid="kpi-candidates"]')).toBeVisible();
    await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
  });

  test('window selector switches the active button', async ({ authenticatedPage: page }) => {
    await page.goto('/typo3/module/admin/vault/analytics?window=30');
    await waitForModuleContent(page);

    const frame = getModuleFrame(page);
    await expect(frame.locator('a.btn-primary')).toContainText('30d');
  });
});
