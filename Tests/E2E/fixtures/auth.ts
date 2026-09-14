import { test as base, expect, Page, FrameLocator } from '@playwright/test';

/**
 * Backend admin credentials. The defaults are the DDEV instance's
 * (.ddev/commands/web/install-v14); CI provisions its own throwaway instance
 * and passes the same values through the environment
 * (Build/Scripts/e2e-provision.sh). Never point these at a real installation.
 */
export const ADMIN_USERNAME = process.env.E2E_ADMIN_USERNAME || 'admin';
export const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD || 'Joh316!!';

/**
 * Extended test fixture with TYPO3 backend authentication.
 *
 * TYPO3 v14 uses an iframe-based backend structure where module content
 * is rendered inside an iframe. This fixture provides both the main page
 * and a frame locator for accessing module content.
 */
export const test = base.extend<{
  authenticatedPage: Page;
  moduleFrame: FrameLocator;
}>({
  authenticatedPage: async ({ page }, use) => {
    // Login to TYPO3 backend
    await page.goto('/typo3/login');

    // Fill login form
    await page.fill('input[name="username"]', ADMIN_USERNAME);
    // TYPO3 uses a visible password field with type="password"
    await page.fill('input[type="password"]', ADMIN_PASSWORD);

    // Submit login
    await page.click('button[type="submit"]');

    // Wait for redirect to backend
    await page.waitForURL(/\/typo3\/(main|module)/);

    // Verify we're logged in
    await expect(page.locator('.scaffold')).toBeVisible();

    await use(page);
  },

  moduleFrame: async ({ authenticatedPage }, use) => {
    // TYPO3 v14 uses an iframe for module content
    // Wait for the iframe to be present
    const frame = authenticatedPage.frameLocator('iframe').first();
    await use(frame);
  },
});

export { expect };

/**
 * Helper to get the module content frame from a page.
 * TYPO3 v14 renders module content inside an iframe.
 */
export function getModuleFrame(page: Page): FrameLocator {
  return page.frameLocator('iframe').first();
}

/**
 * Wait for the module content to load within the iframe.
 */
export async function waitForModuleContent(page: Page): Promise<void> {
  const frame = getModuleFrame(page);
  // Wait for any heading or content to be visible
  try {
    await frame.locator('h1, .module-body, .module-docheader').first().waitFor({ timeout: 10000 });
  } catch {
    // If no content found, that's okay - module might have different structure
  }
}
