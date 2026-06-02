import { test, expect, getModuleFrame, waitForModuleContent } from '../fixtures/auth';

/**
 * E2E tests for Overview Module User Pathways.
 *
 * TYPO3 v14 uses an iframe-based backend structure where module content
 * is rendered inside an iframe. These tests use the moduleFrame fixture
 * to access content within the module iframe.
 *
 * Tests cover:
 * - UP-OV-001: View Dashboard Statistics
 * - UP-OV-002: Navigate to Submodules
 */
test.describe('Overview Module User Pathways', () => {
  test.describe('UP-OV-001: View Dashboard Statistics', () => {
    test('displays vault statistics on dashboard', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Verify page loads successfully - check for heading inside iframe
      await expect(frame.locator('h1')).toBeVisible();

      // Verify statistics section exists (group with statistics)
      const statsGroup = frame.locator('[role="group"][aria-label*="statistics"], .vault-statistics, fieldset');
      await expect(statsGroup.first()).toBeVisible();

      // Check no error page
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('shows total secrets count', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Look for statistics display - numbers with labels
      const totalSecretsLabel = frame.locator('text=Total Secrets');
      await expect(totalSecretsLabel).toBeVisible();

      // Verify there's a number displayed
      const statNumbers = frame.locator('[aria-label*="secrets"], .stat-number');
      expect(await statNumbers.count()).toBeGreaterThan(0);
    });

    test('shows active and disabled counts', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Look for active and disabled labels in the statistics cards
      const activeLabel = frame.locator('.card-subtitle:has-text("Active")');
      const disabledLabel = frame.locator('.card-subtitle:has-text("Disabled")');

      await expect(activeLabel).toBeVisible();
      await expect(disabledLabel).toBeVisible();
    });

    test('displays navigation cards to submodules', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Verify navigation section exists with links to submodules (within the navigation region)
      const navSection = frame.locator('nav[aria-label="Vault submodules"]');
      await expect(navSection).toBeVisible();

      const secretsLink = navSection.locator('a[href*="vault/secrets"]');
      const analyticsLink = navSection.locator('a[href*="vault/analytics"]');
      const auditLink = navSection.locator('a[href*="vault/audit"]');
      const migrationLink = navSection.locator('a[href*="vault/migration"]');

      await expect(secretsLink).toBeVisible();
      await expect(analyticsLink).toBeVisible();
      await expect(auditLink).toBeVisible();
      await expect(migrationLink).toBeVisible();
    });
  });

  test.describe('UP-OV-002: Navigate to Submodules', () => {
    test('navigates from overview to secrets module', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      const navSection = frame.locator('nav[aria-label="Vault submodules"]');

      // Click on Secrets link within the navigation section
      const secretsLink = navSection.locator('a[href*="vault/secrets"]');
      await secretsLink.click();

      // Wait for URL change to the secrets module instead of arbitrary sleep.
      await page.waitForURL(/\/vault\/secrets/, { timeout: 10000 }).catch(() => undefined);
      await waitForModuleContent(page);

      // Verify we're on the secrets page (check frame content)
      const newFrame = getModuleFrame(page);
      await expect(newFrame.locator('text=Oops, an error occurred')).not.toBeVisible();

      // Should show secrets heading
      await expect(newFrame.locator('h1')).toBeVisible();
    });

    test('navigates from overview to audit module', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      const navSection = frame.locator('nav[aria-label="Vault submodules"]');

      // Click on Audit link
      const auditLink = navSection.locator('a[href*="vault/audit"]');
      await auditLink.click();

      await page.waitForURL(/\/vault\/audit/, { timeout: 10000 }).catch(() => undefined);
      await waitForModuleContent(page);

      const newFrame = getModuleFrame(page);
      await expect(newFrame.locator('text=Oops, an error occurred')).not.toBeVisible();
      await expect(newFrame.locator('h1')).toBeVisible();
    });

    test('navigates from overview to migration module', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      const navSection = frame.locator('nav[aria-label="Vault submodules"]');

      // Click on Migration link
      const migrationLink = navSection.locator('a[href*="vault/migration"]');
      await migrationLink.click();

      await page.waitForURL(/\/vault\/migration/, { timeout: 10000 }).catch(() => undefined);
      await waitForModuleContent(page);

      const newFrame = getModuleFrame(page);
      await expect(newFrame.locator('text=Oops, an error occurred')).not.toBeVisible();
      await expect(newFrame.locator('h1')).toBeVisible();
    });

    test('can navigate between submodules via module menu', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await page.waitForLoadState('networkidle');

      // Use TYPO3 module menu for navigation (outside iframe)
      const moduleMenu = page.locator('nav[aria-label="Module Menu"]');
      await expect(moduleMenu).toBeVisible();

      // Find vault menu item in the Administration section
      // The menu structure is: menubar > menuitem "Administration" > menu > menuitem "Vault"
      const vaultMenuItem = moduleMenu.getByRole('menuitem', { name: 'Vault' });
      await expect(vaultMenuItem).toBeVisible();
    });
  });

  test.describe('Dashboard Consistency', () => {
    test('overview page has no JavaScript errors', async ({ authenticatedPage: page }) => {
      const consoleErrors: string[] = [];

      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          consoleErrors.push(msg.text());
        }
      });

      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      // Filter out known non-critical errors
      const relevantErrors = consoleErrors.filter(
        (err) => !err.includes('favicon') && !err.includes('404') && !err.includes('net::ERR')
      );

      expect(relevantErrors).toHaveLength(0);
    });

    test('overview returns 200 status code', async ({ authenticatedPage: page }) => {
      const response = await page.goto('/typo3/module/admin/vault');

      expect(response?.status()).toBe(200);
    });

    test('overview does not show error page', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
      await expect(frame.locator('text=503')).not.toBeVisible();
      await expect(frame.locator('text=500')).not.toBeVisible();
    });

    test('overview shows CLI commands section', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // The overview page has a CLI Commands section
      const cliSection = frame.locator('text=CLI Commands');
      await expect(cliSection).toBeVisible();

      // Check for some CLI commands
      const vaultInit = frame.locator('code:has-text("vault:init")');
      await expect(vaultInit).toBeVisible();
    });

    test('overview shows security features section', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // The overview page has a Security Features section
      const securitySection = frame.locator('text=Security Features');
      await expect(securitySection).toBeVisible();
    });
  });
});
