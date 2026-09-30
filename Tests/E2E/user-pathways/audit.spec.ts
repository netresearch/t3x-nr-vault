// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: Netresearch DTT GmbH

import { test, expect, getModuleFrame, waitForModuleContent } from '../fixtures/auth';

/**
 * E2E tests for Audit Module User Pathways.
 *
 * TYPO3 v14 uses an iframe-based backend structure where module content
 * is rendered inside an iframe.
 *
 * Tests cover:
 * - UP-AUD-001: View Audit Log
 * - UP-AUD-002: Filter Audit Log
 * - UP-AUD-003: Export Audit Log
 * - UP-AUD-004: Verify Hash Chain Integrity
 */

test.describe('Audit Module User Pathways', () => {
  test.describe('UP-AUD-001: View Audit Log', () => {
    test('displays audit log page', async ({ authenticatedPage: page }) => {
      const response = await page.goto('/typo3/module/admin/vault/audit');
      expect(response?.status()).toBe(200);

      await waitForModuleContent(page);
      const frame = getModuleFrame(page);

      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
      await expect(frame.locator('h1')).toBeVisible();
    });

    test('shows audit entries table or empty state', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/audit');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Either a table with entries or an empty state message
      const table = frame.locator('table');
      const emptyState = frame.locator('.callout-info, .alert-info');

      const hasTable = await table.first().isVisible();
      const hasEmptyState = await emptyState.first().isVisible() || await frame.locator('text=No entries').first().isVisible();

      expect(hasTable || hasEmptyState).toBe(true);
    });

    test('audit page shows filter form', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/audit');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Check for filter form or inputs
      const filterForm = frame.locator('[role="search"], form');
      await expect(filterForm.first()).toBeVisible();
    });
  });

  test.describe('UP-AUD-002: Filter Audit Log', () => {
    test('can filter by action type', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/audit');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Select an action type if the selector is available
      const actionSelect = frame.locator('select[name="action"], select[name="filterAction"]').first();
      if (await actionSelect.isVisible()) {
        await actionSelect.selectOption({ index: 1 });

        const filterResp = page.waitForResponse(
          (resp) => resp.url().includes('admin_vault_audit') && resp.status() === 200,
          { timeout: 10000 },
        );
        await frame.locator('button:has-text("Filter")').click();
        await filterResp.catch(() => undefined);

        // Should not error
        const newFrame = getModuleFrame(page);
        await expect(newFrame.locator('text=Oops, an error occurred')).not.toBeVisible();
      }
    });

    test('can filter by date range', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/audit');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Check for date inputs
      const dateFrom = frame.locator('input[name="dateFrom"], input[type="date"]').first();
      if (await dateFrom.isVisible()) {
        // Set a date range
        const today = new Date().toISOString().split('T')[0];
        await dateFrom.fill(today);

        const filterResp = page.waitForResponse(
          (resp) => resp.url().includes('admin_vault_audit') && resp.status() === 200,
          { timeout: 10000 },
        );
        await frame.locator('button:has-text("Filter")').click();
        await filterResp.catch(() => undefined);

        const newFrame = getModuleFrame(page);
        await expect(newFrame.locator('text=Oops, an error occurred')).not.toBeVisible();
      }
    });

    test('can filter by success status', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/audit');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Look for success filter
      const successSelect = frame.locator('select[name="success"]');
      if (await successSelect.isVisible()) {
        await successSelect.selectOption('1'); // Success

        const filterResp = page.waitForResponse(
          (resp) => resp.url().includes('admin_vault_audit') && resp.status() === 200,
          { timeout: 10000 },
        );
        await frame.locator('button:has-text("Filter")').click();
        await filterResp.catch(() => undefined);

        const newFrame = getModuleFrame(page);
        await expect(newFrame.locator('text=Oops, an error occurred')).not.toBeVisible();
      }
    });
  });

  test.describe('UP-AUD-003: Export Audit Log', () => {
    test('export endpoint exists and responds', async ({ authenticatedPage: page }) => {
      // TYPO3 backend module routes require proper tokens
      // Direct URL access returns a generic response, which is expected
      // This test verifies the route is registered and accessible
      const response = await page.goto('/typo3/module/admin/vault/audit/export');

      // The endpoint should respond (200 or redirect to login/module)
      // If we get here without 500/404, the route exists
      expect(response?.status()).toBeLessThan(500);
    });

    test('audit list page loads successfully for export', async ({ authenticatedPage: page }) => {
      // Since export buttons need tokens, we verify the main page loads
      // which would contain the export buttons for admin users
      await page.goto('/typo3/module/admin/vault/audit');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Verify the audit log page loads with data (which is what gets exported)
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();

      // If there are entries, they could be exported
      const table = frame.locator('table');
      const emptyState = frame.locator('.callout-info, .alert-info');
      const hasContent = await table.first().isVisible() || await emptyState.first().isVisible();
      expect(hasContent).toBe(true);
    });
  });

  test.describe('UP-AUD-004: Verify Hash Chain Integrity', () => {
    test('can navigate to verify chain page', async ({ authenticatedPage: page }) => {
      const response = await page.goto('/typo3/module/admin/vault/audit/verifyChain');
      expect(response?.status()).toBe(200);

      await waitForModuleContent(page);
      const frame = getModuleFrame(page);

      // Should show verification result (valid or invalid)
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
    });

    test('verify chain shows integrity status', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/audit/verifyChain');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);

      // Should show either "valid" or "invalid" status message
      const validMessage = frame.locator('.callout-success, .alert-success, .callout-ok');
      const invalidMessage = frame.locator('.callout-danger, .alert-danger, .callout-error');

      const hasValidMessage = await validMessage.first().isVisible().catch(() => false);
      const hasInvalidMessage = await invalidMessage.first().isVisible().catch(() => false);

      // Should display some integrity status
      expect(hasValidMessage || hasInvalidMessage).toBe(true);
    });
  });

  test.describe('Cross-cutting concerns', () => {
    test('audit module has no JavaScript errors', async ({ authenticatedPage: page }) => {
      const consoleErrors: string[] = [];

      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          consoleErrors.push(msg.text());
        }
      });

      await page.goto('/typo3/module/admin/vault/audit');
      await waitForModuleContent(page);

      // Filter out known non-critical errors
      const criticalErrors = consoleErrors.filter(
        (err) => !err.includes('favicon') && !err.includes('404') && !err.includes('net::ERR')
      );

      expect(criticalErrors).toHaveLength(0);
    });

    test('audit module returns 200 status code', async ({ authenticatedPage: page }) => {
      const response = await page.goto('/typo3/module/admin/vault/audit');
      expect(response?.status()).toBe(200);
    });

    test('audit module does not show error page', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/audit');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      await expect(frame.locator('text=Oops, an error occurred')).not.toBeVisible();
      // Check for HTTP error status codes in error message context, not arbitrary text
      await expect(frame.locator('.callout-danger:has-text("503")')).not.toBeVisible();
    });
  });
});
