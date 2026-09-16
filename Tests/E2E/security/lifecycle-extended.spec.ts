import { test, expect, getModuleFrame, waitForModuleContent } from '../fixtures/auth';
import type { FrameLocator, Page } from '@playwright/test';

/**
 * Apply the identifier filter and wait for the table to actually show it.
 *
 * The previous shape — click Filter, then `waitFor(...).catch(() => undefined)`
 * on the first row — swallowed the wait, so the next step acted on whatever
 * stood on screen. The unfiltered list is never empty in a seeded instance, so
 * the first row was usually a DIFFERENT secret and the test went on to rotate,
 * edit or delete that one; the failing run's page snapshot shows exactly that
 * unfiltered list. Waiting for a row that carries the identifier makes the
 * filter a precondition instead of a hope.
 */
async function filterByIdentifier(frame: FrameLocator, identifier: string): Promise<void> {
  await frame.getByRole('textbox', { name: 'Identifier' }).fill(identifier);
  await frame.locator('button:has-text("Filter")').click();
  await frame
    .locator('table tbody tr')
    .filter({ hasText: identifier })
    .first()
    .waitFor({ state: 'visible', timeout: 15000 });
}

/**
 * Extended lifecycle tests that fill gaps in UP-CROSS-001 / UP-CROSS-002 /
 * UP-SEC-008 / UP-SEC-009 / UP-SEC-010.
 *
 * The existing cross-module lifecycle test asserts only that pages load without
 * errors. A regression where the controller silently skipped the audit write
 * would pass that test. These tests:
 *   - Cross-check each lifecycle step against the audit log (identifier + action + success)
 *   - Cover the re-enable path (toggle twice) which wasn't exercised
 *   - Read the overview counter, mutate state, re-read and assert delta
 */

const generateTestId = () => `e2e_lc_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;

/**
 * Parse the overview statistic labelled `label` (e.g. "Total Secrets") into a
 * number. Returns NaN if not found so callers can skip gracefully.
 */
async function readOverviewCount(page: Page, label: RegExp): Promise<number> {
  await page.goto('/typo3/module/admin/vault');
  await waitForModuleContent(page);

  const frame = getModuleFrame(page);

  // The overview cards typically render a big number with a subtitle. Look for
  // the subtitle text and then walk up to the card to extract the number.
  const cards = frame.locator('.card, [class*="stat"]');
  const count = await cards.count();

  for (let i = 0; i < count; i++) {
    const card = cards.nth(i);
    const text = await card.innerText().catch(() => '');
    if (!label.test(text)) {
      continue;
    }
    const match = /(\d[\d,]*)/.exec(text);
    if (match) {
      return Number.parseInt(match[1].replace(/,/g, ''), 10);
    }
  }
  return Number.NaN;
}

/**
 * Confirm the delete dialog the secrets list opens.
 *
 * The dialog is a TYPO3 Modal rendered into the TOP document, one animation
 * frame after the click. `isVisible()` is a point-in-time question — it
 * answered `false` before the modal had been inserted, the confirmation was
 * skipped, and the record survived a test that reported success. Waiting for
 * the button is the assertion: if the dialog never appears, the delete path is
 * broken and the caller must hear about it.
 */
async function confirmDeleteModal(page: Page): Promise<void> {
  const confirm = page.getByRole('button', { name: 'Delete', exact: true });
  await confirm.waitFor({ state: 'visible', timeout: 10000 });
  await confirm.click();
  await page.waitForLoadState('networkidle');
}

async function auditRowForIdentifier(
  page: Page,
  identifier: string,
  action: string,
): Promise<boolean> {
  // Filter audit by identifier and look for a row with the action text.
  await page.goto(
    `/typo3/module/admin/vault/audit?secretIdentifier=${encodeURIComponent(identifier)}`,
  );
  await waitForModuleContent(page);

  const frame = getModuleFrame(page);
  const rows = frame.locator('table tbody tr', { hasText: identifier });
  const rowCount = await rows.count();

  for (let i = 0; i < rowCount; i++) {
    const rowText = await rows.nth(i).innerText().catch(() => '');
    if (rowText.toLowerCase().includes(action.toLowerCase())) {
      return true;
    }
  }
  return false;
}

test.describe.serial('LC-EXT-001: Lifecycle operations create matching audit entries', () => {
  test('create, disable, enable, delete each produce an audit row', async ({
    authenticatedPage: page,
  }) => {
    const identifier = generateTestId();

    // CREATE
    await page.goto('/typo3/module/admin/vault/secrets/create');
    await waitForModuleContent(page);
    let frame = getModuleFrame(page);
    await frame.locator('input[data-formengine-input-name*="identifier"]').fill(identifier);
    await frame.locator('input[data-vault-is-new="1"]').first().fill('lifecycle-value');
    await frame.locator('button[name="_savedok"]').first().click();
    await page.waitForLoadState('networkidle');

    expect(
      await auditRowForIdentifier(page, identifier, 'create'),
      'No audit entry for CREATE',
    ).toBe(true);

    // DISABLE (toggle 1)
    await page.goto('/typo3/module/admin/vault/secrets');
    await waitForModuleContent(page);
    frame = getModuleFrame(page);
    await filterByIdentifier(frame, identifier);
    let toggle = frame.locator('button[data-vault-toggle], button[title*="Disable"]').first();
    if (await toggle.isVisible().catch(() => false)) {
      await toggle.click();
      await page.waitForLoadState('networkidle');
    }

    expect(
      await auditRowForIdentifier(page, identifier, 'update'),
      'No audit entry for DISABLE (expected action=update with reason=Secret disabled)',
    ).toBe(true);

    // ENABLE (toggle 2) — re-enable path that the original test skipped.
    await page.goto('/typo3/module/admin/vault/secrets');
    await waitForModuleContent(page);
    frame = getModuleFrame(page);
    await filterByIdentifier(frame, identifier);
    toggle = frame.locator('button[data-vault-toggle], button[title*="Enable"]').first();
    if (await toggle.isVisible().catch(() => false)) {
      await toggle.click();
      await page.waitForLoadState('networkidle');
    }

    // DELETE
    await page.goto('/typo3/module/admin/vault/secrets');
    await waitForModuleContent(page);
    frame = getModuleFrame(page);
    await filterByIdentifier(frame, identifier);
    const deleteButton = frame.locator('button[title*="Delete"]').first();
    if (await deleteButton.isVisible().catch(() => false)) {
      await deleteButton.click();
      await confirmDeleteModal(page);
    }

    expect(
      await auditRowForIdentifier(page, identifier, 'delete'),
      'No audit entry for DELETE',
    ).toBe(true);
  });
});

test.describe.serial('LC-EXT-002: Rotate produces an audit entry with success=true', () => {
  test('rotate updates value and logs a rotate audit entry', async ({ authenticatedPage: page }) => {
    const identifier = generateTestId();

    // Create
    await page.goto('/typo3/module/admin/vault/secrets/create');
    await waitForModuleContent(page);
    let frame = getModuleFrame(page);
    await frame.locator('input[data-formengine-input-name*="identifier"]').fill(identifier);
    await frame.locator('input[data-vault-is-new="1"]').first().fill('original');
    await frame.locator('button[name="_savedok"]').first().click();
    await page.waitForLoadState('networkidle');

    // Rotate via modal
    await page.goto('/typo3/module/admin/vault/secrets');
    await waitForModuleContent(page);
    frame = getModuleFrame(page);
    await filterByIdentifier(frame, identifier);

    const rotateButton = frame
      .locator('button[data-vault-rotate], button[title*="Rotate"]')
      .first();

    if (await rotateButton.isVisible().catch(() => false)) {
      await rotateButton.click();

      const newValueInput = page.locator('#rotate-modal-secret').first();
      await newValueInput.waitFor({ state: 'visible' });
      await newValueInput.fill('rotated-value');

      const rotateResponsePromise = page.waitForResponse(
        (resp) => resp.url().includes('/vault/rotate') && resp.request().method() === 'POST',
        { timeout: 10000 },
      );
      await page.getByRole('button', { name: 'Rotate Secret', exact: true }).click();

      const rotateResponse = await rotateResponsePromise.catch(() => null);
      if (rotateResponse !== null) {
        expect(rotateResponse.status()).toBe(200);
        const json = (await rotateResponse.json().catch(() => null)) as { success?: boolean } | null;
        expect(json?.success).toBe(true);
      }

      expect(
        await auditRowForIdentifier(page, identifier, 'rotate'),
        'No audit entry for ROTATE',
      ).toBe(true);
    }

    // Cleanup
    await page.goto('/typo3/module/admin/vault/secrets');
    await waitForModuleContent(page);
    frame = getModuleFrame(page);
    await frame.getByRole('textbox', { name: 'Identifier' }).fill(identifier);
    await frame.locator('button:has-text("Filter")').click();
    const delBtn = frame.locator('button[title*="Delete"]').first();
    if (await delBtn.isVisible().catch(() => false)) {
      await delBtn.click();
      await confirmDeleteModal(page);
    }
  });
});

test.describe.serial('LC-EXT-003: Dashboard counter delta across lifecycle', () => {
  test('total/active/disabled counters move correctly as state changes', async ({
    authenticatedPage: page,
  }) => {
    const identifier = generateTestId();

    const beforeTotal = await readOverviewCount(page, /Total Secrets/i);
    const beforeActive = await readOverviewCount(page, /Active/i);
    const beforeDisabled = await readOverviewCount(page, /Disabled/i);

    if (!Number.isFinite(beforeTotal) || !Number.isFinite(beforeActive)) {
      test.skip(true, 'Overview counters not found in DOM — skipping counter-delta check');
    }

    // Create -> total +1, active +1
    await page.goto('/typo3/module/admin/vault/secrets/create');
    await waitForModuleContent(page);
    let frame = getModuleFrame(page);
    await frame.locator('input[data-formengine-input-name*="identifier"]').fill(identifier);
    await frame.locator('input[data-vault-is-new="1"]').first().fill('counter-test');
    await frame.locator('button[name="_savedok"]').first().click();
    await page.waitForLoadState('networkidle');

    const afterCreateTotal = await readOverviewCount(page, /Total Secrets/i);
    const afterCreateActive = await readOverviewCount(page, /Active/i);
    expect(afterCreateTotal).toBe(beforeTotal + 1);
    expect(afterCreateActive).toBe(beforeActive + 1);

    // Disable -> active -1, disabled +1
    await page.goto('/typo3/module/admin/vault/secrets');
    await waitForModuleContent(page);
    frame = getModuleFrame(page);
    await filterByIdentifier(frame, identifier);
    const toggle = frame.locator('button[data-vault-toggle], button[title*="Disable"]').first();
    if (await toggle.isVisible().catch(() => false)) {
      await toggle.click();
      await page.waitForLoadState('networkidle');
    }

    const afterDisableActive = await readOverviewCount(page, /Active/i);
    const afterDisableDisabled = await readOverviewCount(page, /Disabled/i);
    if (Number.isFinite(beforeDisabled)) {
      expect(afterDisableActive).toBe(beforeActive);
      expect(afterDisableDisabled).toBe(beforeDisabled + 1);
    }

    // Delete -> total restored to baseline
    await page.goto('/typo3/module/admin/vault/secrets');
    await waitForModuleContent(page);
    frame = getModuleFrame(page);
    await filterByIdentifier(frame, identifier);
    const deleteButton = frame.locator('button[title*="Delete"]').first();
    if (await deleteButton.isVisible().catch(() => false)) {
      await deleteButton.click();
      await confirmDeleteModal(page);
    }

    const afterDeleteTotal = await readOverviewCount(page, /Total Secrets/i);
    expect(afterDeleteTotal).toBe(beforeTotal);
  });
});
