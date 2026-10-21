// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: Netresearch DTT GmbH

import { test as base, expect, Page, FrameLocator, APIResponse } from '@playwright/test';
import type { Frame, Locator } from '@playwright/test';

/**
 * Whether a backend response is TYPO3's redirect to the login form.
 *
 * TYPO3 13 answers a backend AJAX request that carries no valid session or
 * request token with `302 Location: /typo3/login`; TYPO3 14 answers 401/403.
 * Both reject the request before any extension controller runs. Only
 * meaningful for requests sent with `maxRedirects: 0` — otherwise Playwright
 * follows the redirect and reports the login page's 200. A browser `Response`
 * caught with `page.waitForResponse()` is the redirect itself, so it qualifies
 * as it is.
 */
export function isLoginRedirect(response: Pick<APIResponse, 'status' | 'headers'>): boolean {
  return (
    response.status() === 302 &&
    /^(https?:\/\/[^/]+)?\/typo3\/login(\?|$)/.test(response.headers()['location'] ?? '')
  );
}

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
 * The URL the module iframe currently shows.
 *
 * Navigation inside a backend module happens in that iframe. TYPO3 14 mirrors
 * it into the address bar afterwards; TYPO3 13 does not, so `page.url()` still
 * reports the route the shell was opened with and a wait on it measures the
 * wrong document. Falls back to the top URL when there is no iframe.
 */
export function moduleFrameUrl(page: Page): string {
  const child = page.frames().find((frame) => frame !== page.mainFrame());

  return child === undefined ? page.url() : child.url();
}

/**
 * Run an action that navigates the module iframe and wait for the new document.
 *
 * `page.waitForLoadState('networkidle')` is the wrong instrument for this: it
 * watches the top-level document, which is not the one navigating, and it
 * answers a question about request traffic rather than about the page. The
 * frame's URL is the observable that actually changes, and the content wait
 * behind it is what the caller's next locator needs.
 */
export async function clickAndWaitForModule(page: Page, click: () => Promise<void>): Promise<void> {
  const before = moduleFrameUrl(page);
  await click();
  await expect.poll(() => moduleFrameUrl(page), { timeout: 15000 }).not.toBe(before);
  await waitForModuleContent(page);
}

/**
 * Save the record FormEngine is showing, and wait for the save itself.
 *
 * FormEngine posts the form to `/typo3/record/edit` and follows the answer
 * with a GET of the saved record. Waiting for that POST is a statement about
 * the save; `networkidle` is a statement about the browser being quiet, which
 * on a backend page full of polling widgets is neither necessary nor
 * sufficient. Measured on a provisioned instance: a click issued before the
 * module content is there sends no request at all, and `networkidle` reports
 * success for it.
 */
export async function saveRecord(page: Page, frame: FrameLocator): Promise<void> {
  // Both waits are registered before the click, so neither can be missed.
  // The POST alone is not enough: FormEngine answers it with a redirect and
  // the form is re-rendered by the GET behind it, so a content wait placed
  // directly after the response can be satisfied by the document being left --
  // the same trap the list filter had. The frame's navigation is what says the
  // new document has committed.
  const navigated = page.waitForEvent('framenavigated', {
    predicate: (candidate) => candidate !== page.mainFrame(),
    timeout: 20000,
  });
  const saved = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' && response.url().includes('/typo3/record/edit'),
    { timeout: 20000 },
  );
  await frame.locator('button[name="_savedok"], button:has-text("Save")').first().click();
  await saved;
  await navigated;
  await waitForModuleContent(page);
}

/**
 * Wait for the module content to load within the iframe.
 */
export async function waitForModuleContent(page: Page): Promise<void> {
  const frame = getModuleFrame(page);
  let moduleTemplate = true;
  try {
    await frame.locator('h1, .module-body, .module-docheader').first().waitFor({ timeout: 10000 });
  } catch {
    // Not every page the suite visits is a module template -- FormEngine and
    // the install tool render none of those three -- so a miss is not yet a
    // failure.
    moduleTemplate = false;
  }

  if (!moduleTemplate) {
    // It is a failure when the iframe holds nothing at all: the helper used to
    // return here regardless, and the caller then acted on an empty document,
    // which surfaces much later as a timeout in an unrelated locator and reads
    // as a defect in whatever that locator was looking for.
    await frame
      .locator('body :not(script):not(style)')
      .first()
      .waitFor({ state: 'attached', timeout: 10000 });
  }

  await waitForFormEngineFields(frame);
}

/**
 * Wait until FormEngine has bound the fields of the record form, if the frame
 * shows one.
 *
 * FormEngine renders a field such as `identifier` twice: a visible input
 * carrying `data-formengine-input-params`, and a hidden input with the real
 * `name` that is posted. Only FormEngine's JavaScript copies the visible value
 * into the hidden one, on the visible input's `change` event, and it binds that
 * listener when it initialises the field -- after the document is ready and
 * its modules are imported. A fill that blurs before then fires `change` into
 * nothing: the hidden input stays empty, the server rejects the record ("Vault
 * secret identifier is invalid") and redirects back to an empty new form, and
 * the spec later finds no row for the identifier (#470). The Save button is
 * disabled until FormEngine has run, so the click waits; the fills did not.
 *
 * TYPO3 sets `data-formengine-input-initialized` on each field once its
 * listener is bound, and its source says the attribute exists so that
 * acceptance tests can tell when initialisation has completed
 * (`form-engine-validation.ts`, 13.4 and 14.3). Pages without a record form
 * have no such field and pass at once; the ready-state wait first makes sure
 * the fields have been parsed, so "none pending" is not read off a document
 * that is still arriving.
 */
export async function waitForFormEngineFields(frame: FrameLocator): Promise<void> {
  await expect
    .poll(() => frame.locator('html').evaluate(() => document.readyState), { timeout: 15000 })
    .not.toBe('loading');
  await expect(
    frame.locator(
      'form[name="editform"] [data-formengine-input-params]:not([data-formengine-input-initialized])',
    ),
    'FormEngine did not initialise every field of the record form',
  ).toHaveCount(0, { timeout: 15000 });
}

/**
 * Wait until the secrets list has bound its row actions.
 *
 * Reveal, rotate, delete and the status toggle are plain buttons until
 * `SecretsList.js` has been imported: a click before that focuses the button
 * and does nothing at all. The module sets `data-vault-secrets-list="ready"`
 * on the documentElement once the handlers are attached, which is the only
 * observable moment that window closes.
 */
export async function waitForSecretsListReady(frame: FrameLocator): Promise<void> {
  await frame
    .locator('html[data-vault-secrets-list="ready"]')
    .waitFor({ state: 'attached', timeout: 15000 });
}

/**
 * Wait until vault-secret-input.js has bound the buttons of the
 * `vaultSecretInput` field. Like the secrets list, the form is in the document
 * before the module is imported, so a click before this does nothing. The
 * module sets `data-vault-secret-input="ready"` on the documentElement once
 * its handlers are attached.
 */
export async function waitForSecretInputReady(frame: FrameLocator): Promise<void> {
  await frame
    .locator('html[data-vault-secret-input="ready"]')
    .waitFor({ state: 'attached', timeout: 15000 });
}

/**
 * Apply the identifier filter and wait for the page it produces.
 *
 * The filter is a form submit, so the flag and the row exist in the document
 * being left as well — a wait the old page already satisfies returns at once
 * and the next click lands in the new page's loading window. Clearing the
 * flag first means only the new document can set it.
 */
export async function submitIdentifierFilter(
  frame: FrameLocator,
  identifier: string,
): Promise<void> {
  await frame.getByRole('textbox', { name: 'Identifier' }).fill(identifier);
  await frame.locator('html').evaluate((el) => {
    delete el.dataset.vaultSecretsList;
  });
  await frame.locator('button:has-text("Filter")').click();
  await waitForSecretsListReady(frame);
}

/**
 * Apply the filter and wait for the row it must produce.
 *
 * Callers that expect the identifier to be gone -- after a delete, or for one
 * that never existed -- take `submitIdentifierFilter()` instead and make their
 * own assertion; waiting for a row here would turn their expected absence into
 * a helper timeout.
 */
export async function filterByIdentifier(
  frame: FrameLocator,
  identifier: string,
): Promise<void> {
  await submitIdentifierFilter(frame, identifier);
  await frame
    .locator('table tbody tr')
    .filter({ hasText: identifier })
    .first()
    .waitFor({ state: 'visible', timeout: 15000 });
}

/**
 * The table row carrying this identifier.
 *
 * Row actions must be taken from this row rather than the table's first one:
 * the list is not always narrowed to a single row, and acting on the first
 * one then touches an unrelated secret.
 *
 * Rows are resolved only inside a document whose row actions are bound
 * (`waitForSecretsListReady`). Playwright resolves a locator again at the
 * moment of the click, so a wait for that flag earlier in a spec says nothing
 * about the document the click lands in. A row button clicked before
 * SecretsList.js has run does nothing (the delete button posted its form
 * without the confirmation until #470; LC-EXT-003 failed in CI with exactly
 * that result). Use these helpers for rows a spec acts on or expects to see.
 * An assertion that a row is absent must not be scoped, because an unbound
 * document would satisfy it trivially.
 */
export function rowFor(frame: FrameLocator, identifier: string): Locator {
  return boundList(frame).locator('table tbody tr').filter({ hasText: identifier }).first();
}

/**
 * The secrets list, but only in a document whose row actions are bound. See
 * `rowFor()`.
 */
export function boundList(frame: FrameLocator): Locator {
  return frame.locator('html[data-vault-secrets-list="ready"]');
}

/**
 * The row of this identifier by its test id, in a document whose row actions
 * are bound. See `rowFor()`.
 */
export function secretRow(frame: FrameLocator, identifier: string): Locator {
  return boundList(frame).locator(`[data-testid="secret-row-${identifier}"]`);
}

/**
 * The document that holds the backend dialog which has just been opened.
 *
 * The module's dialogs (delete confirmation, rotate, reveal) are opened with
 * TYPO3's `Modal`, and which document renders them is decided when
 * `@typo3/backend/modal.js` is evaluated inside the module iframe: it reuses
 * the backend shell's `TYPO3.Modal` if the shell has already defined it, and
 * otherwise creates its own and renders into the iframe (`modal.ts`, 13.4.36
 * lines 656-683). A spec that looks for the dialog in the top document only
 * times out whenever the iframe won, although the dialog is on screen (#475).
 * `SecretsList.js` probes both documents for its own modal fields for the same
 * reason.
 *
 * Resolves once a dialog is visible in the top document or in the module
 * iframe and returns that document's frame, so callers locate the dialog's
 * controls and evaluate focus in the document that actually holds it.
 */
export async function openDialogScope(page: Page, timeout = 10000): Promise<Frame> {
  let found: Frame | undefined;
  await expect
    .poll(
      async () => {
        for (const frame of [page.mainFrame(), await moduleFrame(page)]) {
          if (frame === null) {
            continue;
          }
          const dialog = frame.getByRole('dialog');
          if ((await dialog.count()) > 0 && (await dialog.first().isVisible())) {
            found = frame;

            return true;
          }
        }

        return false;
      },
      { timeout, message: 'no backend dialog became visible in the shell or the module iframe' },
    )
    .toBe(true);

  return found as Frame;
}

/**
 * The module iframe as a `Frame`, which, unlike a `FrameLocator`, can evaluate
 * script -- the focus checks need `document.activeElement` of that document.
 */
export async function moduleFrame(page: Page): Promise<Frame | null> {
  const handle = await page.locator('iframe').first().elementHandle();

  return handle === null ? null : handle.contentFrame();
}
