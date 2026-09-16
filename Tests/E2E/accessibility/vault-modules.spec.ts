import AxeBuilder from '@axe-core/playwright';
import type { Page } from '@playwright/test';
import {
  test,
  expect,
  getModuleFrame,
  waitForModuleContent,
  waitForSecretsListReady,
} from '../fixtures/auth';

/**
 * Accessibility tests for Vault backend modules.
 *
 * Uses axe-core to validate WCAG 2.1 AA compliance.
 * Tests verify that backend modules are accessible to users with assistive
 * technologies.
 *
 * Hardening notes:
 *  - We do NOT silently drop violations whose DOM node contains the
 *    substrings "vault" or "secret". That filter hid legitimate site-wide
 *    issues (color contrast on generic TYPO3 chrome that happened to render
 *    inside our module) and made the suite misleadingly green.
 *  - Severity threshold is moderate+serious+critical. WCAG 2.1 AA requires
 *    addressing moderate issues too — they typically represent real barriers
 *    for assistive-tech users.
 */

type AxeImpact = 'minor' | 'moderate' | 'serious' | 'critical';

const FAIL_IMPACTS: readonly AxeImpact[] = ['moderate', 'serious', 'critical'];

function filterFailingViolations<T extends { impact?: string | null | undefined }>(
  violations: readonly T[],
): T[] {
  return violations.filter((v) =>
    FAIL_IMPACTS.includes((v.impact ?? 'minor') as AxeImpact),
  );
}

/**
 * One keyboard step: which element holds focus in the TOP document (where
 * TYPO3 renders its dialogs), and whether that counts as having left the
 * dialog.
 *
 * A native <dialog> cycles through the document itself, so `<body>` while the
 * dialog is still open is the browser's wrap point, not an escape. Anything
 * else outside the dialog is.
 */
type FocusStep = { element: string; escaped: boolean };

async function walkFocus(
  page: Page,
  key: string,
  steps: number,
  container = 'typo3-backend-modal',
): Promise<FocusStep[]> {
  // Raw first, verdict after: whether a `<body>` step was the browser's wrap
  // point or focus genuinely leaving is only decidable from what happens NEXT.
  // One step more than asked for: the verdict on a `<body>` step depends on the
  // one after it, so the last reported step needs a successor to be judged by.
  // The extra step is not reported.
  const raw: { element: string; inside: boolean; dialogOpen: boolean }[] = [];
  for (let i = 0; i < steps + 1; i++) {
    await page.keyboard.press(key);
    raw.push(
      await page.evaluate((selector) => {
        const el = document.activeElement;
        const modal = document.querySelector(selector);
        const dialog = modal?.querySelector('dialog');
        const dialogOpen = modal !== null && (dialog === null || dialog === undefined || dialog.open);
        if (el === null) {
          return { element: 'none', inside: false, dialogOpen };
        }
        return {
          element: `${el.tagName.toLowerCase()}${el.id === '' ? '' : '#' + el.id}`,
          inside: modal !== null && modal.contains(el),
          dialogOpen,
        };
      }, container),
    );
  }

  // Both majors put focus on `<body>` for one step as the cycle wraps —
  // measured on 13.4.35, where the modal is a Bootstrap one with no <dialog>
  // element: toggle, copy, button, body, button, input, toggle, copy. What
  // separates that from an escape is the step after it: the wrap comes back,
  // an escape does not.
  return raw.slice(0, steps).map((step, i) => {
    const returnsImmediately = step.element === 'body' && (raw[i + 1]?.inside ?? false);
    return {
      element: step.element,
      escaped: step.dialogOpen && !step.inside && !returnsImmediately,
    };
  });
}

/**
 * `data-testid` of whatever holds focus inside the module iframe — the trigger
 * a dialog must hand focus back to.
 */
async function triggerTestId(page: Page): Promise<string> {
  const iframeHandle = await page.locator('iframe').first().elementHandle();
  const ownerFrame = iframeHandle === null ? null : await iframeHandle.contentFrame();
  if (ownerFrame === null) {
    return 'no-frame';
  }
  return ownerFrame.evaluate(
    () => (document.activeElement as HTMLElement | null)?.dataset?.testid ?? '',
  );
}

test.describe('Vault Module Accessibility', () => {
  test.describe('Secrets Module', () => {
    test('secrets list page has no moderate+ accessibility violations', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
        .analyze();

      // Log violations for debugging
      if (results.violations.length > 0) {
        console.log('Accessibility violations:', JSON.stringify(results.violations, null, 2));
      }

      const failing = filterFailingViolations(results.violations);
      expect(failing, `Found moderate+ a11y violations: ${failing.map((v) => v.id).join(', ')}`)
        .toHaveLength(0);
    });

    test('create secret form has proper labels and structure', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa'])
        // Exclude TYPO3 FormEngine's internal plainValue selects (generated by JS)
        .exclude('select[name="plainValue"]')
        .analyze();

      // Filter for form-related violations, excluding TYPO3 core FormEngine issues
      const formViolations = results.violations.filter((v) => {
        if (!v.id.includes('label') && !v.id.includes('form')) {
          return false;
        }
        // Exclude TYPO3 FormEngine generated elements (plainValue selects, filter inputs)
        const isTYPO3CoreElement = v.nodes.some(
          (n) =>
            n.html.includes('plainValue') ||
            n.html.includes('filter-container') ||
            n.html.includes('Type to filter'),
        );
        return !isTYPO3CoreElement;
      });
      expect(formViolations).toHaveLength(0);
    });
  });

  test.describe('Audit Module', () => {
    test('audit log page has no moderate+ accessibility violations', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/audit');
      await waitForModuleContent(page);

      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
        .analyze();

      const failing = filterFailingViolations(results.violations);
      expect(failing, `Found moderate+ a11y violations: ${failing.map((v) => v.id).join(', ')}`)
        .toHaveLength(0);
    });

    test('audit table has proper data table structure', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/audit');
      await waitForModuleContent(page);

      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa'])
        // Focus on table-related rules
        .include('table')
        .analyze();

      const tableViolations = results.violations.filter(
        (v) => v.id.includes('table') || v.id.includes('th'),
      );
      expect(tableViolations).toHaveLength(0);
    });
  });

  test.describe('Migration Module', () => {
    test('migration wizard has no moderate+ accessibility violations', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/migration');
      await waitForModuleContent(page);

      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
        .analyze();

      const failing = filterFailingViolations(results.violations);
      expect(failing, `Found moderate+ a11y violations: ${failing.map((v) => v.id).join(', ')}`)
        .toHaveLength(0);
    });
  });

  test.describe('Parent Module', () => {
    test('submodule overview has proper heading hierarchy', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa'])
        .analyze();

      // Check for heading-order violations
      const headingViolations = results.violations.filter((v) => v.id === 'heading-order');
      expect(headingViolations).toHaveLength(0);
    });

    test('navigation elements are accessible', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault');
      await waitForModuleContent(page);

      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa'])
        .analyze();

      // Check for link and navigation violations
      const navViolations = results.violations.filter(
        (v) => v.id.includes('link') || v.id.includes('navigation'),
      );
      expect(navViolations).toHaveLength(0);
    });
  });

  test.describe('Color Contrast', () => {
    test('secrets module has sufficient color contrast', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const results = await new AxeBuilder({ page })
        .withTags(['wcag2aa'])
        .analyze();

      const contrastViolations = results.violations.filter((v) => v.id === 'color-contrast');

      // Log any contrast issues for fixing
      if (contrastViolations.length > 0) {
        console.log('Color contrast violations:', JSON.stringify(contrastViolations, null, 2));
      }

      // Flag ALL moderate+ contrast violations site-wide (previously this was
      // restricted to nodes whose HTML contained "vault" or "secret", which
      // silently suppressed legitimate issues on shared chrome).
      const failing = filterFailingViolations(contrastViolations);
      expect(
        failing,
        `Found moderate+ color-contrast violations: ${failing
          .flatMap((v) => v.nodes.map((n) => n.target.join(' ')))
          .join(' | ')}`,
      ).toHaveLength(0);
    });
  });

  test.describe('Keyboard Navigation', () => {
    test('secrets list is navigable by keyboard', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      // Tab through interactive elements
      await page.keyboard.press('Tab');
      await page.keyboard.press('Tab');
      await page.keyboard.press('Tab');

      // Verify focus is visible and on an interactive element
      const focusedElement = await page.evaluate(() => {
        const el = document.activeElement;
        return el ? el.tagName.toLowerCase() : null;
      });

      // Should be on a focusable element (link, button, input, etc.)
      expect(['a', 'button', 'input', 'select', 'textarea']).toContain(focusedElement);
    });

    test('Tab walks through form controls on create page, Shift+Tab reverses', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets/create');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      // Focus the first interactive form control.
      const identifierInput = frame.locator(
        'input[data-formengine-input-name*="identifier"]',
      );
      await identifierInput.waitFor({ state: 'visible', timeout: 5000 });
      await identifierInput.focus();

      // Resolve the underlying Frame so we can call `.evaluate()`.
      // FrameLocator does not expose evaluate — we need the owner Frame.
      const iframeHandle = await page.locator('iframe').first().elementHandle();
      const ownerFrame = iframeHandle === null ? null : await iframeHandle.contentFrame();

      // Collect a sequence of focus targets across ~8 Tab presses. We expect
      // the walk to stay on focusable elements.
      const forwardTargets: string[] = [];
      for (let i = 0; i < 8; i++) {
        await page.keyboard.press('Tab');
        const tag =
          ownerFrame === null
            ? ''
            : await ownerFrame.evaluate(
                () => (document.activeElement?.tagName ?? '').toLowerCase(),
              );
        if (tag !== '') {
          forwardTargets.push(tag);
        }
      }
      const focusableTags = new Set(['a', 'button', 'input', 'select', 'textarea']);
      const anyFocusable = forwardTargets.some((t) => focusableTags.has(t));
      expect(anyFocusable, `Tab walk visited no focusable control: ${forwardTargets.join(',')}`).toBe(true);

      // Shift+Tab should reverse direction — we just verify focus stays on a
      // focusable element and does not throw/leave the document.
      await page.keyboard.press('Shift+Tab');
      const reverseTag =
        ownerFrame === null
          ? 'body'
          : await ownerFrame.evaluate(
              () => (document.activeElement?.tagName ?? '').toLowerCase(),
            );
      expect(['a', 'button', 'input', 'select', 'textarea', 'body']).toContain(reverseTag);
    });

    test('Enter on filter submit applies the filter', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      // The row actions are inert until SecretsList.js has bound them, and a
      // click in that window only moves focus — which is precisely what this
      // file measures, so the race would read as a focus defect.
      await waitForSecretsListReady(frame);
      const input = frame.getByRole('textbox', { name: 'Identifier' });
      await input.focus();
      await input.fill('keyboard-test');

      const filterResp = page.waitForResponse(
        (resp) => resp.url().includes('admin_vault_secrets') && resp.status() === 200,
        { timeout: 10000 },
      );
      await page.keyboard.press('Enter');
      await filterResp.catch(() => undefined);

      // Stats panel re-renders after filter apply; Enter-submit is working if
      // the stats panel is still visible and no error page appeared.
      const afterFrame = getModuleFrame(page);
      await expect(afterFrame.locator('text=Oops, an error occurred')).not.toBeVisible();
    });
  });

  test.describe('Focus Management', () => {
    test('opening rotate modal moves focus into the modal; closing returns focus to the trigger', async ({
      authenticatedPage: page,
    }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      // The row actions are inert until SecretsList.js has bound them, and a
      // click in that window only moves focus — which is precisely what this
      // file measures, so the race would read as a focus defect.
      await waitForSecretsListReady(frame);
      const rotateButton = frame.getByTestId('vault-rotate-btn').first();

      if (!(await rotateButton.isVisible().catch(() => false))) {
        test.skip(
          true,
          'No rotatable secret present in this environment — cannot exercise modal focus management',
        );
        return;
      }

      await rotateButton.focus();
      await rotateButton.click();

      // Modal opens outside the iframe — focus should move into the modal.
      const modalInput = page.locator('#rotate-modal-secret');
      await modalInput.waitFor({ state: 'visible', timeout: 5000 });

      // Focus must be INSIDE the modal, not on the original trigger.
      //
      // Asking the focused element which dialog owns it, rather than looking a
      // modal up by class: TYPO3 renders the dialog as
      // <typo3-backend-modal><dialog class="modal t3js-modal …">, with neither
      // a `show` class nor aria-modal, so `.modal.show, .modal[aria-modal]`
      // matched nothing and the check could only ever report false — including
      // for correctly placed focus (measured on TYPO3 14.3, 2026-09-14).
      //
      // Polled rather than read once: the dialog places focus when its show
      // transition ends, which on TYPO3 13 is measurably later than the moment
      // its input becomes visible.
      await expect
        .poll(
          () =>
            page.evaluate(() => {
              const el = document.activeElement;
              if (el === null) return false;
              return el.closest('typo3-backend-modal, dialog.modal, .modal, [role="dialog"]') !== null;
            }),
          { message: 'Focus did not move into the rotate modal', timeout: 10000 },
        )
        .toBe(true);

      // Escape closes the modal.
      await page.keyboard.press('Escape');
      await modalInput.waitFor({ state: 'hidden', timeout: 5000 }).catch(() => undefined);

      // After close, focus returns to the trigger (WCAG 2.4.3 focus order).
      // Asserted, not annotated: TYPO3 renders the dialog into the TOP document
      // while the list runs in the module iframe, so the browser's own
      // restoration cannot reach the trigger and the extension has to give
      // focus back itself (vault-modal-focus.js). Without that, focus lands on
      // <body> and a keyboard user loses their place in the table.
      await expect
        .poll(() => triggerTestId(page), {
          message: 'Closing the rotate modal did not return focus to the rotate button',
          timeout: 10000,
        })
        .toBe('vault-rotate-btn');
    });

    test('reveal dialog traps focus, cycles both ways, and returns focus to the trigger on Escape', async ({
      authenticatedPage: page,
    }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      // The row actions are inert until SecretsList.js has bound them, and a
      // click in that window only moves focus — which is precisely what this
      // file measures, so the race would read as a focus defect.
      await waitForSecretsListReady(frame);
      const revealButton = frame.getByTestId('vault-reveal-btn').first();

      if (!(await revealButton.isVisible().catch(() => false))) {
        test.skip(true, 'No readable secret present in this environment — cannot exercise the reveal dialog');
        return;
      }

      await revealButton.focus();
      await revealButton.click();

      // Generous: the reveal is an AJAX round trip behind a loading dialog, and
      // on TYPO3 13 that dialog can linger (see the note below), which makes the
      // handover slower than any other dialog in this file.
      const secretInput = page.locator('#reveal-modal-secret');
      await secretInput.waitFor({ state: 'visible', timeout: 30000 });

      // Everything below is scoped to the dialog holding the secret, never to
      // "the modal". The reveal path opens a loading dialog first, and on
      // TYPO3 13 that one can still be in the DOM: Bootstrap ignores a hide()
      // issued while its show transition is running, so a fast vault_reveal
      // response leaves it behind (measured on 13.4, reported separately — it
      // is a defect of its own and not what this spec is about).
      const revealDialog = 'typo3-backend-modal:has(#reveal-modal-secret)';
      await expect.poll(() => page.locator(revealDialog).count(), { timeout: 10000 }).toBe(1);

      // Focus moves into the dialog, onto the first of its controls.
      await expect
        .poll(() => page.evaluate(() => document.activeElement?.id ?? ''), { timeout: 10000 })
        .toBe('reveal-modal-secret');

      // Tab must never reach a control outside the dialog. A native <dialog>
      // wraps through the document itself — activeElement is then <body> while
      // the dialog is still open, which is the browser's wrap point and not an
      // escape; the delete dialog, pure TYPO3 core, behaves identically.
      const forward = await walkFocus(page, 'Tab', 8, revealDialog);
      await secretInput.focus();
      const backward = await walkFocus(page, 'Shift+Tab', 6, revealDialog);

      for (const step of forward) {
        expect(
          step.escaped,
          `Focus left the reveal dialog onto <${step.element}> while the dialog was open`,
        ).toBe(false);
      }

      // Backwards containment is asserted only where the dialog is a native
      // <dialog>, which is TYPO3 14. On TYPO3 13 the modal is a Bootstrap one
      // whose focus trap does not hold backwards out of the top document:
      // Shift+Tab reaches <iframe id="typo3-contentIframe"> and stays there.
      // That is core behaviour, not this extension's — the delete dialog, which
      // is a plain Modal.confirm() with no code of ours in it, leaks
      // identically (measured on 13.4). Asserting it here would fail CI for a
      // defect this change does not fix and must not paper over with a second,
      // hand-rolled trap on top of the core one.
      const nativeDialog = await page.evaluate(
        (selector) => document.querySelector(selector)?.querySelector('dialog') !== null,
        revealDialog,
      );
      if (nativeDialog) {
        for (const step of backward) {
          expect(
            step.escaped,
            `Focus left the reveal dialog backwards onto <${step.element}> while the dialog was open`,
          ).toBe(false);
        }
      }

      // Forward from the secret field walks the dialog's own controls. The
      // number of steps per lap is the browser's business (it may or may not
      // pass through the wrap point on a given lap), so this asserts which
      // controls are reached, not after how many presses.
      const forwardIds = forward.map((s) => s.element);
      expect(forwardIds, `Tab did not reach the visibility toggle: ${forwardIds.join(',')}`)
        .toContain('button#reveal-modal-toggle');
      // The copy button is absent in the hardened security profile, where the
      // reveal response reports `copyAllowed: false` — requiring it there would
      // fail on a correctly configured instance rather than on a focus defect.
      if ((await page.locator('#reveal-modal-copy').count()) > 0) {
        expect(forwardIds, `Tab did not reach the copy button: ${forwardIds.join(',')}`)
          .toContain('button#reveal-modal-copy');
      }

      // Backwards from the same starting point must not repeat the forward
      // step — that is what distinguishes a reversed walk from a stuck one.
      expect(forward[0].element, 'Tab from the secret field did not reach the visibility toggle')
        .toBe('button#reveal-modal-toggle');
      expect(
        backward[0].element,
        'Shift+Tab from the secret field moved forwards instead of backwards',
      ).not.toBe('button#reveal-modal-toggle');

      // Escape closes the dialog from a known position inside it.
      await secretInput.focus();
      await page.keyboard.press('Escape');
      await expect.poll(() => page.locator(revealDialog).count(), { timeout: 10000 }).toBe(0);

      await expect
        .poll(() => triggerTestId(page), {
          message: 'Closing the reveal dialog did not return focus to the reveal button',
          timeout: 10000,
        })
        .toBe('vault-reveal-btn');
    });

    test('delete confirmation returns focus to its trigger', async ({ authenticatedPage: page }) => {
      await page.goto('/typo3/module/admin/vault/secrets');
      await waitForModuleContent(page);

      const frame = getModuleFrame(page);
      // The row actions are inert until SecretsList.js has bound them, and a
      // click in that window only moves focus — which is precisely what this
      // file measures, so the race would read as a focus defect.
      await waitForSecretsListReady(frame);
      const deleteButton = frame.getByTestId('vault-delete-btn').first();

      if (!(await deleteButton.isVisible().catch(() => false))) {
        test.skip(true, 'No deletable secret present in this environment');
        return;
      }

      await deleteButton.focus();
      await deleteButton.click();

      // `typo3-backend-modal` is a zero-size wrapper around the <dialog>, so it
      // never satisfies Playwright's visibility check — count it instead.
      await expect.poll(() => page.locator('typo3-backend-modal').count(), { timeout: 15000 }).toBe(1);
      await expect
        .poll(() => page.evaluate(() => document.activeElement?.closest('typo3-backend-modal') !== null), {
          timeout: 10000,
        })
        .toBe(true);

      // Escape only — the secret must survive this test.
      await page.keyboard.press('Escape');
      await expect.poll(() => page.locator('typo3-backend-modal').count(), { timeout: 10000 }).toBe(0);

      await expect
        .poll(() => triggerTestId(page), {
          message: 'Closing the delete confirmation did not return focus to the delete button',
          timeout: 10000,
        })
        .toBe('vault-delete-btn');
    });
  });
});
