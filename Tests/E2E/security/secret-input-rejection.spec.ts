// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: Netresearch DTT GmbH

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { expect, test } from '@playwright/test';

type RejectionObservations = {
  unhandled: string[];
  diagnostics: string[];
  notificationErrors: string[];
  countdownInsertionFaults: number;
  reportedDisplays: { source: string; value: string; type: string; activeTimers: number; activeListeners: number }[];
  intervalsStarted: number[];
  intervalsCleared: number[];
  listenersAdded: { event: string; identity: number }[];
  listenersRemoved: { event: string; identity: number }[];
  hideModeUpdateFaults: number;
  registeredAtHideModeFault: { timers: number; listeners: number } | null;
};

type WidgetWindow = Window & {
  __vaultRejectionObservations: RejectionObservations;
  TYPO3: {
    settings: { ajaxUrls: { vault_reveal: string } };
    Notification: { error: (title: unknown, message: unknown) => void };
  };
};

// Every request is fulfilled below. The real widget and lifecycle modules run
// in the browser; the spinner import supplies only a third-party visual element.
const origin = 'https://vault-widget.test';
const partialSecret = 'fixture_partial_reveal_exposure';
const fixtureHtml = `<!doctype html>
<html><head><meta charset="utf-8"><link rel="icon" href="data:,">
<script type="importmap">{
  "imports": {
    "@netresearch/nr-vault/vault-reveal-lifecycle.js": "/vault-reveal-lifecycle.js",
    "@typo3/backend/element/spinner-element.js": "/spinner-element.js"
  }
}</script>
</head><body>
<div class="input-group">
  <input data-vault-display="true" type="password" value="••••••••••••">
  <button type="button" class="t3js-vault-input-reveal"
    data-identifier="fixture_rejection" aria-label="Reveal secret"
    data-label-reveal="Reveal secret" data-label-hide="Hide secret">
    <span class="t3js-icon icon-actions-eye">Reveal</span>
  </button>
  <button type="button" class="t3js-vault-input-copy" style="display:none">Copy</button>
</div>
<script type="module" src="/vault-secret-input.js"></script>
</body></html>`;

for (const failure of ['spinner preparation', 'error notification', 'countdown insertion', 'hide mode update'] as const) {
  test(`secret input recovers a failed reveal during ${failure}`, async ({ page }) => {
    const widget = await readFile(resolve('Resources/Public/JavaScript/vault-secret-input.js'), 'utf8');
    const lifecycle = await readFile(resolve('Resources/Public/JavaScript/vault-reveal-lifecycle.js'), 'utf8');
    const resources = new Map([
      ['/', { contentType: 'text/html', body: fixtureHtml }],
      ['/vault-secret-input.js', { contentType: 'text/javascript', body: widget }],
      ['/vault-reveal-lifecycle.js', { contentType: 'text/javascript', body: lifecycle }],
      ['/spinner-element.js', { contentType: 'text/javascript', body: 'export {};' }],
    ]);
    const pageErrors: string[] = [];
    const unexpectedRequests: string[] = [];
    let revealRequests = 0;
    page.on('pageerror', (error) => pageErrors.push(error.message));
    await page.route('**/*', async (route) => {
      const url = new URL(route.request().url());
      if (url.origin === origin && url.pathname === '/reveal') {
        revealRequests++;
        expect(route.request().method()).toBe('POST');
        await route.fulfill({
          status: ['countdown insertion', 'hide mode update'].includes(failure) ? 200 : 503,
          contentType: 'application/json',
          body: JSON.stringify(['countdown insertion', 'hide mode update'].includes(failure)
            ? { success: true, secret: partialSecret, copyAllowed: true }
            : { success: false }),
        });
        return;
      }
      const resource = url.origin === origin ? resources.get(url.pathname) : undefined;
      if (resource) {
        await route.fulfill(resource);
        return;
      }
      unexpectedRequests.push(route.request().url());
      await route.abort();
    });

    await page.goto(origin);
    await expect(page.locator('html')).toHaveAttribute('data-vault-secret-input', 'ready');

    // Fault only the actual external operation. Do not replace handleReveal,
    // its returned Promise, or the click listener under examination.
    await page.evaluate((failureKind) => {
      const widgetWindow = window as unknown as WidgetWindow;
      const observations: RejectionObservations = {
        unhandled: [], diagnostics: [], notificationErrors: [], countdownInsertionFaults: 0, reportedDisplays: [],
        intervalsStarted: [], intervalsCleared: [], listenersAdded: [], listenersRemoved: [],
        hideModeUpdateFaults: 0, registeredAtHideModeFault: null,
      };
      widgetWindow.__vaultRejectionObservations = observations;
      window.addEventListener('unhandledrejection', (event) => {
        observations.unhandled.push(String(event.reason));
      });
      // Observe the public lifecycle resources while preserving native behavior.
      const setInterval = window.setInterval;
      const clearInterval = window.clearInterval;
      window.setInterval = (...args: Parameters<typeof window.setInterval>) => {
        const identity = Reflect.apply(setInterval, window, args);
        observations.intervalsStarted.push(identity);
        return identity;
      };
      window.clearInterval = (...args: Parameters<typeof window.clearInterval>) => {
        observations.intervalsCleared.push(Number(args[0]));
        return Reflect.apply(clearInterval, window, args);
      };
      const listenerIdentities = new Map<object, number>();
      const identityFor = (listener: object) => {
        if (!listenerIdentities.has(listener)) listenerIdentities.set(listener, listenerIdentities.size + 1);
        return listenerIdentities.get(listener)!;
      };
      const addListener = EventTarget.prototype.addEventListener;
      const removeListener = EventTarget.prototype.removeEventListener;
      const isLifecycleEvent = (target: EventTarget, event: string) =>
        (target === document && event === 'visibilitychange') || (target === window && event === 'pagehide');
      EventTarget.prototype.addEventListener = function (...args: Parameters<EventTarget['addEventListener']>) {
        if (args[1] && isLifecycleEvent(this, args[0])) {
          observations.listenersAdded.push({ event: args[0], identity: identityFor(args[1]) });
        }
        return Reflect.apply(addListener, this, args);
      };
      EventTarget.prototype.removeEventListener = function (...args: Parameters<EventTarget['removeEventListener']>) {
        if (args[1] && isLifecycleEvent(this, args[0])) {
          observations.listenersRemoved.push({ event: args[0], identity: identityFor(args[1]) });
        }
        return Reflect.apply(removeListener, this, args);
      };
      const captureReportedDisplay = (source: string) => {
        const display = document.querySelector('input[data-vault-display]') as HTMLInputElement;
        observations.reportedDisplays.push({
          source, value: display.value, type: display.type,
          activeTimers: observations.intervalsStarted.length - observations.intervalsCleared.length,
          activeListeners: observations.listenersAdded.length - observations.listenersRemoved.length,
        });
      };
      const reportError = console.error.bind(console);
      console.error = (...args: unknown[]) => {
        captureReportedDisplay('diagnostic');
        observations.diagnostics.push(String(args[0]));
        reportError(...args);
      };
      widgetWindow.TYPO3 = {
        settings: { ajaxUrls: { vault_reveal: '/reveal' } },
        Notification: {
          error: (_title, message) => {
            captureReportedDisplay('notification');
            observations.notificationErrors.push(String(message));
            if (failureKind === 'error notification') {
              throw new Error('Synthetic notification failure');
            }
          },
        },
      };
      if (failureKind === 'hide mode update') {
        const button = document.querySelector('button[data-identifier="fixture_rejection"]') as HTMLButtonElement;
        const removeClass = DOMTokenList.prototype.remove;
        let faultThrown = false;
        DOMTokenList.prototype.remove = function (...tokens: string[]) {
          if (!faultThrown && this === button.classList && tokens.includes('t3js-vault-input-reveal')) {
            faultThrown = true;
            observations.hideModeUpdateFaults++;
            observations.registeredAtHideModeFault = {
              timers: observations.intervalsStarted.length,
              listeners: observations.listenersAdded.length,
            };
            throw new Error('Synthetic hide-mode update failure');
          }
          return Reflect.apply(removeClass, this, tokens);
        };
      }
      if (failureKind === 'countdown insertion') {
        const inputGroup = document.querySelector('.input-group') as HTMLElement;
        const insertAfter = inputGroup.after.bind(inputGroup);
        inputGroup.after = (...nodes: (Node | string)[]) => {
          if (nodes.some((node) => node instanceof Element && node.classList.contains('t3js-vault-autohide'))) {
            observations.countdownInsertionFaults++;
            throw new Error('Synthetic countdown insertion failure');
          }
          insertAfter(...nodes);
        };
      }
      if (failureKind === 'spinner preparation') {
        const createElement = Document.prototype.createElement;
        Document.prototype.createElement = function (...args: Parameters<Document['createElement']>) {
          if (args[0] === 'typo3-backend-spinner') {
            throw new Error('Synthetic spinner preparation failure');
          }
          return Reflect.apply(createElement, this, args);
        };
      }
    }, failure);

    const revealButton = page.locator('button[data-identifier="fixture_rejection"]');
    await expect(revealButton).toHaveAccessibleName('Reveal secret');
    try {
      await revealButton.click();
      await expect(revealButton).toBeEnabled();
      // Sample immediately once the handler has re-enabled the control. An
      // auto-retrying negation could otherwise wait for the auto-hide timer.
      expect(
        await page.locator('input[data-vault-display]').inputValue(),
        'Partially revealed plaintext must be wiped after failed reveal setup',
      ).not.toBe(partialSecret);
      await expect(page.locator('input[data-vault-display]')).toHaveAttribute('type', 'password');
      await expect(page.locator('input[data-vault-display]')).toHaveValue('••••••••••••');
      await expect(revealButton.locator('.t3js-icon.icon-actions-eye')).toHaveText('Reveal');
      await expect(revealButton.locator('typo3-backend-spinner')).toHaveCount(0);
      await expect(revealButton).toHaveAccessibleName('Reveal secret');
      await expect(page.getByRole('button', { name: 'Copy', includeHidden: true })).toBeHidden();

      // Let the browser complete a task after the Promise reaction, including
      // its native unhandled-rejection reporting; this is not a timed sleep.
      await page.evaluate(() => new Promise<void>((done) => setTimeout(done, 0)));
      const observations = await page.evaluate(() =>
        (window as unknown as WidgetWindow).__vaultRejectionObservations);
      expect(observations.diagnostics).toContain(['countdown insertion', 'hide mode update'].includes(failure)
        ? 'Error revealing secret:'
        : 'Unexpected error revealing secret');
      expect(observations.countdownInsertionFaults).toBe(failure === 'countdown insertion' ? 1 : 0);
      expect(observations.notificationErrors).toEqual(failure === 'spinner preparation'
        ? []
        : [['countdown insertion', 'hide mode update'].includes(failure)
          ? (failure === 'countdown insertion' ? 'Synthetic countdown insertion failure' : 'Synthetic hide-mode update failure')
          : 'HTTP error! status: 503']);
      expect(observations.hideModeUpdateFaults).toBe(failure === 'hide mode update' ? 1 : 0);
      expect(observations.registeredAtHideModeFault).toEqual(failure === 'hide mode update'
        ? { timers: 1, listeners: 2 }
        : null);
      expect(observations.intervalsStarted).toHaveLength(failure === 'hide mode update' ? 1 : 0);
      expect(observations.intervalsCleared).toEqual(observations.intervalsStarted);
      expect(observations.listenersAdded).toHaveLength(failure === 'hide mode update' ? 2 : 0);
      expect(observations.listenersRemoved).toEqual(observations.listenersAdded);
      expect(observations.reportedDisplays.length).toBeGreaterThan(0);
      for (const reportedDisplay of observations.reportedDisplays) {
        expect(reportedDisplay).toMatchObject({
          value: '••••••••••••', type: 'password', activeTimers: 0, activeListeners: 0,
        });
      }
      expect(observations.unhandled).toEqual([]);
      expect(pageErrors).toEqual([]);
      expect(revealRequests).toBe(failure === 'spinner preparation' ? 0 : 1);
      expect(unexpectedRequests).toEqual([]);
    } finally {
      await test.info().attach('actual-rejection-observations', {
        body: JSON.stringify({
          failure,
          browserVersion: page.context().browser()?.version(),
          ...(await page.evaluate(() =>
            (window as unknown as WidgetWindow).__vaultRejectionObservations)),
          display: await page.locator('input[data-vault-display]').evaluate((input) => ({
            value: (input as HTMLInputElement).value, type: (input as HTMLInputElement).type,
          })),
          buttonEnabled: await revealButton.isEnabled(),
          pageErrors,
          revealRequests,
          unexpectedRequests,
        }),
        contentType: 'application/json',
      });
    }
  });
}
