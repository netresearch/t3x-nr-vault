// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: Netresearch DTT GmbH

import { defineConfig, devices } from '@playwright/test';

/**
 * Shared `use` options applied to every project.
 */
const commonUse = {
  baseURL: process.env.TYPO3_BASE_URL || 'https://v14.nr-vault.ddev.site',
  trace: 'on-first-retry' as const,
  screenshot: 'only-on-failure' as const,
  video: 'on-first-retry' as const,
  ignoreHTTPSErrors: true,
};

/**
 * Specs that mutate shared DB rows (audit log, vault secrets) directly through
 * DDEV or the UI. These must run on a single browser to avoid races where two
 * workers fight over the same uid.
 */
const singleBrowserOnly = /security\/audit-tamper\.spec\.ts$/;

export default defineConfig({
  testDir: './Tests/E2E',
  fullyParallel: false, // Tests within a file run sequentially (safer for state)
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 4 : undefined, // Parallel by spec file; undefined = half of CPUs locally
  reporter: [
    ['html', { outputFolder: '.Build/playwright-report' }],
    ['list'],
  ],
  outputDir: '.Build/playwright-results',
  use: commonUse,
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
      // Skip DB-mutation specs on firefox; the in-spec `test.skip` also guards
      // this, but declaring it here keeps the report clean.
      testIgnore: singleBrowserOnly,
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
      testIgnore: singleBrowserOnly,
    },
  ],
  expect: {
    timeout: 10000,
  },
  timeout: 60000,
});
