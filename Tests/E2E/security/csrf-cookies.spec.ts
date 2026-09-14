import { test as base, expect } from '@playwright/test';
import { test, isLoginRedirect } from '../fixtures/auth';

/**
 * SEC-CSRF / SEC-COOKIES — CSRF and session-cookie hardening.
 *
 * These tests verify invariants that protect the vault from CSRF attacks and
 * session hijacking:
 *
 *   1. AJAX state-changing routes require a valid session cookie. A request
 *      without ANY session cookie must be rejected with 401/403.
 *   2. AJAX state-changing routes require the CSRF token that TYPO3 binds to
 *      the session. A request with the session cookie but no token — or a
 *      clearly-bogus token — must be rejected with 401/403.
 *   3. Session cookies issued by the backend must be hardened: httpOnly=true
 *      for all session cookies, secure=true on HTTPS contexts, sameSite set
 *      to Strict or Lax (never None, which would enable cross-site sends).
 *
 * Anything that degrades these guarantees should fail this suite BEFORE it
 * reaches production.
 */

test.describe('SEC-CSRF-001: AJAX reveal rejects request without session cookie', () => {
  base('POST /vault/reveal without cookies returns 401 or 403', async ({ request }) => {
    // Raw HTTP request — no browser context, so no cookies are attached.
    const response = await request.post('/typo3/ajax/vault/reveal', {
      data: { identifier: 'whatever' },
      failOnStatusCode: false,
      // Do not follow a redirect: TYPO3 13 rejects with 302 → /typo3/login,
      // and following it would report the login page's 200.
      maxRedirects: 0,
    });

    const status = response.status();
    expect(
      [401, 403].includes(status) || isLoginRedirect(response),
      `vault/reveal without session cookie returned ${status} — expected 401, 403 or a redirect to /typo3/login`,
    ).toBe(true);
  });
});

test.describe('SEC-CSRF-002: AJAX reveal rejects request without CSRF token', () => {
  test('POST /vault/reveal with session but without CSRF token is rejected', async ({
    authenticatedPage: page,
    request,
  }) => {
    // Collect the session cookies from the authenticated context but DO NOT
    // extract the CSRF token — we deliberately omit it to simulate a CSRF
    // attempt that rides an existing session.
    const cookies = await page.context().cookies();
    const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join('; ');

    const response = await request.post('/typo3/ajax/vault/reveal', {
      headers: {
        Cookie: cookieHeader,
        'Content-Type': 'application/json',
        // NO X-Csrf-Token / no request-token — TYPO3 must reject this.
      },
      data: JSON.stringify({ identifier: 'whatever' }),
      failOnStatusCode: false,
      // TYPO3 13 rejects a token-less request with 302 → /typo3/login.
      maxRedirects: 0,
    });

    const status = response.status();
    // Pinned rejection codes. A 200 here would indicate the route accepts
    // the request without CSRF protection — a critical regression.
    expect(
      [401, 403, 400].includes(status) || isLoginRedirect(response),
      `POST /vault/reveal with session cookie but no CSRF token returned ${status} — expected 400|401|403 or a redirect to /typo3/login`,
    ).toBe(true);

    // Also: the body must NOT include a plaintext secret field. A
    // well-formed rejection returns either HTML or JSON with success=false.
    const body = await response.text();
    if (body.trim().startsWith('{')) {
      const json = JSON.parse(body) as { success?: boolean; secret?: string };
      expect(json.success ?? false, 'Response reports success without CSRF token').toBe(false);
      expect(json.secret, 'Response leaked a secret without CSRF token').toBeUndefined();
    }
  });

  test('POST /vault/reveal with obviously-bogus CSRF token is rejected', async ({
    authenticatedPage: page,
    request,
  }) => {
    const cookies = await page.context().cookies();
    const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join('; ');

    const response = await request.post('/typo3/ajax/vault/reveal', {
      headers: {
        Cookie: cookieHeader,
        'Content-Type': 'application/json',
        'X-Csrf-Token': 'not-a-real-token',
      },
      data: JSON.stringify({ identifier: 'whatever' }),
      failOnStatusCode: false,
      // TYPO3 13 rejects a request with an invalid token with 302 → /typo3/login.
      maxRedirects: 0,
    });

    const status = response.status();
    expect(
      [401, 403, 400].includes(status) || isLoginRedirect(response),
      `POST /vault/reveal with bogus CSRF token returned ${status}`,
    ).toBe(true);
  });
});

test.describe('SEC-COOKIES-001: Session cookie hardening', () => {
  test('session cookies are httpOnly, secure on HTTPS, and sameSite=Strict/Lax', async ({
    authenticatedPage: page,
  }) => {
    const baseUrl = page.url();
    const isHttps = baseUrl.startsWith('https://');

    const cookies = await page.context().cookies();

    // Consider cookies named like TYPO3 backend session cookies. TYPO3 v14
    // default is `be_typo_user`; some installs rename it. We also cover any
    // cookie whose name contains `sess` or `typo3`.
    const sessionCookieNames = /be_typo_user|typo3|sess/i;
    const sessionCookies = cookies.filter((c) => sessionCookieNames.test(c.name));

    expect(
      sessionCookies.length,
      `No session cookies found — expected at least one matching ${sessionCookieNames}. All cookies: ${cookies.map((c) => c.name).join(', ')}`,
    ).toBeGreaterThan(0);

    for (const cookie of sessionCookies) {
      expect(
        cookie.httpOnly,
        `Session cookie '${cookie.name}' is missing httpOnly=true — vulnerable to XSS cookie theft`,
      ).toBe(true);

      if (isHttps) {
        expect(
          cookie.secure,
          `Session cookie '${cookie.name}' is missing secure=true on HTTPS — will be sent over plain HTTP`,
        ).toBe(true);
      }

      const sameSite = (cookie.sameSite ?? '').toLowerCase();
      expect(
        ['strict', 'lax'],
        `Session cookie '${cookie.name}' has sameSite='${cookie.sameSite}' — must be 'Strict' or 'Lax' to prevent CSRF`,
      ).toContain(sameSite);
    }
  });
});
