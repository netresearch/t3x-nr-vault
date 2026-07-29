<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Secret;

/**
 * The single catalogue of recognisable secret shapes (ADR-031).
 *
 * Before this existed the same knowledge was maintained four times — once in
 * this extension's plaintext scanner and three times in nr-llm (a response/prompt
 * guardrail, a privacy redactor, an environment-listing tool) — and the copies
 * had drifted: the scanner knew Stripe, SendGrid, Twilio and Mailchimp but not
 * OpenAI project keys or fine-grained GitHub PATs, while the redactors knew the
 * latter and not the former.
 *
 * The scanner and the three nr-llm redactors now read from here.
 * {@see \Netresearch\NrVault\Http\OAuth\OAuthTokenManager} deliberately keeps its
 * own patterns: it also has to reach credentials inside quoted and JSON-escaped
 * forms (``"client_secret":"…\"…"``), which this catalogue does not model.
 *
 * Every pattern is linear: bounded character classes separated by literals, with
 * no nested quantifiers, so none is vulnerable to catastrophic backtracking.
 *
 * The anchored forms and their names are deliberately byte-identical to the ones
 * this extension's scanner used before the catalogue was extracted, so existing
 * findings keep their names and severities. New shapes were only added, never
 * renamed or loosened.
 */
final class SecretPatternLibrary
{
    /** Matches an e-mail address. Not a secret, but personal data some consumers mask alongside secrets. */
    public const EMAIL_PATTERN = '/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/';

    /**
     * Vendor-specific API-key, token and credential shapes.
     *
     * Shapes with no inline form are too generic to hunt for inside prose: a bare
     * 32-character hex string is a Twilio auth token, but it is also every MD5
     * digest, and an ``E`` followed by 50 base64 characters is a PayPal secret but
     * also an ordinary long identifier. Masking those inline would corrupt far
     * more legitimate text than it would protect.
     *
     * @return list<SecretPattern>
     */
    public static function valueShapes(): array
    {
        return [
            // --- Generic bearer credentials ----------------------------------
            // FIRST on purpose. A 'Bearer <token>' match subsumes whatever the
            // token happens to be, so running it before the prefix-specific shapes
            // makes 'Bearer sk-…' collapse to a single mask. The other way round,
            // the OpenAI rule rewrote the key to 'sk-***' and the Bearer rule then
            // matched the remaining 'Bearer sk-', yielding 'Bearer ******'.
            // The character class covers base64-standard characters (+ / =) so a
            // token's tail is not left behind after the mask.
            new SecretPattern(
                name: 'Bearer Token',
                inlinePattern: '/\b(Bearer\s+)[A-Za-z0-9._~+\/\-]+=*/i',
                inlineReplacement: '$1' . SecretPattern::MASK,
            ),

            // --- OpenAI ------------------------------------------------------
            // The inline class allows '-' and '_' so modern project keys
            // (sk-proj-…) match, and the mask keeps the 'sk-' prefix so a reader
            // can still tell WHAT was removed.
            new SecretPattern(
                name: 'OpenAI API Key',
                anchoredPattern: '/^sk-[A-Za-z0-9_\-]{16,}$/',
                inlinePattern: '/\bsk-[A-Za-z0-9_\-]{16,}/',
                inlineReplacement: 'sk-' . SecretPattern::MASK,
            ),

            // --- Stripe ------------------------------------------------------
            new SecretPattern(
                name: 'Stripe live key',
                anchoredPattern: '/^sk_live_[a-zA-Z0-9]{24,}$/',
                inlinePattern: '/\bsk_live_[a-zA-Z0-9]{24,}/',
            ),
            new SecretPattern(
                name: 'Stripe test key',
                anchoredPattern: '/^sk_test_[a-zA-Z0-9]{24,}$/',
                inlinePattern: '/\bsk_test_[a-zA-Z0-9]{24,}/',
            ),
            new SecretPattern(
                name: 'Stripe publishable live',
                anchoredPattern: '/^pk_live_[a-zA-Z0-9]{24,}$/',
                inlinePattern: '/\bpk_live_[a-zA-Z0-9]{24,}/',
            ),
            new SecretPattern(
                name: 'Stripe publishable test',
                anchoredPattern: '/^pk_test_[a-zA-Z0-9]{24,}$/',
                inlinePattern: '/\bpk_test_[a-zA-Z0-9]{24,}/',
            ),

            // --- AWS ---------------------------------------------------------
            new SecretPattern(
                name: 'AWS Access Key',
                anchoredPattern: '/^AKIA[0-9A-Z]{16}$/',
                inlinePattern: '/\bAKIA[0-9A-Z]{16,}/',
            ),

            // --- GitHub ------------------------------------------------------
            new SecretPattern(
                name: 'GitHub Personal Access Token',
                anchoredPattern: '/^ghp_[a-zA-Z0-9]{36}$/',
                inlinePattern: '/\bghp_[A-Za-z0-9]{36,}/',
            ),
            new SecretPattern(
                name: 'GitHub OAuth Token',
                anchoredPattern: '/^gho_[a-zA-Z0-9]{36}$/',
                inlinePattern: '/\bgho_[A-Za-z0-9]{36,}/',
            ),
            new SecretPattern(
                name: 'GitHub App Token',
                anchoredPattern: '/^ghu_[a-zA-Z0-9]{36}$/',
                inlinePattern: '/\bghu_[A-Za-z0-9]{36,}/',
            ),
            new SecretPattern(
                name: 'GitHub Refresh Token',
                anchoredPattern: '/^ghr_[a-zA-Z0-9]{36}$/',
                inlinePattern: '/\bghr_[A-Za-z0-9]{36,}/',
            ),
            new SecretPattern(
                name: 'GitHub Server Token',
                anchoredPattern: '/^ghs_[a-zA-Z0-9]{36}$/',
                inlinePattern: '/\bghs_[A-Za-z0-9]{36,}/',
            ),
            new SecretPattern(
                name: 'GitHub Fine-Grained PAT',
                anchoredPattern: '/^github_pat_\w{22,}$/',
                inlinePattern: '/\bgithub_pat_\w{22,}/',
            ),

            // --- Slack -------------------------------------------------------
            // The anchored forms keep the scanner's strict segment structure; the
            // inline forms are deliberately looser, because a redactor that
            // under-matches leaks whereas a scanner that over-matches cries wolf.
            new SecretPattern(
                name: 'Slack Bot Token',
                anchoredPattern: '/^xoxb-\d{10,13}-\d{10,13}-[a-zA-Z0-9]{24}$/',
                inlinePattern: '/\bxoxb-[A-Za-z0-9\-]{10,}/',
            ),
            new SecretPattern(
                name: 'Slack User Token',
                anchoredPattern: '/^xoxp-\d{10,13}-\d{10,13}-[a-zA-Z0-9]{24}$/',
                inlinePattern: '/\bxoxp-[A-Za-z0-9\-]{10,}/',
            ),
            new SecretPattern(
                name: 'Slack App Token',
                anchoredPattern: '/^xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+$/',
                inlinePattern: '/\bxapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+/',
            ),
            // Covers the remaining xox? prefixes (xoxa, xoxr, xoxs) that have no
            // dedicated anchored entry, so a redactor never misses one.
            new SecretPattern(
                name: 'Slack Legacy Token',
                inlinePattern: '/\bxox[ars]-[A-Za-z0-9\-]{10,}/',
            ),

            // --- Google ------------------------------------------------------
            new SecretPattern(
                name: 'Google API Key',
                anchoredPattern: '/^AIza[0-9A-Za-z_-]{35}$/',
                inlinePattern: '/\bAIza[0-9A-Za-z_\-]{35,}/',
            ),

            // --- Other vendors ----------------------------------------------
            new SecretPattern(
                name: 'Mailchimp API Key',
                anchoredPattern: '/^[a-f0-9]{32}-us\d{1,2}$/',
                inlinePattern: '/\b[a-f0-9]{32}-us\d{1,2}\b/',
            ),
            new SecretPattern(
                name: 'SendGrid API Key',
                anchoredPattern: '/^SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}$/',
                inlinePattern: '/\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/',
            ),
            new SecretPattern(
                name: 'Twilio Auth Token',
                anchoredPattern: '/^[a-f0-9]{32}$/',
            ),
            new SecretPattern(
                name: 'PayPal Client Secret',
                anchoredPattern: '/^E[A-Za-z0-9_-]{50,80}$/',
            ),

            // --- Generic bearer credentials ----------------------------------
            // A JWT is the canonical bearer secret even without a 'Bearer '
            // prefix. The inline form does not require the payload segment to
            // start with 'eyJ' (only the header does), so tokens with a
            // non-JSON-object payload still match.
            new SecretPattern(
                name: 'JWT Token',
                anchoredPattern: '/^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/',
                inlinePattern: '/\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/',
            ),
        ];
    }

    /**
     * Credentials carried inside a URL: the well-known credential query
     * parameters, and the password of a ``scheme://user:password@host`` userinfo
     * component (as found in database and cache connection strings).
     *
     * Kept separate from {@see valueShapes()} because some consumers — error-message
     * sanitising in particular — want only this narrow, high-confidence set.
     *
     * @return list<SecretPattern>
     */
    public static function urlCredentials(): array
    {
        return [
            // The parameter NAME accepts an optional vendor prefix, so the OAuth 2.0
            // standard names match: 'client_secret' (RFC 6749 §2.3.1) is
            // 'client' + '_' + 'secret'. Without the prefix the alternation missed
            // it entirely and an OAuth client secret in a query string survived
            // redaction. A name like 'monkey' cannot match: the prefixed form needs
            // a '_' or '-' separator, and the bare form must consume the whole name.
            //
            // The VALUE class is bounded by structural characters, not just '&' and
            // whitespace — the technique already used by
            // {@see \Netresearch\NrVault\Http\OAuth\OAuthTokenManager}. An
            // unbounded class runs past the end of the URL and eats the rest of the
            // line: masking '{"url":"…?token=abc","next":"keepme"}' swallowed the
            // closing quote, the brace and the following key, leaving unparseable
            // JSON and losing context the reader needed.
            new SecretPattern(
                name: 'URL Credential Parameter',
                inlinePattern: '/([?&])((?:[a-z0-9]+[_\-])?(?:api[_\-]?key|apikey|access[_\-]?token|refresh[_\-]?token|id[_\-]?token|client[_\-]?secret|auth[_\-]?token|key|secret|token|password|passwd|pwd|credential|signature))=[^&\s"\'<>{}\[\](),;#]+/i',
                inlineReplacement: '$1$2=' . SecretPattern::MASK,
            ),
            // The username may be empty (e.g. redis://:password@host). A '~'
            // delimiter is used because the pattern itself contains '#'.
            //
            // The password class is bounded the same way. Left unbounded it did not
            // stop at the end of the URL either: in
            // '{"url":"https://example.com:8080","contact":"support@example.org"}'
            // it treated everything from the port to the address' '@' as one
            // password, deleting the port and the whole contact field — and
            // fabricated 'https://example.com:***@example.org', which reads as if a
            // credential had been redacted from a request to a host that was never
            // contacted.
            new SecretPattern(
                name: 'URL Userinfo Password',
                inlinePattern: '~(\b[a-z][a-z0-9+.\-]*://[^:/?#\s@]*):[^@/?#\s"\'<>{}\[\](),;]+@~i',
                inlineReplacement: '$1:' . SecretPattern::MASK . '@',
            ),
        ];
    }

    /**
     * URL credentials first, then value shapes.
     *
     * The order matters: masking ``?token=<jwt>`` as a whole parameter is more
     * informative than masking the JWT and leaving the parameter name dangling,
     * and ``Bearer <openai key>`` should collapse to one mask rather than two.
     *
     * @return list<SecretPattern>
     */
    public static function all(): array
    {
        return [...self::urlCredentials(), ...self::valueShapes()];
    }

    /**
     * Whole-value classification patterns, keyed by shape name.
     *
     * @return array<string, string>
     */
    public static function anchoredByName(): array
    {
        $anchored = [];
        foreach (self::valueShapes() as $pattern) {
            if ($pattern->anchoredPattern !== null) {
                $anchored[$pattern->name] = $pattern->anchoredPattern;
            }
        }

        return $anchored;
    }

    /**
     * Database column names that typically hold a secret.
     *
     * @return list<string>
     */
    public static function columnNameHints(): array
    {
        return [
            '/password$/i',
            '/^password/i',
            '/api[_-]?key$/i',
            '/api[_-]?secret$/i',
            '/secret[_-]?key$/i',
            '/secret$/i',
            '/token$/i',
            '/access[_-]?token$/i',
            '/refresh[_-]?token$/i',
            '/auth[_-]?token$/i',
            '/credential/i',
            '/private[_-]?key$/i',
            '/encryption[_-]?key$/i',
            '/smtp[_-]?password$/i',
            '/db[_-]?password$/i',
            '/database[_-]?password$/i',
        ];
    }

    /**
     * Configuration keys that typically hold a secret. Anchored on suffixes to
     * avoid false positives such as "secretPrefix".
     *
     * @return list<string>
     */
    public static function configKeyHints(): array
    {
        return [
            '/password$/i',           // ends with "password" (smtpPassword, dbPassword)
            '/^password$/i',          // exactly "password"
            '/secret$/i',             // ends with "secret" (apiSecret, clientSecret) - NOT "secretPrefix"
            '/token$/i',              // ends with "token" (accessToken, authToken)
            '/apiKey$/i',             // ends with "apiKey"
            '/privateKey$/i',         // ends with "privateKey"
            '/encryptionKey$/i',      // ends with "encryptionKey"
            '/credential/i',          // contains "credential"
        ];
    }

    /**
     * Environment-variable names that typically hold a secret.
     *
     * Deliberately broader and substring-based rather than suffix-anchored:
     * process environments use terse, inconsistent names (``PGPASSWORD``,
     * ``DATABASE_URL``, ``TYPO3_ENCRYPTION_KEY``) where a suffix rule misses.
     *
     * @return list<string>
     */
    public static function environmentNameHints(): array
    {
        return [
            '/PASS|PASSWORD|PWD|SECRET|TOKEN|KEY|SALT|CREDENTIAL|AUTH|PRIVATE|MASTER|ENCRYPT|DSN|DATABASE_URL|APIKEY|API_KEY/i',
        ];
    }
}
