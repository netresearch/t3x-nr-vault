<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Secret;

use Netresearch\NrVault\Secret\SecretIdentifierKind;
use Netresearch\NrVault\Secret\SecretRedactor;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(SecretRedactor::class)]
final class SecretRedactorTest extends TestCase
{
    private SecretRedactor $redactor;

    protected function setUp(): void
    {
        parent::setUp();

        $this->redactor = new SecretRedactor();
    }

    /**
     * One row per secret shape that must not survive a redaction pass.
     *
     * The seven marked GAP were the concrete leak this catalogue was built to
     * close: nr-llm's privacy redactor missed them while its guardrail caught
     * them, so a secret masked on the way to a provider was still written to the
     * database in cleartext.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function secretShapeProvider(): iterable
    {
        // The OpenAI mask deliberately keeps the 'sk-' prefix so a reader can
        // tell what was removed, so these two assert on the key BODY.
        yield 'OpenAI legacy key' => ['sk-abcdefghijklmnopqrstuvwxyz012345', 'abcdefghijklmnop'];
        yield 'OpenAI project key (GAP)' => ['sk-proj-AbCdEf01234567890abcdefGHIJKLmnopqr', 'AbCdEf01234567890'];
        yield 'GitHub PAT (GAP)' => ['ghp_' . self::repeat('a', 36), 'ghp_'];
        yield 'GitHub fine-grained PAT (GAP)' => ['github_pat_' . self::repeat('b', 30), 'github_pat_'];
        yield 'GitHub server token' => ['ghs_' . self::repeat('c', 36), 'ghs_'];
        yield 'AWS access key (GAP)' => ['AKIAIOSFODNN7EXAMPLE', 'AKIA'];
        yield 'Google API key (GAP)' => ['AIza' . self::repeat('d', 35), 'AIza'];
        yield 'Slack bot token (GAP)' => ['xoxb-1234567890-abcdefghij', 'xoxb-'];
        yield 'Slack legacy token' => ['xoxa-1234567890-abcdefghij', 'xoxa-'];
        yield 'JWT (GAP)' => ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123', 'eyJ'];
        yield 'Stripe live key' => ['sk_live_' . self::repeat('9', 24), 'sk_live_'];
        yield 'Stripe publishable key' => ['pk_test_' . self::repeat('8', 24), 'pk_test_'];
        yield 'SendGrid key' => [
            'SG.' . self::repeat('a', 22) . '.' . self::repeat('b', 43),
            'SG.',
        ];
        yield 'Mailchimp key' => [self::repeat('a', 32) . '-us14', '-us14'];
        yield 'Bearer header' => ['Authorization: Bearer abc.def-ghi_jkl+mno/pqr=', 'abc.def'];
        yield 'URL credential parameter' => ['https://api.example.com/v1?key=SUPERSECRET123&x=1', 'SUPERSECRET123'];
        yield 'connection string password' => ['postgres://user:hunter2@db.internal:5432/app', 'hunter2'];
        yield 'passwordless userinfo' => ['redis://:s3cr3tpw@cache:6379/0', 's3cr3tpw'];
    }

    #[Test]
    #[DataProvider('secretShapeProvider')]
    public function secretShapesDoNotSurviveRedaction(string $input, string $mustNotRemain): void
    {
        $redacted = $this->redactor->redact($input);

        self::assertStringNotContainsString(
            $mustNotRemain,
            $redacted,
            \sprintf('Secret material survived redaction: %s', $redacted),
        );
        self::assertNotSame($input, $redacted, 'Redaction did not change the input at all.');
    }

    #[Test]
    #[DataProvider('secretShapeProvider')]
    public function redactionIsIdempotent(string $input, string $mustNotRemain): void
    {
        $once = $this->redactor->redact($input);
        $twice = $this->redactor->redact($once);

        self::assertSame($once, $twice, 'A second pass changed already-redacted output.');
        self::assertStringNotContainsString($mustNotRemain, $twice);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function innocuousTextProvider(): iterable
    {
        yield 'prose' => ['The quick brown fox jumps over the lazy dog.'];
        yield 'plain url' => ['https://example.com/page?id=42&sort=name'];
        yield 'md5 digest' => ['d41d8cd98f00b204e9800998ecf8427e'];
        yield 'cache identifier' => ['cache_pages_' . self::repeat('f', 32)];
        yield 'long identifier starting with E' => ['E' . self::repeat('x', 60)];
        yield 'german sentence' => ['Der Schlüssel liegt unter der Matte.'];
        yield 'code snippet' => ['$config = [\'timeout\' => 30, \'retries\' => 3];'];
        yield 'semver list' => ['1.2.3, 4.5.6, 7.8.9'];
    }

    /**
     * The generic anchored-only shapes exist precisely so ordinary text survives:
     * an MD5 digest and a 60-character identifier must come back untouched.
     */
    #[Test]
    #[DataProvider('innocuousTextProvider')]
    public function innocuousTextIsLeftAlone(string $input): void
    {
        self::assertSame($input, $this->redactor->redact($input));
    }

    #[Test]
    public function emailsAreKeptByDefaultAndMaskedOnRequest(): void
    {
        $text = 'Write to person@example.com about it.';

        self::assertSame($text, $this->redactor->redact($text));
        self::assertStringNotContainsString(
            'person@example.com',
            $this->redactor->redact($text, includeEmails: true),
        );
    }

    #[Test]
    public function emptyInputStaysEmpty(): void
    {
        self::assertSame('', $this->redactor->redact(''));
    }

    #[Test]
    public function secretsEmbeddedInSurroundingProseAreMaskedInPlace(): void
    {
        $redacted = $this->redactor->redact(
            'Use the key ghp_' . self::repeat('a', 36) . ' for the API and report back.',
        );

        self::assertStringStartsWith('Use the key ', $redacted);
        self::assertStringEndsWith(' for the API and report back.', $redacted);
        self::assertStringNotContainsString('ghp_', $redacted);
    }

    /**
     * A `preg_replace()` that gives up returns null. Casting that to string would
     * yield '' — wiping the caller's entire content, which on a redaction path
     * looks exactly like a very thorough redaction. The redactor must keep the
     * text instead.
     */
    #[Test]
    public function aFailingRegexEngineDoesNotWipeTheContent(): void
    {
        $original = \ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', '1');

        try {
            $text = 'Bearer ' . self::repeat('a', 5000);

            // Precondition: the crushed limit really does make the engine give up
            // on this pattern. Asserted so the test cannot quietly stop testing
            // anything if PCRE's accounting changes.
            self::assertNull(
                preg_replace('/\b(Bearer\s+)[A-Za-z0-9._~+\/\-]+=*/i', '$1***', $text),
                'Precondition failed: preg_replace was expected to return null here.',
            );
            self::assertSame(PREG_BACKTRACK_LIMIT_ERROR, preg_last_error());

            $result = $this->redactor->redact($text);

            self::assertNotSame('', $result, 'Content was wiped when the regex engine failed.');
            self::assertSame($text, $result, 'With the matching pattern failing, the input must come back unchanged.');
        } finally {
            ini_set('pcre.backtrack_limit', $original === false ? '1000000' : $original);
        }
    }

    /**
     * @return iterable<string, array{string, string|null}>
     */
    public static function wholeValueProvider(): iterable
    {
        yield 'stripe live' => ['sk_live_' . self::repeat('9', 24), 'Stripe live key'];
        yield 'aws' => ['AKIAIOSFODNN7EXAMPLE', 'AWS Access Key'];
        yield 'github pat' => ['ghp_' . self::repeat('a', 36), 'GitHub Personal Access Token'];
        yield 'openai' => ['sk-proj-' . self::repeat('a', 20), 'OpenAI API Key'];
        yield 'twilio' => [self::repeat('a', 32), 'Twilio Auth Token'];
        yield 'surrounded by whitespace' => ['  AKIAIOSFODNN7EXAMPLE  ', 'AWS Access Key'];
        yield 'not a secret' => ['just a value', null];
        yield 'empty' => ['', null];
        yield 'whitespace only' => ['   ', null];
        // Embedded, not the whole value: classification must not fire.
        yield 'embedded secret' => ['key is AKIAIOSFODNN7EXAMPLE here', null];
    }

    #[Test]
    #[DataProvider('wholeValueProvider')]
    public function identifyValueClassifiesOnlyWholeValues(string $value, ?string $expected): void
    {
        self::assertSame($expected, $this->redactor->identifyValue($value));
    }

    /**
     * @return iterable<string, array{string, SecretIdentifierKind, bool}>
     */
    public static function identifierProvider(): iterable
    {
        yield 'column: password' => ['password', SecretIdentifierKind::DatabaseColumn, true];
        yield 'column: api_key' => ['api_key', SecretIdentifierKind::DatabaseColumn, true];
        yield 'column: keyword' => ['keyword', SecretIdentifierKind::DatabaseColumn, false];
        yield 'column: title' => ['title', SecretIdentifierKind::DatabaseColumn, false];

        yield 'config: clientSecret' => ['clientSecret', SecretIdentifierKind::ConfigurationKey, true];
        yield 'config: secretPrefix' => ['secretPrefix', SecretIdentifierKind::ConfigurationKey, false];
        yield 'config: baseUrl' => ['baseUrl', SecretIdentifierKind::ConfigurationKey, false];

        // The two shapes that leaked out of nr-llm's environment listing: neither
        // name ends in a recognised suffix, so only a substring rule catches them.
        yield 'env: GITHUB_PAT' => ['GITHUB_PAT', SecretIdentifierKind::EnvironmentVariable, false];
        yield 'env: DATABASE_URL' => ['DATABASE_URL', SecretIdentifierKind::EnvironmentVariable, true];
        yield 'env: PGPASSWORD' => ['PGPASSWORD', SecretIdentifierKind::EnvironmentVariable, true];
        yield 'env: TYPO3_ENCRYPTION_KEY' => ['TYPO3_ENCRYPTION_KEY', SecretIdentifierKind::EnvironmentVariable, true];
        yield 'env: PATH' => ['PATH', SecretIdentifierKind::EnvironmentVariable, false];
    }

    #[Test]
    #[DataProvider('identifierProvider')]
    public function identifiersAreJudgedWithinTheirOwnNamespace(
        string $identifier,
        SecretIdentifierKind $kind,
        bool $expected,
    ): void {
        self::assertSame($expected, $this->redactor->isSecretIdentifier($identifier, $kind));
    }

    /**
     * GITHUB_PAT is the case that proves a name rule alone is not enough: nothing
     * in the NAME says secret, so only classifying the VALUE catches it. This is
     * why a consumer listing an environment must check both.
     */
    #[Test]
    public function aSecretNameRuleAloneMissesGithubPatButValueClassificationCatchesIt(): void
    {
        $name = 'GITHUB_PAT';
        $value = 'ghp_' . self::repeat('a', 36);

        self::assertFalse($this->redactor->isSecretIdentifier($name, SecretIdentifierKind::EnvironmentVariable));
        self::assertSame('GitHub Personal Access Token', $this->redactor->identifyValue($value));
        self::assertStringNotContainsString('ghp_', $this->redactor->redact($value));
    }

    private static function repeat(string $char, int $times): string
    {
        return str_repeat($char, $times);
    }
}
