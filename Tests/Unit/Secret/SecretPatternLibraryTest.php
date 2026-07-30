<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Secret;

use Netresearch\NrVault\Secret\SecretIdentifierKind;
use Netresearch\NrVault\Secret\SecretPattern;
use Netresearch\NrVault\Secret\SecretPatternLibrary;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(SecretPatternLibrary::class)]
#[CoversClass(SecretPattern::class)]
final class SecretPatternLibraryTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function preExtractionPatternProvider(): iterable
    {
        foreach (self::catalogueBeforeExtraction() as $name => $pattern) {
            yield $name => [$name, $pattern];
        }
    }

    #[Test]
    #[DataProvider('preExtractionPatternProvider')]
    public function everyPatternFromBeforeTheExtractionSurvivesByteIdentically(
        string $name,
        string $pattern,
    ): void {
        $anchored = SecretPatternLibrary::anchoredByName();

        self::assertArrayHasKey($name, $anchored, \sprintf('Pattern "%s" was dropped from the catalogue.', $name));
        self::assertSame(
            $pattern,
            $anchored[$name],
            \sprintf('Pattern "%s" changed; existing scan findings would change with it.', $name),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function addedShapeProvider(): iterable
    {
        // Shapes the redactors in nr-llm knew and this scanner did not, folded in
        // by the extraction.
        yield 'OpenAI' => ['OpenAI API Key'];
        yield 'GitHub server token' => ['GitHub Server Token'];
        yield 'GitHub fine-grained PAT' => ['GitHub Fine-Grained PAT'];
    }

    #[Test]
    #[DataProvider('addedShapeProvider')]
    public function catalogueGainedTheShapesTheRedactorsKnew(string $name): void
    {
        self::assertArrayHasKey($name, SecretPatternLibrary::anchoredByName());
    }

    /**
     * @return iterable<string, array{SecretPattern}>
     */
    public static function everyPatternProvider(): iterable
    {
        foreach (SecretPatternLibrary::all() as $pattern) {
            yield $pattern->name => [$pattern];
        }
    }

    #[Test]
    #[DataProvider('everyPatternProvider')]
    public function everyPatternIsAValidRegexAndCarriesAtLeastOneForm(SecretPattern $pattern): void
    {
        self::assertTrue(
            $pattern->anchoredPattern !== null || $pattern->inlinePattern !== null,
            \sprintf('Pattern "%s" has neither an anchored nor an inline form and can never match.', $pattern->name),
        );

        foreach ([$pattern->anchoredPattern, $pattern->inlinePattern] as $regex) {
            if ($regex === null) {
                continue;
            }

            // A pattern that does not compile makes preg_match() return false (and
            // raise a diagnostic, which the suite treats as a failure too).
            self::assertNotFalse(
                preg_match($regex, 'probe'),
                \sprintf('Pattern "%s" does not compile: %s', $pattern->name, $regex),
            );
        }
    }

    #[Test]
    #[DataProvider('everyPatternProvider')]
    public function noAnchoredPatternIsUnanchored(SecretPattern $pattern): void
    {
        if ($pattern->anchoredPattern === null) {
            self::assertTrue(true, 'No anchored form to check.');

            return;
        }

        self::assertStringContainsString(
            '^',
            $pattern->anchoredPattern,
            \sprintf('Anchored pattern "%s" is missing a start anchor.', $pattern->name),
        );
        self::assertStringContainsString(
            '$',
            $pattern->anchoredPattern,
            \sprintf('Anchored pattern "%s" is missing an end anchor.', $pattern->name),
        );
    }

    /**
     * The generic shapes must stay anchored-only. A 32-character hex string is a
     * Twilio auth token, but it is also every MD5 digest and every TYPO3 cache
     * identifier; hunting for it inside prose would mangle ordinary text.
     *
     * @return iterable<string, array{string}>
     */
    public static function anchoredOnlyShapeProvider(): iterable
    {
        yield 'Twilio (bare 32 hex)' => ['Twilio Auth Token'];
        yield 'PayPal (E + base64ish)' => ['PayPal Client Secret'];
    }

    #[Test]
    #[DataProvider('anchoredOnlyShapeProvider')]
    public function genericShapesHaveNoInlineForm(string $name): void
    {
        foreach (SecretPatternLibrary::all() as $pattern) {
            if ($pattern->name === $name) {
                self::assertNull(
                    $pattern->inlinePattern,
                    \sprintf('Shape "%s" is too generic to redact inline.', $name),
                );

                return;
            }
        }

        self::fail(\sprintf('Shape "%s" is not in the catalogue.', $name));
    }

    /**
     * Order is behaviour, not cosmetics: masking ``?token=<jwt>`` as a whole
     * parameter beats masking the JWT and leaving a dangling parameter name, so
     * the URL shapes must be applied before the value shapes.
     */
    #[Test]
    public function allIsUrlCredentialsFollowedByValueShapes(): void
    {
        $nameOf = static fn (SecretPattern $pattern): string => $pattern->name;

        self::assertSame(
            [
                ...array_map($nameOf, SecretPatternLibrary::urlCredentials()),
                ...array_map($nameOf, SecretPatternLibrary::valueShapes()),
            ],
            array_map($nameOf, SecretPatternLibrary::all()),
        );
    }

    #[Test]
    public function urlCredentialsCarryNoAnchoredForm(): void
    {
        foreach (SecretPatternLibrary::urlCredentials() as $pattern) {
            self::assertNull(
                $pattern->anchoredPattern,
                \sprintf('"%s" describes an embedded occurrence, not a whole value.', $pattern->name),
            );
        }
    }

    #[Test]
    public function identifierKindsResolveToTheirOwnHintSets(): void
    {
        self::assertSame(
            SecretPatternLibrary::columnNameHints(),
            SecretIdentifierKind::DatabaseColumn->hints(),
        );
        self::assertSame(
            SecretPatternLibrary::configKeyHints(),
            SecretIdentifierKind::ConfigurationKey->hints(),
        );
        self::assertSame(
            SecretPatternLibrary::environmentNameHints(),
            SecretIdentifierKind::EnvironmentVariable->hints(),
        );
    }

    /**
     * The three namespaces must NOT share one union: the environment rule matches
     * any name containing "KEY", which would flag a column called "keyword".
     */
    #[Test]
    public function environmentHintsAreBroaderThanColumnHints(): void
    {
        $columnMatches = false;
        foreach (SecretIdentifierKind::DatabaseColumn->hints() as $hint) {
            if (preg_match($hint, 'keyword') === 1) {
                $columnMatches = true;
            }
        }

        $environmentMatches = false;
        foreach (SecretIdentifierKind::EnvironmentVariable->hints() as $hint) {
            if (preg_match($hint, 'keyword') === 1) {
                $environmentMatches = true;
            }
        }

        self::assertFalse($columnMatches, 'A column named "keyword" must not be treated as a secret.');
        self::assertTrue($environmentMatches, 'The environment rule is substring-based by design.');
    }

    /**
     * The whole-value patterns and their names as SecretDetectionService carried
     * them before the catalogue was extracted, copied verbatim from the private
     * `VALUE_PATTERNS` constant at commit c7d40a6.
     *
     * This is the non-regression contract of the extraction: a scan finding is
     * labelled with the pattern name and its severity is derived from whether a
     * pattern matched, so renaming or loosening any of these would silently
     * change findings in every installation. New shapes may be ADDED; these may
     * not be touched.
     *
     * @return array<string, string>
     */
    private static function catalogueBeforeExtraction(): array
    {
        return [
            'Stripe live key' => '/^sk_live_[a-zA-Z0-9]{24,}$/',
            'Stripe test key' => '/^sk_test_[a-zA-Z0-9]{24,}$/',
            'Stripe publishable live' => '/^pk_live_[a-zA-Z0-9]{24,}$/',
            'Stripe publishable test' => '/^pk_test_[a-zA-Z0-9]{24,}$/',
            'AWS Access Key' => '/^AKIA[0-9A-Z]{16}$/',
            'GitHub Personal Access Token' => '/^ghp_[a-zA-Z0-9]{36}$/',
            'GitHub OAuth Token' => '/^gho_[a-zA-Z0-9]{36}$/',
            'GitHub App Token' => '/^ghu_[a-zA-Z0-9]{36}$/',
            'GitHub Refresh Token' => '/^ghr_[a-zA-Z0-9]{36}$/',
            'Slack Bot Token' => '/^xoxb-\d{10,13}-\d{10,13}-[a-zA-Z0-9]{24}$/',
            'Slack User Token' => '/^xoxp-\d{10,13}-\d{10,13}-[a-zA-Z0-9]{24}$/',
            'Slack App Token' => '/^xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+$/',
            'Google API Key' => '/^AIza[0-9A-Za-z_-]{35}$/',
            'Mailchimp API Key' => '/^[a-f0-9]{32}-us\d{1,2}$/',
            'SendGrid API Key' => '/^SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}$/',
            'Twilio Auth Token' => '/^[a-f0-9]{32}$/',
            'PayPal Client Secret' => '/^E[A-Za-z0-9_-]{50,80}$/',
            'JWT Token' => '/^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/',
        ];
    }
}
