<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Hook;

use Closure;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Hook\VaultFailureReporter;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\AbstractLogger;
use Stringable;

#[CoversClass(VaultFailureReporter::class)]
final class VaultFailureReporterTest extends TestCase
{
    /** The correlation reference: 8 random bytes, hex-encoded. */
    private const REFERENCE_PATTERN = '/\b[0-9a-f]{16}\b/';

    private const PROBE_IDENTIFIER = 'probe-identifier';

    /** @var list<array{string, array<mixed>}> */
    private array $records = [];

    private VaultFailureReporter $subject;

    protected function setUp(): void
    {
        parent::setUp();

        /** @param array<mixed> $context */
        $record = function (string $message, array $context): void {
            $this->records[] = [$message, $context];
        };

        // A real recording logger rather than a mock: the assertions below are
        // about the record that actually reaches a PSR-3 writer.
        $logger = new class ($record) extends AbstractLogger {
            /**
             * @param Closure(string, array<mixed>): void $record
             */
            public function __construct(private readonly Closure $record) {}

            /**
             * @param mixed $level
             * @param array<mixed> $context
             */
            public function log($level, string|Stringable $message, array $context = []): void
            {
                ($this->record)((string) $message, $context);
            }
        };

        $this->subject = new VaultFailureReporter($logger);
    }

    /**
     * The existence oracle this class closes: "does not exist" and "exists but
     * you may not touch it" must be indistinguishable to the editor who
     * submitted the identifier.
     */
    #[Test]
    public function userMessageIsIdenticalForNotFoundAndAccessDenied(): void
    {
        $notFound = $this->subject->report(
            SecretNotFoundException::forIdentifier(self::PROBE_IDENTIFIER),
        );
        $accessDenied = $this->subject->report(
            AccessDeniedException::forIdentifier(self::PROBE_IDENTIFIER, 'rotate permission denied'),
        );

        self::assertSame(
            preg_replace(self::REFERENCE_PATTERN, 'REFERENCE', $notFound),
            preg_replace(self::REFERENCE_PATTERN, 'REFERENCE', $accessDenied),
            'The two causes must differ only in the correlation reference',
        );
    }

    #[Test]
    public function userMessageCarriesNeitherTheCauseNorTheProbedIdentifier(): void
    {
        $message = $this->subject->report(
            SecretNotFoundException::forIdentifier(self::PROBE_IDENTIFIER),
            ['identifier' => self::PROBE_IDENTIFIER],
        );

        self::assertStringNotContainsString('not found', $message);
        self::assertStringNotContainsString(self::PROBE_IDENTIFIER, $message);
        self::assertMatchesRegularExpression(self::REFERENCE_PATTERN, $message);
    }

    #[Test]
    public function userMessageQuotesTheReferenceOfItsOwnLogRecord(): void
    {
        $message = $this->subject->report(new VaultException('Boom'));

        [, $context] = $this->records[0];

        self::assertIsString($context['reference']);
        self::assertStringContainsString($context['reference'], $message);
    }

    /**
     * The PSR-3 message argument is written verbatim by TYPO3's FileWriter, so
     * it must be a constant; the cause belongs in the json-encoded context.
     */
    #[Test]
    public function causeIsLoggedInTheContextAndNeverInTheMessage(): void
    {
        $this->subject->report(new VaultException('Boom'), ['table' => 'tx_test', 'uid' => 42]);

        [$message, $context] = $this->records[0];

        self::assertSame('Vault operation failed', $message);
        self::assertSame('Boom', $context['error']);
        self::assertSame(VaultException::class, $context['exceptionClass']);
        self::assertSame('tx_test', $context['table']);
        self::assertSame(42, $context['uid']);
    }

    /**
     * `FileWriter::writeLog()` folds a Throwable stored under the `exception`
     * key straight into the unescaped message — so that key must stay unused.
     */
    #[Test]
    public function throwableIsNotPassedUnderTheExceptionContextKey(): void
    {
        $this->subject->report(new VaultException('Boom'));

        [, $context] = $this->records[0];

        self::assertArrayNotHasKey('exception', $context);
    }

    #[Test]
    public function controlBytesAreStrippedFromEveryLoggedValue(): void
    {
        $crafted = "probe\r\nMon, 01 Jan 2035 00:00:00 +0000 [ALERT] request=\"0\" component=\"forged\": owned\x00\x07";

        $this->subject->report(
            SecretNotFoundException::forIdentifier($crafted),
            ['identifier' => $crafted, 'table' => "tx\ntest"],
        );

        [$message, $context] = $this->records[0];

        self::assertDoesNotMatchRegularExpression('/[[:cntrl:]]/', $message);

        foreach ($context as $key => $value) {
            if (!\is_string($value)) {
                continue;
            }

            self::assertDoesNotMatchRegularExpression(
                '/[[:cntrl:]]/',
                $value,
                \sprintf('Context value "%s" must not carry control bytes', $key),
            );
        }
    }

    #[Test]
    public function loggedValuesAreLengthCapped(): void
    {
        $long = str_repeat('A', 5000);

        $this->subject->report(new VaultException($long), ['identifier' => $long]);

        [, $context] = $this->records[0];

        self::assertIsString($context['error']);
        self::assertIsString($context['identifier']);
        self::assertLessThanOrEqual(200, \strlen($context['error']));
        self::assertLessThanOrEqual(200, \strlen($context['identifier']));
    }

    /**
     * `json_encode()` returns false on malformed UTF-8, which would silently
     * drop the whole context array from the log record.
     */
    #[Test]
    public function contextSurvivesJsonEncodingForMalformedUtf8Input(): void
    {
        $this->subject->report(
            new VaultException("bad \xFF\xFE bytes"),
            ['identifier' => str_repeat('ä', 200)],
        );

        [, $context] = $this->records[0];

        self::assertIsString(json_encode($context, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }
}
