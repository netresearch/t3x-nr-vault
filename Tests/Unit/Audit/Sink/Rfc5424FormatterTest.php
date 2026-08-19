<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Sink;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\Sink\Rfc5424Formatter;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(Rfc5424Formatter::class)]
final class Rfc5424FormatterTest extends TestCase
{
    private Rfc5424Formatter $subject;

    protected function setUp(): void
    {
        parent::setUp();
        $this->subject = new Rfc5424Formatter();
    }

    #[Test]
    public function entryMessageCarriesTheContractedFieldSet(): void
    {
        $message = $this->subject->formatEntry($this->createEntry(), 'tip-hash-abc');

        self::assertStringStartsWith('[' . Rfc5424Formatter::SD_ID_ENTRY . ' ', $message);
        self::assertStringContainsString('uid="42"', $message);
        self::assertStringContainsString('secret="api/stripe"', $message);
        self::assertStringContainsString('action="read"', $message);
        self::assertStringContainsString('actor="editor"', $message);
        self::assertStringContainsString('actorUid="7"', $message);
        self::assertStringContainsString('success="true"', $message);
        self::assertStringContainsString('chainTip="tip-hash-abc"', $message);
    }

    #[Test]
    public function failedEntryReportsSuccessFalse(): void
    {
        $message = $this->subject->formatEntry($this->createEntry(success: false), 'tip');

        self::assertStringContainsString('success="false"', $message);
        self::assertStringContainsString('FAILED', $message);
    }

    #[Test]
    public function structuredDataElementIsClosedBeforeTheHumanReadableSummary(): void
    {
        $message = $this->subject->formatEntry($this->createEntry(), 'tip');

        // `[SD-ELEMENT] free text` — a collector splitting on the first `] `
        // must get a complete SD element.
        self::assertMatchesRegularExpression('/^\[[^\]]+\] \S/', $message);
    }

    /**
     * RFC 5424 §6.3.3: `"`, `\` and `]` must be backslash-escaped inside a
     * PARAM-VALUE. Anything less lets a crafted secret identifier terminate the
     * structured-data element and inject its own fields.
     */
    #[Test]
    #[DataProvider('escapableCharacterProvider')]
    public function paramValueEscapesRfc5424SpecialCharacters(string $identifier, string $expectedFragment): void
    {
        $message = $this->subject->formatEntry(
            $this->createEntry(secretIdentifier: $identifier),
            'tip',
        );

        self::assertStringContainsString($expectedFragment, $message);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function escapableCharacterProvider(): iterable
    {
        yield 'double quote' => ['api"key', 'secret="api\\"key"'];
        yield 'closing bracket' => ['api]key', 'secret="api\\]key"'];
        yield 'backslash' => ['api\\key', 'secret="api\\\\key"'];
        yield 'backslash before quote' => ['a\\"b', 'secret="a\\\\\\"b"'];
    }

    /**
     * A newline terminates a syslog record, so an unescaped one in an
     * attacker-controlled field (user agent, secret identifier) would let the
     * caller append a second, forged record (CWE-117).
     */
    #[Test]
    #[DataProvider('controlCharacterProvider')]
    public function controlCharactersAreStrippedFromTheWholeMessage(string $injected): void
    {
        $message = $this->subject->formatEntry(
            $this->createEntry(secretIdentifier: 'api' . $injected . 'key'),
            'tip',
        );

        self::assertDoesNotMatchRegularExpression('/[\x00-\x1F\x7F]/', $message);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function controlCharacterProvider(): iterable
    {
        yield 'line feed' => ["\n"];
        yield 'carriage return' => ["\r"];
        yield 'crlf' => ["\r\n"];
        yield 'null byte' => ["\0"];
        yield 'tab' => ["\t"];
        yield 'delete' => ["\x7F"];
    }

    #[Test]
    public function oversizedParamValueIsTruncatedWithAnEllipsis(): void
    {
        $message = $this->subject->formatEntry(
            $this->createEntry(secretIdentifier: str_repeat('a', 500)),
            'tip',
        );

        // 200-char cap: 197 characters plus the three-dot marker.
        self::assertStringContainsString('secret="' . str_repeat('a', 197) . '..."', $message);
    }

    /**
     * The free-text summary interpolates the same caller-influenced fields, so it
     * needs its own cap — otherwise one oversized identifier inflates the record
     * however carefully the structured-data params were trimmed.
     */
    #[Test]
    public function oversizedSummaryIsTruncated(): void
    {
        $message = $this->subject->formatEntry(
            $this->createEntry(secretIdentifier: str_repeat('a', 5000)),
            'tip',
        );

        $summary = substr($message, (int) strpos($message, '] ') + 2);

        // Exact, not "at most": a cap asserted only as an upper bound is met
        // by a summary that lost its leading characters, kept only its last
        // one, or was replaced by the ellipsis alone — all of which are still
        // short enough and still end in "...". The truncation has to keep the
        // beginning of the text, which is the part that identifies the record.
        self::assertSame(300, mb_strlen($summary, 'UTF-8'));
        self::assertStringEndsWith('...', $summary);
        self::assertStringStartsWith('vault audit ', $summary);
    }

    /**
     * The cap counts characters, not bytes. A byte-wise truncation of a
     * multibyte summary both overshoots the character budget and can sever a
     * UTF-8 sequence, which produces a record a strict collector rejects.
     */
    #[Test]
    public function oversizedMultibyteSummaryIsTruncatedByCharacters(): void
    {
        $message = $this->subject->formatEntry(
            $this->createEntry(secretIdentifier: str_repeat('ä', 5000)),
            'tip',
        );

        $summary = substr($message, (int) strpos($message, '] ') + 2);

        self::assertSame(300, mb_strlen($summary, 'UTF-8'));
        self::assertStringEndsWith('...', $summary);
        self::assertSame($summary, mb_convert_encoding($summary, 'UTF-8', 'UTF-8'));
    }

    /**
     * Guards the whole record, not just its parts: a receiver is only required to
     * accept 2048 bytes, and every field here is bounded, so a pathological input
     * must not produce a record a collector will truncate or drop.
     */
    #[Test]
    public function recordStaysWithinTheSyslogSizeThatReceiversMustAccept(): void
    {
        $message = $this->subject->formatEntry(
            new AuditLogEntry(
                uid: PHP_INT_MAX,
                secretIdentifier: str_repeat('s', 5000),
                action: str_repeat('a', 5000),
                success: true,
                errorMessage: null,
                reason: null,
                actorUid: PHP_INT_MAX,
                actorType: str_repeat('t', 5000),
                actorUsername: str_repeat('u', 5000),
                actorRole: '',
                ipAddress: '',
                userAgent: str_repeat('g', 5000),
                requestId: '',
                previousHash: '',
                entryHash: '',
                hashBefore: '',
                hashAfter: '',
                crdate: 0,
                context: [],
            ),
            str_repeat('c', 5000),
        );

        self::assertLessThanOrEqual(2048, \strlen($message));
    }

    #[Test]
    public function invalidUtf8IsRepairedRatherThanEmitted(): void
    {
        $message = $this->subject->formatEntry(
            $this->createEntry(secretIdentifier: "api\xC3\x28key"),
            'tip',
        );

        self::assertTrue(mb_check_encoding($message, 'UTF-8'));
    }

    #[Test]
    public function emptyChainTipIsEmittedAsAnEmptyValueRatherThanOmitted(): void
    {
        $message = $this->subject->formatEntry($this->createEntry(), '');

        self::assertStringContainsString('chainTip=""', $message);
    }

    #[Test]
    public function anchorMessageCarriesSequenceTipAndEpoch(): void
    {
        $message = $this->subject->formatAnchor(new ChainTipAnchor(
            sequence: 128,
            chainTip: 'anchor-tip',
            timestamp: 1_750_000_000,
            hmacEpoch: 3,
        ));

        self::assertStringStartsWith('[' . Rfc5424Formatter::SD_ID_ANCHOR . ' ', $message);
        self::assertStringContainsString('sequence="128"', $message);
        self::assertStringContainsString('chainTip="anchor-tip"', $message);
        self::assertStringContainsString('hmacEpoch="3"', $message);
        self::assertStringContainsString('anchoredAt="1750000000"', $message);
    }

    #[Test]
    public function alertMessageCarriesReasonAndTamperFlag(): void
    {
        $message = $this->subject->formatAlert(AuditIntegrityAlert::create(
            AuditIntegrityReason::TableReset,
            'chain shrank',
            ['anchoredSequence' => 99],
        ));

        self::assertStringStartsWith('[' . Rfc5424Formatter::SD_ID_ALERT . ' ', $message);
        self::assertStringContainsString('reason="TABLE_RESET"', $message);
        self::assertStringContainsString('tamperEvidence="true"', $message);
        self::assertStringContainsString('ctx_anchoredSequence="99"', $message);
        self::assertStringContainsString('chain shrank', $message);
    }

    #[Test]
    public function nonTamperAlertReportsTamperEvidenceFalse(): void
    {
        $message = $this->subject->formatAlert(AuditIntegrityAlert::create(
            AuditIntegrityReason::SinkFailure,
            'webhook unreachable',
        ));

        self::assertStringContainsString('tamperEvidence="false"', $message);
    }

    /**
     * Context keys are caller-supplied. An unfiltered key containing `="` would
     * close the current param and inject a new one, so keys are sanitised too.
     */
    #[Test]
    public function alertContextKeysAreSanitisedIntoValidParamNames(): void
    {
        $message = $this->subject->formatAlert(AuditIntegrityAlert::create(
            AuditIntegrityReason::SinkFailure,
            'detail',
            ['bad key="injected' => 'value'],
        ));

        self::assertStringContainsString('ctx_bad_key__injected="value"', $message);
    }

    #[Test]
    public function alertContextBooleansAreRenderedAsTrueFalseNotOneZero(): void
    {
        $message = $this->subject->formatAlert(AuditIntegrityAlert::create(
            AuditIntegrityReason::SinkFailure,
            'detail',
            ['retried' => true, 'fatal' => false],
        ));

        self::assertStringContainsString('ctx_retried="true"', $message);
        self::assertStringContainsString('ctx_fatal="false"', $message);
    }

    /**
     * The three record kinds must be distinguishable by SD-ID so a collector can
     * route them without parsing the free-text summary.
     */
    #[Test]
    public function eachRecordKindUsesItsOwnStructuredDataId(): void
    {
        $sdIds = [
            Rfc5424Formatter::SD_ID_ENTRY,
            Rfc5424Formatter::SD_ID_ANCHOR,
            Rfc5424Formatter::SD_ID_ALERT,
        ];

        self::assertSameSize($sdIds, array_unique($sdIds));
    }

    /**
     * RFC 5424 §6.3.2 requires a non-IANA SD-ID to be `name@<enterprise-number>`.
     */
    #[Test]
    #[DataProvider('structuredDataIdProvider')]
    public function structuredDataIdsFollowThePrivateEnterpriseNumberForm(string $sdId): void
    {
        self::assertMatchesRegularExpression('/^[A-Za-z][A-Za-z0-9]*@\d+$/', $sdId);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function structuredDataIdProvider(): iterable
    {
        yield 'entry' => [Rfc5424Formatter::SD_ID_ENTRY];
        yield 'anchor' => [Rfc5424Formatter::SD_ID_ANCHOR];
        yield 'alert' => [Rfc5424Formatter::SD_ID_ALERT];
    }

    #[Test]
    public function summaryFallsBackToActorUidWhenTheUsernameIsUnknown(): void
    {
        $message = $this->subject->formatEntry(
            $this->createEntry(actorUsername: ''),
            'tip',
        );

        self::assertStringContainsString('by uid:7', $message);
    }

    private function createEntry(
        string $secretIdentifier = 'api/stripe',
        bool $success = true,
        string $actorUsername = 'editor',
    ): AuditLogEntry {
        return new AuditLogEntry(
            uid: 42,
            secretIdentifier: $secretIdentifier,
            action: 'read',
            success: $success,
            errorMessage: null,
            reason: null,
            actorUid: 7,
            actorType: 'be_user',
            actorUsername: $actorUsername,
            actorRole: 'groups:1',
            ipAddress: '203.0.113.7',
            userAgent: 'Mozilla/5.0',
            requestId: 'req-1',
            previousHash: 'prev',
            entryHash: 'tip-hash-abc',
            hashBefore: '',
            hashAfter: '',
            crdate: 1_750_000_000,
            context: [],
        );
    }
}
