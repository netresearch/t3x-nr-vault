<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Anchor;

use Netresearch\NrVault\Audit\Anchor\AnchorFileReader;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Tests\Unit\Fixtures\FailingStreamWrapper;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\ErrorSuppressionTrait;
use org\bovigo\vfs\vfsStream;
use org\bovigo\vfs\vfsStreamDirectory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * The reader only ever reads, so vfsStream models it faithfully (unlike the
 * write path in {@see \Netresearch\NrVault\Tests\Unit\Audit\Sink\JsonFileAuditSinkTest},
 * which needs real `flock`/`chmod`/`realpath` behaviour).
 */
#[CoversClass(AnchorFileReader::class)]
final class AnchorFileReaderTest extends TestCase
{
    use ErrorSuppressionTrait;

    private vfsStreamDirectory $root;

    protected function setUp(): void
    {
        parent::setUp();
        $this->root = vfsStream::setup('anchors');
    }

    #[Test]
    public function missingFileYieldsNoAnchor(): void
    {
        $subject = $this->createSubject($this->root->url() . '/absent.ndjson');

        self::assertNull($subject->readLatestAnchor());
        self::assertFalse($subject->isAvailable());
    }

    #[Test]
    public function existingFileIsReportedAsAvailable(): void
    {
        $path = $this->writeFile('');

        self::assertTrue($this->createSubject($path)->isAvailable());
    }

    /**
     * A directory is readable but is not a file, so both guards have to hold at
     * once: `is_file() && is_readable()`. A misconfigured path pointing at the
     * containing directory must be rejected before the open is even attempted —
     * otherwise the reader opens a directory handle and reports the failure as a
     * warning, turning a configuration typo into log noise on every run.
     */
    #[Test]
    public function aDirectoryAtTheAnchorPathIsRejectedBeforeAnyOpenIsAttempted(): void
    {
        vfsStream::newDirectory('store')->at($this->root);
        $path = $this->root->url() . '/store';

        self::assertTrue(is_readable($path), 'precondition: only is_file() separates this from an anchor file');

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('warning');

        $subject = $this->createSubject($path, $logger);

        self::assertFalse($subject->isAvailable());
        self::assertNull($subject->readLatestAnchor());
    }

    #[Test]
    public function emptyFileYieldsNoAnchor(): void
    {
        $subject = $this->createSubject($this->writeFile(''));

        self::assertNull($subject->readLatestAnchor());
        // Distinguishable from "never set up": the store exists but holds nothing.
        self::assertTrue($subject->isAvailable());
    }

    #[Test]
    public function singleAnchorIsRead(): void
    {
        $path = $this->writeFile($this->anchorLine(10, 'tip-10', 1_750_000_000, 3));

        $anchor = $this->createSubject($path)->readLatestAnchor();

        self::assertInstanceOf(ChainTipAnchor::class, $anchor);
        self::assertSame(10, $anchor->sequence);
        self::assertSame('tip-10', $anchor->chainTip);
        self::assertSame(1_750_000_000, $anchor->timestamp);
        self::assertSame(3, $anchor->hmacEpoch);
    }

    /**
     * The security-relevant rule. Picking the LAST line would let an attacker
     * with append-only access weaken the baseline by appending a low-sequence
     * anchor that a truncated chain satisfies. Taking the maximum means the file
     * must be rewritten or truncated to weaken it — which is exactly what
     * append-only storage prevents.
     */
    #[Test]
    public function highestSequenceWinsOverAppendOrder(): void
    {
        $path = $this->writeFile(
            $this->anchorLine(100, 'tip-100', 1_750_000_000, 3)
            . $this->anchorLine(1, 'tip-1', 1_750_000_900, 3),
        );

        $anchor = $this->createSubject($path)->readLatestAnchor();

        self::assertInstanceOf(ChainTipAnchor::class, $anchor);
        self::assertSame(100, $anchor->sequence);
        self::assertSame('tip-100', $anchor->chainTip);
    }

    /**
     * The same rule one step further: a later line at the sequence that is
     * already the maximum must not replace it either. `>` rather than `>=` means
     * the first anchor seen at a sequence wins, so an attacker who can append
     * cannot overwrite the tip recorded for a sequence with one of their own.
     */
    #[Test]
    public function aLaterAnchorAtTheSameSequenceDoesNotReplaceTheOneAlreadySeen(): void
    {
        $path = $this->writeFile(
            $this->anchorLine(5, 'tip-genuine', 1_750_000_000, 3)
            . $this->anchorLine(5, 'tip-forged', 1_750_000_900, 3),
        );

        $anchor = $this->createSubject($path)->readLatestAnchor();

        self::assertInstanceOf(ChainTipAnchor::class, $anchor);
        self::assertSame('tip-genuine', $anchor->chainTip);
    }

    #[Test]
    public function anchorsAreReadAcrossManyLines(): void
    {
        $lines = '';
        foreach ([5, 25, 15] as $sequence) {
            $lines .= $this->anchorLine($sequence, 'tip-' . $sequence, 1_750_000_000, 3);
        }

        $anchor = $this->createSubject($this->writeFile($lines))->readLatestAnchor();

        self::assertInstanceOf(ChainTipAnchor::class, $anchor);
        self::assertSame(25, $anchor->sequence);
    }

    /**
     * A crash mid-write leaves a truncated final line. Losing every earlier
     * anchor over it would destroy the baseline exactly when it matters.
     */
    #[Test]
    public function truncatedFinalLineDoesNotDiscardEarlierAnchors(): void
    {
        $path = $this->writeFile(
            $this->anchorLine(42, 'tip-42', 1_750_000_000, 3)
            . '{"type":"anchor","anchor":{"sequence":43,"chainTi',
        );

        $anchor = $this->createSubject($path)->readLatestAnchor();

        self::assertInstanceOf(ChainTipAnchor::class, $anchor);
        self::assertSame(42, $anchor->sequence);
    }

    /**
     * Alerts share the anchor stream, so a non-anchor record is normal traffic
     * that must be skipped without disturbing the scan.
     */
    #[Test]
    public function alertRecordsInTheSameStreamAreSkipped(): void
    {
        $path = $this->writeFile(
            '{"type":"alert","alert":{"reason":"TABLE_RESET"}}' . "\n"
            . $this->anchorLine(7, 'tip-7', 1_750_000_000, 3) . "\n"
            . '{"type":"alert","alert":{"reason":"SINK_FAILURE"}}' . "\n",
        );

        $anchor = $this->createSubject($path)->readLatestAnchor();

        self::assertInstanceOf(ChainTipAnchor::class, $anchor);
        self::assertSame(7, $anchor->sequence);
    }

    #[Test]
    public function blankLinesAreIgnored(): void
    {
        $path = $this->writeFile("\n\n" . $this->anchorLine(3, 'tip-3', 1, 3) . "\n   \n");

        $anchor = $this->createSubject($path)->readLatestAnchor();

        self::assertInstanceOf(ChainTipAnchor::class, $anchor);
        self::assertSame(3, $anchor->sequence);
    }

    /**
     * A structurally incomplete anchor must not become a comparison baseline —
     * a missing `chainTip` would compare against '' and could read as a match.
     */
    #[Test]
    public function structurallyIncompleteAnchorRecordsAreRejected(): void
    {
        $path = $this->writeFile(
            '{"type":"anchor","anchor":{"sequence":9}}' . "\n"
            . '{"type":"anchor","anchor":{"chainTip":"x"}}' . "\n"
            . '{"type":"anchor"}' . "\n"
            . '{"type":"anchor","anchor":"not-an-array"}' . "\n",
        );

        self::assertNull($this->createSubject($path)->readLatestAnchor());
    }

    /**
     * A record is only a baseline when it says `type: "anchor"`. An `alert`
     * record carrying an otherwise well-formed `anchor` payload is exactly what
     * an attacker with append access to the shared stream would write to plant a
     * weaker baseline, so the type check has to reject it even though the
     * payload parses.
     */
    #[Test]
    public function anAlertRecordCarryingAnAnchorPayloadIsNotUsedAsABaseline(): void
    {
        $path = $this->writeFile(
            '{"type":"alert","anchor":{"sequence":1,"chainTip":"tip-1","timestamp":1,"hmacEpoch":3}}' . "\n",
        );

        self::assertNull($this->createSubject($path)->readLatestAnchor());
    }

    /**
     * A torn write can leave the line padded with NUL bytes (a delayed-allocation
     * filesystem after a power loss). The payload itself is intact, so trimming
     * the padding keeps the anchor usable instead of losing the baseline to
     * bytes that carry no data.
     */
    #[Test]
    public function aLineNulPaddedByATornWriteIsStillParsed(): void
    {
        $path = $this->writeFile(
            rtrim($this->anchorLine(6, 'tip-6', 1_750_000_000, 3), "\n") . "\0\0\0\n",
        );

        $anchor = $this->createSubject($path)->readLatestAnchor();

        self::assertInstanceOf(ChainTipAnchor::class, $anchor);
        self::assertSame(6, $anchor->sequence);
    }

    /**
     * The anchor file lives on a filesystem this code does not control, so the
     * decoder keeps PHP's default nesting cap of 512: a hand-crafted line cannot
     * push the parser arbitrarily deep, and a line just inside the cap still
     * yields its anchor.
     */
    #[Test]
    public function theDecoderKeepsTheDefaultNestingCap(): void
    {
        // 2 levels of anchor envelope + the padding array = exactly the cap.
        $atTheCap = $this->createSubject($this->writeFile($this->paddedAnchorLine(509)))->readLatestAnchor();

        self::assertInstanceOf(ChainTipAnchor::class, $atTheCap);
        self::assertSame(8, $atTheCap->sequence);

        // One level deeper: rejected as a whole line, no anchor.
        self::assertNull($this->createSubject($this->writeFile($this->paddedAnchorLine(510)))->readLatestAnchor());
    }

    #[Test]
    public function nonJsonLinesAreSkipped(): void
    {
        $path = $this->writeFile(
            "not json at all\n"
            . $this->anchorLine(4, 'tip-4', 1, 3),
        );

        $anchor = $this->createSubject($path)->readLatestAnchor();

        self::assertInstanceOf(ChainTipAnchor::class, $anchor);
        self::assertSame(4, $anchor->sequence);
    }

    /**
     * A file that stats as a readable regular file but cannot actually be opened
     * (a revoked ACL, an NFS mount that went away between the stat and the open).
     * Verification then has no external baseline — and must say so by returning
     * null rather than by dying inside the integrity check.
     */
    #[Test]
    public function anUnopenableAnchorFileYieldsNoAnchorInsteadOfFailing(): void
    {
        FailingStreamWrapper::register(FailingStreamWrapper::MODE_OPEN_REFUSED);

        $path = FailingStreamWrapper::path('anchor.ndjson');

        // Silence is the danger here: an operator who never learns the baseline
        // went away reads "chain valid" as "chain anchored". The path travels in
        // the context because that is what tells them which mount to fix.
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with(
                'nr-vault could not open the audit anchor file; verification has no external baseline.',
                ['path' => $path],
            );

        try {
            $subject = $this->createSubject($path, $logger);

            // `isAvailable()` still reports true: the file is there, which is
            // exactly why the read path needs its own guard.
            self::assertTrue($subject->isAvailable());
            self::assertNull($this->withoutPhpDiagnostics(static fn (): ?ChainTipAnchor => $subject->readLatestAnchor()));
        } finally {
            FailingStreamWrapper::unregister();
        }
    }

    /**
     * On a host whose error handler promotes warnings to exceptions, the failed
     * open arrives as a Throwable rather than as `false`. Both must degrade to
     * "no baseline", never propagate out of the verifier.
     */
    #[Test]
    public function aThrowingOpenAlsoYieldsNoAnchor(): void
    {
        FailingStreamWrapper::register(FailingStreamWrapper::MODE_OPEN_THROWS);

        try {
            self::assertNull($this->createSubject(FailingStreamWrapper::path('anchor.ndjson'))->readLatestAnchor());
        } finally {
            FailingStreamWrapper::unregister();
        }
    }

    private function createSubject(string $path, ?LoggerInterface $logger = null): AnchorFileReader
    {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getAuditSinkAnchorPath')->willReturn($path);

        return new AnchorFileReader($configuration, $logger ?? new NullLogger());
    }

    /**
     * A valid anchor record whose payload carries `$depth` extra array levels,
     * on top of the two levels of `{"type":…,"anchor":{…}}` envelope.
     */
    private function paddedAnchorLine(int $depth): string
    {
        return '{"type":"anchor","anchor":{"sequence":8,"chainTip":"tip-8","timestamp":1,"hmacEpoch":3,'
            . '"padding":' . str_repeat('[', $depth) . '1' . str_repeat(']', $depth) . '}}' . "\n";
    }

    private function writeFile(string $contents): string
    {
        $path = $this->root->url() . '/anchor.ndjson';
        file_put_contents($path, $contents);

        return $path;
    }

    private function anchorLine(int $sequence, string $chainTip, int $timestamp, int $epoch): string
    {
        return json_encode([
            'type' => 'anchor',
            'anchor' => [
                'sequence' => $sequence,
                'chainTip' => $chainTip,
                'timestamp' => $timestamp,
                'hmacEpoch' => $epoch,
            ],
        ], JSON_THROW_ON_ERROR) . "\n";
    }
}
