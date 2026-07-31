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
use Netresearch\NrVault\Tests\Unit\TestCase;
use org\bovigo\vfs\vfsStream;
use org\bovigo\vfs\vfsStreamDirectory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\NullLogger;

/**
 * The reader only ever reads, so vfsStream models it faithfully (unlike the
 * write path in {@see \Netresearch\NrVault\Tests\Unit\Audit\Sink\JsonFileAuditSinkTest},
 * which needs real `flock`/`chmod`/`realpath` behaviour).
 */
#[CoversClass(AnchorFileReader::class)]
final class AnchorFileReaderTest extends TestCase
{
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

    private function createSubject(string $path): AnchorFileReader
    {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getAuditSinkAnchorPath')->willReturn($path);

        return new AnchorFileReader($configuration, new NullLogger());
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
