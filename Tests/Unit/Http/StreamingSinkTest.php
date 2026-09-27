<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Http\StreamingSink;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

/**
 * The bounded buffer a streaming response body is written into.
 */
#[CoversClass(StreamingSink::class)]
final class StreamingSinkTest extends TestCase
{
    #[Test]
    public function theDefaultLimitIsSixteenMebibytes(): void
    {
        self::assertSame(16 * 1024 * 1024, (new StreamingSink())->limitBytes());
    }

    #[Test]
    public function aWriteUpToTheLimitIsAcceptedWhole(): void
    {
        $sink = new StreamingSink(10);

        self::assertSame(6, $sink->write('abcdef'));
        self::assertSame(4, $sink->write('ghij'));
        self::assertSame(10, $sink->getSize());
        self::assertFalse($sink->overflowed());
    }

    #[Test]
    public function aWritePastTheLimitIsRefusedWholeAndRecorded(): void
    {
        $sink = new StreamingSink(10);
        $sink->write('abcdef');

        self::assertSame(0, $sink->write('ghijk'), 'curl takes a short write as a transfer error; 0 is the refusal.');
        self::assertTrue($sink->overflowed());
        self::assertSame('abcdef', $sink->getContents(), 'A refused write adds nothing, not even part of itself.');
    }

    #[Test]
    public function theLimitCountsUnreadBytesOnly(): void
    {
        $sink = new StreamingSink(10);
        $sink->write('abcdefghij');
        self::assertSame('abcdefgh', $sink->read(8));

        self::assertSame(8, $sink->write('klmnopqr'), 'Two unread bytes plus eight new ones fit a ten-byte limit.');
        self::assertFalse($sink->overflowed());
        self::assertSame('ijklmnopqr', $sink->read(100));
    }

    #[Test]
    public function readsConsumeInOrderAndTellCountsWhatWasRead(): void
    {
        $sink = new StreamingSink(100);
        $sink->write('0123456789');

        self::assertSame('012', $sink->read(3));
        self::assertSame('34567', $sink->read(5), 'Past the half-way point the consumed prefix is dropped.');
        self::assertSame(2, $sink->getSize());
        self::assertSame(8, $sink->tell());

        $sink->write('ab');
        self::assertSame('89ab', $sink->read(100));
        self::assertSame(12, $sink->tell());
        self::assertTrue($sink->eof());
        self::assertSame('', $sink->read(1));
    }

    #[Test]
    public function drainingAFullBufferInSmallReadsReturnsEveryByteOnce(): void
    {
        $payload = random_bytes(64 * 1024);
        $sink = new StreamingSink(128 * 1024);
        $sink->write($payload);

        $read = '';
        while (!$sink->eof()) {
            $read .= $sink->read(1000);
        }

        self::assertSame($payload, $read);
        self::assertSame(\strlen($payload), $sink->tell());
    }

    #[Test]
    public function itIsWritableButNeitherSeekableNorExposingMetadata(): void
    {
        $sink = new StreamingSink();

        self::assertTrue($sink->isWritable());
        self::assertTrue($sink->isReadable());
        self::assertFalse($sink->isSeekable());
        self::assertSame([], $sink->getMetadata());
        self::assertNull($sink->getMetadata('uri'));

        foreach ([static fn () => $sink->seek(0), $sink->rewind(...)] as $call) {
            try {
                $call();
                self::fail('Seeking must be refused.');
            } catch (VaultException $e) {
                self::assertSame(1790487101, $e->getCode());
            }
        }
    }

    #[Test]
    public function closingOrDetachingDropsTheBuffer(): void
    {
        $sink = new StreamingSink();
        $sink->write('abc');
        $sink->close();
        self::assertSame(0, $sink->getSize());

        $sink->write('def');
        self::assertNull($sink->detach());
        self::assertSame('', (string) $sink);
    }
}
