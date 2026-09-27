<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use GuzzleHttp\Psr7\Response;
use Netresearch\NrVault\Http\TransferProgress;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

/**
 * The progress rule every send on the cancellable transport hands its idle
 * bound. The sends' own suites pin it end to end; these pin the rule itself.
 */
#[CoversClass(TransferProgress::class)]
final class TransferProgressTest extends TestCase
{
    private int $bytes = 0;

    #[Test]
    public function nothingCountsBeforeTheFirstHead(): void
    {
        $progress = $this->progress();
        $this->bytes = 10;

        self::assertSame(0, $progress->count());
        self::assertNull($progress->head());
    }

    #[Test]
    public function aFinalHeadCountsAndSoDoBytesAfterIt(): void
    {
        $progress = $this->progress();
        $head = new Response(200);

        $progress->onHeaders($head);
        self::assertSame(1, $progress->count());
        self::assertSame($head, $progress->head());

        $this->bytes = 5;
        self::assertSame(6, $progress->count());
    }

    #[Test]
    public function anInterimHeadCountsNothingAndFreezesTheCounter(): void
    {
        $progress = $this->progress();

        $progress->onHeaders(new Response(100));
        $progress->onHeaders(new Response(100));
        self::assertSame(0, $progress->count());

        $progress->onHeaders(new Response(200));
        $this->bytes = 3;
        self::assertSame(4, $progress->count());

        // A 101 replaces the final head: the raw bytes after it buy nothing,
        // and the counter keeps the value it had.
        $progress->onHeaders(new Response(101));
        $this->bytes = 50;
        self::assertSame(4, $progress->count());
        self::assertNull($progress->head());
    }

    #[Test]
    public function aLaterFinalHeadReplacesTheEarlierOneAndCountsAgain(): void
    {
        $progress = $this->progress();
        $proxyReply = new Response(200, [], null, '1.1', 'Connection established');
        $origin = new Response(401);

        $progress->onHeaders($proxyReply);
        $progress->onHeaders($origin);

        self::assertSame($origin, $progress->head());
        self::assertSame(2, $progress->count());
    }

    private function progress(): TransferProgress
    {
        return new TransferProgress(fn (): int => $this->bytes);
    }
}
