<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use ArrayObject;
use Netresearch\NrVault\Audit\AuditSinkPublicationBuffer;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(AuditSinkPublicationBuffer::class)]
final class AuditSinkPublicationBufferTest extends TestCase
{
    #[Test]
    public function aPublicationOutsideCollectionRunsAtOnce(): void
    {
        $buffer = new AuditSinkPublicationBuffer();
        $calls  = $this->recorder();

        $buffer->defer(static fn () => $calls->append('a'));

        self::assertFalse($buffer->isCollecting());
        self::assertSame(['a'], $calls->getArrayCopy());
    }

    #[Test]
    public function aFlushPublishesInWriteOrderAndEndsCollection(): void
    {
        $buffer = new AuditSinkPublicationBuffer();
        $calls  = $this->recorder();

        $buffer->collect();
        $buffer->defer(static fn () => $calls->append('a'));
        $buffer->defer(static fn () => $calls->append('b'));
        self::assertSame([], $calls->getArrayCopy());

        $buffer->flush();

        self::assertSame(['a', 'b'], $calls->getArrayCopy());
        self::assertFalse($buffer->isCollecting());
    }

    #[Test]
    public function aDiscardDropsWhatWasCollectedAndEndsCollection(): void
    {
        $buffer = new AuditSinkPublicationBuffer();
        $calls  = $this->recorder();

        $buffer->collect();
        $buffer->defer(static fn () => $calls->append('rolled back'));
        $buffer->discard();
        $buffer->flush();

        self::assertSame([], $calls->getArrayCopy());
        self::assertFalse($buffer->isCollecting());
    }

    /**
     * A second collection does not inherit what an earlier one left behind.
     */
    #[Test]
    public function collectStartsEmpty(): void
    {
        $buffer = new AuditSinkPublicationBuffer();
        $calls  = $this->recorder();

        $buffer->collect();
        $buffer->defer(static fn () => $calls->append('stale'));
        $buffer->collect();
        $buffer->flush();

        self::assertSame([], $calls->getArrayCopy());
    }

    /**
     * @return ArrayObject<int, string>
     */
    private function recorder(): ArrayObject
    {
        return new ArrayObject();
    }
}
