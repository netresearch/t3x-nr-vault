<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Http;

use Netresearch\NrVault\Exception\VaultException;
use Psr\Http\Message\StreamInterface;

/**
 * The bounded buffer the curl handler writes a streaming response body into.
 *
 * Bounded because one transport step can deliver far more than the network
 * carried: libcurl decodes `Content-Encoding` inside the step, so 255 KiB of
 * gzip becomes 256 MiB of body before `sendStreaming()` gets control back.
 * Past the limit, `write()` accepts nothing and answers 0. Both supported Guzzle
 * majors abort the transfer on a short write, so it fails closed — Guzzle 7
 * reports cURL error 23, Guzzle 8 "Unable to write to stream" — and
 * `overflowed()` is what tells the caller why, whichever message came back.
 *
 * Reads move an offset instead of copying the rest of the buffer on every call,
 * and the consumed prefix is dropped once it is at least half the buffer, so
 * draining a full buffer in small reads costs linear time, not quadratic.
 *
 * @internal Created by `VaultHttpClient::sendStreamingly()`, written by the
 *           curl handler, read by `StreamingResponseBody`.
 */
final class StreamingSink implements StreamInterface
{
    /**
     * The most unread body bytes one streaming transfer may hold.
     *
     * The buffer only grows during a transport step — `read()` steps the
     * transport only once the buffer is empty — so this bounds what a single
     * step may deliver. An LLM event stream delivers kilobytes per step.
     */
    public const DEFAULT_LIMIT_BYTES = 16 * 1024 * 1024;

    private const NOT_SEEKABLE_MESSAGE = 'Streaming sink is not seekable';

    private string $buffer = '';

    private int $offset = 0;

    private int $consumed = 0;

    private bool $overflowed = false;

    public function __construct(private readonly int $limitBytes = self::DEFAULT_LIMIT_BYTES) {}

    public function __toString(): string
    {
        return $this->getContents();
    }

    /**
     * Whether a write was refused because it would have passed the limit.
     */
    public function overflowed(): bool
    {
        return $this->overflowed;
    }

    public function limitBytes(): int
    {
        return $this->limitBytes;
    }

    public function close(): void
    {
        $this->buffer = '';
        $this->offset = 0;
    }

    public function detach()
    {
        $this->close();

        return null;
    }

    /**
     * The number of unread bytes.
     */
    public function getSize(): int
    {
        return \strlen($this->buffer) - $this->offset;
    }

    /**
     * The number of bytes read so far.
     */
    public function tell(): int
    {
        return $this->consumed;
    }

    public function eof(): bool
    {
        return $this->getSize() === 0;
    }

    public function isSeekable(): bool
    {
        return false;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        throw new VaultException(self::NOT_SEEKABLE_MESSAGE, 1790487101);
    }

    public function rewind(): void
    {
        throw new VaultException(self::NOT_SEEKABLE_MESSAGE, 1790487101);
    }

    public function isWritable(): bool
    {
        return true;
    }

    /**
     * Append `$string`, or accept nothing when it would pass the limit.
     *
     * All or nothing: a partial write would hand curl a count it also takes as
     * an error, and would leave a truncated chunk in the buffer.
     */
    public function write(string $string): int
    {
        if ($this->getSize() + \strlen($string) > $this->limitBytes) {
            $this->overflowed = true;

            return 0;
        }

        $this->buffer .= $string;

        return \strlen($string);
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function read(int $length): string
    {
        $chunk = substr($this->buffer, $this->offset, $length);
        $this->offset += \strlen($chunk);
        $this->consumed += \strlen($chunk);

        if ($this->offset >= \strlen($this->buffer)) {
            $this->buffer = '';
            $this->offset = 0;
        } elseif ($this->offset * 2 >= \strlen($this->buffer)) {
            $this->buffer = substr($this->buffer, $this->offset);
            $this->offset = 0;
        }

        return $chunk;
    }

    public function getContents(): string
    {
        return $this->read($this->getSize());
    }

    public function getMetadata(?string $key = null)
    {
        return $key === null ? [] : null;
    }
}
