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

use Netresearch\NrVault\Exception\RequestCancelledException;
use Netresearch\NrVault\Exception\VaultException;
use Psr\Http\Message\StreamInterface;
use Throwable;

/**
 * The body of a response from `VaultHttpClient::sendStreaming()`.
 *
 * Reading it advances the transfer: `read()` returns what has arrived, and
 * when nothing has, it steps the transport until bytes arrive or the transfer
 * ends. Three rules hold for every way out:
 *
 * - **A failed transfer is never a short body.** End of stream is reported only
 *   when the transport fulfilled its promise; a rejected one throws from
 *   `read()` once the bytes that did arrive have been handed out.
 * - **An abandoned body closes the transfer.** `close()`, `detach()` and the
 *   destructor cancel the transport's promise, which removes the easy handle
 *   from the multi handle and closes it.
 * - **A step cannot flood memory.** The sink holds at most
 *   `StreamingSink::DEFAULT_LIMIT_BYTES` unread bytes; a step that delivers
 *   more fails the transfer, and `read()` reports it with its own literal.
 * - **A read cannot hang the worker.** Every step checks the caller's signal
 *   and the wall-clock bound of the transfer, and libcurl's own `timeout`
 *   applies on every tick.
 *
 * The body is not seekable and not writable. Its metadata is empty: nothing
 * about the request — whose URI can carry the secret for
 * `SecretPlacement::QueryParam` — is exposed through it.
 *
 * @internal Constructed by `VaultHttpClient` only; callers see it as a PSR-7
 *           `StreamInterface`.
 */
final class StreamingResponseBody implements StreamInterface
{
    private const CLOSED_MESSAGE = 'Streaming response body is closed';

    private const CANCELLED_MESSAGE = 'Streaming response cancelled while the body was being read';

    private const BUDGET_EXHAUSTED_MESSAGE = 'Streaming transfer exceeded its wall-clock budget and was aborted';

    private const FAILED_MESSAGE = 'Streaming transfer failed after the headers arrived; the body is incomplete';

    private const BUFFER_LIMIT_MESSAGE
        = 'Streaming transfer aborted: one step delivered more body than the 16 MiB streaming buffer holds';

    private const NOT_SEEKABLE_MESSAGE = 'Streaming response body is not seekable';

    private const NOT_WRITABLE_MESSAGE = 'Streaming response body is not writable';

    private bool $closed = false;

    private int $position = 0;

    /**
     * @param StreamingTransfer $transfer The transfer this body is read from
     * @param StreamingSink $sink The bounded buffer the transport writes into; consumed by `read()`
     */
    public function __construct(
        private readonly StreamingTransfer $transfer,
        private readonly StreamingSink $sink,
    ) {}

    /**
     * An abandoned body must not leave its transfer on the transport.
     */
    public function __destruct()
    {
        $this->transfer->abandon();
    }

    public function __toString(): string
    {
        // Throws rather than returning what arrived so far: a string that
        // silently stops where the transfer failed is exactly the short body
        // this class exists to rule out.
        return $this->getContents();
    }

    public function close(): void
    {
        $this->closed = true;
        $this->transfer->abandon();
    }

    public function detach()
    {
        $this->close();

        return null;
    }

    public function getSize(): ?int
    {
        return null;
    }

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        return $this->closed
            || ($this->transfer->isSettled() && !$this->transfer->isRejected() && $this->sink->getSize() === 0);
    }

    public function isSeekable(): bool
    {
        return false;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        throw new VaultException(self::NOT_SEEKABLE_MESSAGE, 1790475707);
    }

    public function rewind(): void
    {
        throw new VaultException(self::NOT_SEEKABLE_MESSAGE, 1790475707);
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new VaultException(self::NOT_WRITABLE_MESSAGE, 1790475708);
    }

    public function isReadable(): bool
    {
        return !$this->closed;
    }

    /**
     * Return up to `$length` bytes, stepping the transport until some arrive.
     *
     * Returns `''` only at the end of a transfer the transport completed.
     *
     * @throws RequestCancelledException When the caller's signal aborted the transfer
     * @throws VaultException When the body is closed, the transfer failed or it overran its bound
     */
    public function read(int $length): string
    {
        if ($this->closed) {
            throw new VaultException(self::CLOSED_MESSAGE, 1790475703);
        }

        while (true) {
            if ($this->sink->getSize() > 0) {
                $chunk = $this->sink->read($length);
                $this->position += \strlen($chunk);

                return $chunk;
            }

            if ($this->transfer->isSettled()) {
                if ($this->transfer->isRejected()) {
                    $reason = $this->transfer->settledValue();

                    if ($this->sink->overflowed()) {
                        throw new VaultException(
                            self::BUFFER_LIMIT_MESSAGE,
                            1790487103,
                            $reason instanceof Throwable ? $reason : null,
                        );
                    }

                    throw new VaultException(
                        self::FAILED_MESSAGE,
                        1790475706,
                        $reason instanceof Throwable ? $reason : null,
                    );
                }

                return '';
            }

            $step = $this->transfer->advance();

            if ($step === StreamingTransfer::CANCELLED) {
                $this->closed = true;

                throw new RequestCancelledException(self::CANCELLED_MESSAGE, 1790475704);
            }

            if ($step === StreamingTransfer::BUDGET_EXHAUSTED) {
                $this->closed = true;

                throw new VaultException(self::BUDGET_EXHAUSTED_MESSAGE, 1790475705);
            }
        }
    }

    public function getContents(): string
    {
        // `read()` returns '' only at the end of a completed transfer and
        // throws for everything else, so this loop cannot stop early.
        $contents = '';
        while (($chunk = $this->read(8192)) !== '') {
            $contents .= $chunk;
        }

        return $contents;
    }

    public function getMetadata(?string $key = null)
    {
        return $key === null ? [] : null;
    }
}
