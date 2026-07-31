<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Fixtures;

use RuntimeException;

/**
 * A stream wrapper that reports a perfectly healthy, writable regular file and
 * then fails at a chosen point of the write.
 *
 * ## Why a wrapper and not a real file
 *
 * The audit sinks guard their writes in layers: a pre-flight `assertAppendable()`
 * check, then `fopen()`, then `flock()`, then a short-write check. The later
 * layers are unreachable on a real filesystem *precisely because* the earlier
 * ones work — a file that `fopen()` refuses is a file that `is_writable()`
 * already rejected, and `flock()` does not fail on a local file that opened
 * successfully. Short writes need a full disk.
 *
 * Those layers exist for hosts this code does not control (NFS with locking
 * disabled, a full volume, a quota hit mid-write). A wrapper is the only way to
 * put the production code in front of that filesystem without needing one, and
 * it keeps the assertions on behaviour: which `AuditSinkException` message comes
 * out, and whether the failure is contained.
 *
 * `url_stat()` deliberately reports a mode-0666 regular file (and a mode-0777
 * directory for any path without a file extension) so that `file_exists()`,
 * `is_file()`, `is_writable()` and `is_dir()` all succeed regardless of the
 * running uid, and the sink's own guards pass.
 *
 * Usage:
 *
 * ```php
 * FailingStreamWrapper::register(FailingStreamWrapper::MODE_LOCK_REFUSED);
 * // … exercise code against FailingStreamWrapper::path('audit.ndjson') …
 * FailingStreamWrapper::unregister();
 * ```
 *
 * @internal test fixture
 */
final class FailingStreamWrapper
{
    public const SCHEME = 'nrvaultfail';

    /** `fopen()` returns false, the classic "cannot open stream". */
    public const MODE_OPEN_REFUSED = 'open-refused';

    /**
     * `fopen()` throws — what a host error handler that promotes warnings to
     * exceptions (TYPO3's own does) produces instead of a false return.
     */
    public const MODE_OPEN_THROWS = 'open-throws';

    /** The advisory lock cannot be taken (NFS without lock daemon, …). */
    public const MODE_LOCK_REFUSED = 'lock-refused';

    /** A short write — a full volume or an exceeded quota mid-line. */
    public const MODE_SHORT_WRITE = 'short-write';

    /** Everything succeeds; the baseline that proves the wrapper itself works. */
    public const MODE_HEALTHY = 'healthy';

    /** @var resource|null set by PHP when the wrapper is used */
    public $context;

    private static string $mode = self::MODE_HEALTHY;

    private static string $written = '';

    /** @var list<array{path: string, mode: string}> */
    private static array $opens = [];

    public static function register(string $mode): void
    {
        self::$mode = $mode;
        self::$written = '';
        self::$opens = [];

        if (\in_array(self::SCHEME, stream_get_wrappers(), true)) {
            stream_wrapper_unregister(self::SCHEME);
        }

        stream_wrapper_register(self::SCHEME, self::class);
        clearstatcache(true);
    }

    public static function unregister(): void
    {
        if (\in_array(self::SCHEME, stream_get_wrappers(), true)) {
            stream_wrapper_unregister(self::SCHEME);
        }

        self::$mode = self::MODE_HEALTHY;
        clearstatcache(true);
    }

    /**
     * Every `fopen()` seen since the last `register()`, with its mode.
     *
     * @return list<array{path: string, mode: string}>
     */
    public static function opens(): array
    {
        return self::$opens;
    }

    /**
     * Everything handed to `stream_write()` since the last `register()`.
     */
    public static function writtenData(): string
    {
        return self::$written;
    }

    /**
     * Absolute wrapper URL for a stream file inside a (virtual) directory.
     */
    public static function path(string $fileName): string
    {
        return self::SCHEME . '://streams/' . $fileName;
    }

    /**
     * @param string $path Wrapper URL fopen() was called with
     * @param string $mode The fopen() mode — recorded so a test can assert that
     *                     the sink opens append-only rather than truncating
     */
    public function stream_open(string $path, string $mode): bool
    {
        self::$opens[] = ['path' => $path, 'mode' => $mode];

        if (self::$mode === self::MODE_OPEN_THROWS) {
            throw new RuntimeException('fopen(): failed to open stream: simulated host failure', 1750000001);
        }

        return self::$mode !== self::MODE_OPEN_REFUSED;
    }

    /**
     * @param int $operation
     */
    public function stream_lock($operation): bool
    {
        // Unlocking always succeeds; only the exclusive acquisition is refused,
        // which is the failure mode the sink guards against.
        if (($operation & LOCK_UN) === LOCK_UN) {
            return true;
        }

        return self::$mode !== self::MODE_LOCK_REFUSED;
    }

    /**
     * @param string $data
     *
     * @return int Bytes "written"
     */
    public function stream_write($data): int
    {
        self::$written .= $data;

        if (self::$mode === self::MODE_SHORT_WRITE) {
            // One byte short of the line: enough to break the NDJSON contract.
            return max(0, \strlen($data) - 1);
        }

        return \strlen($data);
    }

    public function stream_read(): string
    {
        return '';
    }

    public function stream_eof(): bool
    {
        return true;
    }

    public function stream_flush(): bool
    {
        return true;
    }

    /**
     * @return array<int|string, int>
     */
    public function stream_stat(): array
    {
        return $this->statFor(self::SCHEME . '://streams/file.ndjson');
    }

    /**
     * @return array<int|string, int>
     */
    public function url_stat(string $path): array
    {
        return $this->statFor($path);
    }

    /**
     * A regular, world-writable file — unless the path has no extension, in
     * which case it is the containing directory the sink probes with `is_dir()`.
     *
     * @return array<int|string, int>
     */
    private function statFor(string $path): array
    {
        $isDirectory = !str_contains(basename($path), '.');
        $mode = $isDirectory ? 0o040777 : 0o100666;

        return [
            'dev' => 0, 'ino' => 0, 'mode' => $mode, 'nlink' => 1,
            'uid' => 0, 'gid' => 0, 'rdev' => 0, 'size' => 0,
            'atime' => 0, 'mtime' => 0, 'ctime' => 0,
            'blksize' => -1, 'blocks' => -1,
        ];
    }
}
