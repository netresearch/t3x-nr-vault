<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Sink;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\AuditSinkException;
use Psr\Log\LoggerInterface;
use Throwable;
use TYPO3\CMS\Core\Core\Environment;

/**
 * Appends audit evidence to newline-delimited JSON files.
 *
 * Two separate streams, because they have different retention and access needs:
 *  - the **entry stream** (`auditSinkFilePath`) — one JSON object per audit
 *    entry, carrying its `uid` and the `chainTip` it produced;
 *  - the **anchor stream** (`auditSinkAnchorPath`) — one JSON object per
 *    published chain-tip anchor. This is the file `vault:audit-verify` reads back
 *    to detect a full audit-table reset, so it is the one worth putting on
 *    append-only or off-host storage.
 *
 * Both are append-only by construction (`fopen($path, 'ab')`) and every write
 * takes an exclusive advisory lock, so concurrent PHP workers cannot interleave
 * half-written lines. Files are created with mode 0600: an audit stream names
 * every secret identifier and every actor, which is reconnaissance material even
 * without the secret values.
 *
 * ## Why the public-web-root check disables the sink
 *
 * A path under the public document root would publish the audit trail — secret
 * identifiers, usernames, IP addresses, chain hashes — to anyone who guesses the
 * URL. That is a worse outcome than having no external sink, so a path inside the
 * public root makes {@see isEnabled()} report false rather than writing anyway.
 * The refusal is logged with the resolved path and the setting to change, and
 * `vault:audit-verify` surfaces it, so it fails loudly rather than silently.
 *
 * The default (`<var>/log/…`) is outside the public root in every Composer-based
 * TYPO3 installation. A legacy (non-Composer) layout, where `getVarPath()` lives
 * under `typo3temp/`, must configure an explicit path.
 */
final class JsonFileAuditSink implements AuditSinkInterface
{
    public const IDENTIFIER = 'file';

    /** Mode for freshly created stream files — owner read/write only. */
    private const FILE_MODE = 0o600;

    /** Mode for a stream directory we have to create — owner only. */
    private const DIRECTORY_MODE = 0o700;

    /**
     * Memoised result of the path-safety check, keyed by path.
     *
     * `isEnabled()` is called for every audit write; resolving `realpath()` each
     * time would add filesystem syscalls to the hot path of every vault
     * operation. The check depends only on configuration and the filesystem
     * layout, neither of which changes within a request.
     *
     * @var array<string, bool>
     */
    private array $pathSafetyCache = [];

    public function __construct(
        private readonly ExtensionConfigurationInterface $extensionConfiguration,
        private readonly LoggerInterface $logger,
    ) {}

    public function publish(AuditLogEntry $entry, string $chainTip): void
    {
        $this->appendLine($this->extensionConfiguration->getAuditSinkFilePath(), [
            'type' => 'entry',
            'uid' => $entry->uid,
            'chainTip' => $chainTip,
            'entry' => $entry->jsonSerialize(),
        ]);
    }

    public function publishAnchor(ChainTipAnchor $anchor): void
    {
        $this->appendLine($this->extensionConfiguration->getAuditSinkAnchorPath(), [
            'type' => 'anchor',
            'anchor' => $anchor->toArray(),
        ]);
    }

    public function publishAlert(AuditIntegrityAlert $alert): void
    {
        // Alerts go to the anchor stream, not the entry stream: both are the
        // "chain health" record an auditor reads, and keeping them together means
        // a single off-host file tells the whole integrity story.
        $this->appendLine($this->extensionConfiguration->getAuditSinkAnchorPath(), [
            'type' => 'alert',
            'alert' => $alert->toArray(),
        ]);
    }

    public function getIdentifier(): string
    {
        return self::IDENTIFIER;
    }

    public function isEnabled(): bool
    {
        if (!$this->extensionConfiguration->isAuditSinkFileEnabled()) {
            return false;
        }

        // BOTH streams must be safe. Enabling the sink with a safe entry path but
        // a web-exposed anchor path would publish the integrity record, and the
        // anchor stream is the more sensitive of the two (it is the file an
        // auditor trusts).
        return $this->isPathSafe($this->extensionConfiguration->getAuditSinkFilePath())
            && $this->isPathSafe($this->extensionConfiguration->getAuditSinkAnchorPath());
    }

    /**
     * Append one JSON object as a single line.
     *
     * @param array<string, mixed> $payload
     *
     * @throws AuditSinkException On any filesystem or encoding failure — the
     *                            registry catches, logs and counts it
     */
    private function appendLine(string $path, array $payload): void
    {
        $json = json_encode(
            $payload,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE,
        );

        if ($json === false) {
            throw AuditSinkException::encodingFailed(self::IDENTIFIER, json_last_error_msg());
        }

        $this->ensureDirectory($path);
        $this->assertAppendable($path);

        $isNew = !file_exists($path);

        // `fopen()` reports failure by returning false AND emitting a warning; under
        // TYPO3's warning-to-exception error handler the warning arrives as a
        // Throwable instead. Normalise both into AuditSinkException so the registry
        // sees one failure type either way.
        try {
            $handle = fopen($path, 'ab');
        } catch (Throwable $e) {
            throw AuditSinkException::writeFailed(self::IDENTIFIER, 'cannot open stream for appending: ' . $e->getMessage());
        }

        if ($handle === false) {
            throw AuditSinkException::writeFailed(self::IDENTIFIER, 'cannot open stream for appending');
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                throw AuditSinkException::writeFailed(self::IDENTIFIER, 'cannot acquire exclusive lock');
            }

            try {
                // A short write (disk full, quota) would leave a truncated line
                // that breaks the NDJSON contract for every later reader, so it
                // is an error, not a partial success.
                $line = $json . "\n";
                $written = fwrite($handle, $line);
                if ($written === false || $written !== \strlen($line)) {
                    throw AuditSinkException::writeFailed(self::IDENTIFIER, 'incomplete write (disk full or quota exceeded?)');
                }

                fflush($handle);
            } finally {
                flock($handle, LOCK_UN);
            }
        } finally {
            fclose($handle);
        }

        if ($isNew) {
            // `fopen()` honours the process umask, which commonly yields 0644.
            // Tighten immediately after creation. The window is bounded by the
            // directory mode (0700 for directories we create ourselves).
            chmod($path, self::FILE_MODE);
        }
    }

    /**
     * Reject an unusable target before `fopen()` sees it.
     *
     * Two reasons to check up front rather than letting `fopen()` fail: the
     * exception says WHAT is wrong ("path is a directory") instead of the generic
     * "cannot open stream", and `fopen()` emits a PHP warning on failure which —
     * depending on the host's error handler — either pollutes the log or is
     * converted into an unrelated exception type.
     *
     * @throws AuditSinkException
     */
    private function assertAppendable(string $path): void
    {
        if (file_exists($path)) {
            if (!is_file($path)) {
                throw AuditSinkException::writeFailed(self::IDENTIFIER, 'path exists but is not a regular file');
            }

            if (!is_writable($path)) {
                throw AuditSinkException::writeFailed(self::IDENTIFIER, 'stream file is not writable');
            }

            return;
        }

        if (!is_writable(\dirname($path))) {
            throw AuditSinkException::writeFailed(self::IDENTIFIER, 'stream directory is not writable');
        }
    }

    /**
     * Create the stream's parent directory when missing.
     *
     * @throws AuditSinkException If the directory cannot be created
     */
    private function ensureDirectory(string $path): void
    {
        $directory = \dirname($path);
        if (is_dir($directory)) {
            return;
        }

        if (!mkdir($directory, self::DIRECTORY_MODE, true) && !is_dir($directory)) {
            throw AuditSinkException::writeFailed(self::IDENTIFIER, 'cannot create stream directory');
        }
    }

    /**
     * Whether the path is outside the public web root.
     *
     * Resolution walks up to the nearest EXISTING ancestor before comparing:
     * the stream file (and possibly its directory) does not exist on the first
     * write, and `realpath()` returns false for a missing path — which would
     * otherwise make an unwritten path look safe by accident. Resolving an
     * existing ancestor also collapses `..` segments and symlinks, so a path
     * like `<var>/log/../../public/audit.ndjson` cannot slip past the check.
     */
    private function isPathSafe(string $path): bool
    {
        if (isset($this->pathSafetyCache[$path])) {
            return $this->pathSafetyCache[$path];
        }

        return $this->pathSafetyCache[$path] = $this->evaluatePathSafety($path);
    }

    private function evaluatePathSafety(string $path): bool
    {
        if ($path === '' || !$this->isAbsolute($path)) {
            $this->logger->error(
                'nr-vault audit file sink disabled: path must be absolute.',
                ['sink' => self::IDENTIFIER, 'path' => $path],
            );

            return false;
        }

        $publicPath = realpath(Environment::getPublicPath());
        if ($publicPath === false) {
            // Cannot establish the boundary → cannot prove the path is outside
            // it. Fail closed.
            $this->logger->error(
                'nr-vault audit file sink disabled: public web root could not be resolved.',
                ['sink' => self::IDENTIFIER],
            );

            return false;
        }

        $resolved = $this->resolveAgainstNearestExistingAncestor($path);
        if ($resolved === null) {
            $this->logger->error(
                'nr-vault audit file sink disabled: no existing ancestor directory for the configured path.',
                ['sink' => self::IDENTIFIER, 'path' => $path],
            );

            return false;
        }

        if ($resolved === $publicPath || str_starts_with($resolved, $publicPath . \DIRECTORY_SEPARATOR)) {
            $this->logger->error(
                'nr-vault audit file sink disabled: the configured path is inside the public web root, '
                . 'which would expose the audit trail over HTTP. Point auditSinkFilePath / '
                . 'auditSinkAnchorPath at a location outside the document root.',
                ['sink' => self::IDENTIFIER, 'path' => $path, 'resolved' => $resolved],
            );

            return false;
        }

        return true;
    }

    /**
     * Resolve `$path` to an absolute, symlink- and `..`-free form by resolving
     * its nearest existing ancestor and re-appending the missing tail.
     *
     * Returns null when not even the filesystem root of the path exists.
     */
    private function resolveAgainstNearestExistingAncestor(string $path): ?string
    {
        $tail = [];
        $current = $path;

        while (true) {
            $real = realpath($current);
            if ($real !== false) {
                return $tail === [] ? $real : $real . \DIRECTORY_SEPARATOR . implode(\DIRECTORY_SEPARATOR, array_reverse($tail));
            }

            $parent = \dirname($current);
            if ($parent === $current) {
                return null;
            }

            $tail[] = basename($current);
            $current = $parent;
        }
    }

    /**
     * Absolute-path test that also accepts Windows drive/UNC forms, so the
     * sink is not silently unusable off Linux.
     */
    private function isAbsolute(string $path): bool
    {
        return str_starts_with($path, '/')
            || str_starts_with($path, '\\\\')
            || preg_match('/^[A-Za-z]:[\\\\\/]/', $path) === 1;
    }
}
