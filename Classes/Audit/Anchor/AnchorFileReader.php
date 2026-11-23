<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Anchor;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Psr\Log\LoggerInterface;
use Throwable;

use function is_array;

/**
 * Reads chain-tip anchors from the NDJSON anchor file written by
 * {@see \Netresearch\NrVault\Audit\Sink\JsonFileAuditSink}.
 *
 * ## Why the highest sequence wins, not the last line
 *
 * The file is append-only, so the last line is *usually* the newest anchor — but
 * "usually" is not a security property. An attacker with write access to the file
 * can append an anchor claiming sequence 1, and picking the last line would then
 * silently downgrade the baseline to something a truncated chain satisfies. Taking
 * the MAXIMUM sequence makes appending useless: to weaken the baseline an attacker
 * must rewrite or truncate the file, which is exactly what append-only storage
 * (or an off-host copy) is there to prevent.
 *
 * ## Anchors without a chain tip do not count while a real one exists
 *
 * An anchor whose chain tip is empty compares nothing (see
 * {@see ChainTipAnchor::isEmpty()}). Taken as the baseline it would switch the
 * reset comparison off, and an appended line with a huge sequence and no tip
 * would do exactly that. So the highest anchor WITH a tip wins; a tip-less
 * anchor is returned only when the file holds no other, so the verifier can
 * still tell "anchored while empty" from "no anchor at all".
 *
 * ## Bounded reading
 *
 * The file grows by one line per anchoring run, so it stays small — but it lives
 * on a filesystem this code does not control, so it is read line-by-line rather
 * than slurped, and unparseable lines are skipped rather than aborting the scan.
 * A single corrupted line must not cost the verification its entire baseline.
 */
final readonly class AnchorFileReader implements AnchorReaderInterface
{
    public function __construct(
        private ExtensionConfigurationInterface $extensionConfiguration,
        private LoggerInterface $logger,
    ) {}

    public function readLatestAnchor(): ?ChainTipAnchor
    {
        $path = $this->extensionConfiguration->getAuditSinkAnchorPath();
        if (!is_file($path) || !is_readable($path)) {
            return null;
        }

        // No `@` suppression (the project's PHPStan ruleset forbids it) — an
        // unreadable file surfaces as either `false` or, under TYPO3's
        // warning-to-exception error handler, a Throwable. Both mean the same
        // thing here: verification has no external baseline.
        try {
            $handle = fopen($path, 'rb');
        } catch (Throwable) {
            $handle = false;
        }

        if ($handle === false) {
            $this->logger->warning(
                'nr-vault could not open the audit anchor file; verification has no external baseline.',
                ['path' => $path],
            );

            return null;
        }

        $best      = null;
        $bestEmpty = null;

        try {
            while (($line = fgets($handle)) !== false) {
                $anchor = $this->parseLine($line);
                if (!$anchor instanceof ChainTipAnchor) {
                    continue;
                }

                if ($anchor->isEmpty()) {
                    $bestEmpty = $this->higher($bestEmpty, $anchor);
                } else {
                    $best = $this->higher($best, $anchor);
                }
            }
        } finally {
            fclose($handle);
        }

        return $best ?? $bestEmpty;
    }

    public function isAvailable(): bool
    {
        $path = $this->extensionConfiguration->getAuditSinkAnchorPath();

        return is_file($path) && is_readable($path);
    }

    public function readAnchors(): array
    {
        $path = $this->extensionConfiguration->getAuditSinkAnchorPath();
        if (!is_file($path) || !is_readable($path)) {
            return [];
        }

        try {
            $handle = fopen($path, 'rb');
        } catch (Throwable) {
            $handle = false;
        }

        if ($handle === false) {
            return [];
        }

        $anchors = [];

        try {
            while (($line = fgets($handle)) !== false) {
                $anchor = $this->parseLine($line);
                if ($anchor instanceof ChainTipAnchor) {
                    $anchors[] = $anchor;
                }
            }
        } finally {
            fclose($handle);
        }

        return $anchors;
    }

    /**
     * The first anchor seen wins a tie (strict `>`).
     */
    private function higher(?ChainTipAnchor $current, ChainTipAnchor $candidate): ChainTipAnchor
    {
        return $current instanceof ChainTipAnchor && $candidate->sequence <= $current->sequence ? $current : $candidate;
    }

    /**
     * Decode one NDJSON line into an anchor, or null when it is not an anchor
     * record.
     *
     * The anchor stream also carries `alert` records (see
     * {@see \Netresearch\NrVault\Audit\Sink\JsonFileAuditSink::publishAlert()}),
     * so a non-anchor line is normal traffic, not corruption — it is skipped
     * without a log entry.
     */
    private function parseLine(string $line): ?ChainTipAnchor
    {
        $line = trim($line);
        if ($line === '') {
            return null;
        }

        try {
            $decoded = json_decode($line, true, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            // A truncated final line (crash mid-write) or a hand-edit. Skipping
            // keeps every intact earlier anchor usable.
            return null;
        }

        if (!is_array($decoded) || ($decoded['type'] ?? null) !== 'anchor') {
            return null;
        }

        $payload = $decoded['anchor'] ?? null;
        if (!is_array($payload)) {
            return null;
        }

        /** @var array<string, mixed> $payload */
        return ChainTipAnchor::fromArray($payload);
    }
}
