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

        $best = null;

        try {
            while (($line = fgets($handle)) !== false) {
                $anchor = $this->parseLine($line);
                if (!$anchor instanceof ChainTipAnchor) {
                    continue;
                }

                if (!$best instanceof ChainTipAnchor || $anchor->sequence > $best->sequence) {
                    $best = $anchor;
                }
            }
        } finally {
            fclose($handle);
        }

        return $best;
    }

    public function isAvailable(): bool
    {
        $path = $this->extensionConfiguration->getAuditSinkAnchorPath();

        return is_file($path) && is_readable($path);
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

        if (!\is_array($decoded) || ($decoded['type'] ?? null) !== 'anchor') {
            return null;
        }

        $payload = $decoded['anchor'] ?? null;
        if (!\is_array($payload)) {
            return null;
        }

        /** @var array<string, mixed> $payload */
        return ChainTipAnchor::fromArray($payload);
    }
}
