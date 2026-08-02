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

/**
 * Builds RFC 5424 §6.3 STRUCTURED-DATA elements for the syslog sink.
 *
 * Split out from {@see SyslogAuditSink} for one reason: `syslog()` writes to a
 * process-global handle and its output is not observable from a unit test. The
 * formatting — which is where the bugs live (escaping, field order, truncation)
 * — is pure and fully testable here.
 *
 * ## What we emit, and what syslog adds
 *
 * A complete RFC 5424 frame is
 * `HEADER SP STRUCTURED-DATA [SP MSG]`. PHP's `syslog()` only lets us supply the
 * MSG portion; the PRI, VERSION, TIMESTAMP, HOSTNAME, APP-NAME and PROCID of the
 * HEADER are produced by the local syslog implementation (APP-NAME from the
 * `openlog()` ident). We therefore emit
 * `STRUCTURED-DATA SP <human-readable summary>` and let the daemon prepend the
 * header. Collectors that parse RFC 5424 see a well-formed SD element; a plain
 * `tail -f` still shows a readable line.
 *
 * ## SD-ID
 *
 * RFC 5424 §6.3.2 requires an SD-ID to be either IANA-registered or of the form
 * `name@<private-enterprise-number>`. Netresearch has no registered PEN, so the
 * elements use IANA's documentation/example PEN 32473 (RFC 5612 §5) — a
 * syntactically valid, deliberately non-colliding choice. Collector rules should
 * match on the full SD-ID string.
 *
 * ## Escaping
 *
 * Inside a PARAM-VALUE, RFC 5424 §6.3.3 requires `"`, `\` and `]` to be escaped
 * with a backslash. Control characters are additionally stripped: audit fields
 * such as `user_agent` originate from attacker-controlled request headers, and an
 * embedded newline would let a caller forge an extra syslog record
 * (CWE-117 log injection).
 */
final readonly class Rfc5424Formatter
{
    /** Structured-data element for a single audit entry. */
    public const SD_ID_ENTRY = 'nrVaultAudit@32473';

    /** Structured-data element for a chain-tip anchor. */
    public const SD_ID_ANCHOR = 'nrVaultAnchor@32473';

    /** Structured-data element for an integrity alert. */
    public const SD_ID_ALERT = 'nrVaultAlert@32473';

    /**
     * Cap on a single PARAM-VALUE. Keeps one oversized field (a 500-char
     * user-agent, a long error message) from pushing the record past the
     * 1024-byte minimum a receiver is required to accept.
     */
    private const MAX_PARAM_LENGTH = 200;

    /**
     * Cap on the free-text summary that follows the structured-data element.
     *
     * Bounded for the same reason as a PARAM-VALUE: the summary interpolates
     * caller-influenced fields (secret identifier, actor username, alert detail),
     * so leaving it unbounded would let one oversized value inflate the record
     * regardless of how carefully the SD params are trimmed.
     */
    private const MAX_SUMMARY_LENGTH = 300;

    /**
     * Format one audit entry.
     *
     * Field set per the sink contract: secret identifier, action, actor,
     * success, uid, chain tip. `actor` is the human-readable username plus its
     * uid so a SIEM can correlate without a second lookup.
     */
    public function formatEntry(AuditLogEntry $entry, string $chainTip): string
    {
        $sd = $this->buildStructuredData(self::SD_ID_ENTRY, [
            'uid' => (string) $entry->uid,
            'secret' => $entry->secretIdentifier,
            'action' => $entry->action,
            'actor' => $entry->actorUsername,
            'actorUid' => (string) $entry->actorUid,
            'actorType' => $entry->actorType,
            'success' => $entry->success ? 'true' : 'false',
            'chainTip' => $chainTip,
        ]);

        return $sd . ' ' . $this->summary(\sprintf(
            'vault audit %s %s on %s by %s',
            $entry->action,
            $entry->success ? 'succeeded' : 'FAILED',
            $entry->secretIdentifier,
            $entry->actorUsername !== '' ? $entry->actorUsername : ('uid:' . $entry->actorUid),
        ));
    }

    /**
     * Format a chain-tip anchor.
     */
    public function formatAnchor(ChainTipAnchor $anchor): string
    {
        $sd = $this->buildStructuredData(self::SD_ID_ANCHOR, [
            'sequence' => (string) $anchor->sequence,
            'chainTip' => $anchor->chainTip,
            'hmacEpoch' => (string) $anchor->hmacEpoch,
            'anchoredAt' => (string) $anchor->timestamp,
        ]);

        return $sd . ' ' . $this->summary(\sprintf(
            'vault audit chain anchored at sequence %d (epoch %d)',
            $anchor->sequence,
            $anchor->hmacEpoch,
        ));
    }

    /**
     * Format an integrity alert.
     */
    public function formatAlert(AuditIntegrityAlert $alert): string
    {
        $params = [
            'reason' => $alert->reason->value,
            'tamperEvidence' => $alert->reason->isTamperEvidence() ? 'true' : 'false',
            'raisedAt' => (string) $alert->timestamp,
        ];

        foreach ($alert->context as $key => $value) {
            // Prefix so a context key can never collide with (or override) one
            // of the fixed params above.
            $params['ctx_' . $key] = \is_bool($value) ? ($value ? 'true' : 'false') : (string) $value;
        }

        $sd = $this->buildStructuredData(self::SD_ID_ALERT, $params);

        return $sd . ' ' . $this->summary(\sprintf(
            'vault audit integrity alert %s: %s',
            $alert->reason->value,
            $alert->detail,
        ));
    }

    /**
     * Assemble `[SD-ID name="value" ...]` from an ordered param map.
     *
     * Empty values are kept rather than dropped: a collector rule matching on
     * `chainTip=""` should be able to see that the field was present and blank,
     * not have to guess whether the sink omitted it.
     *
     * @param array<string, string> $params
     */
    private function buildStructuredData(string $sdId, array $params): string
    {
        $parts = [$sdId];
        foreach ($params as $name => $value) {
            $parts[] = \sprintf('%s="%s"', $this->sanitizeParamName($name), $this->escapeParamValue($value));
        }

        return '[' . implode(' ', $parts) . ']';
    }

    /**
     * RFC 5424 PARAM-NAME is restricted to printable US-ASCII without `=`,
     * space, `]` or `"`. Every name we emit is a literal from this class, but
     * alert context keys come from callers — filter rather than trust.
     */
    private function sanitizeParamName(string $name): string
    {
        $clean = (string) preg_replace('/[^A-Za-z0-9_.-]/', '_', $name);

        return $clean === '' ? 'param' : $clean;
    }

    /**
     * Escape a PARAM-VALUE per RFC 5424 §6.3.3, after stripping control
     * characters and bounding the length.
     */
    private function escapeParamValue(string $value): string
    {
        $clean = $this->sanitize($value);

        if (mb_strlen($clean, 'UTF-8') > self::MAX_PARAM_LENGTH) {
            $clean = mb_substr($clean, 0, self::MAX_PARAM_LENGTH - 3, 'UTF-8') . '...';
        }

        // Order matters: the backslash must be doubled before the escapes that
        // introduce new backslashes, otherwise those get double-escaped.
        return str_replace(['\\', '"', ']'], ['\\\\', '\\"', '\\]'], $clean);
    }

    /**
     * Sanitise and bound the free-text summary.
     */
    private function summary(string $text): string
    {
        $clean = $this->sanitize($text);

        if (mb_strlen($clean, 'UTF-8') > self::MAX_SUMMARY_LENGTH) {
            return mb_substr($clean, 0, self::MAX_SUMMARY_LENGTH - 3, 'UTF-8') . '...';
        }

        return $clean;
    }

    /**
     * Drop control characters (including CR/LF) and repair invalid UTF-8.
     *
     * A newline in a syslog MSG terminates the record, so an unfiltered
     * attacker-controlled field could append a second, forged record.
     */
    private function sanitize(string $value): string
    {
        if ($value === '') {
            return '';
        }

        if (!mb_check_encoding($value, 'UTF-8')) {
            $scrubbed = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
            $value = \is_string($scrubbed) ? $scrubbed : '';
        }

        return trim((string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', $value));
    }
}
