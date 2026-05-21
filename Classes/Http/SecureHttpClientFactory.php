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

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use Psr\Http\Client\ClientInterface;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Log\LogManager;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Factory for creating HTTP clients that respect TYPO3 settings but prevent secret leakage.
 *
 * This factory reads TYPO3's HTTP configuration ($GLOBALS['TYPO3_CONF_VARS']['HTTP'])
 * to respect corporate proxy settings, SSL certificates, timeouts, and host restrictions.
 *
 * Security measures:
 * - debug is always disabled to prevent request/response logging that could expose secrets
 * - http_errors is disabled so VaultHttpClient can handle errors and audit them properly
 *
 * Respected TYPO3 settings:
 * - proxy: Corporate proxy configuration
 * - verify, cert, ssl_key: SSL/TLS certificate settings
 * - connect_timeout, timeout: Connection timeouts
 * - allow_redirects: Redirect behavior
 * - allowed_hosts: Host restrictions (checked manually if needed)
 *
 * @see https://docs.typo3.org/m/typo3/reference-coreapi/main/en-us/Configuration/Typo3ConfVars/HTTP.html
 */
final class SecureHttpClientFactory
{
    /**
     * Create a PSR-18 HTTP client with TYPO3 settings and security hardening.
     */
    public function create(): ClientInterface
    {
        /** @var array<string, array<string, mixed>> $confVars */
        $confVars = $GLOBALS['TYPO3_CONF_VARS'] ?? [];
        /** @var array<string, mixed> $typo3Config */
        $typo3Config = $confVars['HTTP'] ?? [];

        /** @var array<string, mixed> $options */
        $options = [
            // Security: Always disable debug to prevent secret logging
            'debug' => false,

            // Let VaultHttpClient handle errors for proper audit logging
            'http_errors' => false,

            // Respect TYPO3's timeout settings, with sensible defaults
            'timeout' => \is_int($typo3Config['timeout'] ?? null) ? $typo3Config['timeout'] : 30,
            'connect_timeout' => \is_int($typo3Config['connect_timeout'] ?? null) ? $typo3Config['connect_timeout'] : 10,

            // Respect TYPO3's HTTP version preference
            'version' => \is_string($typo3Config['version'] ?? null) ? $typo3Config['version'] : '1.1',
        ];

        // Proxy settings (critical for corporate networks)
        if (!empty($typo3Config['proxy'])) {
            $options['proxy'] = $typo3Config['proxy'];
        } else {
            // Fall back to environment variables (common in containers)
            $options['proxy'] = $this->getProxyFromEnvironment();
        }

        // SSL/TLS settings
        if (\array_key_exists('verify', $typo3Config)) {
            if ($typo3Config['verify'] === false) {
                $this->getLogger()->warning(
                    'TLS verification is disabled in TYPO3 HTTP configuration. '
                    . 'This weakens security for vault HTTP client requests.',
                );
            }
            $options['verify'] = $typo3Config['verify'];
        }
        if (!empty($typo3Config['cert'])) {
            $options['cert'] = $typo3Config['cert'];
        }
        if (!empty($typo3Config['ssl_key'])) {
            $options['ssl_key'] = $typo3Config['ssl_key'];
        }

        // Redirect settings: disable by default to prevent credential leakage on cross-origin redirects
        if (\array_key_exists('allow_redirects', $typo3Config)) {
            $options['allow_redirects'] = $typo3Config['allow_redirects'];
        } else {
            $options['allow_redirects'] = false;
        }

        // Create handler stack without any logging middleware
        $stack = HandlerStack::create();
        $options['handler'] = $stack;

        return new Client($options);
    }

    /**
     * Check if a host is allowed per TYPO3's allowed_hosts configuration.
     *
     * Defence-in-depth: regardless of the allowlist, IP literals and resolved
     * hostnames that point into private/link-local/loopback/multicast/metadata
     * ranges are always rejected. This blocks SSRF into AWS/GCP/Azure metadata
     * services (169.254.169.254) and internal RFC1918 networks even on
     * installations that left `allowed_hosts` unconfigured.
     *
     * Accepts either a bare hostname/IP or a `host:port` / `[ipv6]:port` /
     * `[ipv6]` form — port and IPv6 brackets are normalised away before
     * filtering. Callers passing PSR-7 `UriInterface::getHost()` get the
     * already-normalised form for free.
     */
    public function isHostAllowed(string $host): bool
    {
        $host = $this->normaliseHost($host);
        if ($host === '') {
            return false;
        }

        // Hard block: IP literals in dangerous ranges
        if ($this->isDangerousIpLiteral($host)) {
            return false;
        }

        // Hard block: hostname that resolves into dangerous ranges (DNS rebind defence)
        if ($this->resolvesToDangerousIp($host)) {
            return false;
        }

        /** @var array<string, array<string, mixed>> $confVars */
        $confVars = \is_array($GLOBALS['TYPO3_CONF_VARS'] ?? null) ? $GLOBALS['TYPO3_CONF_VARS'] : [];
        /** @var array<string, mixed> $httpConfig */
        $httpConfig = $confVars['HTTP'] ?? [];
        $allowedHosts = $httpConfig['allowed_hosts'] ?? null;

        // No allowlist configured → fall through to default-allow,
        // but only after the IP/DNS checks above have passed.
        if (!\is_array($allowedHosts) || $allowedHosts === []) {
            return true;
        }

        foreach ($allowedHosts as $pattern) {
            if (!\is_string($pattern)) {
                continue;
            }

            // Exact match
            if ($pattern === $host) {
                return true;
            }

            // Wildcard match (e.g., *.example.com)
            if (str_starts_with($pattern, '*.')) {
                $suffix = substr($pattern, 1); // .example.com
                if (str_ends_with($host, $suffix)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Normalise the various shapes a host string can arrive in to a bare host:
     *  - `127.0.0.1:8080`        → `127.0.0.1`
     *  - `[::1]:8080`            → `::1`
     *  - `[2001:db8::1]`         → `2001:db8::1`
     *  - `::1`                   → `::1`           (bare IPv6 — auto-bracketed)
     *  - `example.com.`          → `example.com`   (trailing dot)
     *  - `EXAMPLE.com`           → `example.com`
     *  - `  127.0.0.1\t`         → `127.0.0.1`
     *
     * Anything that doesn't parse cleanly returns '' so the caller fails closed.
     */
    private function normaliseHost(string $host): string
    {
        $host = trim($host, " \t\n\r\0\x0B");
        if ($host === '') {
            return '';
        }

        // If the input already validates as a bare IPv6 literal, return it
        // lowercased — parse_url would otherwise misread `::1` as host=':' port=1.
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return strtolower($host);
        }

        // For bracketed-IPv6 (with or without port) and host:port forms, parse_url
        // handles both consistently. Use a stub scheme so the input is treated
        // as authority.
        $parsed = parse_url('http://' . $host);
        if (!\is_array($parsed) || !isset($parsed['host']) || !\is_string($parsed['host'])) {
            return '';
        }

        $bare = strtolower($parsed['host']);

        // parse_url's IPv6 host comes back BRACKETED ('[::1]'); strip them.
        if (str_starts_with($bare, '[') && str_ends_with($bare, ']')) {
            $bare = substr($bare, 1, -1);
        }

        // strip any trailing dot from a FQDN
        return rtrim($bare, '.');
    }

    /**
     * Reject IP literals in private/link-local/loopback/multicast/metadata ranges.
     *
     * The check combines:
     *  - `FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE` (covers RFC1918
     *    private space, loopback, link-local, and PHP's idea of "reserved");
     *  - explicit deny ranges that PHP's filter does NOT cover:
     *    - 100.64.0.0/10  — RFC6598 CGNAT
     *    - 224.0.0.0/4    — multicast
     *    - 240.0.0.0/4    — class E / reserved
     *
     * Final deny list, in CIDR form:
     *  - 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
     *    169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16,
     *    198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4
     *  - ::1/128, fc00::/7, fe80::/10, ff00::/8 (multicast),
     *    ::ffff:0:0/96 (IPv4-mapped IPv6 — checked via mapping)
     *
     * Caveat: this defence is bypassable by DNS rebinding when the upstream
     * HTTP client (Guzzle/curl) re-resolves at connect-time. For full
     * protection, callers must pin to the resolved IP via curl
     * `CURLOPT_RESOLVE`; that is a follow-up.
     */
    private function isDangerousIpLiteral(string $host): bool
    {
        $packed = inet_pton($host);
        if ($packed === false) {
            return false;
        }

        // IPv4: PHP's filter flags cover 0/8, 10/8, 127/8, 169.254/16,
        // 172.16/12, 192.168/16, 224/4 and (per PHP docs) 240/4. We then add
        // CGNAT (100.64/10), 192.0.0/24 IETF protocol, and 198.18/15 benchmark
        // ranges that the filter does NOT cover.
        if (\strlen($packed) === 4) {
            $isPublic = filter_var(
                $host,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
            );
            if ($isPublic === false) {
                return true;
            }
            $octets = unpack('C4', $packed);
            if ($octets === false) {
                return false;
            }
            // CGNAT 100.64.0.0/10
            if ($octets[1] === 100 && ($octets[2] & 0xC0) === 64) {
                return true;
            }
            // IETF protocol assignments 192.0.0.0/24
            if ($octets[1] === 192 && $octets[2] === 0 && $octets[3] === 0) {
                return true;
            }
            // Benchmark 198.18.0.0/15
            if (($octets[1] === 198) && ($octets[2] === 18 || $octets[2] === 19)) {
                return true;
            }
            // Multicast 224.0.0.0/4 (PHP's NO_RES_RANGE flag does not reliably block this)
            if (($octets[1] & 0xF0) === 224) {
                return true;
            }

            // Class E reserved 240.0.0.0/4
            return ($octets[1] & 0xF0) === 240;
        }

        // IPv6: PHP's filter flags do NOT apply to v6. Explicit ranges:
        //   ::                  (unspecified)
        //   ::1/128             (loopback)
        //   ::ffff:0:0/96       (IPv4-mapped — recurse to v4 check)
        //   64:ff9b::/96        (NAT64 well-known prefix)
        //   100::/64            (discard-only)
        //   fc00::/7            (ULA)
        //   fe80::/10           (link-local)
        //   ff00::/8            (multicast)
        if (\strlen($packed) === 16) {
            // ::1 loopback
            if ($packed === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01") {
                return true;
            }
            // ::
            if ($packed === str_repeat("\x00", 16)) {
                return true;
            }
            // IPv4-mapped ::ffff:0:0/96 — recurse on the embedded IPv4
            if (substr($packed, 0, 10) === str_repeat("\x00", 10) && substr($packed, 10, 2) === "\xff\xff") {
                $v4 = inet_ntop(substr($packed, 12, 4));
                if (\is_string($v4) && $this->isDangerousIpLiteral($v4)) {
                    return true;
                }
            }
            $b0 = \ord($packed[0]);
            // fc00::/7 — top 7 bits == 1111110 → byte0 is 0xfc or 0xfd
            if (($b0 & 0xFE) === 0xFC) {
                return true;
            }
            // fe80::/10 — top 10 bits == 1111111010 → byte0=0xfe and (byte1 & 0xC0) == 0x80
            if ($b0 === 0xFE && (\ord($packed[1]) & 0xC0) === 0x80) {
                return true;
            }
            // ff00::/8 multicast
            if ($b0 === 0xFF) {
                return true;
            }
            // 64:ff9b::/96 NAT64
            if (substr($packed, 0, 12) === "\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00") {
                return true;
            }
            // 100::/64 discard
            if (substr($packed, 0, 8) === "\x01\x00\x00\x00\x00\x00\x00\x00") {
                return true;
            }
        }

        return false;
    }

    /**
     * Resolve a hostname and reject if any A/AAAA record points into a dangerous range.
     *
     * Returns false if resolution fails (caller will then pass the host through;
     * upstream HTTP client will produce a connection error rather than a security
     * bypass).
     */
    private function resolvesToDangerousIp(string $host): bool
    {
        // Already an IP literal — handled by isDangerousIpLiteral
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return false;
        }

        // Suppress DNS lookup warnings without using `@` (banned by phpstan-strict-rules).
        set_error_handler(static fn (): bool => true);

        try {
            $records = dns_get_record($host, DNS_A | DNS_AAAA);
        } finally {
            restore_error_handler();
        }

        if (!\is_array($records) || $records === []) {
            return false;
        }

        foreach ($records as $record) {
            $ip = $record['ip'] ?? $record['ipv6'] ?? null;
            if (\is_string($ip) && $this->isDangerousIpLiteral($ip)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get proxy configuration from environment variables.
     *
     * @return array<string, list<string>|string>|null
     */
    private function getProxyFromEnvironment(): ?array
    {
        /** @var array<string, list<string>|string> $proxy */
        $proxy = [];

        // HTTP_PROXY is only trusted in CLI due to PHP limitations
        if (PHP_SAPI === 'cli') {
            $httpProxy = getenv('HTTP_PROXY') ?: getenv('http_proxy');
            if ($httpProxy !== false && $httpProxy !== '') {
                $proxy['http'] = $httpProxy;
            }
        }

        // HTTPS_PROXY is always safe to read
        $httpsProxy = getenv('HTTPS_PROXY') ?: getenv('https_proxy');
        if ($httpsProxy !== false && $httpsProxy !== '') {
            $proxy['https'] = $httpsProxy;
        }

        // NO_PROXY for exclusions
        $noProxy = getenv('NO_PROXY') ?: getenv('no_proxy');
        if ($noProxy !== false && $noProxy !== '') {
            $proxy['no'] = explode(',', $noProxy);
        }

        return $proxy !== [] ? $proxy : null;
    }

    private function getLogger(): LoggerInterface
    {
        return GeneralUtility::makeInstance(LogManager::class)->getLogger(self::class);
    }
}
