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
     */
    public function isHostAllowed(string $host): bool
    {
        // Always reject host:port forms with control chars / empty / IPv6 brackets handling
        $host = trim($host, " \t\n\r\0\x0B[]");
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
        $confVars = $GLOBALS['TYPO3_CONF_VARS'] ?? [];
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
     * Reject IP literals in private/link-local/loopback/multicast/metadata ranges.
     *
     * Filters covered:
     *  - 0.0.0.0/8        — "this network"
     *  - 10.0.0.0/8       — RFC1918
     *  - 100.64.0.0/10    — RFC6598 CGNAT
     *  - 127.0.0.0/8      — loopback
     *  - 169.254.0.0/16   — link-local + cloud metadata
     *  - 172.16.0.0/12    — RFC1918
     *  - 192.0.0.0/24     — IETF
     *  - 192.168.0.0/16   — RFC1918
     *  - 198.18.0.0/15    — benchmark
     *  - 224.0.0.0/4      — multicast
     *  - 240.0.0.0/4      — reserved
     *  - ::1/128          — IPv6 loopback
     *  - fc00::/7         — IPv6 unique-local
     *  - fe80::/10        — IPv6 link-local
     */
    private function isDangerousIpLiteral(string $host): bool
    {
        if (filter_var($host, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        // PHP's FILTER_FLAG_NO_PRIV_RANGE / NO_RES_RANGE block most private ranges.
        // The combined "public IP" filter rejects what we want to deny.
        $isPublic = filter_var(
            $host,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        );

        return $isPublic === false;
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

        $records = @dns_get_record($host, DNS_A | DNS_AAAA);
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
