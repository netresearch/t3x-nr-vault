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

use Closure;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\HandlerStack;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
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
    public function __construct(
        private readonly DnsResolverInterface $dnsResolver = new DefaultDnsResolver(),
    ) {}

    /**
     * Create a PSR-18 HTTP client with TYPO3 settings and security hardening.
     *
     * @param int|null $timeoutSeconds Optional override for Guzzle's `timeout`
     *                                 option (total request duration in seconds)
     *                                 used by `VaultHttpClient::withTimeout()`.
     *                                 Null or non-positive values keep the
     *                                 platform default from
     *                                 $GLOBALS['TYPO3_CONF_VARS']['HTTP']['timeout'].
     *                                 `connect_timeout` deliberately stays
     *                                 platform-managed: the override bounds the
     *                                 whole transfer, not the TCP/TLS handshake.
     */
    public function create(?int $timeoutSeconds = null): ClientInterface
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

        // Per-client timeout override: long-running API calls (LLM generation,
        // large exports) may legitimately exceed the instance-wide TYPO3
        // timeout. Only `timeout` is overridden — `connect_timeout` keeps the
        // platform value because a slow RESPONSE never justifies waiting
        // longer for the connection to be established.
        if ($timeoutSeconds !== null && $timeoutSeconds > 0) {
            $options['timeout'] = $timeoutSeconds;
        }

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

        // Push the DNS-rebinding defence middleware on top of the stack.
        // It resolves the host AT REQUEST TIME and pins the resulting IP via
        // curl's CURLOPT_RESOLVE so the upstream client can't re-resolve to
        // a different (internal) address between our check and the connect.
        $stack->push($this->buildSsrfDefenceMiddleware(), 'ssrf-dns-pin');
        $options['handler'] = $stack;

        // ext-curl absence: Guzzle's HandlerStack::create() falls back to
        // StreamHandler, which IGNORES the curl-only `CURLOPT_RESOLVE` option.
        // The middleware still rejects dangerous-resolving hosts at lookup
        // time (defence-in-depth), but the race-free pinning guarantee is
        // gone — between our DNS check and stream's own resolution, an
        // attacker can still rebind. Warn so operators notice the gap.
        if (!\function_exists('curl_init')) {
            $this->getLogger()->warning(
                'PHP ext-curl is not loaded; the nr-vault HTTP client falls back '
                . 'to the stream handler. DNS rebinding is no longer race-protected '
                . '(the pre-request resolve-and-check is still enforced, but the '
                . 'connect-time IP can drift). Install ext-curl to restore the '
                . 'CURLOPT_RESOLVE pin.',
            );
        }

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

        $allowedHostsList = $this->resolveAllowedHostsList();

        // EXPLICIT allowlist match overrides the private-IP defence so on-prem
        // deployments where the Vault server lives on RFC1918 can still reach
        // it via a documented filesystem-only override. Wildcard patterns
        // (`*.example.com`) do NOT bypass the IP guard — only literal matches.
        if ($this->isExplicitlyAllowlisted($host, $allowedHostsList)) {
            return true;
        }

        // Hard block: IP literals in dangerous ranges
        if ($this->isDangerousIpLiteral($host)) {
            return false;
        }

        // Hard block: hostname that resolves into dangerous ranges (DNS rebind defence)
        if ($this->resolvesToDangerousIp($host)) {
            return false;
        }

        // No allowlist configured → fall through to default-allow,
        // but only after the IP/DNS checks above have passed.
        if ($allowedHostsList === []) {
            return true;
        }

        foreach ($allowedHostsList as $pattern) {
            if (!\is_string($pattern)) {
                continue;
            }

            // Wildcard match (e.g., *.example.com) — literals already handled above.
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
     * Guzzle middleware factory: resolves and validates the request host on
     * every outgoing request, then pins the resolved IP via curl's
     * `CURLOPT_RESOLVE` option so curl skips its own (potentially rebound)
     * DNS lookup at connect time.
     *
     * Why we cannot do this once in `create()`: that factory builds a
     * URL-agnostic Guzzle Client. The host isn't known until a request is
     * actually sent. A middleware fires per request and can inspect the URI.
     *
     * Behaviour:
     *  - Host that resolves to one or more SAFE IPs → those IPs are pinned;
     *    curl uses them without re-resolving.
     *  - Host that resolves to a dangerous IP → the request is rejected
     *    with a `RequestException` BEFORE the socket opens.
     *  - Host that cannot be resolved at all → no pin is added; curl handles
     *    the resolution failure with its usual error path. (The caller's
     *    earlier `isHostAllowed()` check already rejected IP-literal targets
     *    in dangerous ranges.)
     *  - IP-literal hosts (already an IPv4/IPv6 address) → no pin needed;
     *    `isHostAllowed()` validated the literal directly.
     */
    private function buildSsrfDefenceMiddleware(): Closure /** @phpstan-ignore missingType.callable (Guzzle's middleware contract is loosely-typed by design) */
    {
        return function (callable $handler): Closure { /** @phpstan-ignore missingType.callable */
            return function (RequestInterface $request, array $options) use ($handler) {
                // PSR-7 `getHost()` returns IPv6 literals wrapped in brackets
                // (`[::1]`). The IP validators and `dns_get_record()` reject
                // that form, so normalise to the bare host first.
                $host = $this->normaliseHost($request->getUri()->getHost());
                $port = $request->getUri()->getPort()
                    ?? (strtolower($request->getUri()->getScheme()) === 'https' ? 443 : 80);

                // A literal `allowed_hosts` entry opts this host back in past
                // the private-IP guard (e.g. an on-prem service or a
                // self-hosted endpoint the operator deliberately trusts). This
                // mirrors isHostAllowed() so both the helper gate and the
                // request-time middleware honour the same opt-in. Wildcard
                // entries never bypass the guard (DNS-rebinding pivot risk).
                $allowlisted = $this->isExplicitlyAllowlisted(
                    $host,
                    $this->resolveAllowedHostsList(),
                );

                $resolveEntries = $this->buildResolveEntries($host, $port, $allowlisted);

                if ($resolveEntries === null) {
                    throw new RequestException(
                        \sprintf(
                            'Refused to send request: host "%s" resolves to a disallowed IP range '
                            . '(DNS rebinding defence).',
                            $host,
                        ),
                        $request,
                    );
                }

                if ($resolveEntries !== []) {
                    $curlOptions = \is_array($options['curl'] ?? null) ? $options['curl'] : [];
                    /** @var list<string> $existing */
                    $existing = \is_array($curlOptions[\CURLOPT_RESOLVE] ?? null)
                        ? $curlOptions[\CURLOPT_RESOLVE]
                        : [];
                    $curlOptions[\CURLOPT_RESOLVE] = array_values(array_unique(
                        array_merge($existing, $resolveEntries),
                    ));
                    $options['curl'] = $curlOptions;
                }

                return $handler($request, $options);
            };
        };
    }

    /**
     * Resolve `$host` to one or more IP addresses and convert each safe entry
     * into the `host:port:ip` form curl expects for `CURLOPT_RESOLVE`.
     *
     * Returns:
     *  - `null` if the host resolved to AT LEAST ONE dangerous IP and is NOT
     *    explicitly allowlisted (the entire request must be rejected — even if
     *    some A records look safe, the presence of a dangerous answer signals
     *    an active rebinding attempt).
     *  - `[]` if the host is an IP literal (no pin needed) OR if resolution
     *    failed entirely (let curl handle the error path).
     *  - `list<string>` of pin entries to add to `CURLOPT_RESOLVE` for safe
     *    multi-record hosts.
     *
     * @param bool $allowlisted When the host carries a literal `allowed_hosts`
     *                          entry, resolved IPs in otherwise-dangerous
     *                          ranges are pinned instead of rejected — the
     *                          operator has explicitly opted in. The pin is
     *                          still added so rebinding to a *different*
     *                          address stays blocked.
     *
     * @return list<string>|null
     */
    private function buildResolveEntries(string $host, int $port, bool $allowlisted = false): ?array
    {
        // IP literal — `isHostAllowed()` already validated it; no DNS to pin.
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [];
        }

        $records = $this->dnsResolver->resolve($host);
        if ($records === []) {
            // Resolution failed — let curl produce the usual connection error.
            return [];
        }

        $formattedIps = [];
        foreach ($records as $record) {
            $ip = $record['ip'] ?? $record['ipv6'] ?? null;
            if (!\is_string($ip)) {
                continue;
            }
            if (!$allowlisted && $this->isDangerousIpLiteral($ip)) {
                // ANY dangerous answer kills the entire request. A "split-horizon"
                // rebinding setup could otherwise return one safe + one internal
                // IP; if curl picked the internal one, we'd leak. A literal
                // allowed_hosts opt-in skips this rejection but still pins the
                // resolved IP below, so rebinding to a *different* address
                // remains blocked.
                return null;
            }
            // libcurl's CURLOPT_RESOLVE format is `host:port:address`. IPv6
            // addresses contain colons, so they MUST be bracketed or curl
            // misparses the entry (see curl docs / CVE-2025-* class of bugs).
            $formattedIps[] = str_contains($ip, ':') ? '[' . $ip . ']' : $ip;
        }

        if ($formattedIps === []) {
            return [];
        }

        // Pin ALL validated addresses in a SINGLE comma-separated
        // CURLOPT_RESOLVE entry (`host:port:ip1,ip2,[ipv6],…`) rather than one
        // entry per IP. curl performs Happy-Eyeballs fall-back across the
        // addresses of a single entry, so a host that resolves to an
        // unreachable address family (e.g. an AAAA record on an IPv4-only
        // network, or an A record on an IPv6-only one) still connects via a
        // reachable pinned address. Separate per-IP entries defeat that
        // fall-back and fail with "could not connect".
        //
        // This remains rebinding-proof: curl may still only connect to these
        // pinned, already-validated addresses — it cannot re-resolve.
        return [\sprintf('%s:%d:%s', $host, $port, implode(',', $formattedIps))];
    }

    /**
     * Read the `allowed_hosts` allowlist from TYPO3's HTTP configuration.
     *
     * Shared by isHostAllowed() and the request-time SSRF middleware so both
     * honour the same operator-controlled opt-in list.
     *
     * @return array<int|string, mixed>
     */
    private function resolveAllowedHostsList(): array
    {
        /** @var array<string, array<string, mixed>> $confVars */
        $confVars = \is_array($GLOBALS['TYPO3_CONF_VARS'] ?? null) ? $GLOBALS['TYPO3_CONF_VARS'] : [];
        /** @var array<string, mixed> $httpConfig */
        $httpConfig = $confVars['HTTP'] ?? [];
        $allowedHosts = $httpConfig['allowed_hosts'] ?? null;

        return \is_array($allowedHosts) ? $allowedHosts : [];
    }

    /**
     * Literal allowlist match — exact, case-insensitive, no wildcards.
     *
     * Only literal entries can override the private-IP block; wildcards
     * (`*.example.com`) cannot, because a wildcard owner could otherwise
     * register an internal DNS record under their zone and pivot.
     *
     * @param list<mixed>|array<int|string, mixed> $allowedHostsList
     */
    private function isExplicitlyAllowlisted(string $host, array $allowedHostsList): bool
    {
        foreach ($allowedHostsList as $pattern) {
            if (\is_string($pattern) && strtolower($pattern) === $host) {
                return true;
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
        // handles both consistently. Use a protocol-relative `//` prefix so the
        // input is treated as authority (no scheme literal — the host is parsed,
        // never fetched, so there is no http/https insecurity).
        $parsed = parse_url('//' . $host);
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

        return match (\strlen($packed)) {
            4 => $this->isDangerousIpv4($host, $packed),
            16 => $this->isDangerousIpv6($packed),
            default => false,
        };
    }

    /**
     * IPv4 check. PHP's filter flags cover 0/8, 10/8, 127/8, 169.254/16,
     * 172.16/12, 192.168/16, 224/4 and (per PHP docs) 240/4. Explicit ranges
     * cover CGNAT (100.64/10), IETF (192.0.0/24), benchmark (198.18/15) and
     * 224/4 + 240/4 (which `NO_RES_RANGE` does not reliably block).
     */
    private function isDangerousIpv4(string $host, string $packed): bool
    {
        $isPublic = filter_var(
            $host,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        );
        if ($isPublic === false) {
            return true;
        }

        /** @var array{1: int, 2: int, 3: int, 4: int}|false $octets */
        $octets = unpack('C4', $packed);
        if ($octets === false) {
            return false;
        }
        $o1 = (int) $octets[1];
        $o2 = (int) $octets[2];
        $o3 = (int) $octets[3];

        // CGNAT 100.64.0.0/10
        // IETF protocol assignments 192.0.0.0/24
        // Benchmark 198.18.0.0/15
        // Multicast 224.0.0.0/4
        // Class E reserved 240.0.0.0/4
        return ($o1 === 100 && ($o2 & 0xC0) === 64)
            || ($o1 === 192 && $o2 === 0 && $o3 === 0)
            || ($o1 === 198 && ($o2 === 18 || $o2 === 19))
            || (($o1 & 0xF0) === 224)
            || (($o1 & 0xF0) === 240);
    }

    /**
     * IPv6 check. PHP's `FILTER_FLAG_NO_*_RANGE` does not apply to IPv6, so
     * every dangerous range is checked explicitly:
     *   ::                  (unspecified)
     *   ::1/128             (loopback)
     *   ::ffff:0:0/96       (IPv4-mapped — recurse to v4 check)
     *   ::a.b.c.d/96        (IPv4-compatible, deprecated — recurse to v4 check)
     *   64:ff9b::/96        (NAT64 well-known prefix)
     *   2002::/16           (6to4 — recurse on the embedded IPv4)
     *   2001::/32           (Teredo — recurse on the embedded client+server IPv4)
     *   100::/64            (discard-only)
     *   fc00::/7            (ULA)
     *   fe80::/10           (link-local)
     *   ff00::/8            (multicast)
     *
     * The transition forms (6to4 / Teredo / IPv4-compatible) embed an IPv4
     * address inside the IPv6 address. A naive range check that omits them
     * lets an attacker smuggle a metadata/RFC1918 IPv4 target past the SSRF
     * filter as a valid AAAA record or IP literal (CVE-2026-48736 class).
     * Each branch decodes the embedded IPv4 and recurses into the v4 deny
     * check, mirroring the existing NAT64/IPv4-mapped handling.
     */
    private function isDangerousIpv6(string $packed): bool
    {
        $b0 = \ord($packed[0]);

        // Short-circuit byte-0-based checks first (cheapest).
        if (($b0 & 0xFE) === 0xFC) {
            return true; // fc00::/7 ULA
        }
        if ($b0 === 0xFF) {
            return true; // ff00::/8 multicast
        }
        if ($b0 === 0xFE && (\ord($packed[1]) & 0xC0) === 0x80) {
            return true; // fe80::/10 link-local
        }

        // Special prefixes
        if ($packed === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01") {
            return true; // ::1 loopback
        }
        if ($packed === str_repeat("\x00", 16)) {
            return true; // ::
        }
        if (substr($packed, 0, 12) === "\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00") {
            return true; // 64:ff9b::/96 NAT64
        }
        if (substr($packed, 0, 8) === "\x01\x00\x00\x00\x00\x00\x00\x00") {
            return true; // 100::/64 discard
        }

        // IPv4-mapped ::ffff:0:0/96 — recurse on the embedded IPv4
        if (substr($packed, 0, 10) === str_repeat("\x00", 10) && substr($packed, 10, 2) === "\xff\xff") {
            return $this->embeddedIpv4IsDangerous(substr($packed, 12, 4));
        }

        // 6to4 2002::/16 — bytes 2-5 carry the embedded IPv4 (RFC 3056).
        if (substr($packed, 0, 2) === "\x20\x02") {
            return $this->embeddedIpv4IsDangerous(substr($packed, 2, 4));
        }

        // Teredo 2001::/32 (prefix 2001:0000::/32, RFC 4380). The Teredo
        // server IPv4 is bytes 4-7 verbatim; the Teredo CLIENT IPv4 is
        // bytes 12-15 stored obfuscated (XOR 0xFFFFFFFF). Either reaching a
        // dangerous IPv4 is enough to reject.
        if (substr($packed, 0, 4) === "\x20\x01\x00\x00") {
            $serverV4 = substr($packed, 4, 4);
            $clientV4 = substr($packed, 12, 4) ^ "\xff\xff\xff\xff";

            return $this->embeddedIpv4IsDangerous($serverV4)
                || $this->embeddedIpv4IsDangerous($clientV4);
        }

        // IPv4-compatible ::a.b.c.d/96 (deprecated, RFC 4291 §2.5.5.1):
        // first 12 bytes zero and a non-trivial trailing IPv4. `::` and `::1`
        // are already handled above, so any remaining all-zero-prefix address
        // here carries an embedded IPv4 we must inspect (e.g. ::127.0.0.1).
        if (substr($packed, 0, 12) === str_repeat("\x00", 12)) {
            return $this->embeddedIpv4IsDangerous(substr($packed, 12, 4));
        }

        return false;
    }

    /**
     * Decode a 4-byte packed IPv4 address embedded inside an IPv6 transition
     * form and recurse into the IPv4 deny check.
     */
    private function embeddedIpv4IsDangerous(string $packedV4): bool
    {
        if (\strlen($packedV4) !== 4) {
            return false;
        }

        $v4 = inet_ntop($packedV4);

        return \is_string($v4) && $this->isDangerousIpLiteral($v4);
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

        foreach ($this->dnsResolver->resolve($host) as $record) {
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
