<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Sink;

use GuzzleHttp\Psr7\HttpFactory;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\AuditSinkException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Throwable;

/**
 * POSTs audit evidence as JSON to an HTTP endpoint (typically a SIEM collector).
 *
 * ## Payload
 *
 * One JSON object per request, always with a `type` discriminator
 * (`entry` | `anchor` | `alert`) plus a `source` marker, so a single collector
 * endpoint can route all three record kinds without a per-kind URL.
 *
 * ## Transport hardening
 *
 * The client is built by
 * {@see \Netresearch\NrVault\Http\SecureHttpClientFactory} (wired in
 * `Services.yaml`), so this sink inherits the extension-wide SSRF and
 * DNS-rebinding defences, the no-redirect default, and TYPO3's proxy/TLS
 * configuration. That has one operational consequence worth stating plainly: a
 * collector on a private/RFC1918/loopback address is REFUSED unless the operator
 * allow-lists the host literally in
 * `$GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts']`.
 *
 * That is the intended trade-off. The webhook URL is settable from the backend
 * Settings module, so a compromised admin could otherwise repoint it at a cloud
 * metadata service and use the vault as an SSRF pivot. `allowed_hosts` is
 * filesystem-bound and out of the backend's reach, which keeps the pivot closed
 * while leaving the legitimate on-premise path available. The refusal is not
 * silent: it surfaces as a sink failure (logged, counted, and reported by
 * `vault:audit-verify`).
 *
 * ## Timeouts
 *
 * The injected client is created with a short total timeout (see `Services.yaml`).
 * Audit fan-out happens after the chain write and outside the advisory lock, so a
 * slow endpoint cannot serialise vault operations — but it can still hold a web
 * request open, so the bound is deliberately tight rather than generous.
 */
final readonly class WebhookAuditSink implements AuditSinkInterface
{
    public const IDENTIFIER = 'webhook';

    /** Marks the payload's origin so a shared collector can filter on it. */
    private const PAYLOAD_SOURCE = 'nr-vault';

    // No explicit `readonly` modifier: the class is readonly, so its properties
    // are implicitly readonly and PHP rejects the redundant keyword.
    private RequestFactoryInterface $requestFactory;

    private StreamFactoryInterface $streamFactory;

    /**
     * @param ClientInterface $httpClient MUST be a hardened client — `Services.yaml`
     *                                    injects one built by `SecureHttpClientFactory::create(3)`
     * @param RequestFactoryInterface|null $requestFactory PSR-17 factories are not
     *                                                     registered in the TYPO3 core DI container, so they default to
     *                                                     Guzzle's `HttpFactory` (the same approach as
     *                                                     {@see \Netresearch\NrVault\Http\OAuth\OAuthTokenManager}) and stay
     *                                                     injectable for tests
     */
    public function __construct(
        private ExtensionConfigurationInterface $extensionConfiguration,
        private ClientInterface $httpClient,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
    ) {
        $httpFactory = new HttpFactory();
        $this->requestFactory = $requestFactory ?? $httpFactory;
        $this->streamFactory = $streamFactory ?? $httpFactory;
    }

    public function publish(AuditLogEntry $entry, string $chainTip): void
    {
        $this->post([
            'type' => 'entry',
            'source' => self::PAYLOAD_SOURCE,
            'uid' => $entry->uid,
            'chainTip' => $chainTip,
            'entry' => $entry->jsonSerialize(),
        ]);
    }

    public function publishAnchor(ChainTipAnchor $anchor): void
    {
        $this->post([
            'type' => 'anchor',
            'source' => self::PAYLOAD_SOURCE,
            'anchor' => $anchor->toArray(),
        ]);
    }

    public function publishAlert(AuditIntegrityAlert $alert): void
    {
        $this->post([
            'type' => 'alert',
            'source' => self::PAYLOAD_SOURCE,
            'alert' => $alert->toArray(),
        ]);
    }

    public function getIdentifier(): string
    {
        return self::IDENTIFIER;
    }

    public function isEnabled(): bool
    {
        if (!$this->extensionConfiguration->isAuditSinkWebhookEnabled()) {
            return false;
        }

        // An enabled-but-unconfigured webhook would report itself as external
        // evidence while delivering nothing, which is precisely the false
        // confidence the hardened-profile check exists to catch.
        return $this->isUsableUrl($this->extensionConfiguration->getAuditSinkWebhookUrl());
    }

    /**
     * Send one JSON payload.
     *
     * @param array<string, mixed> $payload
     *
     * @throws AuditSinkException On encoding, transport, or non-2xx response
     */
    private function post(array $payload): void
    {
        $url = $this->extensionConfiguration->getAuditSinkWebhookUrl();
        if (!$this->isUsableUrl($url)) {
            throw AuditSinkException::writeFailed(self::IDENTIFIER, 'no usable http(s) endpoint configured');
        }

        $json = json_encode(
            $payload,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE,
        );
        if ($json === false) {
            throw AuditSinkException::encodingFailed(self::IDENTIFIER, json_last_error_msg());
        }

        $request = $this->requestFactory->createRequest('POST', $url)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream($json));

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            // PSR-18 transport failure: DNS, TLS, timeout, refused connection —
            // and the SSRF guard's own rejection, which arrives as a
            // RequestException. The endpoint URL is omitted from the message so
            // a URL carrying a collector token cannot reach the log.
            throw AuditSinkException::transportFailed(self::IDENTIFIER, $e->getMessage());
        } catch (Throwable $e) {
            // A PSR-17/18 implementation may also throw InvalidArgumentException
            // for a malformed URI before any request is attempted. Normalise it
            // so the registry's per-sink handling stays uniform.
            throw AuditSinkException::transportFailed(self::IDENTIFIER, $e->getMessage());
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw AuditSinkException::rejectedByEndpoint(self::IDENTIFIER, $status);
        }
    }

    /**
     * Whether the configured value is a syntactically usable http(s) URL.
     *
     * Scheme is restricted to http/https so a `file://` or `php://` value cannot
     * turn an audit fan-out into a local-file write. Reachability is NOT probed
     * here — that is the request's job, and probing on every `isEnabled()` call
     * would put a network round-trip in the path of every vault operation.
     */
    private function isUsableUrl(string $url): bool
    {
        if ($url === '') {
            return false;
        }

        $scheme = parse_url($url, PHP_URL_SCHEME);
        if (!\is_string($scheme) || !\in_array(strtolower($scheme), ['http', 'https'], true)) {
            return false;
        }

        $host = parse_url($url, PHP_URL_HOST);

        return \is_string($host) && $host !== '';
    }
}
