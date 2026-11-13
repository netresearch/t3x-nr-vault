<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage\HashiCorp;

use Netresearch\NrVault\Configuration\Dto\VaultServerConfig;
use Netresearch\NrVault\Exception\HashiCorpException;

use function is_array;
use function sprintf;

/**
 * The validated shape of the configured Vault location.
 *
 * Everything that reaches a URL is checked here, once: the scheme (https unless
 * the operator opted out), the absence of credentials, query or fragment in the
 * address, and every path segment of the mount, the prefix and the identifier.
 * `.` and `..` are legal characters in a Vault mount name but are traversal
 * segments in a URL, so a segment must hold at least one other character.
 */
final readonly class HashiCorpEndpoint
{
    private const SEGMENT_PATTERN = '/^[A-Za-z0-9._-]+$/';

    /** Identifiers are a user pattern, a UUID v7 or the `site:<ns>:<name>` form. */
    private const IDENTIFIER_PATTERN = '/^[A-Za-z0-9_:-]{1,255}$/';

    /**
     * @param list<string> $kvMount  Segments of the KV v2 mount
     * @param list<string> $kvPrefix Segments between `data/` and the identifier
     */
    private function __construct(
        private string $baseUrl,
        private array $kvMount,
        private array $kvPrefix,
    ) {}

    /**
     * @throws HashiCorpException
     */
    public static function fromConfig(VaultServerConfig $config): self
    {
        if ($config->address === '') {
            throw HashiCorpException::notConfigured('hashicorp.address is empty');
        }

        if ($config->path === '') {
            throw HashiCorpException::notConfigured('hashicorp.path is empty');
        }

        $baseUrl = self::validateAddress($config);

        $segments = explode('/', trim($config->path, '/'));
        $dataAt   = array_search('data', $segments, true);
        if ($dataAt === false || $dataAt < 1) {
            throw HashiCorpException::notConfigured('hashicorp.path must look like <mount>/data/<prefix>');
        }

        $mount  = array_slice($segments, 0, $dataAt);
        $prefix = array_slice($segments, $dataAt + 1);
        foreach ([...$mount, ...$prefix] as $segment) {
            self::assertSafeSegment($segment, 'path');
        }

        return new self($baseUrl, $mount, $prefix);
    }

    /**
     * URL of the login endpoint of an auth method mount.
     *
     * @throws HashiCorpException
     */
    public static function loginUrl(VaultServerConfig $config, string $mount): string
    {
        $baseUrl = self::validateAddress($config);
        $parts   = explode('/', trim($mount, '/'));
        foreach ($parts as $segment) {
            self::assertSafeSegment($segment, 'auth mount');
        }

        return sprintf('%s/v1/auth/%s/login', $baseUrl, implode('/', $parts));
    }

    /**
     * @throws HashiCorpException
     */
    public function dataUrl(string $identifier): string
    {
        return $this->objectUrl('data', $identifier);
    }

    /**
     * Metadata URL: a DELETE there removes the key with all its versions.
     *
     * @throws HashiCorpException
     */
    public function metadataUrl(string $identifier): string
    {
        return $this->objectUrl('metadata', $identifier);
    }

    /**
     * The object path as stored in the registry row's external reference.
     *
     * @throws HashiCorpException
     */
    public function reference(string $identifier): string
    {
        $this->assertIdentifier($identifier);

        return implode('/', [...$this->kvMount, 'data', ...$this->kvPrefix, $identifier]);
    }

    /**
     * @throws HashiCorpException
     */
    private function objectUrl(string $kind, string $identifier): string
    {
        $this->assertIdentifier($identifier);

        $segments = [...$this->kvMount, $kind, ...$this->kvPrefix, $identifier];

        return sprintf('%s/v1/%s', $this->baseUrl, implode('/', array_map(rawurlencode(...), $segments)));
    }

    /**
     * @throws HashiCorpException
     */
    private function assertIdentifier(string $identifier): void
    {
        if (preg_match(self::IDENTIFIER_PATTERN, $identifier) !== 1) {
            throw HashiCorpException::unsafePath('secret identifier');
        }
    }

    /**
     * @throws HashiCorpException
     */
    private static function assertSafeSegment(string $segment, string $what): void
    {
        if (preg_match(self::SEGMENT_PATTERN, $segment) !== 1 || trim($segment, '.') === '') {
            throw HashiCorpException::unsafePath($what);
        }
    }

    /**
     * @throws HashiCorpException
     */
    private static function validateAddress(VaultServerConfig $config): string
    {
        $parts = parse_url(trim($config->address));
        if (!is_array($parts) || ($parts['host'] ?? '') === '') {
            throw HashiCorpException::notConfigured('hashicorp.address is not a valid URL');
        }

        $scheme = strtolower($parts['scheme'] ?? '');
        if ($scheme !== 'https' && ($scheme !== 'http' || !$config->allowInsecureHttp)) {
            throw HashiCorpException::insecureTransport();
        }

        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
            || !in_array($parts['path'] ?? '', ['', '/'], true)
        ) {
            throw HashiCorpException::notConfigured(
                'hashicorp.address must be a bare origin without credentials, path, query or fragment',
            );
        }

        $host = $parts['host'];
        // parse_url() keeps the brackets of an IPv6 literal.
        $port = isset($parts['port']) ? ':' . $parts['port'] : '';

        return sprintf('%s://%s%s', $scheme, $host, $port);
    }
}
