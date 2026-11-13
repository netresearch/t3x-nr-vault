<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage\Aws;

use Netresearch\NrVault\Configuration\Dto\AwsSecretsConfig;
use Netresearch\NrVault\Exception\AwsSecretsManagerException;

use function is_array;
use function sprintf;
use function strlen;

/**
 * The validated shape of the configured AWS location.
 *
 * Everything that reaches the SDK is checked here, once: the region, the
 * transport of a custom endpoint (https unless the operator opted out, and a
 * bare origin without credentials, path, query or fragment) and every segment
 * of the secret name prefix and of the identifier.
 *
 * AWS secret names allow letters, digits and `/_+=.@-`. An identifier may also
 * contain `:` (the `site:<namespace>:<name>` form), which AWS refuses, so the
 * colon is written as `+`. The mapping is injective because `+` is not part of
 * the identifier alphabet: two identifiers never share a name.
 */
final readonly class AwsSecretsEndpoint
{
    private const REGION_PATTERN = '/^[a-z0-9]+(?:-[a-z0-9]+)+$/D';

    private const SEGMENT_PATTERN = '/^[A-Za-z0-9_+=.@-]+$/D';

    /** Identifiers are a user pattern, a UUID v7 or the `site:<ns>:<name>` form. */
    private const IDENTIFIER_PATTERN = '/^[A-Za-z0-9_:-]{1,255}$/D';

    /**
     * AWS allows 512 characters. The registry row stores `<region>:<name>` in a
     * 500 character column, so the name is kept well below both.
     */
    private const MAX_NAME_LENGTH = 400;

    /**
     * @param list<string> $prefix Segments of the secret name before the identifier
     */
    private function __construct(
        public string $region,
        public ?string $endpoint,
        private array $prefix,
    ) {}

    /**
     * @throws AwsSecretsManagerException
     */
    public static function fromConfig(AwsSecretsConfig $config): self
    {
        $region = trim($config->region);
        if ($region === '') {
            throw AwsSecretsManagerException::notConfigured('aws.region is empty');
        }

        if (strlen($region) > 32 || preg_match(self::REGION_PATTERN, $region) !== 1) {
            throw AwsSecretsManagerException::notConfigured('aws.region is not an AWS region name');
        }

        $prefix = [];
        $raw    = trim($config->secretPrefix, '/');
        if ($raw !== '') {
            $prefix = explode('/', $raw);
            foreach ($prefix as $segment) {
                self::assertSafeSegment($segment, 'aws.secretPrefix');
            }
        }

        return new self($region, self::validateEndpoint($config), $prefix);
    }

    /**
     * The secret name AWS stores the envelope under.
     *
     * @throws AwsSecretsManagerException
     */
    public function name(string $identifier): string
    {
        if (preg_match(self::IDENTIFIER_PATTERN, $identifier) !== 1) {
            throw AwsSecretsManagerException::unsafeName('secret identifier');
        }

        $name = implode('/', [...$this->prefix, str_replace(':', '+', $identifier)]);
        if (strlen($name) > self::MAX_NAME_LENGTH) {
            throw AwsSecretsManagerException::unsafeName('secret name');
        }

        return $name;
    }

    /**
     * The location as stored in the registry row's external reference.
     *
     * @throws AwsSecretsManagerException
     */
    public function reference(string $identifier): string
    {
        return sprintf('%s:%s', $this->region, $this->name($identifier));
    }

    /**
     * @throws AwsSecretsManagerException
     */
    private static function assertSafeSegment(string $segment, string $what): void
    {
        if (preg_match(self::SEGMENT_PATTERN, $segment) !== 1) {
            throw AwsSecretsManagerException::unsafeName($what);
        }
    }

    /**
     * @throws AwsSecretsManagerException
     */
    private static function validateEndpoint(AwsSecretsConfig $config): ?string
    {
        if ($config->endpoint === '') {
            return null;
        }

        $parts = parse_url($config->endpoint);
        if (!is_array($parts) || ($parts['host'] ?? '') === '') {
            throw AwsSecretsManagerException::notConfigured('aws.endpoint is not a valid URL');
        }

        $scheme = strtolower($parts['scheme'] ?? '');
        if ($scheme !== 'https' && ($scheme !== 'http' || !$config->allowInsecureHttp)) {
            throw AwsSecretsManagerException::insecureTransport();
        }

        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
            || !in_array($parts['path'] ?? '', ['', '/'], true)
        ) {
            throw AwsSecretsManagerException::notConfigured(
                'aws.endpoint must be a bare origin without credentials, path, query or fragment',
            );
        }

        // parse_url() keeps the brackets of an IPv6 literal.
        $port = isset($parts['port']) ? ':' . $parts['port'] : '';

        return sprintf('%s://%s%s', $scheme, $parts['host'], $port);
    }
}
