<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use GuzzleHttp\Client;
use Psr\Http\Client\ClientInterface;
use ReflectionProperty;

/**
 * Reads the request-option configuration out of a built Guzzle client.
 *
 * The options array is private on GuzzleHttp\Client and the supported
 * accessor (getConfig()) is deprecated, so tests reflect into it instead.
 */
trait GuzzleClientConfigTrait
{
    /**
     * @return array<string, mixed>
     */
    private function getGuzzleConfig(ClientInterface $client): array
    {
        self::assertInstanceOf(Client::class, $client);

        $config = (new ReflectionProperty(Client::class, 'config'))->getValue($client);
        self::assertIsArray($config);

        /** @var array<string, mixed> $config */
        return $config;
    }

    /**
     * The same configuration with object values reduced to their class name.
     *
     * Two clients built the same way hold equal options but not identical
     * objects, and Guzzle 8 adds four PSR-17 factory defaults
     * (`request_factory`, `uri_factory`, `stream_factory`, `response_factory`)
     * that are a fresh instance per client. Comparing raw arrays therefore
     * reports a difference in the infrastructure rather than in the
     * configuration under test. The class name is kept so a client built with
     * a different factory still fails the comparison.
     *
     * @param array<string, mixed> $config
     *
     * @return array<string, mixed>
     */
    private function comparableGuzzleConfig(array $config): array
    {
        return array_map(
            static fn (mixed $value): mixed => \is_object($value) ? $value::class : $value,
            $config,
        );
    }
}
