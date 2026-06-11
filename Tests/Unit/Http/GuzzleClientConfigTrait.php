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
}
