<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use Netresearch\NrVault\Audit\AuditContextInterface;
use Netresearch\NrVault\Audit\HttpCallContext;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(HttpCallContext::class)]
final class HttpCallContextTest extends TestCase
{
    #[Test]
    public function implementsAuditContextInterface(): void
    {
        $context = new HttpCallContext('GET', 'example.com', '/', 200);

        self::assertInstanceOf(AuditContextInterface::class, $context);
    }

    #[Test]
    public function constructorSetsProperties(): void
    {
        $context = new HttpCallContext('POST', 'api.example.com', '/v1/charge', 201);

        self::assertEquals('POST', $context->method);
        self::assertEquals('api.example.com', $context->host);
        self::assertEquals('/v1/charge', $context->path);
        self::assertEquals(201, $context->statusCode);
    }

    #[Test]
    public function fromRequestParsesUrl(): void
    {
        $context = HttpCallContext::fromRequest(
            'GET',
            'https://api.stripe.com/v1/customers?limit=10',
            200,
        );

        self::assertEquals('GET', $context->method);
        self::assertEquals('api.stripe.com', $context->host);
        self::assertEquals('/v1/customers', $context->path);
        self::assertEquals(200, $context->statusCode);
    }

    #[Test]
    public function fromRequestHandlesMissingHost(): void
    {
        $context = HttpCallContext::fromRequest('GET', '/path/only', 200);

        self::assertEquals('unknown', $context->host);
        self::assertEquals('/path/only', $context->path);
    }

    #[Test]
    public function fromRequestHandlesMissingPath(): void
    {
        $context = HttpCallContext::fromRequest('GET', 'https://example.com', 200);

        self::assertEquals('example.com', $context->host);
        self::assertEquals('/', $context->path);
    }

    #[Test]
    public function toArrayReturnsCorrectStructure(): void
    {
        $context = new HttpCallContext('DELETE', 'api.example.com', '/resource/123', 204);

        self::assertEquals([
            'method'      => 'DELETE',
            'host'        => 'api.example.com',
            'path'        => '/resource/123',
            'status_code' => 204,
        ], $context->toArray());
    }

    #[Test]
    public function jsonSerializeReturnsSameAsToArray(): void
    {
        $context = new HttpCallContext('PUT', 'api.example.com', '/update', 200);

        self::assertEquals($context->toArray(), $context->jsonSerialize());
    }

    #[Test]
    public function canBeJsonEncoded(): void
    {
        $context = new HttpCallContext('GET', 'api.test.com', '/health', 200);

        $json = json_encode($context);

        self::assertEquals(
            '{"method":"GET","host":"api.test.com","path":"\/health","status_code":200}',
            $json,
        );
    }
}
