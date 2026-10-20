<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use Netresearch\NrVault\Audit\AuditContextInterface;
use Netresearch\NrVault\Audit\GenericContext;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(GenericContext::class)]
final class GenericContextTest extends TestCase
{
    #[Test]
    public function implementsAuditContextInterface(): void
    {
        $context = new GenericContext([]);

        self::assertInstanceOf(AuditContextInterface::class, $context);
    }

    #[Test]
    public function constructorAcceptsData(): void
    {
        $data    = ['key' => 'value', 'number' => 42];
        $context = new GenericContext($data);

        self::assertEquals($data, $context->toArray());
    }

    #[Test]
    public function fromArrayCreatesContextFromNamedArgs(): void
    {
        $context = GenericContext::fromArray(
            service: 'stripe',
            amount: 1000,
            success: true,
        );

        self::assertEquals([
            'service' => 'stripe',
            'amount'  => 1000,
            'success' => true,
        ], $context->toArray());
    }

    #[Test]
    public function fromArrayFiltersNonScalarValues(): void
    {
        $context = GenericContext::fromArray(
            valid: 'string',
            also_valid: null,
        );

        // Only scalar values and null should be kept
        $array = $context->toArray();
        self::assertArrayHasKey('valid', $array);
        self::assertArrayHasKey('also_valid', $array);
    }

    #[Test]
    public function toArrayReturnsData(): void
    {
        $data    = ['foo' => 'bar'];
        $context = new GenericContext($data);

        self::assertEquals($data, $context->toArray());
    }

    #[Test]
    public function jsonSerializeReturnsSameAsToArray(): void
    {
        $data    = ['key' => 'value'];
        $context = new GenericContext($data);

        self::assertEquals($context->toArray(), $context->jsonSerialize());
    }

    #[Test]
    public function canBeJsonEncoded(): void
    {
        $data    = ['service' => 'api', 'count' => 5];
        $context = new GenericContext($data);

        $json = json_encode($context);

        self::assertEquals('{"service":"api","count":5}', $json);
    }
}
