<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use Netresearch\NrVault\Crypto\EnvelopeCodecInterface;
use Netresearch\NrVault\Crypto\EnvelopeRotationContext;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;
use ReflectionMethod;

#[CoversClass(EnvelopeRotationContext::class)]
final class EnvelopeRotationContextTest extends TestCase
{
    private const OLD_KEY = 'old-master-key-000000000000000000';

    private const NEW_KEY = 'new-master-key-111111111111111111';

    #[Test]
    public function rewrapPassesBothKeysToTheCodecSoTheConsumerNeverHandlesThem(): void
    {
        $codec = $this->createMock(EnvelopeCodecInterface::class);
        $codec->expects(self::once())
            ->method('rewrap')
            ->with('nrv1:sealed', 'purpose:a', self::OLD_KEY, self::NEW_KEY)
            ->willReturn('nrv1:rewrapped');

        $context = new EnvelopeRotationContext($codec, self::OLD_KEY, self::NEW_KEY);

        self::assertSame('nrv1:rewrapped', $context->rewrap('nrv1:sealed', 'purpose:a'));
    }

    #[Test]
    public function isSealedDelegatesToTheCodec(): void
    {
        $codec = $this->createMock(EnvelopeCodecInterface::class);
        $codec->expects(self::once())
            ->method('isSealed')
            ->with('some value')
            ->willReturn(true);

        $context = new EnvelopeRotationContext($codec, self::OLD_KEY, self::NEW_KEY);

        self::assertTrue($context->isSealed('some value'));
    }

    /**
     * The context exists so a consumer can move envelopes between keys WITHOUT
     * being handed key material. Both keys must therefore stay private — a public
     * property or getter would defeat the whole point of the indirection.
     */
    #[Test]
    public function noKeyMaterialIsReachableThroughThePublicApi(): void
    {
        $reflection = new ReflectionClass(EnvelopeRotationContext::class);

        foreach ($reflection->getProperties() as $property) {
            self::assertTrue(
                $property->isPrivate(),
                \sprintf('Property $%s must be private; it may hold key material.', $property->getName()),
            );
        }

        $publicMethods = array_map(
            static fn (ReflectionMethod $method): string => $method->getName(),
            $reflection->getMethods(ReflectionMethod::IS_PUBLIC),
        );

        self::assertSame(['__construct', 'rewrap', 'isSealed'], $publicMethods);
    }
}
