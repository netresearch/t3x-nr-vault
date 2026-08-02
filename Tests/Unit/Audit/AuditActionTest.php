<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The backing values are bound into the HMAC hash payload of every audit row, so
 * a changed string would break verification of all historical entries that used
 * the old one. They are pinned here so such a change fails a test rather than a
 * production chain verification.
 */
#[CoversClass(AuditAction::class)]
final class AuditActionTest extends TestCase
{
    #[Test]
    #[DataProvider('labelProvider')]
    public function labelHumanisesTheBackingValue(AuditAction $action, string $expected): void
    {
        self::assertSame($expected, $action->label());
    }

    /**
     * @return iterable<string, array{AuditAction, string}>
     */
    public static function labelProvider(): iterable
    {
        yield 'no underscore' => [AuditAction::Create, 'Create'];
        yield 'single underscore' => [AuditAction::MetadataUpdate, 'Metadata Update'];
        yield 'three underscores' => [AuditAction::MasterKeyRotateStart, 'Master Key Rotate Start'];
        yield 'longest value' => [
            AuditAction::OAuthFallbackClientCredentials,
            'Oauth Fallback Client Credentials',
        ];
    }

    /**
     * `ucwords()` capitalises but must not otherwise rewrite the value: every
     * label has to remain recognisable as its wire form with separators swapped.
     */
    #[Test]
    public function labelDiffersFromTheWireValueOnlyInSeparatorsAndCase(): void
    {
        foreach (AuditAction::cases() as $action) {
            self::assertStringNotContainsString('_', $action->label());
            self::assertSame(
                $action->value,
                strtolower(str_replace(' ', '_', $action->label())),
                'label() must be losslessly reversible to the persisted action string',
            );
        }
    }

    #[Test]
    public function unknownActionIsRejected(): void
    {
        self::assertNull(AuditAction::tryFrom('exfiltrate'));
    }
}
