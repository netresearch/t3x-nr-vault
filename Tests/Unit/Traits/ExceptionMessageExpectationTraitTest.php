<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Traits;

use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;

/**
 * Pins `expectExceptionMessageToContain()` to the substring semantics of the
 * `expectExceptionMessage()` it replaces.
 *
 * The metacharacter cases are the ones that matter: passing the needle to
 * `expectExceptionMessageMatches()` unquoted turns `(` into an unterminated
 * group and `/` into a premature delimiter, which PHPUnit rejects as an invalid
 * expected-message regular expression. They fail loudly here if the quoting is
 * ever dropped.
 */
#[CoversNothing]
final class ExceptionMessageExpectationTraitTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function messageProvider(): iterable
    {
        yield 'needle is a strict substring' => [
            'Master key not found at: /var/keys/master.key',
            'not found',
        ];

        yield 'needle is the full message' => [
            'TYPO3 encryption key is not set',
            'TYPO3 encryption key is not set',
        ];

        yield 'needle contains an unbalanced parenthesis' => [
            'Unknown encryptionAlgorithm marker (xchacha20 expected',
            'marker (xchacha20',
        ];

        yield 'needle contains a slash and a dollar sign' => [
            'Refusing to read $GLOBALS/TYPO3_CONF_VARS as a master key',
            '$GLOBALS/TYPO3_CONF_VARS',
        ];

        yield 'needle contains regex quantifiers and anchors' => [
            'Identifier must match ^[a-z0-9._-]+$ but did not',
            '^[a-z0-9._-]+$',
        ];
    }

    #[Test]
    #[DataProvider('messageProvider')]
    public function matchesTheSameMessagesAsAContainsCheck(string $thrown, string $needle): void
    {
        self::assertStringContainsString($needle, $thrown, 'provider is inconsistent');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageToContain($needle);

        throw new RuntimeException($thrown);
    }

    #[Test]
    public function treatsAnEmptyNeedleAsRequiringAnEmptyMessage(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageToContain('');

        throw new RuntimeException('');
    }
}
