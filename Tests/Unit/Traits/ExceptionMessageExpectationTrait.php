<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Traits;

use PHPUnit\Framework\TestCase;

/**
 * Substring expectation for exception messages that works on every supported
 * PHPUnit major.
 *
 * PHPUnit 13.2.0 soft-deprecated `expectExceptionMessage()` in favour of
 * `expectExceptionMessageIsOrContains()`
 * (<https://github.com/sebastianbergmann/phpunit/issues/6560>). The replacement
 * method does NOT exist before 13.2.0, and the CI matrix still resolves PHPUnit
 * 11.5 on PHP 8.2 and PHPUnit 12.5 on PHP 8.3, so calling it directly would be a
 * fatal error on half the supported cells.
 *
 * `expectExceptionMessageMatches()` has existed unchanged since PHPUnit 8.4 and
 * is available everywhere. Quoting the needle turns it into a literal, unanchored
 * search — which is exactly what `str_contains()` does inside PHPUnit's
 * `ExceptionMessageIsOrContains` constraint, on 11.5, 12.5 and 13.2 alike.
 *
 * Once the PHPUnit floor is >= 13.2 this trait can be reduced to a forward to
 * `expectExceptionMessageIsOrContains()`, or deleted after inlining it.
 *
 * @phpstan-require-extends TestCase
 */
trait ExceptionMessageExpectationTrait
{
    /**
     * Expect the raised exception's message to contain `$message` verbatim.
     *
     * Drop-in replacement for the deprecated `expectExceptionMessage()`,
     * including its treatment of the empty needle: PHPUnit reads that not as
     * "matches anything" but as "the message must itself be empty".
     */
    protected function expectExceptionMessageToContain(string $message): void
    {
        if ($message === '') {
            $this->expectExceptionMessageMatches('/^$/D');

            return;
        }

        $this->expectExceptionMessageMatches('/' . \preg_quote($message, '/') . '/');
    }
}
