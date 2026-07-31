<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Traits;

/**
 * Runs a callable with PHP's diagnostics silenced.
 *
 * Needed where production code deliberately handles a native failure by
 * inspecting the RETURN value rather than by suppressing the diagnostic: the
 * audit sinks avoid `@` (the project's PHPStan ruleset forbids it) and instead
 * check `fopen()`/`mkdir()` for `false` while normalising the throwing variant a
 * host error handler would produce. Exercising the false-return branch therefore
 * emits a genuine PHP warning, which PHPUnit escalates into a failing test under
 * `failOnWarning`.
 *
 * Suppressing it here keeps the assertion on the behaviour under test (which
 * exception the sink raises) instead of on the host's error-reporting
 * configuration. Use it ONLY around the single call that is expected to warn.
 */
trait ErrorSuppressionTrait
{
    /**
     * @template TReturn
     *
     * @param callable(): TReturn $callback
     *
     * @return TReturn
     */
    private function withoutPhpDiagnostics(callable $callback): mixed
    {
        set_error_handler(static fn (): bool => true);

        try {
            return $callback();
        } finally {
            restore_error_handler();
        }
    }
}
