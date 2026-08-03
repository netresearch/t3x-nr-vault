<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit;

use Netresearch\NrVault\Tests\Unit\Traits\BackendUserMockTrait;
use Netresearch\NrVault\Tests\Unit\Traits\ExceptionMessageExpectationTrait;
use Netresearch\NrVault\Tests\Unit\Traits\TcaSchemaMockTrait;
use TYPO3\TestingFramework\Core\Unit\UnitTestCase;

/**
 * Project base class for nr-vault unit tests.
 *
 * New unit tests SHOULD extend this class instead of
 * `TYPO3\TestingFramework\Core\Unit\UnitTestCase` (or PHPUnit's
 * `TestCase`) directly. The class is intentionally empty: its job is to
 *
 *  1. compose the shared helper traits (TCA schema mocks, backend-user
 *     mocks, exception-message expectations) so test authors opt in with
 *     one `extends` line rather than three `use` statements, and
 *  2. serve as a convention anchor for the architecture check run by
 *     `Tests/scripts/check-test-base-class.php`.
 *
 * Existing tests that still extend PHPUnit's `TestCase` or TYPO3's
 * `UnitTestCase` directly are tracked as technical debt and migrated in a
 * separate PR. See `Tests/AGENTS.md` for the rationale.
 */
abstract class TestCase extends UnitTestCase
{
    use BackendUserMockTrait;
    use ExceptionMessageExpectationTrait;
    use TcaSchemaMockTrait;
}
