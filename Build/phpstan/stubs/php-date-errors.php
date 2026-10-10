<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

/*
 * Analysis only: PHPStan runs on PHP 8.2 as well as newer runtimes, while
 * OAuthToken intentionally recognizes the PHP 8.3+ timestamp range error.
 * Model its real inheritance and inherited Error constructor for that older
 * analysis process. This is never loaded by TYPO3 or the PHPUnit bootstrap,
 * and every guard preserves the real internal classes on PHP 8.3+.
 *
 * https://www.php.net/manual/en/class.daterangeerror.php
 * https://www.php.net/manual/en/class.dateerror.php
 */
if (!class_exists('DateError', false)) {
    class DateError extends Error {}
}

if (!class_exists('DateRangeError', false)) {
    class DateRangeError extends DateError {}
}
