<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

/**
 * Bootstrap file for PHPUnit tests.
 */

// Ensure consistent timezone
date_default_timezone_set('UTC');

// Load Composer autoloader
$autoloadFile = __DIR__ . '/../.Build/vendor/autoload.php';
if (!file_exists($autoloadFile)) {
    $autoloadFile = dirname(__DIR__, 4) . '/vendor/autoload.php';
}

if (!file_exists($autoloadFile)) {
    throw new RuntimeException(
        'Could not find autoload.php. Please run "composer install" first.',
        5506203611,
    );
}

require_once $autoloadFile;

// TYPO3 v13+ defines the TYPO3 constant automatically via testing-framework bootstrap
