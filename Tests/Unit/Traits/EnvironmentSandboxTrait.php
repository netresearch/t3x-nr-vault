<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Traits;

use TYPO3\CMS\Core\Core\ApplicationContext;
use TYPO3\CMS\Core\Core\Environment;

/**
 * Gives a unit test a throwaway TYPO3 project layout and points
 * {@see Environment} at it.
 *
 * Needed by anything that resolves a path through `Environment::getVarPath()` or
 * checks a boundary against `Environment::getPublicPath()` — the audit file sink
 * and the extension-configuration path defaults. `Environment` is a static
 * singleton that the unit bootstrap leaves uninitialised, so those methods throw
 * a `TypeError` until something initialises it.
 *
 * A real directory rather than vfsStream: the consumers use `realpath()`, which
 * cannot resolve a stream-wrapper URL, so a virtual filesystem would force the
 * production code to be loosened to suit the test.
 *
 * It is also the only place allowed to call the `@internal`
 * `Environment::initialize()` (see the scoped exemption in `phpstan.neon`), so
 * anything a unit test needs from that singleton — including a specific
 * application context — goes through here rather than into the test itself.
 *
 * Usage: call `setUpEnvironmentSandbox()` from `setUp()` and
 * `tearDownEnvironmentSandbox()` from `tearDown()`.
 */
trait EnvironmentSandboxTrait
{
    private string $environmentSandbox = '';

    /**
     * Create `<sandbox>/{public,var,config}` and point Environment at it.
     *
     * `$applicationContext` exists for the checks that branch on
     * `Environment::getContext()->isProduction()`; the default keeps every other
     * consumer on the context a test process should report.
     */
    private function setUpEnvironmentSandbox(string $applicationContext = 'Testing'): void
    {
        $this->environmentSandbox = sys_get_temp_dir() . '/nr-vault-env-' . bin2hex(random_bytes(6));

        mkdir($this->environmentSandbox . '/public/fileadmin', 0o700, true);
        mkdir($this->environmentSandbox . '/var', 0o700, true);
        mkdir($this->environmentSandbox . '/config', 0o700, true);

        $this->initializeEnvironment(
            $this->environmentSandbox,
            $this->environmentSandbox . '/public',
            $this->environmentSandbox . '/var',
            $this->environmentSandbox . '/config',
            $applicationContext,
        );
    }

    /**
     * Switch the application context of an existing sandbox.
     *
     * For tests that need to observe both sides of an `isProduction()` branch
     * without standing up a second sandbox directory.
     */
    private function setEnvironmentApplicationContext(string $applicationContext): void
    {
        $this->initializeEnvironment(
            $this->environmentSandbox,
            $this->environmentSandbox . '/public',
            $this->environmentSandbox . '/var',
            $this->environmentSandbox . '/config',
            $applicationContext,
        );
    }

    /**
     * Remove the sandbox and re-point Environment at a path that still exists.
     *
     * Leaving the singleton referencing a deleted directory would give a later
     * test in the same process a confusing failure far from its cause.
     */
    private function tearDownEnvironmentSandbox(): void
    {
        $this->removeSandboxDirectory($this->environmentSandbox);
        $this->environmentSandbox = '';

        $fallback = sys_get_temp_dir();
        $this->initializeEnvironment($fallback, $fallback, $fallback, $fallback, 'Testing');
    }

    /**
     * Absolute path of the sandbox root ('' before setUp / after tearDown).
     */
    private function getEnvironmentSandboxPath(): string
    {
        return $this->environmentSandbox;
    }

    private function initializeEnvironment(
        string $projectPath,
        string $publicPath,
        string $varPath,
        string $configPath,
        string $applicationContext,
    ): void {
        Environment::initialize(
            new ApplicationContext($applicationContext),
            true,
            true,
            $projectPath,
            $publicPath,
            $varPath,
            $configPath,
            '',
            'UNIX',
        );
    }

    private function removeSandboxDirectory(string $directory): void
    {
        if ($directory === '' || !is_dir($directory)) {
            return;
        }

        $items = scandir($directory);
        if ($items === false) {
            return;
        }

        foreach ($items as $item) {
            if ($item === '.') {
                continue;
            }
            if ($item === '..') {
                continue;
            }
            $path = $directory . '/' . $item;
            if (is_dir($path)) {
                $this->removeSandboxDirectory($path);

                continue;
            }

            // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned temp path
            unlink($path);
        }

        rmdir($directory);
    }
}
