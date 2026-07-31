<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Traits;

/**
 * Points the NDJSON audit sink at a throwaway directory outside the test instance.
 *
 * Outside on purpose: the functional test instance uses the LEGACY layout, where
 * `Environment::getVarPath()` resolves to `<publicPath>/typo3temp/var` — inside
 * the public web root, which
 * {@see \Netresearch\NrVault\Audit\Sink\JsonFileAuditSink} refuses because it
 * would publish the audit trail over HTTP. A path under the system temp directory
 * reproduces the Composer-based production layout these tests need to exercise.
 *
 * Usage: call `prepareAuditSinkSandbox()` BEFORE `parent::setUp()` (so the paths
 * land in `$this->extensionConfiguration` before the singleton is built) and
 * `cleanUpAuditSinkSandbox()` in `tearDown()`.
 */
trait AuditSinkSandboxTrait
{
    private string $auditSinkDirectory = '';

    private string $auditSinkAnchorPath = '';

    private string $auditSinkEntryPath = '';

    /**
     * Register the sandbox paths in the extension configuration under test.
     *
     * @param array<string, mixed> $extensionConfiguration Existing configuration to extend
     *
     * @return array<string, mixed> Configuration with the sink keys added
     */
    private function prepareAuditSinkSandbox(array $extensionConfiguration, bool $enableFileSink = true): array
    {
        $this->auditSinkDirectory = sys_get_temp_dir() . '/nr-vault-sink-' . bin2hex(random_bytes(6));
        $this->auditSinkAnchorPath = $this->auditSinkDirectory . '/anchor.ndjson';
        $this->auditSinkEntryPath = $this->auditSinkDirectory . '/entries.ndjson';

        $extensionConfiguration['auditSinkFileEnabled'] = $enableFileSink ? 1 : 0;
        $extensionConfiguration['auditSinkFilePath'] = $this->auditSinkEntryPath;
        $extensionConfiguration['auditSinkAnchorPath'] = $this->auditSinkAnchorPath;

        return $extensionConfiguration;
    }

    private function cleanUpAuditSinkSandbox(): void
    {
        if ($this->auditSinkDirectory === '' || !is_dir($this->auditSinkDirectory)) {
            return;
        }

        $files = glob($this->auditSinkDirectory . '/*');
        foreach ($files === false ? [] : $files as $file) {
            // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned temp path
            unlink($file);
        }

        rmdir($this->auditSinkDirectory);
        $this->auditSinkDirectory = '';
    }
}
