<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor\Check;

use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\DocsLink;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\ReadinessCheckInterface;
use TYPO3\CMS\Core\Core\Environment;

/**
 * The TYPO3 installation around the vault.
 *
 * Two controls only, and that is the point. The vault sits inside a TYPO3
 * installation whose own settings can undo its protection — a revealed secret
 * travelling over plain HTTP is exposed regardless of how well it was encrypted
 * at rest — but a doctor that guesses at the host environment produces findings
 * an operator cannot act on and learns to ignore.
 *
 * So this check reads exactly two values that are unambiguous and locally
 * knowable: the application context and `[BE][lockSSL]`. Notably absent:
 *
 *  - a separate "secure cookie" control. TYPO3 derives the backend cookie's
 *    `secure` flag from `lockSSL`; there is no independent setting to read, so a
 *    second finding would report the same fact twice.
 *  - anything requiring an outbound request (real TLS termination, HSTS headers,
 *    reverse-proxy behaviour). Those are worth checking — by something that can
 *    actually see the edge, not by a CLI process behind it.
 */
final readonly class EnvironmentCheck implements ReadinessCheckInterface
{
    public function getId(): string
    {
        return 'environment';
    }

    public function appliesTo(SecurityProfile $profile): bool
    {
        return true;
    }

    public function run(DoctorContext $context): array
    {
        return [
            $this->checkApplicationContext($context),
            $this->checkBackendLockSsl(),
        ];
    }

    /**
     * Is the installation running in a Production context?
     *
     * Only a finding under the hardened profile, where it is a genuine
     * contradiction: a Development context enables verbose error output and
     * relaxes framework-level protections, so claiming a fail-closed audit-ready
     * posture from it is claiming something the environment does not support.
     * Under the standard profile a Development context is the normal state of a
     * developer machine and reporting it would be noise.
     */
    private function checkApplicationContext(DoctorContext $context): Finding
    {
        $id = 'environment.production_context';
        $applicationContext = (string) Environment::getContext();
        $isProduction = Environment::getContext()->isProduction();
        $details = ['applicationContext' => $applicationContext];

        if ($isProduction || !$context->isHardened()) {
            return Finding::pass(
                id: $id,
                summary: \sprintf('Application context is "%s".', $applicationContext),
                details: $details,
            );
        }

        return Finding::warning(
            id: $id,
            summary: \sprintf(
                'The hardened profile is active but the application context is "%s", not Production.',
                $applicationContext,
            ),
            risk: 'Non-production contexts show detailed errors and stack traces to the browser and relax '
                . 'framework protections. A stack trace from the crypto layer can name the master-key '
                . 'path; a hardened deployment is supposed to give an attacker nothing.',
            remediation: 'Set TYPO3_CONTEXT=Production on the production host. If this run is on a '
                . 'staging or developer machine, this finding is expected there and only the production '
                . 'run needs to pass.',
            docsUrl: DocsLink::DEPLOYMENT_GATE,
            details: $details,
        );
    }

    /**
     * Is the backend restricted to HTTPS?
     *
     * Profile-independent: the reveal endpoint returns plaintext secrets to a
     * browser, so an unencrypted backend session leaks them on the wire whatever
     * profile is configured.
     */
    private function checkBackendLockSsl(): Finding
    {
        $id = 'environment.backend_lock_ssl';

        if ($this->isBackendSslLocked()) {
            return Finding::pass(
                id: $id,
                summary: 'The TYPO3 backend is restricted to HTTPS ([BE][lockSSL] is set).',
                details: ['lockSSL' => true],
            );
        }

        return Finding::warning(
            id: $id,
            summary: 'The TYPO3 backend is not restricted to HTTPS ([BE][lockSSL] is not set).',
            risk: 'The reveal endpoint sends secret plaintext to the browser and the backend session '
                . 'cookie is not marked secure. On an unencrypted connection both are readable on the '
                . 'wire, which defeats the encryption at rest entirely.',
            remediation: 'Set $GLOBALS[TYPO3_CONF_VARS][BE][lockSSL] = true in '
                . 'config/system/settings.php once TLS terminates in front of the backend.',
            docsUrl: DocsLink::DEPLOYMENT_GATE,
            details: ['lockSSL' => false],
        );
    }

    /**
     * Is `$TYPO3_CONF_VARS[BE][lockSSL]` set?
     *
     * Read from `$GLOBALS` rather than injected because there is no service-shaped
     * accessor for core settings, and mirrors
     * {@see \Netresearch\NrVault\Configuration\ExtensionConfiguration} — an absent
     * or unexpectedly-shaped section reads as "not configured", which is the
     * direction that produces the finding rather than hiding it.
     */
    private function isBackendSslLocked(): bool
    {
        $confVars = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        if (!\is_array($confVars)) {
            return false;
        }

        $backend = $confVars['BE'] ?? null;
        if (!\is_array($backend)) {
            return false;
        }

        return (bool) ($backend['lockSSL'] ?? false);
    }
}
