<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor\Check;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Service\Doctor\DocsLink;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\ReadinessCheckInterface;

/**
 * Is the profile a real profile, and do the toggles around it agree with it?
 *
 * A profile is a single coherent policy, not a bag of switches, which makes the
 * *mismatch* between a switch and the profile a finding in its own right. Both
 * directions mislead an operator, in opposite ways:
 *
 *  - `disableAdminOverride` set while the profile is `standard` reads like the
 *    override is gone. It is not: the flag is inert outside the hardened profile,
 *    so every admin still bypasses every gate while the configuration screen says
 *    otherwise. A control believed to be on is worse than one known to be off.
 *  - the `hardened` profile *without* `disableAdminOverride` is a genuine
 *    hardened deployment that kept its widest bypass. Defensible — the flag is a
 *    lockout risk, so it stays opt-in — but not something to discover during an
 *    audit.
 */
final readonly class SecurityProfileCheck implements ReadinessCheckInterface
{
    public function __construct(
        private ExtensionConfigurationInterface $configuration,
    ) {}

    public function getId(): string
    {
        return 'profile';
    }

    public function appliesTo(SecurityProfile $profile): bool
    {
        return true;
    }

    public function run(DoctorContext $context): array
    {
        return [
            $this->checkProfileValue(),
            $this->checkAdminOverrideConsistency($context),
        ];
    }

    /**
     * Is the configured profile string one the extension knows?
     *
     * `getSecurityProfile()` throws on an unknown value rather than degrading to
     * standard, so this check exists to turn that fail-closed exception into a
     * readable finding. It is the one control that must be evaluated even though
     * the doctor service already needed the profile to build the context — the
     * service falls back to standard silently so the rest of the report stays
     * readable, and this is where the operator is told that happened.
     */
    private function checkProfileValue(): Finding
    {
        $id = 'profile.valid';

        try {
            $profile = $this->configuration->getSecurityProfile();
        } catch (ConfigurationException $e) {
            return Finding::critical(
                id: $id,
                summary: 'The configured security profile is not a valid profile.',
                risk: 'Every code path that resolves the profile throws, which takes down secret '
                    . 'retrieval, the backend modules and the audit verifier. The extension refuses to '
                    . 'guess a profile rather than silently running a weaker policy than intended — so '
                    . 'this is an outage, not a degradation. Reported message: ' . $e->getMessage(),
                remediation: 'Set the "securityProfile" extension setting to exactly "standard" or '
                    . '"hardened".',
                docsUrl: DocsLink::SECURITY_PROFILES,
            );
        }

        return Finding::pass(
            id: $id,
            summary: \sprintf('Security profile "%s" is in force.', $profile->value),
            docsUrl: DocsLink::SECURITY_PROFILES,
            details: ['profile' => $profile->value],
        );
    }

    /**
     * Does the admin-override flag mean what the profile makes it mean?
     */
    private function checkAdminOverrideConsistency(DoctorContext $context): Finding
    {
        $id = 'profile.admin_override';
        $disabled = $this->configuration->isAdminOverrideDisabled();
        $details = [
            'disableAdminOverride' => $disabled,
            'profile' => $context->profile->value,
        ];

        if ($disabled && !$context->isHardened()) {
            return Finding::warning(
                id: $id,
                summary: 'disableAdminOverride is set, but it has no effect outside the hardened profile.',
                risk: 'The configuration reads as though the admin bypass were removed while every '
                    . 'administrator still holds every vault permission and read/write/delete on every '
                    . 'secret. An operator relying on this flag believes in a control that is not there.',
                remediation: 'Either switch "securityProfile" to "hardened" so the flag takes effect, or '
                    . 'clear "disableAdminOverride" so the configuration stops implying a control it does '
                    . 'not provide.',
                docsUrl: DocsLink::ADMIN_OVERRIDE,
                details: $details,
            );
        }

        if (!$disabled && $context->isHardened()) {
            return Finding::warning(
                id: $id,
                summary: 'The hardened profile is active but the admin override is still in place.',
                risk: 'Any administrator or system maintainer bypasses every operation permission and '
                    . 'every per-secret ACL. The granular permission model is advisory for them, so a '
                    . 'single compromised admin account reads the whole vault.',
                remediation: 'Pin disableAdminOverride in config/system/additional.php '
                    . '($GLOBALS[TYPO3_CONF_VARS][SYS][nrVault][disableAdminOverride] = true) so it '
                    . 'cannot be undone from the backend, and grant yourself the vault permissions you '
                    . 'need through a group first. Keep vault:break-glass available for lockout recovery.',
                docsUrl: DocsLink::ADMIN_OVERRIDE,
                details: $details,
            );
        }

        return Finding::pass(
            id: $id,
            summary: $disabled
                ? 'The admin override is disabled and the hardened profile makes that effective.'
                : 'The admin override is active, consistent with the standard profile.',
            docsUrl: DocsLink::ADMIN_OVERRIDE,
            details: $details,
        );
    }
}
