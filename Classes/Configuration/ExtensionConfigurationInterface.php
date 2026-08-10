<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Configuration;

use Netresearch\NrVault\Configuration\Dto\AwsSecretsConfig;
use Netresearch\NrVault\Configuration\Dto\TransitConfig;
use Netresearch\NrVault\Configuration\Dto\VaultServerConfig;
use Netresearch\NrVault\Exception\ConfigurationException;

/**
 * Interface for extension configuration access.
 */
interface ExtensionConfigurationInterface
{
    /**
     * Get the configured security profile.
     *
     * @throws ConfigurationException if the configured value is not a valid
     *                                profile (fail-closed: an unknown profile
     *                                must never silently degrade to Standard)
     */
    public function getSecurityProfile(): SecurityProfile;

    /**
     * Get storage adapter identifier (local, hashicorp, aws).
     */
    public function getStorageAdapter(): string;

    /**
     * Get master key provider identifier (typo3, file, env, transit).
     */
    public function getMasterKeyProvider(): string;

    /**
     * Get master key source (file path for 'file', env var name for 'env').
     */
    public function getMasterKeySource(): string;

    /**
     * Get audit log retention days (0 = forever).
     */
    public function getAuditLogRetention(): int;

    /**
     * Check if CLI access is allowed.
     */
    public function isCliAccessAllowed(): bool;

    /**
     * Get backend groups that can access secrets via CLI.
     *
     * @return int[]
     */
    public function getCliAccessGroups(): array;

    /**
     * Operation permissions the unattributed CLI actor may hold when
     * `allowCliAccess` is on. High-risk operations are excluded by default
     * and must be opted into explicitly.
     *
     * @return list<string>
     */
    public function getCliAllowedOperations(): array;

    /**
     * UID of the technical backend user that `vault:store --as-provisioner`
     * enters via {@see TechnicalActorContextInterface::runAs()}.
     *
     * The alternative for an unattended deployment is `allowCliAccess`, which
     * grants the operation to every process holding a shell in that container.
     * A named actor narrows it to one identity that needs no admin flag —
     * a group carrying `tx_nrvault:secret.create` is enough — and makes every
     * write attributable in the audit log.
     *
     * Deliberately read from configuration rather than accepted as a command
     * argument: a flag taking a UID would be a general impersonation
     * primitive, strictly worse than the switch it replaces.
     *
     * @return int<0, max> 0 when no provisioning actor is configured
     */
    public function getProvisioningBeUserUid(): int;

    /**
     * Check if read operations should be written to the audit log.
     */
    public function isAuditReadsEnabled(): bool;

    /**
     * Is the unconditional admin / system-maintainer bypass disabled?
     *
     * Honours a `$TYPO3_CONF_VARS[SYS][nrVault][disableAdminOverride]`
     * filesystem override ahead of the BE-editable extension configuration, so
     * a compromised admin cannot re-enable their own bypass from the Settings
     * module.
     *
     * Reports the raw configuration. The flag only takes EFFECT in the
     * {@see SecurityProfile::Hardened} profile; pair this with
     * {@see self::getSecurityProfile()} to detect the "flag set while the
     * profile is standard" mismatch.
     */
    public function isAdminOverrideDisabled(): bool;

    /**
     * Does the CLI keep the pre-ADR-035 behaviour of resolving every
     * frontend-accessible `%vault(id)%` placeholder, whoever authored it?
     *
     * Off by default — the CLI enforces the same allow-set as a frontend
     * request. Honours a
     * `$TYPO3_CONF_VARS[SYS][nrVault][frontendPlaceholderLegacyCli]`
     * filesystem override ahead of the BE-editable extension configuration, so
     * a compromised admin cannot re-open the gate from the Settings module.
     */
    public function isFrontendPlaceholderLegacyCliEnabled(): bool;

    /**
     * Check if XChaCha20-Poly1305 should be preferred over AES-256-GCM.
     *
     * Only consulted for legacy (encryption version 1) envelopes without a
     * per-secret algorithm marker.
     */
    public function preferXChaCha20(): bool;

    /**
     * AEAD algorithm marker recorded for newly encrypted secrets.
     *
     * @return string An EncryptionAlgorithm backing value, or '' for the
     *                built-in default (XChaCha20-Poly1305)
     */
    public function getEncryptionAlgorithm(): string;

    /**
     * Get HashiCorp Vault configuration.
     */
    public function getHashiCorpConfig(): VaultServerConfig;

    /**
     * Get the HashiCorp Vault Transit master-key provider configuration.
     */
    public function getTransitConfig(): TransitConfig;

    /**
     * Get AWS Secrets Manager configuration.
     */
    public function getAwsConfig(): AwsSecretsConfig;

    /**
     * Get the audit HMAC epoch (0 = legacy SHA-256, 1+ = HMAC-SHA256).
     */
    public function getAuditHmacEpoch(): int;

    /**
     * Whether a missing audit chain tip anchor is an ERROR rather than a warning.
     *
     * Off by default: "never anchored" and "anchor deleted" look the same from
     * database state, so enabling it before the first audit write following the
     * upgrade would make every install report an invalid chain.
     */
    public function isAuditAnchorRequired(): bool;

    /**
     * Whether the syslog audit sink is enabled.
     */
    public function isAuditSinkSyslogEnabled(): bool;

    /**
     * `openlog()` ident for the syslog audit sink (never empty).
     */
    public function getAuditSinkSyslogIdent(): string;

    /**
     * Whether the append-only NDJSON file audit sink is enabled.
     */
    public function isAuditSinkFileEnabled(): bool;

    /**
     * Absolute path of the append-only NDJSON audit file.
     *
     * Never empty — an unconfigured value resolves to `<var>/log/`.
     */
    public function getAuditSinkFilePath(): string;

    /**
     * Absolute path of the append-only chain-tip anchor file.
     *
     * Never empty — an unconfigured value resolves to `<var>/log/`.
     */
    public function getAuditSinkAnchorPath(): string;

    /**
     * Whether the webhook audit sink is enabled.
     */
    public function isAuditSinkWebhookEnabled(): bool;

    /**
     * Endpoint the webhook audit sink POSTs to ('' = unconfigured).
     */
    public function getAuditSinkWebhookUrl(): string;

    /**
     * Hours after which the last successful external delivery of an enabled
     * sink counts as stale for the readiness surface (minimum 1).
     */
    public function getAuditSinkStaleDeliveryHours(): int;

    /**
     * Days after creation with zero reads before a secret is "dead".
     */
    public function getStaleNeverReadDays(): int;

    /**
     * Days since last read of any kind before a secret is "dead".
     */
    public function getStaleNotReadDays(): int;

    /**
     * Days since last rotation (or creation) before a secret is "never rotated".
     */
    public function getStaleNeverRotatedDays(): int;

    /**
     * Get the auto-generated key storage path (for development).
     */
    public function getAutoKeyPath(): string;
}
