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
