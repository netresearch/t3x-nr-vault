<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Configuration;

use Netresearch\NrVault\Configuration\Dto\AwsSecretsConfig;
use Netresearch\NrVault\Configuration\Dto\VaultServerConfig;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration as Typo3ExtensionConfiguration;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\SingletonInterface;

/**
 * Extension configuration wrapper with typed accessors.
 */
final class ExtensionConfiguration implements ExtensionConfigurationInterface, SingletonInterface
{
    // Default values as constants for maintainability
    public const DEFAULT_STORAGE_ADAPTER = 'local';

    public const DEFAULT_MASTER_KEY_PROVIDER = 'typo3';

    public const DEFAULT_MASTER_KEY_SOURCE = 'NR_VAULT_MASTER_KEY';

    public const DEFAULT_AUDIT_LOG_RETENTION = 365;

    public const DEFAULT_ALLOW_CLI_ACCESS = false;

    public const DEFAULT_CACHE_ENABLED = true;

    public const DEFAULT_AUDIT_READS = true;

    public const DEFAULT_PREFER_XCHACHA20 = false;

    public const DEFAULT_AUDIT_HMAC_EPOCH = 1;

    private const EXTENSION_KEY = 'nr_vault';

    /** @var array<string, mixed> */
    private array $configuration;

    public function __construct(
        private readonly Typo3ExtensionConfiguration $extensionConfiguration,
    ) {
        $config = $this->extensionConfiguration->get(self::EXTENSION_KEY);
        /** @var array<string, mixed> $configArray */
        $configArray = \is_array($config) ? $config : [];
        $this->configuration = $configArray;
    }

    /**
     * Get storage adapter identifier (local, hashicorp, aws).
     */
    public function getStorageAdapter(): string
    {
        $val = $this->configuration['storageAdapter'] ?? self::DEFAULT_STORAGE_ADAPTER;

        return \is_string($val) ? $val : self::DEFAULT_STORAGE_ADAPTER;
    }

    /**
     * Get master key provider identifier (typo3, file, env, derived).
     */
    public function getMasterKeyProvider(): string
    {
        $val = $this->configuration['masterKeyProvider'] ?? self::DEFAULT_MASTER_KEY_PROVIDER;

        return \is_string($val) ? $val : self::DEFAULT_MASTER_KEY_PROVIDER;
    }

    /**
     * Get master key source (file path for 'file', env var name for 'env').
     */
    public function getMasterKeySource(): string
    {
        $val = $this->configuration['masterKeySource'] ?? self::DEFAULT_MASTER_KEY_SOURCE;

        return \is_string($val) ? $val : self::DEFAULT_MASTER_KEY_SOURCE;
    }

    /**
     * Get audit log retention days (0 = forever).
     */
    public function getAuditLogRetention(): int
    {
        $val = $this->configuration['auditLogRetention'] ?? self::DEFAULT_AUDIT_LOG_RETENTION;

        return is_numeric($val) ? (int) $val : self::DEFAULT_AUDIT_LOG_RETENTION;
    }

    /**
     * Check if CLI access is allowed.
     */
    public function isCliAccessAllowed(): bool
    {
        return (bool) ($this->configuration['allowCliAccess'] ?? self::DEFAULT_ALLOW_CLI_ACCESS);
    }

    /**
     * Get backend groups that can access secrets via CLI.
     *
     * @return int[]
     */
    public function getCliAccessGroups(): array
    {
        $groups = $this->configuration['cliAccessGroups'] ?? [];
        if (\is_string($groups)) {
            return array_filter(array_map(
                static fn (string $v): int => (int) trim($v),
                explode(',', $groups),
            ));
        }

        if (\is_array($groups)) {
            return array_map(
                static fn (mixed $v): int => is_numeric($v) ? (int) $v : 0,
                $groups,
            );
        }

        return [];
    }

    /**
     * Check if request-scoped caching is enabled.
     */
    public function isCacheEnabled(): bool
    {
        return (bool) ($this->configuration['cacheEnabled'] ?? self::DEFAULT_CACHE_ENABLED);
    }

    /**
     * Check if read operations should be written to the audit log.
     *
     * Resolution order:
     *  1. `$TYPO3_CONF_VARS[SYS][nrVault][auditReads]` config override — typically
     *     set in `LocalConfiguration.php` / `additional.php`, where it is NOT
     *     reachable from the BE Settings module. (Other `ext_localconf.php`
     *     files can technically write it too; treat the override as
     *     filesystem-bound only when the rest of the bootstrap is trusted.)
     *  2. The standard `auditReads` extension configuration (default 1).
     *
     * The override exists so that production operators can pin the value out
     * of admin reach: a compromised admin would otherwise be able to silence
     * read logging via the BE Settings module without leaving an audit trail.
     */
    public function isAuditReadsEnabled(): bool
    {
        $sys = \is_array($GLOBALS['TYPO3_CONF_VARS'] ?? null)
            && \is_array($GLOBALS['TYPO3_CONF_VARS']['SYS'] ?? null)
                ? $GLOBALS['TYPO3_CONF_VARS']['SYS'] : [];
        $nrVault = \is_array($sys['nrVault'] ?? null) ? $sys['nrVault'] : [];
        if (\array_key_exists('auditReads', $nrVault)) {
            return (bool) $nrVault['auditReads'];
        }

        return (bool) ($this->configuration['auditReads'] ?? self::DEFAULT_AUDIT_READS);
    }

    /**
     * Check if XChaCha20-Poly1305 should be preferred over AES-256-GCM.
     */
    public function preferXChaCha20(): bool
    {
        return (bool) ($this->configuration['preferXChaCha20'] ?? self::DEFAULT_PREFER_XCHACHA20);
    }

    /**
     * Get the audit HMAC epoch (0 = legacy SHA-256, 1+ = HMAC-SHA256).
     */
    public function getAuditHmacEpoch(): int
    {
        $val = $this->configuration['auditHmacEpoch'] ?? self::DEFAULT_AUDIT_HMAC_EPOCH;

        return is_numeric($val) ? (int) $val : self::DEFAULT_AUDIT_HMAC_EPOCH;
    }

    /**
     * Get HashiCorp Vault configuration.
     */
    public function getHashiCorpConfig(): VaultServerConfig
    {
        $config = $this->configuration['hashicorp'] ?? [];

        if (!\is_array($config)) {
            return new VaultServerConfig();
        }

        /** @var array{address?: string, path?: string, authMethod?: string, token?: string} $config */
        return VaultServerConfig::fromArray($config);
    }

    /**
     * Get AWS Secrets Manager configuration.
     */
    public function getAwsConfig(): AwsSecretsConfig
    {
        $config = $this->configuration['aws'] ?? [];

        if (!\is_array($config)) {
            return new AwsSecretsConfig();
        }

        /** @var array{region?: string, secretPrefix?: string} $config */
        return AwsSecretsConfig::fromArray($config);
    }

    /**
     * Get the auto-generated key storage path (for development).
     */
    public function getAutoKeyPath(): string
    {
        return Environment::getVarPath() . '/secrets/vault-master.key';
    }
}
