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
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration as Typo3ExtensionConfiguration;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\SingletonInterface;

/**
 * Extension configuration wrapper with typed accessors.
 */
final class ExtensionConfiguration implements ExtensionConfigurationInterface, SingletonInterface
{
    // Default values as constants for maintainability
    public const DEFAULT_SECURITY_PROFILE = 'standard';

    public const DEFAULT_STORAGE_ADAPTER = 'local';

    public const DEFAULT_MASTER_KEY_PROVIDER = 'typo3';

    public const DEFAULT_MASTER_KEY_SOURCE = 'NR_VAULT_MASTER_KEY';

    public const DEFAULT_AUDIT_LOG_RETENTION = 365;

    public const DEFAULT_ALLOW_CLI_ACCESS = false;

    public const DEFAULT_CACHE_ENABLED = true;

    public const DEFAULT_AUDIT_READS = true;

    public const DEFAULT_DISABLE_ADMIN_OVERRIDE = false;

    public const DEFAULT_PREFER_XCHACHA20 = false;

    /**
     * '' = use the built-in default (XChaCha20-Poly1305) for new secrets;
     * see EncryptionAlgorithm::forNewSecrets().
     */
    public const DEFAULT_ENCRYPTION_ALGORITHM = '';

    /**
     * Audit-chain hash epoch.
     *  - 0: legacy SHA-256 over identity fields only (no HMAC key).
     *  - 1: HMAC-SHA256 over identity fields only.
     *  - 2: HMAC-SHA256 over identity + forensic fields (success,
     *       error_message, reason, ip_address, user_agent, hash_before,
     *       hash_after, context).
     *  - 3: HMAC-SHA256 over the epoch-2 payload PLUS the algorithm selector
     *       (hmac_key_epoch) and the attribution fields (actor_type,
     *       actor_username, actor_role, request_id).
     *
     * Default 3 additionally binds the epoch selector into the chain — so a
     * DB-write attacker can no longer downgrade a row's hmac_key_epoch to the
     * keyless SHA-256 path and re-sign it without the HMAC key — and the
     * human-readable attribution columns, so blame can no longer be reassigned
     * on a row without breaking the chain. Existing epoch-0/1/2 entries
     * continue to verify under their stored epoch until
     * `AuditHmacMigrationWizard` rehashes them.
     */
    public const DEFAULT_AUDIT_HMAC_EPOCH = 3;

    public const DEFAULT_AUDIT_SINK_SYSLOG_ENABLED = false;

    public const DEFAULT_AUDIT_SINK_SYSLOG_IDENT = 'nr-vault';

    public const DEFAULT_AUDIT_SINK_FILE_ENABLED = false;

    /** Basename appended to `Environment::getVarPath() . '/log'` when no path is configured. */
    public const DEFAULT_AUDIT_SINK_FILE_BASENAME = 'nr-vault-audit.ndjson';

    /** Basename appended to `Environment::getVarPath() . '/log'` when no anchor path is configured. */
    public const DEFAULT_AUDIT_SINK_ANCHOR_BASENAME = 'nr-vault-audit-anchor.ndjson';

    public const DEFAULT_AUDIT_SINK_WEBHOOK_ENABLED = false;

    public const DEFAULT_AUDIT_SINK_WEBHOOK_URL = '';

    public const DEFAULT_STALE_NEVER_READ_DAYS = 30;

    public const DEFAULT_STALE_NOT_READ_DAYS = 90;

    public const DEFAULT_STALE_NEVER_ROTATED_DAYS = 180;

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
     * Get the configured security profile.
     *
     * Fail-closed: an unknown profile value throws instead of silently
     * degrading to Standard — a typo in a hardened deployment must never
     * weaken the effective policy.
     *
     * @throws ConfigurationException
     */
    public function getSecurityProfile(): SecurityProfile
    {
        $val = $this->configuration['securityProfile'] ?? self::DEFAULT_SECURITY_PROFILE;
        if (!\is_string($val) || $val === '') {
            $val = self::DEFAULT_SECURITY_PROFILE;
        }

        return SecurityProfile::tryFrom($val)
            ?? throw ConfigurationException::invalidSecurityProfile($val);
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
     * Get master key provider identifier (typo3, file, env, transit).
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
        return $this->pinnedOverride('auditReads')
            ?? (bool) ($this->configuration['auditReads'] ?? self::DEFAULT_AUDIT_READS);
    }

    /**
     * Is the admin / system-maintainer bypass disabled?
     *
     * Resolution order is identical to {@see self::isAuditReadsEnabled()} —
     * the `$TYPO3_CONF_VARS[SYS][nrVault][disableAdminOverride]` override wins
     * over the BE-editable extension configuration — and for the same reason,
     * only sharper here: a compromised admin must not be able to silently
     * re-enable their own bypass from the backend Settings module. Pin the
     * value in `config/system/additional.php` and the only way back is
     * filesystem access (or a time-boxed, audited break-glass session).
     *
     * The flag is only EFFECTIVE in the Hardened security profile — see
     * {@see \Netresearch\NrVault\Security\AccessControlService} for the
     * footgun-lockout rationale. This getter reports the raw configuration, so
     * a diagnostic tool can pair it with {@see self::getSecurityProfile()} and
     * report the "flag set but profile is standard" mismatch.
     */
    public function isAdminOverrideDisabled(): bool
    {
        return $this->pinnedOverride('disableAdminOverride')
            ?? (bool) ($this->configuration['disableAdminOverride'] ?? self::DEFAULT_DISABLE_ADMIN_OVERRIDE);
    }

    /**
     * Check if XChaCha20-Poly1305 should be preferred over AES-256-GCM.
     *
     * Only consulted for LEGACY (encryption version 1) envelopes, which carry
     * no per-secret algorithm marker. New envelopes record their algorithm
     * explicitly; see {@see self::getEncryptionAlgorithm()}.
     */
    public function preferXChaCha20(): bool
    {
        return (bool) ($this->configuration['preferXChaCha20'] ?? self::DEFAULT_PREFER_XCHACHA20);
    }

    /**
     * AEAD algorithm recorded for newly encrypted secrets.
     *
     * '' (default) = XChaCha20-Poly1305. Validation happens at the crypto
     * boundary (`EncryptionService::algorithmForNewSecrets()`), which fails
     * loudly on unknown or host-unavailable values.
     */
    public function getEncryptionAlgorithm(): string
    {
        $val = $this->configuration['encryptionAlgorithm'] ?? self::DEFAULT_ENCRYPTION_ALGORITHM;

        return \is_string($val) ? $val : self::DEFAULT_ENCRYPTION_ALGORITHM;
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
     * Whether the syslog audit sink is enabled.
     */
    public function isAuditSinkSyslogEnabled(): bool
    {
        return (bool) ($this->configuration['auditSinkSyslogEnabled'] ?? self::DEFAULT_AUDIT_SINK_SYSLOG_ENABLED);
    }

    /**
     * `openlog()` ident for the syslog audit sink.
     *
     * Falls back to the default for an empty or non-string value: an empty
     * ident makes syslog lines unattributable, which defeats the point of the
     * sink.
     */
    public function getAuditSinkSyslogIdent(): string
    {
        $val = $this->configuration['auditSinkSyslogIdent'] ?? null;
        if (!\is_string($val) || trim($val) === '') {
            return self::DEFAULT_AUDIT_SINK_SYSLOG_IDENT;
        }

        return trim($val);
    }

    /**
     * Whether the append-only NDJSON file audit sink is enabled.
     */
    public function isAuditSinkFileEnabled(): bool
    {
        return (bool) ($this->configuration['auditSinkFileEnabled'] ?? self::DEFAULT_AUDIT_SINK_FILE_ENABLED);
    }

    /**
     * Absolute path of the append-only NDJSON audit file.
     *
     * An unset/empty value resolves to `<var>/log/nr-vault-audit.ndjson`, which
     * is outside the public web root on every standard TYPO3 layout.
     */
    public function getAuditSinkFilePath(): string
    {
        return $this->resolveLogPath(
            $this->configuration['auditSinkFilePath'] ?? null,
            self::DEFAULT_AUDIT_SINK_FILE_BASENAME,
        );
    }

    /**
     * Absolute path of the append-only chain-tip anchor file.
     *
     * Deliberately a separate setting rather than a name derived from the
     * NDJSON path: the anchor file is the external evidence that survives a
     * full audit-table reset, so operators must be able to point it at a
     * different (ideally append-only or off-host) location than the bulk
     * entry stream.
     */
    public function getAuditSinkAnchorPath(): string
    {
        return $this->resolveLogPath(
            $this->configuration['auditSinkAnchorPath'] ?? null,
            self::DEFAULT_AUDIT_SINK_ANCHOR_BASENAME,
        );
    }

    /**
     * Whether the webhook audit sink is enabled.
     */
    public function isAuditSinkWebhookEnabled(): bool
    {
        return (bool) ($this->configuration['auditSinkWebhookEnabled'] ?? self::DEFAULT_AUDIT_SINK_WEBHOOK_ENABLED);
    }

    /**
     * Endpoint the webhook audit sink POSTs to ('' = unconfigured).
     */
    public function getAuditSinkWebhookUrl(): string
    {
        $val = $this->configuration['auditSinkWebhookUrl'] ?? self::DEFAULT_AUDIT_SINK_WEBHOOK_URL;

        return \is_string($val) ? trim($val) : self::DEFAULT_AUDIT_SINK_WEBHOOK_URL;
    }

    /**
     * Days after creation with zero reads before a secret is "dead".
     */
    public function getStaleNeverReadDays(): int
    {
        $val = $this->configuration['staleNeverReadDays'] ?? self::DEFAULT_STALE_NEVER_READ_DAYS;

        return is_numeric($val) ? (int) $val : self::DEFAULT_STALE_NEVER_READ_DAYS;
    }

    /**
     * Days since last read of any kind before a secret is "dead".
     */
    public function getStaleNotReadDays(): int
    {
        $val = $this->configuration['staleNotReadDays'] ?? self::DEFAULT_STALE_NOT_READ_DAYS;

        return is_numeric($val) ? (int) $val : self::DEFAULT_STALE_NOT_READ_DAYS;
    }

    /**
     * Days since last rotation (or creation) before a secret is "never rotated".
     */
    public function getStaleNeverRotatedDays(): int
    {
        $val = $this->configuration['staleNeverRotatedDays'] ?? self::DEFAULT_STALE_NEVER_ROTATED_DAYS;

        return is_numeric($val) ? (int) $val : self::DEFAULT_STALE_NEVER_ROTATED_DAYS;
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
     * Get the HashiCorp Vault Transit master-key provider configuration.
     *
     * Shares the `hashicorp.*` group with the (planned) storage adapter so an
     * installation configures the Vault address once. The wrapped-key path
     * falls back to the var path when unset, mirroring
     * {@see self::getAutoKeyPath()} for the file provider.
     */
    public function getTransitConfig(): TransitConfig
    {
        $config = $this->configuration['hashicorp'] ?? [];

        if (!\is_array($config)) {
            $config = [];
        }

        /** @var array{address?: string, authMethod?: string, token?: string, transitMount?: string, transitKeyName?: string, transitWrappedKeyPath?: string, tokenEnvVar?: string} $config */
        $configuredPath = \is_string($config['transitWrappedKeyPath'] ?? null)
            ? trim($config['transitWrappedKeyPath'])
            : '';

        // Resolve the var-path default lazily: it touches Environment, which an
        // explicitly configured path makes unnecessary.
        return TransitConfig::fromArray(
            $config,
            $configuredPath === '' ? $this->getTransitWrappedKeyPathDefault() : '',
        );
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

    /**
     * Resolve a configured audit-sink file path, falling back to
     * `<var>/log/<basename>` when unset or empty.
     *
     * Only whitespace is trimmed here; whether the resulting path is *safe*
     * (outside the public web root, writable) is decided by the sink, which is
     * the layer that can disable itself and report the reason.
     */
    private function resolveLogPath(mixed $configured, string $defaultBasename): string
    {
        if (\is_string($configured) && trim($configured) !== '') {
            return trim($configured);
        }

        return Environment::getVarPath() . '/log/' . $defaultBasename;
    }

    /**
     * Read a boolean setting pinned in
     * `$TYPO3_CONF_VARS[SYS][nrVault][<key>]` — typically set in
     * `LocalConfiguration.php` / `additional.php`, where it is NOT reachable
     * from the BE Settings module. (Other `ext_localconf.php` files can
     * technically write it too; treat the override as filesystem-bound only
     * when the rest of the bootstrap is trusted.)
     *
     * Returns null when the key is absent, so callers fall through to the
     * BE-editable extension configuration.
     */
    private function pinnedOverride(string $key): ?bool
    {
        $sys = \is_array($GLOBALS['TYPO3_CONF_VARS'] ?? null)
            && \is_array($GLOBALS['TYPO3_CONF_VARS']['SYS'] ?? null)
                ? $GLOBALS['TYPO3_CONF_VARS']['SYS'] : [];
        $nrVault = \is_array($sys['nrVault'] ?? null) ? $sys['nrVault'] : [];

        return \array_key_exists($key, $nrVault) ? (bool) $nrVault[$key] : null;
    }

    /**
     * Default location of the Vault-wrapped master key.
     *
     * The stored blob is Transit ciphertext (`vault:v1:…`), never key material,
     * so it lives next to the auto key path rather than in a separate store.
     */
    private function getTransitWrappedKeyPathDefault(): string
    {
        return $this->getAutoKeyPath() . '.transit';
    }
}
