<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service;

use Doctrine\DBAL\Exception as DbalException;
use Doctrine\DBAL\Types\BlobType;
use Doctrine\DBAL\Types\StringType;
use Doctrine\DBAL\Types\TextType;
use Exception;
use Netresearch\NrVault\Service\Detection\ConfigSecretFinding;
use Netresearch\NrVault\Service\Detection\DatabaseSecretFinding;
use Netresearch\NrVault\Service\Detection\SecretFinding;
use Netresearch\NrVault\Service\Detection\Severity;
use Netresearch\NrVault\Utility\IdentifierValidator;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Configuration\Exception\ExtensionConfigurationExtensionNotConfiguredException;
use TYPO3\CMS\Core\Configuration\Exception\ExtensionConfigurationPathDoesNotExistException;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Package\PackageManager;

/**
 * Service for detecting potential plaintext secrets in the TYPO3 installation.
 *
 * Scans database columns, extension configuration, and LocalConfiguration
 * for values that appear to be unencrypted secrets based on naming patterns
 * and known API key formats.
 */
final class SecretDetectionService implements SecretDetectionServiceInterface
{
    /**
     * Table.column combinations that should be excluded (contain hashes, not secrets).
     *
     * @var array<string>
     */
    private const EXCLUDED_COLUMNS = [
        'be_users.password',    // Contains password hashes (bcrypt/argon2)
        'fe_users.password',    // Contains password hashes (bcrypt/argon2)
    ];

    /**
     * Column name patterns that typically contain secrets.
     *
     * @var array<string>
     */
    private const COLUMN_NAME_PATTERNS = [
        '/password$/i',
        '/^password/i',
        '/api[_-]?key$/i',
        '/api[_-]?secret$/i',
        '/secret[_-]?key$/i',
        '/secret$/i',
        '/token$/i',
        '/access[_-]?token$/i',
        '/refresh[_-]?token$/i',
        '/auth[_-]?token$/i',
        '/credential/i',
        '/private[_-]?key$/i',
        '/encryption[_-]?key$/i',
        '/smtp[_-]?password$/i',
        '/db[_-]?password$/i',
        '/database[_-]?password$/i',
    ];

    /**
     * Value patterns that indicate known API key formats.
     *
     * @var array<string, string>
     */
    private const VALUE_PATTERNS = [
        'Stripe live key' => '/^sk_live_[a-zA-Z0-9]{24,}$/',
        'Stripe test key' => '/^sk_test_[a-zA-Z0-9]{24,}$/',
        'Stripe publishable live' => '/^pk_live_[a-zA-Z0-9]{24,}$/',
        'Stripe publishable test' => '/^pk_test_[a-zA-Z0-9]{24,}$/',
        'AWS Access Key' => '/^AKIA[0-9A-Z]{16}$/',
        'GitHub Personal Access Token' => '/^ghp_[a-zA-Z0-9]{36}$/',
        'GitHub OAuth Token' => '/^gho_[a-zA-Z0-9]{36}$/',
        'GitHub App Token' => '/^ghu_[a-zA-Z0-9]{36}$/',
        'GitHub Refresh Token' => '/^ghr_[a-zA-Z0-9]{36}$/',
        'Slack Bot Token' => '/^xoxb-\d{10,13}-\d{10,13}-[a-zA-Z0-9]{24}$/',
        'Slack User Token' => '/^xoxp-\d{10,13}-\d{10,13}-[a-zA-Z0-9]{24}$/',
        'Slack App Token' => '/^xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+$/',
        'Google API Key' => '/^AIza[0-9A-Za-z_-]{35}$/',
        'Mailchimp API Key' => '/^[a-f0-9]{32}-us\d{1,2}$/',
        'SendGrid API Key' => '/^SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}$/',
        'Twilio Auth Token' => '/^[a-f0-9]{32}$/',
        'PayPal Client Secret' => '/^E[A-Za-z0-9_-]{50,80}$/',
        'JWT Token' => '/^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/',
    ];

    /**
     * Patterns for extension configuration keys that typically contain secrets.
     * Uses regex with word boundaries to avoid false positives like "secretPrefix".
     *
     * @var array<string>
     */
    private const EXT_CONFIG_KEY_PATTERNS = [
        '/password$/i',           // ends with "password" (smtpPassword, dbPassword)
        '/^password$/i',          // exactly "password"
        '/secret$/i',             // ends with "secret" (apiSecret, clientSecret) - NOT "secretPrefix"
        '/token$/i',              // ends with "token" (accessToken, authToken)
        '/apiKey$/i',             // ends with "apiKey"
        '/privateKey$/i',         // ends with "privateKey"
        '/encryptionKey$/i',      // ends with "encryptionKey"
        '/credential/i',          // contains "credential"
    ];

    /** @var array<string, SecretFinding> */
    private array $detectedSecrets = [];

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly PackageManager $packageManager,
        private readonly ExtensionConfiguration $extensionConfiguration,
        private readonly LoggerInterface $logger,
    ) {}

    /**
     * Scan for potential plaintext secrets across all sources.
     *
     * @param array<string> $excludeTables Tables to exclude from scanning
     *
     * @return array<string, SecretFinding>
     */
    public function scan(array $excludeTables = []): array
    {
        $this->detectedSecrets = [];

        $this->scanDatabaseTables($excludeTables);
        $this->scanExtensionConfiguration();
        $this->scanLocalConfiguration();

        return $this->detectedSecrets;
    }

    /**
     * Scan database tables for columns that might contain secrets.
     *
     * @param array<string> $excludeTables Tables to exclude
     */
    public function scanDatabaseTables(array $excludeTables = []): void
    {
        $defaultExclusions = [
            'tx_nrvault_secret',
            'tx_nrvault_audit_log',
            'be_sessions',
            'fe_sessions',
            'cache_*',
            'cf_*',
            'sys_log',
            'sys_history',
        ];

        $excludeTables = array_merge($defaultExclusions, $excludeTables);

        try {
            $connection = $this->connectionPool->getConnectionByName('Default');
            $schemaManager = $connection->createSchemaManager();
            $tables = $schemaManager->listTableNames();

            foreach ($tables as $tableName) {
                if ($this->isTableExcluded($tableName, $excludeTables)) {
                    continue;
                }

                $this->scanTable($tableName);
            }
        } catch (DbalException $e) {
            $this->logger->warning('Secret detection: database scan failed', [
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Scan extension configuration for potential secrets.
     */
    public function scanExtensionConfiguration(): void
    {
        foreach ($this->packageManager->getActivePackages() as $package) {
            $extKey = $package->getPackageKey();

            try {
                $config = $this->extensionConfiguration->get($extKey);
                if (\is_array($config)) {
                    /** @var array<string, mixed> $configArray */
                    $configArray = $config;
                    $this->scanConfigArray($configArray, "extension:{$extKey}");
                }
            } catch (ExtensionConfigurationExtensionNotConfiguredException|ExtensionConfigurationPathDoesNotExistException) {
                // Extension has no configuration - skip
            } catch (Exception $e) {
                $this->logger->warning('Failed to scan extension configuration', [
                    'extension' => $extKey,
                    'error' => $e->getMessage(),
                ]);
            }
        }
    }

    /**
     * Scan LocalConfiguration for potential secrets.
     */
    public function scanLocalConfiguration(): void
    {
        if (!isset($GLOBALS['TYPO3_CONF_VARS'])) {
            return;
        }

        /** @var array<string, mixed> $typo3ConfVars */
        $typo3ConfVars = $GLOBALS['TYPO3_CONF_VARS'];

        // Check MAIL configuration
        /** @var array<string, mixed> $mailConfig */
        $mailConfig = \is_array($typo3ConfVars['MAIL'] ?? null) ? $typo3ConfVars['MAIL'] : [];
        $smtpPassword = $mailConfig['transport_smtp_password'] ?? '';
        if (\is_string($smtpPassword) && $smtpPassword !== '' && !IdentifierValidator::looksLikeVaultIdentifier($smtpPassword)) {
            $finding = new ConfigSecretFinding(
                path: 'MAIL.transport_smtp_password',
                severity: Severity::High,
                isLocalConfiguration: true,
            );
            $this->detectedSecrets[$finding->getKey()] = $finding;
        }

        // Check SYS encryptionKey if it looks weak
        /** @var array<string, mixed> $sysConfig */
        $sysConfig = \is_array($typo3ConfVars['SYS'] ?? null) ? $typo3ConfVars['SYS'] : [];
        $encryptionKey = $sysConfig['encryptionKey'] ?? '';
        if (\is_string($encryptionKey) && $encryptionKey !== '' && \strlen($encryptionKey) < 32) {
            $finding = new ConfigSecretFinding(
                path: 'SYS.encryptionKey',
                severity: Severity::Medium,
                isLocalConfiguration: true,
                message: 'Encryption key appears too short (< 32 characters)',
            );
            $this->detectedSecrets[$finding->getKey()] = $finding;
        }

        // Note: Extension configuration is already scanned in scanExtensionConfiguration()
        // which properly applies EXCLUDED_EXTENSIONS filter. Do not duplicate here.
    }

    /**
     * Get detected secrets grouped by severity.
     *
     * @return array<string, array<string, SecretFinding>>
     */
    public function getDetectedSecretsBySeverity(): array
    {
        $grouped = [
            Severity::Critical->value => [],
            Severity::High->value => [],
            Severity::Medium->value => [],
            Severity::Low->value => [],
        ];

        foreach ($this->detectedSecrets as $key => $finding) {
            $grouped[$finding->getSeverity()->value][$key] = $finding;
        }

        return $grouped;
    }

    /**
     * Get total count of detected secrets.
     */
    public function getDetectedSecretsCount(): int
    {
        return \count($this->detectedSecrets);
    }

    /**
     * Scan a specific table for secret columns.
     */
    private function scanTable(string $tableName): void
    {
        try {
            $connection = $this->connectionPool->getConnectionByName('Default');
            $schemaManager = $connection->createSchemaManager();
            $columns = $schemaManager->listTableColumns($tableName);

            foreach ($columns as $column) {
                /** @phpstan-ignore method.internalClass */
                $columnName = $column->getName();
                $columnType = $column->getType();

                // Only check string-type columns (DBAL 4.x removed Type::getName())
                if (!($columnType instanceof StringType)
                    && !($columnType instanceof TextType)
                    && !($columnType instanceof BlobType)) {
                    continue;
                }

                // Skip known hash columns (e.g., be_users.password, fe_users.password)
                if (\in_array("{$tableName}.{$columnName}", self::EXCLUDED_COLUMNS, true)) {
                    continue;
                }

                if ($this->isSecretColumn($columnName)) {
                    $this->analyzeTableColumn($tableName, $columnName);
                }
            }
        } catch (DbalException $e) {
            $this->logger->warning('Secret detection: failed to scan table', [
                'table' => $tableName,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Analyze a table column for plaintext secrets.
     */
    private function analyzeTableColumn(string $tableName, string $columnName): void
    {
        try {
            $queryBuilder = $this->connectionPool->getQueryBuilderForTable($tableName);

            // Count non-empty values
            $count = $queryBuilder
                ->count('uid')
                ->from($tableName)
                ->where(
                    $queryBuilder->expr()->isNotNull($columnName),
                    $queryBuilder->expr()->neq($columnName, $queryBuilder->createNamedParameter('')),
                )
                ->executeQuery()
                ->fetchOne();

            if ($count > 0) {
                // Check if values look encrypted (vault identifiers or encrypted blobs)
                $sampleQuery = $this->connectionPool->getQueryBuilderForTable($tableName);
                $samples = $sampleQuery
                    ->select($columnName)
                    ->from($tableName)
                    ->where(
                        $sampleQuery->expr()->isNotNull($columnName),
                        $sampleQuery->expr()->neq($columnName, $sampleQuery->createNamedParameter('')),
                    )
                    ->setMaxResults(5)
                    ->executeQuery()
                    ->fetchAllAssociative();

                [$plaintextCount, $patterns] = $this->matchPattern($samples, $columnName);

                if ($plaintextCount > 0) {
                    $recordCount = is_numeric($count) ? (int) $count : 0;
                    $finding = new DatabaseSecretFinding(
                        table: $tableName,
                        column: $columnName,
                        recordCount: $recordCount,
                        plaintextCount: $plaintextCount,
                        severity: $this->calculateSeverity($columnName, array_keys($patterns)),
                        patterns: array_keys($patterns),
                    );
                    $this->detectedSecrets[$finding->getKey()] = $finding;
                }
            }
        } catch (DbalException $e) {
            $this->logger->warning('Secret detection: failed to analyze column', [
                'table' => $tableName,
                'column' => $columnName,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Inspect sampled column values, skipping vault identifiers and encrypted blobs.
     *
     * @param array<int, array<string, mixed>> $samples
     *
     * @return array{int, array<string, true>} Plaintext count and detected patterns keyed by name
     */
    private function matchPattern(array $samples, string $columnName): array
    {
        $plaintextCount = 0;
        $patterns = [];

        foreach ($samples as $row) {
            $rawValue = $row[$columnName] ?? '';
            $value = \is_string($rawValue) || is_numeric($rawValue) ? (string) $rawValue : '';

            // Skip if it looks like a vault identifier
            if (IdentifierValidator::looksLikeVaultIdentifier($value)) {
                continue;
            }

            // Skip if it looks already encrypted
            if ($this->looksEncrypted($value)) {
                continue;
            }

            // Check for known patterns
            $detectedPattern = $this->detectValuePattern($value);
            if ($detectedPattern !== null) {
                $patterns[$detectedPattern] = true;
            }

            ++$plaintextCount;
        }

        return [$plaintextCount, $patterns];
    }

    /**
     * Recursively scan a configuration array for secret keys.
     *
     * @param array<string, mixed> $config Configuration array
     * @param string $prefix Path prefix for keys
     */
    private function scanConfigArray(array $config, string $prefix): void
    {
        foreach ($config as $key => $value) {
            if (\is_array($value)) {
                /** @var array<string, mixed> $valueArray */
                $valueArray = $value;
                $this->scanConfigArray($valueArray, "{$prefix}.{$key}");
                continue;
            }
            if (!\is_string($value)) {
                continue;
            }
            if ($value === '') {
                continue;
            }

            // Check if key name suggests a secret
            if ($this->isSecretConfigKey($key)) {
                // Skip vault references
                if (IdentifierValidator::looksLikeVaultIdentifier($value)) {
                    continue;
                }

                $detectedPattern = $this->detectValuePattern($value);
                $patterns = $detectedPattern !== null ? [$detectedPattern] : [];

                $finding = new ConfigSecretFinding(
                    path: "{$prefix}.{$key}",
                    severity: $this->calculateSeverity($key, $patterns),
                    isLocalConfiguration: false,
                    patterns: $patterns,
                );
                $this->detectedSecrets[$finding->getKey()] = $finding;
            }
        }
    }

    /**
     * Check if a column name matches secret patterns.
     */
    private function isSecretColumn(string $columnName): bool
    {
        foreach (self::COLUMN_NAME_PATTERNS as $pattern) {
            if (preg_match($pattern, $columnName) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a config key matches secret patterns.
     * Uses regex to match suffixes/patterns, avoiding false positives like "secretPrefix".
     */
    private function isSecretConfigKey(string $key): bool
    {
        foreach (self::EXT_CONFIG_KEY_PATTERNS as $pattern) {
            if (preg_match($pattern, $key) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a table should be excluded from scanning.
     *
     * @param string $tableName Table name
     * @param array<string> $excludePatterns Patterns to exclude
     */
    private function isTableExcluded(string $tableName, array $excludePatterns): bool
    {
        foreach ($excludePatterns as $pattern) {
            if (str_contains($pattern, '*')) {
                // Quote all special chars first, then replace escaped \* with .*
                $quotedPattern = preg_quote($pattern, '/');
                $regex = '/^' . str_replace('\\*', '.*', $quotedPattern) . '$/';
                if (preg_match($regex, $tableName)) {
                    return true;
                }
            } elseif ($tableName === $pattern) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a value looks already encrypted or is a password hash.
     */
    private function looksEncrypted(string $value): bool
    {
        // Check for bcrypt hash ($2y$, $2a$, $2b$)
        if (preg_match('/^\$2[yab]\$\d{2}\$[.\/A-Za-z0-9]{53}$/', $value)) {
            return true;
        }

        // Check for Argon2 hash ($argon2i$, $argon2id$)
        if (str_starts_with($value, '$argon2i$') || str_starts_with($value, '$argon2id$')) {
            return true;
        }

        // Check for base64-encoded encrypted data (typically >= 80 chars, high entropy)
        if (\strlen($value) >= 80 && preg_match('/^[A-Za-z0-9+\/]{40,}={0,2}$/', $value)) {
            return true;
        }

        // Check for hex-encoded data (require longer length to reduce false positives)
        return \strlen($value) >= 80 && preg_match('/^[0-9a-f]+$/i', $value);
    }

    /**
     * Detect if a value matches known API key patterns.
     */
    private function detectValuePattern(string $value): ?string
    {
        $trimmed = trim($value);
        foreach (self::VALUE_PATTERNS as $name => $pattern) {
            if (preg_match($pattern, $trimmed)) {
                return $name;
            }
        }

        return null;
    }

    /**
     * Calculate severity based on column/key name and detected patterns.
     *
     * @param string $name Column or config key name
     * @param array<string> $patterns Detected value patterns
     */
    private function calculateSeverity(string $name, array $patterns): Severity
    {
        $nameLower = strtolower($name);

        // Critical: Known API key patterns detected
        if ($patterns !== []) {
            return Severity::Critical;
        }

        // High: Password or private key fields
        if (str_contains($nameLower, 'password')
            || str_contains($nameLower, 'private')
            || str_contains($nameLower, 'secret')) {
            return Severity::High;
        }

        // Medium: Token or API key fields
        if (str_contains($nameLower, 'token')
            || str_contains($nameLower, 'apikey')
            || str_contains($nameLower, 'api_key')) {
            return Severity::Medium;
        }

        return Severity::Low;
    }
}
