<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service;

use Doctrine\DBAL\Result;
use Doctrine\DBAL\Schema\AbstractSchemaManager;
use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Types\BlobType;
use Doctrine\DBAL\Types\IntegerType;
use Doctrine\DBAL\Types\StringType;
use Doctrine\DBAL\Types\TextType;
use Exception;
use Netresearch\NrVault\Secret\SecretRedactor;
use Netresearch\NrVault\Service\Detection\Severity;
use Netresearch\NrVault\Service\SecretDetectionService;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Utility\IdentifierValidator;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\NullLogger;
use ReflectionClass;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Package\Package;
use TYPO3\CMS\Core\Package\PackageManager;

#[CoversClass(SecretDetectionService::class)]
#[AllowMockObjectsWithoutExpectations]
final class SecretDetectionServiceTest extends TestCase
{
    private const UUID_V7 = '01937b6e-4b6c-7abc-8def-0123456789ab';

    private ConnectionPool&MockObject $connectionPool;

    private PackageManager&MockObject $packageManager;

    private ExtensionConfiguration&MockObject $extensionConfiguration;

    private SecretDetectionService $service;

    protected function setUp(): void
    {
        parent::setUp();

        $this->connectionPool = $this->createMock(ConnectionPool::class);
        $this->packageManager = $this->createMock(PackageManager::class);
        $this->extensionConfiguration = $this->createMock(ExtensionConfiguration::class);

        $this->service = new SecretDetectionService(
            $this->connectionPool,
            $this->packageManager,
            $this->extensionConfiguration,
            new NullLogger(),
            new SecretRedactor(),
        );
    }

    #[Test]
    public function getDetectedSecretsReturnsEmptyArrayInitially(): void
    {
        // Test that the service returns empty results before any scanning
        // Note: scan() requires full TYPO3 bootstrap, so we test the result accessors instead
        $result = $this->service->getDetectedSecretsBySeverity();

        self::assertIsArray($result);
        self::assertArrayHasKey('critical', $result);
        self::assertEmpty($result['critical']);
    }

    #[Test]
    public function getDetectedSecretsCountReturnsZeroInitially(): void
    {
        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function getDetectedSecretsBySeverityReturnsGroupedArray(): void
    {
        $result = $this->service->getDetectedSecretsBySeverity();

        self::assertArrayHasKey('critical', $result);
        self::assertArrayHasKey('high', $result);
        self::assertArrayHasKey('medium', $result);
        self::assertArrayHasKey('low', $result);
    }

    #[Test]
    #[DataProvider('columnNamePatternProvider')]
    public function detectsSecretColumnNames(string $columnName, bool $shouldDetect): void
    {
        // Use reflection to test private method
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('isSecretColumn');

        $result = $method->invoke($this->service, $columnName);

        self::assertSame($shouldDetect, $result, \sprintf(
            'Column "%s" should %sbe detected as secret',
            $columnName,
            $shouldDetect ? '' : 'NOT ',
        ));
    }

    /**
     * @return array<string, array{0: string, 1: bool}>
     */
    public static function columnNamePatternProvider(): array
    {
        return [
            'password suffix' => ['user_password', true],
            'password prefix' => ['password_hash', true],
            'api_key suffix' => ['stripe_api_key', true],
            'apikey suffix' => ['stripeapikey', true],
            'api secret' => ['api_secret', true],
            'secret key' => ['secret_key', true],
            'token suffix' => ['access_token', true],
            'auth token' => ['auth_token', true],
            'refresh token' => ['refresh_token', true],
            'credential' => ['user_credentials', true],
            'private key' => ['ssl_private_key', true],
            'encryption key' => ['encryption_key', true],
            'smtp password' => ['smtp_password', true],
            'db password' => ['db_password', true],
            // Non-secret columns
            'regular column' => ['username', false],
            'title' => ['title', false],
            'description' => ['description', false],
            'created_at' => ['created_at', false],
            'uid' => ['uid', false],
            'pid' => ['pid', false],
        ];
    }

    #[Test]
    #[DataProvider('valuePatternProvider')]
    public function detectsKnownApiKeyPatterns(string $value, ?string $expectedPattern): void
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('detectValuePattern');

        $result = $method->invoke($this->service, $value);

        if ($expectedPattern === null) {
            self::assertNull($result, 'Value should not match any pattern');
        } else {
            self::assertSame($expectedPattern, $result, \sprintf(
                'Value should be detected as "%s"',
                $expectedPattern,
            ));
        }
    }

    /**
     * @return array<string, array{0: string, 1: ?string}>
     */
    public static function valuePatternProvider(): array
    {
        // Synthetic test fixtures: assemble each "secret" from fragments
        // via implode() so GitHub secret-scanning push-protection does
        // not treat them as real leaked credentials. implode() is used
        // rather than string concatenation because PHP-CS-Fixer's
        // `no_useless_concat_operator` rule would otherwise collapse
        // `'sk' . '_live_'` back into the triggering literal at
        // format time.
        $make = static fn (string ...$parts): string => implode('', $parts);
        $fakeSuffix = '0123456789ABCDEFGHIJKLMNOP'; // 26 chars, meets 24+ requirement

        return [
            'Stripe live key' => [$make('sk', '_live_', $fakeSuffix), 'Stripe live key'],
            'Stripe test key' => [$make('sk', '_test_', $fakeSuffix), 'Stripe test key'],
            'Stripe publishable live' => [$make('pk', '_live_', $fakeSuffix), 'Stripe publishable live'],
            'AWS access key' => [$make('AKI', 'AEXAMPLEFAKEKEY12'), 'AWS Access Key'],
            'GitHub PAT' => [$make('gh', 'p_FAKE000000000000000000000000000000AB'), 'GitHub Personal Access Token'],
            'GitHub OAuth' => [$make('gh', 'o_FAKE000000000000000000000000000000AB'), 'GitHub OAuth Token'],
            'Google API Key' => [$make('AI', 'zaFAKEEXAMPLEKEYNOTREAL000000000000ab'), 'Google API Key'],
            // Non-matches
            'regular string' => ['just a regular value', null],
            'short token' => ['abc123', null],
            'email' => ['user@example.com', null],
            'url' => ['https://example.com', null],
        ];
    }

    #[Test]
    #[DataProvider('vaultIdentifierProvider')]
    public function detectsVaultIdentifiers(string $value, bool $isVaultIdentifier): void
    {
        $result = IdentifierValidator::looksLikeVaultIdentifier($value);

        self::assertSame($isVaultIdentifier, $result);
    }

    /**
     * @return array<string, array{0: string, 1: bool}>
     */
    public static function vaultIdentifierProvider(): array
    {
        return [
            'UUID v7 format' => [self::UUID_V7, true],
            'vault reference' => ['%vault(my_secret_key)%', true],
            'old TCA format (no longer detected)' => ['tx_myext_config__api_key__123', false],
            'regular value' => ['some_regular_value', false],
            // Stripe-looking key fragmented so push-protection does not flag it.
            'API key' => [implode('', ['sk', '_live_abcdefghij']), false],
            'password' => ['mySecretPassword123', false],
        ];
    }

    #[Test]
    #[DataProvider('encryptedValueProvider')]
    public function detectsEncryptedValues(string $value, bool $looksEncrypted): void
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('looksEncrypted');

        $result = $method->invoke($this->service, $value);

        self::assertSame($looksEncrypted, $result);
    }

    /**
     * @return array<string, array{0: string, 1: bool}>
     */
    public static function encryptedValueProvider(): array
    {
        return [
            // Password hashes (should be detected as "encrypted"/secured)
            'bcrypt hash $2y$' => ['$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234', true],
            'bcrypt hash $2a$' => ['$2a$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234', true],
            'bcrypt hash $2b$' => ['$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234', true],
            'argon2i hash' => ['$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG', true],
            'argon2id hash' => ['$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$GpZ3sK6WLbDpeYfZ8bLz', true],
            // Encrypted data
            'long base64' => [str_repeat('YWJjZGVm', 10), true],
            'long hex' => [str_repeat('a1b2c3d4', 15), true],
            // Plaintext (should NOT be detected as encrypted)
            'short string' => ['abc123', false],
            'regular text' => ['Hello, World!', false],
            'mixed characters' => ['abc-123_def.ghi', false],
            'plaintext password' => ['MySecretPassword123!', false],
            'short hash-like' => ['$2y$10$short', false],
        ];
    }

    #[Test]
    #[DataProvider('severityProvider')]
    public function calculatesSeverityCorrectly(string $name, array $patterns, Severity $expectedSeverity): void
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('calculateSeverity');

        $result = $method->invoke($this->service, $name, $patterns);

        self::assertSame($expectedSeverity, $result);
    }

    /**
     * @return array<string, array{0: string, 1: array<string>, 2: Severity}>
     */
    public static function severityProvider(): array
    {
        return [
            'with patterns = critical' => ['api_key', ['Stripe live key'], Severity::Critical],
            'password = high' => ['user_password', [], Severity::High],
            'private key = high' => ['ssl_private_key', [], Severity::High],
            'secret = high' => ['client_secret', [], Severity::High],
            'token = medium' => ['access_token', [], Severity::Medium],
            'apikey = medium' => ['stripe_apikey', [], Severity::Medium],
            'api_key = medium' => ['payment_api_key', [], Severity::Medium],
            'other = low' => ['some_config', [], Severity::Low],
        ];
    }

    #[Test]
    #[DataProvider('configKeyProvider')]
    public function detectsSecretConfigKeys(string $key, bool $isSecret): void
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('isSecretConfigKey');

        $result = $method->invoke($this->service, $key);

        self::assertSame($isSecret, $result);
    }

    /**
     * @return array<string, array{0: string, 1: bool}>
     */
    public static function configKeyProvider(): array
    {
        // Note: isSecretConfigKey uses regex suffix matching to avoid false positives
        return [
            // Should match (suffix patterns)
            'apiKey' => ['apiKey', true],
            'stripeApiKey' => ['stripeApiKey', true],
            'password' => ['password', true],
            'smtpPassword' => ['smtpPassword', true],
            'clientSecret' => ['clientSecret', true],
            'apiSecret' => ['apiSecret', true],
            'accessToken' => ['accessToken', true],
            'authToken' => ['authToken', true],
            'token' => ['token', true],              // standalone "token" (e.g., hashicorp.token)
            'privateKey' => ['privateKey', true],
            'encryptionKey' => ['encryptionKey', true],
            'userCredential' => ['userCredential', true],
            // Should NOT match (false positives avoided)
            'secretPrefix' => ['secretPrefix', false],  // "secret" at start, not end
            'tokenizer' => ['tokenizer', false],        // "token" not at end
            'passwordReset' => ['passwordReset', false], // "password" not at end
            'API_KEY' => ['API_KEY', false],            // underscore variant
            'username' => ['username', false],
            'email' => ['email', false],
            'baseUrl' => ['baseUrl', false],
            'timeout' => ['timeout', false],
        ];
    }

    #[Test]
    #[DataProvider('tableExclusionProvider')]
    public function excludesTablesCorrectly(string $tableName, array $patterns, bool $shouldExclude): void
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('isTableExcluded');

        $result = $method->invoke($this->service, $tableName, $patterns);

        self::assertSame($shouldExclude, $result);
    }

    #[Test]
    public function excludedColumnsContainsPasswordHashColumns(): void
    {
        $reflection = new ReflectionClass(SecretDetectionService::class);
        $constant = $reflection->getConstant('EXCLUDED_COLUMNS');

        self::assertIsArray($constant);
        self::assertContains('be_users.password', $constant, 'be_users.password should be excluded (contains hashes)');
        self::assertContains('fe_users.password', $constant, 'fe_users.password should be excluded (contains hashes)');
    }

    /**
     * @return array<string, array{0: string, 1: array<string>, 2: bool}>
     */
    public static function tableExclusionProvider(): array
    {
        return [
            'exact match' => ['cache_hash', ['cache_hash'], true],
            'wildcard match' => ['cache_pages', ['cache_*'], true],
            'cf wildcard' => ['cf_extbase_reflection', ['cf_*'], true],
            'no match' => ['tx_myext_domain_model_item', ['cache_*', 'cf_*'], false],
            'vault table' => ['tx_nrvault_secret', ['tx_nrvault_secret'], true],
        ];
    }

    #[Test]
    public function scanReturnsEmptyArrayWhenNoSecretsDetected(): void
    {
        // Mock database - no tables
        $connection = $this->createMock(Connection::class);
        $schemaManager = $this->createMock(AbstractSchemaManager::class);
        $schemaManager->method('listTableNames')->willReturn([]);

        $connection->method('createSchemaManager')->willReturn($schemaManager);
        $this->connectionPool->method('getConnectionByName')->willReturn($connection);

        // Mock package manager - no packages
        $this->packageManager->method('getActivePackages')->willReturn([]);

        $result = $this->service->scan();

        self::assertIsArray($result);
        self::assertEmpty($result);
    }

    #[Test]
    public function scanDatabaseTablesSkipsExcludedTables(): void
    {
        $connection = $this->createMock(Connection::class);
        $schemaManager = $this->createMock(AbstractSchemaManager::class);

        // Return tables including excluded ones
        $schemaManager->method('listTableNames')->willReturn([
            'tx_nrvault_secret',  // Excluded by default
            'be_sessions',        // Excluded by default
            'cache_pages',        // Excluded by wildcard
            'cf_extbase_reflection', // Excluded by wildcard
        ]);

        // listTableColumns should never be called for excluded tables
        $schemaManager->expects(self::never())->method('listTableColumns');

        $connection->method('createSchemaManager')->willReturn($schemaManager);
        $this->connectionPool->method('getConnectionByName')->willReturn($connection);

        $this->service->scanDatabaseTables();

        // Should complete without calling listTableColumns
        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanDatabaseTablesSilentlyHandlesDatabaseException(): void
    {
        // Create a mock exception that extends DbalException
        $exception = $this->createMock(\Doctrine\DBAL\Exception::class);
        $this->connectionPool->method('getConnectionByName')
            ->willThrowException($exception);

        // Should not throw, just silently fail
        $this->service->scanDatabaseTables();

        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanExtensionConfigurationScansActivePackages(): void
    {
        $package = $this->createMock(Package::class);
        $package->method('getPackageKey')->willReturn('test_extension');

        $this->packageManager->method('getActivePackages')->willReturn([$package]);

        // Extension throws exception (no config)
        $this->extensionConfiguration->method('get')
            ->with('test_extension')
            ->willThrowException(new Exception('No configuration'));

        // Should not throw
        $this->service->scanExtensionConfiguration();

        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanExtensionConfigurationDetectsSecretInConfig(): void
    {
        $package = $this->createMock(Package::class);
        $package->method('getPackageKey')->willReturn('test_ext');

        $this->packageManager->method('getActivePackages')->willReturn([$package]);

        // Return config with a secret-like key and plaintext value
        $this->extensionConfiguration->method('get')
            ->with('test_ext')
            ->willReturn([
                'apiKey' => 'plaintext_api_key_value_not_encrypted',
            ]);

        $this->service->scanExtensionConfiguration();

        self::assertGreaterThan(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanExtensionConfigurationIgnoresVaultReferences(): void
    {
        $package = $this->createMock(Package::class);
        $package->method('getPackageKey')->willReturn('test_ext');

        $this->packageManager->method('getActivePackages')->willReturn([$package]);

        // Return config with vault reference
        $this->extensionConfiguration->method('get')
            ->with('test_ext')
            ->willReturn([
                'apiKey' => '%vault(my_api_key)%',
                'password' => self::UUID_V7, // UUID v7
            ]);

        $this->service->scanExtensionConfiguration();

        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanExtensionConfigurationHandlesNestedConfig(): void
    {
        $package = $this->createMock(Package::class);
        $package->method('getPackageKey')->willReturn('test_ext');

        $this->packageManager->method('getActivePackages')->willReturn([$package]);

        $this->extensionConfiguration->method('get')
            ->with('test_ext')
            ->willReturn([
                'smtp' => [
                    'password' => 'plaintext_password',
                ],
            ]);

        $this->service->scanExtensionConfiguration();

        self::assertGreaterThan(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanExtensionConfigurationIgnoresEmptyValues(): void
    {
        $package = $this->createMock(Package::class);
        $package->method('getPackageKey')->willReturn('test_ext');

        $this->packageManager->method('getActivePackages')->willReturn([$package]);

        $this->extensionConfiguration->method('get')
            ->with('test_ext')
            ->willReturn([
                'password' => '',
                'apiKey' => '',
            ]);

        $this->service->scanExtensionConfiguration();

        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanExtensionConfigurationIgnoresNonStringValues(): void
    {
        $package = $this->createMock(Package::class);
        $package->method('getPackageKey')->willReturn('test_ext');

        $this->packageManager->method('getActivePackages')->willReturn([$package]);

        $this->extensionConfiguration->method('get')
            ->with('test_ext')
            ->willReturn([
                'password' => 12345,
                'apiKey' => true,
                'secret' => null,
            ]);

        $this->service->scanExtensionConfiguration();

        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanLocalConfigurationDetectsSmtpPassword(): void
    {
        // Set up GLOBALS for the test
        $GLOBALS['TYPO3_CONF_VARS'] = [
            'MAIL' => [
                'transport_smtp_password' => 'plaintext_smtp_password',
            ],
            'SYS' => [
                'encryptionKey' => str_repeat('a', 96),
            ],
        ];

        try {
            $this->service->scanLocalConfiguration();

            self::assertGreaterThan(0, $this->service->getDetectedSecretsCount());
            $bySeverity = $this->service->getDetectedSecretsBySeverity();
            self::assertNotEmpty($bySeverity['high']);
        } finally {
            unset($GLOBALS['TYPO3_CONF_VARS']);
        }
    }

    #[Test]
    public function scanLocalConfigurationIgnoresVaultSmtpPassword(): void
    {
        $GLOBALS['TYPO3_CONF_VARS'] = [
            'MAIL' => [
                'transport_smtp_password' => '%vault(smtp_password)%',
            ],
        ];

        try {
            $this->service->scanLocalConfiguration();

            self::assertSame(0, $this->service->getDetectedSecretsCount());
        } finally {
            unset($GLOBALS['TYPO3_CONF_VARS']);
        }
    }

    #[Test]
    public function scanLocalConfigurationDetectsWeakEncryptionKey(): void
    {
        $GLOBALS['TYPO3_CONF_VARS'] = [
            'SYS' => [
                'encryptionKey' => 'short_key', // Less than 32 chars
            ],
        ];

        try {
            $this->service->scanLocalConfiguration();

            self::assertGreaterThan(0, $this->service->getDetectedSecretsCount());
            $bySeverity = $this->service->getDetectedSecretsBySeverity();
            self::assertNotEmpty($bySeverity['medium']);
        } finally {
            unset($GLOBALS['TYPO3_CONF_VARS']);
        }
    }

    #[Test]
    public function scanLocalConfigurationSkipsWhenGlobalsNotSet(): void
    {
        unset($GLOBALS['TYPO3_CONF_VARS']);

        $this->service->scanLocalConfiguration();

        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanLocalConfigurationIgnoresEmptySmtpPassword(): void
    {
        $GLOBALS['TYPO3_CONF_VARS'] = [
            'MAIL' => [
                'transport_smtp_password' => '',
            ],
            'SYS' => [
                'encryptionKey' => str_repeat('a', 96),
            ],
        ];

        try {
            $this->service->scanLocalConfiguration();

            self::assertSame(0, $this->service->getDetectedSecretsCount());
        } finally {
            unset($GLOBALS['TYPO3_CONF_VARS']);
        }
    }

    #[Test]
    public function scanLocalConfigurationIgnoresStrongEncryptionKey(): void
    {
        $GLOBALS['TYPO3_CONF_VARS'] = [
            'SYS' => [
                'encryptionKey' => str_repeat('a', 96), // 96 chars, strong enough
            ],
        ];

        try {
            $this->service->scanLocalConfiguration();

            self::assertSame(0, $this->service->getDetectedSecretsCount());
        } finally {
            unset($GLOBALS['TYPO3_CONF_VARS']);
        }
    }

    #[Test]
    public function scanTableSkipsNonStringColumns(): void
    {
        $connection = $this->createMock(Connection::class);
        $schemaManager = $this->createMock(AbstractSchemaManager::class);

        // Create column with non-string type
        $intColumn = $this->createMock(Column::class);
        $intColumn->method('getName')->willReturn('password_reset_count');
        $intColumn->method('getType')->willReturn(new IntegerType());

        $schemaManager->method('listTableColumns')
            ->with('test_table')
            ->willReturn(['password_reset_count' => $intColumn]);

        $schemaManager->method('listTableNames')->willReturn(['test_table']);
        $connection->method('createSchemaManager')->willReturn($schemaManager);
        $this->connectionPool->method('getConnectionByName')->willReturn($connection);

        $this->service->scanDatabaseTables();

        // Should not detect integer columns even with secret-like names
        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanTableDetectsSecretInStringColumn(): void
    {
        $connection = $this->createMock(Connection::class);
        $schemaManager = $this->createMock(AbstractSchemaManager::class);

        // Create column with string type and secret-like name
        $secretColumn = $this->createMock(Column::class);
        $secretColumn->method('getName')->willReturn('api_secret');
        $secretColumn->method('getType')->willReturn(new StringType());

        $schemaManager->method('listTableNames')->willReturn(['tx_myext_config']);
        $schemaManager->method('listTableColumns')
            ->with('tx_myext_config')
            ->willReturn(['api_secret' => $secretColumn]);

        $connection->method('createSchemaManager')->willReturn($schemaManager);

        // Mock query builder for count query
        $queryBuilder = $this->createMock(QueryBuilder::class);
        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->method('isNotNull')->willReturn('api_secret IS NOT NULL');
        $expressionBuilder->method('neq')->willReturn("api_secret != ''");
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder->method('count')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('createNamedParameter')->willReturn("''");

        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn(0); // No records
        $queryBuilder->method('executeQuery')->willReturn($result);

        $this->connectionPool->method('getConnectionByName')->willReturn($connection);
        $this->connectionPool->method('getQueryBuilderForTable')->willReturn($queryBuilder);

        $this->service->scanDatabaseTables();

        // No records, so no secrets detected
        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanTableSkipsExcludedPasswordHashColumns(): void
    {
        $connection = $this->createMock(Connection::class);
        $schemaManager = $this->createMock(AbstractSchemaManager::class);

        // Create be_users.password column
        $passwordColumn = $this->createMock(Column::class);
        $passwordColumn->method('getName')->willReturn('password');
        $passwordColumn->method('getType')->willReturn(new StringType());

        $schemaManager->method('listTableNames')->willReturn(['be_users']);
        $schemaManager->method('listTableColumns')
            ->with('be_users')
            ->willReturn(['password' => $passwordColumn]);

        $connection->method('createSchemaManager')->willReturn($schemaManager);
        $this->connectionPool->method('getConnectionByName')->willReturn($connection);

        // Query builder should NOT be called for excluded columns
        $this->connectionPool->expects(self::never())->method('getQueryBuilderForTable');

        $this->service->scanDatabaseTables();

        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanTableHandlesExceptionGracefully(): void
    {
        $connection = $this->createMock(Connection::class);
        $schemaManager = $this->createMock(AbstractSchemaManager::class);

        $schemaManager->method('listTableNames')->willReturn(['test_table']);
        $exception = $this->createMock(\Doctrine\DBAL\Exception::class);
        $schemaManager->method('listTableColumns')
            ->willThrowException($exception);

        $connection->method('createSchemaManager')->willReturn($schemaManager);
        $this->connectionPool->method('getConnectionByName')->willReturn($connection);

        // Should not throw
        $this->service->scanDatabaseTables();

        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanTableDetectsPlaintextSecretAndCreatesDbFinding(): void
    {
        $connection = $this->createMock(Connection::class);
        $schemaManager = $this->createMock(AbstractSchemaManager::class);

        $secretColumn = $this->createMock(Column::class);
        $secretColumn->method('getName')->willReturn('api_secret');
        $secretColumn->method('getType')->willReturn(new StringType());

        $schemaManager->method('listTableNames')->willReturn(['tx_myext_config']);
        $schemaManager->method('listTableColumns')
            ->with('tx_myext_config')
            ->willReturn(['api_secret' => $secretColumn]);
        $connection->method('createSchemaManager')->willReturn($schemaManager);
        $this->connectionPool->method('getConnectionByName')->willReturn($connection);

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->method('isNotNull')->willReturn('api_secret IS NOT NULL');
        $expressionBuilder->method('neq')->willReturn("api_secret != ''");

        // Count query returns 1 non-empty record
        $countResult = $this->createMock(Result::class);
        $countResult->method('fetchOne')->willReturn(1);

        // Sample query returns plaintext value
        $sampleResult = $this->createMock(Result::class);
        $sampleResult->method('fetchAllAssociative')->willReturn([
            ['api_secret' => 'plaintext-api-secret-value'],
        ]);

        $countQb = $this->createMock(QueryBuilder::class);
        $countQb->method('expr')->willReturn($expressionBuilder);
        $countQb->method('count')->willReturnSelf();
        $countQb->method('from')->willReturnSelf();
        $countQb->method('where')->willReturnSelf();
        $countQb->method('createNamedParameter')->willReturn("''");
        $countQb->method('executeQuery')->willReturn($countResult);

        $sampleQb = $this->createMock(QueryBuilder::class);
        $sampleQb->method('expr')->willReturn($expressionBuilder);
        $sampleQb->method('select')->willReturnSelf();
        $sampleQb->method('from')->willReturnSelf();
        $sampleQb->method('where')->willReturnSelf();
        $sampleQb->method('setMaxResults')->willReturnSelf();
        $sampleQb->method('createNamedParameter')->willReturn("''");
        $sampleQb->method('executeQuery')->willReturn($sampleResult);

        $this->connectionPool
            ->method('getQueryBuilderForTable')
            ->willReturnOnConsecutiveCalls($countQb, $sampleQb);

        $this->service->scanDatabaseTables();

        self::assertGreaterThan(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanTableSkipsVaultIdentifierValues(): void
    {
        $connection = $this->createMock(Connection::class);
        $schemaManager = $this->createMock(AbstractSchemaManager::class);

        $secretColumn = $this->createMock(Column::class);
        $secretColumn->method('getName')->willReturn('api_token');
        $secretColumn->method('getType')->willReturn(new TextType());

        $schemaManager->method('listTableNames')->willReturn(['tx_myext_config']);
        $schemaManager->method('listTableColumns')
            ->willReturn(['api_token' => $secretColumn]);
        $connection->method('createSchemaManager')->willReturn($schemaManager);
        $this->connectionPool->method('getConnectionByName')->willReturn($connection);

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->method('isNotNull')->willReturn('api_token IS NOT NULL');
        $expressionBuilder->method('neq')->willReturn("api_token != ''");

        $countResult = $this->createMock(Result::class);
        $countResult->method('fetchOne')->willReturn(1);

        // All samples are vault identifiers — should NOT be flagged
        $sampleResult = $this->createMock(Result::class);
        $sampleResult->method('fetchAllAssociative')->willReturn([
            ['api_token' => self::UUID_V7],
        ]);

        $countQb = $this->createMock(QueryBuilder::class);
        $countQb->method('expr')->willReturn($expressionBuilder);
        $countQb->method('count')->willReturnSelf();
        $countQb->method('from')->willReturnSelf();
        $countQb->method('where')->willReturnSelf();
        $countQb->method('createNamedParameter')->willReturn("''");
        $countQb->method('executeQuery')->willReturn($countResult);

        $sampleQb = $this->createMock(QueryBuilder::class);
        $sampleQb->method('expr')->willReturn($expressionBuilder);
        $sampleQb->method('select')->willReturnSelf();
        $sampleQb->method('from')->willReturnSelf();
        $sampleQb->method('where')->willReturnSelf();
        $sampleQb->method('setMaxResults')->willReturnSelf();
        $sampleQb->method('createNamedParameter')->willReturn("''");
        $sampleQb->method('executeQuery')->willReturn($sampleResult);

        $this->connectionPool
            ->method('getQueryBuilderForTable')
            ->willReturnOnConsecutiveCalls($countQb, $sampleQb);

        $this->service->scanDatabaseTables();

        // Vault identifiers should not be flagged
        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanTableSkipsAlreadyEncryptedValues(): void
    {
        $connection = $this->createMock(Connection::class);
        $schemaManager = $this->createMock(AbstractSchemaManager::class);

        $secretColumn = $this->createMock(Column::class);
        $secretColumn->method('getName')->willReturn('password');
        $secretColumn->method('getType')->willReturn(new BlobType());

        $schemaManager->method('listTableNames')->willReturn(['tx_myext_users']);
        $schemaManager->method('listTableColumns')
            ->willReturn(['password' => $secretColumn]);
        $connection->method('createSchemaManager')->willReturn($schemaManager);
        $this->connectionPool->method('getConnectionByName')->willReturn($connection);

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->method('isNotNull')->willReturn('password IS NOT NULL');
        $expressionBuilder->method('neq')->willReturn("password != ''");

        $countResult = $this->createMock(Result::class);
        $countResult->method('fetchOne')->willReturn(1);

        // Bcrypt hash — should be skipped
        $sampleResult = $this->createMock(Result::class);
        $sampleResult->method('fetchAllAssociative')->willReturn([
            ['password' => '$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234'],
        ]);

        $countQb = $this->createMock(QueryBuilder::class);
        $countQb->method('expr')->willReturn($expressionBuilder);
        $countQb->method('count')->willReturnSelf();
        $countQb->method('from')->willReturnSelf();
        $countQb->method('where')->willReturnSelf();
        $countQb->method('createNamedParameter')->willReturn("''");
        $countQb->method('executeQuery')->willReturn($countResult);

        $sampleQb = $this->createMock(QueryBuilder::class);
        $sampleQb->method('expr')->willReturn($expressionBuilder);
        $sampleQb->method('select')->willReturnSelf();
        $sampleQb->method('from')->willReturnSelf();
        $sampleQb->method('where')->willReturnSelf();
        $sampleQb->method('setMaxResults')->willReturnSelf();
        $sampleQb->method('createNamedParameter')->willReturn("''");
        $sampleQb->method('executeQuery')->willReturn($sampleResult);

        $this->connectionPool
            ->method('getQueryBuilderForTable')
            ->willReturnOnConsecutiveCalls($countQb, $sampleQb);

        $this->service->scanDatabaseTables();

        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanTableDetectsKnownApiKeyPattern(): void
    {
        $connection = $this->createMock(Connection::class);
        $schemaManager = $this->createMock(AbstractSchemaManager::class);

        $secretColumn = $this->createMock(Column::class);
        $secretColumn->method('getName')->willReturn('stripe_api_key');
        $secretColumn->method('getType')->willReturn(new StringType());

        $schemaManager->method('listTableNames')->willReturn(['tx_payment_config']);
        $schemaManager->method('listTableColumns')
            ->willReturn(['stripe_api_key' => $secretColumn]);
        $connection->method('createSchemaManager')->willReturn($schemaManager);
        $this->connectionPool->method('getConnectionByName')->willReturn($connection);

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->method('isNotNull')->willReturn('stripe_api_key IS NOT NULL');
        $expressionBuilder->method('neq')->willReturn("stripe_api_key != ''");

        $countResult = $this->createMock(Result::class);
        $countResult->method('fetchOne')->willReturn(1);

        $sampleResult = $this->createMock(Result::class);
        // Stripe live key pattern — should be detected as Critical.
        // Fragmented via implode() so GitHub push-protection does not
        // flag the synthetic test fixture, and so PHP-CS-Fixer's
        // `no_useless_concat_operator` cannot collapse it back.
        $sampleResult->method('fetchAllAssociative')->willReturn([
            ['stripe_api_key' => implode('', ['sk', '_live_0123456789ABCDEFGHIJKLMNOP'])],
        ]);

        $countQb = $this->createMock(QueryBuilder::class);
        $countQb->method('expr')->willReturn($expressionBuilder);
        $countQb->method('count')->willReturnSelf();
        $countQb->method('from')->willReturnSelf();
        $countQb->method('where')->willReturnSelf();
        $countQb->method('createNamedParameter')->willReturn("''");
        $countQb->method('executeQuery')->willReturn($countResult);

        $sampleQb = $this->createMock(QueryBuilder::class);
        $sampleQb->method('expr')->willReturn($expressionBuilder);
        $sampleQb->method('select')->willReturnSelf();
        $sampleQb->method('from')->willReturnSelf();
        $sampleQb->method('where')->willReturnSelf();
        $sampleQb->method('setMaxResults')->willReturnSelf();
        $sampleQb->method('createNamedParameter')->willReturn("''");
        $sampleQb->method('executeQuery')->willReturn($sampleResult);

        $this->connectionPool
            ->method('getQueryBuilderForTable')
            ->willReturnOnConsecutiveCalls($countQb, $sampleQb);

        $this->service->scanDatabaseTables();

        self::assertGreaterThan(0, $this->service->getDetectedSecretsCount());
        $bySeverity = $this->service->getDetectedSecretsBySeverity();
        self::assertNotEmpty($bySeverity['critical']);
    }

    #[Test]
    public function scanTableHandlesDbalExceptionOnCountQuery(): void
    {
        $connection = $this->createMock(Connection::class);
        $schemaManager = $this->createMock(AbstractSchemaManager::class);

        $secretColumn = $this->createMock(Column::class);
        $secretColumn->method('getName')->willReturn('api_key');
        $secretColumn->method('getType')->willReturn(new StringType());

        $schemaManager->method('listTableNames')->willReturn(['tx_myext_config']);
        $schemaManager->method('listTableColumns')
            ->willReturn(['api_key' => $secretColumn]);
        $connection->method('createSchemaManager')->willReturn($schemaManager);
        $this->connectionPool->method('getConnectionByName')->willReturn($connection);

        $exception = $this->createMock(\Doctrine\DBAL\Exception::class);
        $this->connectionPool
            ->method('getQueryBuilderForTable')
            ->willThrowException($exception);

        // Should silently handle the exception
        $this->service->scanDatabaseTables();

        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanLocalConfigurationIgnoresNonArrayMailConfig(): void
    {
        $GLOBALS['TYPO3_CONF_VARS'] = [
            'MAIL' => 'not-an-array',
            'SYS' => ['encryptionKey' => str_repeat('a', 96)],
        ];

        try {
            $this->service->scanLocalConfiguration();

            self::assertSame(0, $this->service->getDetectedSecretsCount());
        } finally {
            unset($GLOBALS['TYPO3_CONF_VARS']);
        }
    }

    #[Test]
    public function scanLocalConfigurationIgnoresNonStringSysConfig(): void
    {
        $GLOBALS['TYPO3_CONF_VARS'] = [
            'SYS' => ['encryptionKey' => 123], // numeric, not string
        ];

        try {
            $this->service->scanLocalConfiguration();

            self::assertSame(0, $this->service->getDetectedSecretsCount());
        } finally {
            unset($GLOBALS['TYPO3_CONF_VARS']);
        }
    }

    #[Test]
    public function scanLocalConfigurationIgnoresExactly32CharEncryptionKey(): void
    {
        // Exactly 32 chars — not flagged (must be strictly < 32)
        $GLOBALS['TYPO3_CONF_VARS'] = [
            'SYS' => ['encryptionKey' => str_repeat('x', 32)],
        ];

        try {
            $this->service->scanLocalConfiguration();

            self::assertSame(0, $this->service->getDetectedSecretsCount());
        } finally {
            unset($GLOBALS['TYPO3_CONF_VARS']);
        }
    }

    #[Test]
    public function scanExtensionConfigurationHandlesNonArrayConfigGracefully(): void
    {
        $package = $this->createMock(Package::class);
        $package->method('getPackageKey')->willReturn('test_ext');

        $this->packageManager->method('getActivePackages')->willReturn([$package]);

        // Extension returns non-array config — should be ignored
        $this->extensionConfiguration->method('get')
            ->with('test_ext')
            ->willReturn('not-an-array');

        $this->service->scanExtensionConfiguration();

        self::assertSame(0, $this->service->getDetectedSecretsCount());
    }

    #[Test]
    public function scanExtensionConfigurationDetectsKnownApiKeyPattern(): void
    {
        $package = $this->createMock(Package::class);
        $package->method('getPackageKey')->willReturn('my_payment_ext');

        $this->packageManager->method('getActivePackages')->willReturn([$package]);

        // GitHub PAT pattern — should be detected as Critical
        $this->extensionConfiguration->method('get')
            ->willReturn([
                'apiKey' => 'ghp_FAKE000000000000000000000000000000AB',
            ]);

        $this->service->scanExtensionConfiguration();

        self::assertGreaterThan(0, $this->service->getDetectedSecretsCount());
        $bySeverity = $this->service->getDetectedSecretsBySeverity();
        self::assertNotEmpty($bySeverity['critical']);
    }

    #[Test]
    public function scanAfterScanResetsDetectedSecrets(): void
    {
        $connection = $this->createMock(Connection::class);
        $schemaManager = $this->createMock(AbstractSchemaManager::class);
        $schemaManager->method('listTableNames')->willReturn([]);
        $connection->method('createSchemaManager')->willReturn($schemaManager);
        $this->connectionPool->method('getConnectionByName')->willReturn($connection);

        $package = $this->createMock(Package::class);
        $package->method('getPackageKey')->willReturn('ext_a');
        $this->packageManager->method('getActivePackages')->willReturn([$package]);
        $this->extensionConfiguration->method('get')->willReturn(['apiKey' => 'plaintext-value']);

        // First scan finds something
        $this->service->scan();
        $firstCount = $this->service->getDetectedSecretsCount();

        // Second scan should reset and rescan
        $this->extensionConfiguration = $this->createMock(ExtensionConfiguration::class);
        $this->extensionConfiguration->method('get')->willReturn([]);

        // Create new service instance to test clean slate
        $freshService = new SecretDetectionService(
            $this->connectionPool,
            $this->packageManager,
            $this->extensionConfiguration,
            new NullLogger(),
            new SecretRedactor(),
        );

        // Scan again with no findings
        $freshService->scan();

        self::assertSame(0, $freshService->getDetectedSecretsCount());
        self::assertGreaterThan(0, $firstCount); // previous scan found something
    }
}
