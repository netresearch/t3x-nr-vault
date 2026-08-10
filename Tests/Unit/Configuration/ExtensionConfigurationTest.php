<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Configuration;

use Netresearch\NrVault\Configuration\Dto\AwsSecretsConfig;
use Netresearch\NrVault\Configuration\Dto\VaultServerConfig;
use Netresearch\NrVault\Configuration\ExtensionConfiguration;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\EnvironmentSandboxTrait;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration as Typo3ExtensionConfiguration;

#[CoversClass(ExtensionConfiguration::class)]
#[AllowMockObjectsWithoutExpectations]
final class ExtensionConfigurationTest extends TestCase
{
    use EnvironmentSandboxTrait;

    private Typo3ExtensionConfiguration&MockObject $typo3Config;

    protected function setUp(): void
    {
        parent::setUp();
        $this->typo3Config = $this->createMock(Typo3ExtensionConfiguration::class);

        // The path getters (auto key path, audit sink paths) resolve their
        // defaults through Environment, which the unit bootstrap leaves
        // uninitialised.
        $this->setUpEnvironmentSandbox();
    }

    protected function tearDown(): void
    {
        $this->tearDownEnvironmentSandbox();

        parent::tearDown();
    }

    #[Test]
    public function getStorageAdapterReturnsConfiguredValue(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['storageAdapter' => 'hashicorp']);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame('hashicorp', $config->getStorageAdapter());
    }

    #[Test]
    public function getStorageAdapterReturnsDefaultWhenNotConfigured(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(ExtensionConfiguration::DEFAULT_STORAGE_ADAPTER, $config->getStorageAdapter());
    }

    #[Test]
    public function getMasterKeyProviderReturnsConfiguredValue(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['masterKeyProvider' => 'env']);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame('env', $config->getMasterKeyProvider());
    }

    #[Test]
    public function getMasterKeyProviderReturnsDefaultWhenNotConfigured(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(ExtensionConfiguration::DEFAULT_MASTER_KEY_PROVIDER, $config->getMasterKeyProvider());
    }

    #[Test]
    public function getMasterKeySourceReturnsConfiguredValue(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['masterKeySource' => '/path/to/key']);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame('/path/to/key', $config->getMasterKeySource());
    }

    #[Test]
    public function getAuditLogRetentionReturnsConfiguredValue(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['auditLogRetention' => 90]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(90, $config->getAuditLogRetention());
    }

    #[Test]
    public function getAuditLogRetentionReturnsDefaultWhenNotConfigured(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(ExtensionConfiguration::DEFAULT_AUDIT_LOG_RETENTION, $config->getAuditLogRetention());
    }

    #[Test]
    public function isCliAccessAllowedReturnsTrueWhenEnabled(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['allowCliAccess' => true]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertTrue($config->isCliAccessAllowed());
    }

    #[Test]
    public function isCliAccessAllowedReturnsFalseByDefault(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertFalse($config->isCliAccessAllowed());
    }

    /**
     * Every non-usable value must read as "no provisioning actor". Anything that
     * fell through to a numeric 0 would name the unauthenticated CLI placeholder
     * TYPO3 puts in $GLOBALS['BE_USER'] — the actor this option exists to avoid —
     * so the failure mode of a typo has to be "off", never "unattributed".
     *
     * @param mixed $configured the raw provisioningBeUserUid value
     */
    #[DataProvider('provisioningUidProvider')]
    #[Test]
    public function getProvisioningBeUserUidFailsClosed(mixed $configured, int $expected): void
    {
        $this->typo3Config->method('get')->willReturn(['provisioningBeUserUid' => $configured]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame($expected, $config->getProvisioningBeUserUid());
    }

    /**
     * @return iterable<string, array{mixed, int}>
     */
    public static function provisioningUidProvider(): iterable
    {
        yield 'configured uid' => [991, 991];
        yield 'numeric string' => ['991', 991];
        yield 'explicitly off' => [0, 0];
        yield 'negative' => [-5, 0];
        yield 'non-numeric' => ['admin', 0];
        yield 'empty string' => ['', 0];
        yield 'array' => [[991], 0];
        yield 'null' => [null, 0];
    }

    #[Test]
    public function getProvisioningBeUserUidIsOffWhenUnset(): void
    {
        $this->typo3Config->method('get')->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(0, $config->getProvisioningBeUserUid());
    }

    #[Test]
    public function getCliAccessGroupsParsesCommaString(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['cliAccessGroups' => '1,2,3']);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame([1, 2, 3], $config->getCliAccessGroups());
    }

    #[Test]
    public function getCliAccessGroupsHandlesArray(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['cliAccessGroups' => [1, 2, 3]]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame([1, 2, 3], $config->getCliAccessGroups());
    }

    #[Test]
    public function getCliAllowedOperationsReturnsSafeDefault(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(
            ['secret.use', 'secret.create', 'secret.rotate'],
            $config->getCliAllowedOperations(),
        );
    }

    #[Test]
    public function getCliAllowedOperationsParsesAndTrimsConfiguredList(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['cliAllowedOperations' => ' secret.use , secret.delete ,, ']);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(['secret.use', 'secret.delete'], $config->getCliAllowedOperations());
    }

    #[Test]
    public function getCliAllowedOperationsFallsBackToTheDefaultOnANonStringValue(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['cliAllowedOperations' => ['not', 'a', 'string']]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(
            ['secret.use', 'secret.create', 'secret.rotate'],
            $config->getCliAllowedOperations(),
        );
    }

    #[Test]
    public function getCliAllowedOperationsCanBeEmptiedExplicitly(): void
    {
        // An operator may strip the CLI actor of every operation while
        // keeping the per-secret CLI tiers (allowCliAccess) intact.
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['cliAllowedOperations' => '']);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame([], $config->getCliAllowedOperations());
    }

    #[Test]
    public function isAuditReadsEnabledReturnsTrueByDefault(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertTrue($config->isAuditReadsEnabled());
    }

    #[Test]
    public function isAuditReadsEnabledReturnsFalseWhenDisabled(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['auditReads' => false]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertFalse($config->isAuditReadsEnabled());
    }

    #[Test]
    public function isAuditReadsEnabledRespectsFilesystemOverrideTrue(): void
    {
        $original = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        $GLOBALS['TYPO3_CONF_VARS'] = ['SYS' => ['nrVault' => ['auditReads' => true]]];

        // BE-config says "disabled" but filesystem override forces enabled.
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['auditReads' => false]);

        try {
            $config = new ExtensionConfiguration($this->typo3Config);
            self::assertTrue($config->isAuditReadsEnabled());
        } finally {
            if ($original !== null) {
                $GLOBALS['TYPO3_CONF_VARS'] = $original;
            } else {
                unset($GLOBALS['TYPO3_CONF_VARS']);
            }
        }
    }

    #[Test]
    public function isAuditReadsEnabledRespectsFilesystemOverrideFalse(): void
    {
        $original = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        $GLOBALS['TYPO3_CONF_VARS'] = ['SYS' => ['nrVault' => ['auditReads' => false]]];

        // BE-config says "enabled" but filesystem override silences reads.
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['auditReads' => true]);

        try {
            $config = new ExtensionConfiguration($this->typo3Config);
            self::assertFalse($config->isAuditReadsEnabled());
        } finally {
            if ($original !== null) {
                $GLOBALS['TYPO3_CONF_VARS'] = $original;
            } else {
                unset($GLOBALS['TYPO3_CONF_VARS']);
            }
        }
    }

    #[Test]
    public function isFrontendPlaceholderLegacyCliEnabledReturnsFalseByDefault(): void
    {
        // The CLI enforces the ADR-035 allow-set unless a deployment opts back
        // out. An install that never heard of the setting must be strict.
        $this->typo3Config->method('get')->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertFalse($config->isFrontendPlaceholderLegacyCliEnabled());
    }

    #[Test]
    public function isFrontendPlaceholderLegacyCliEnabledReturnsTrueWhenConfigured(): void
    {
        $this->typo3Config->method('get')->willReturn(['frontendPlaceholderLegacyCli' => true]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertTrue($config->isFrontendPlaceholderLegacyCliEnabled());
    }

    #[Test]
    public function isFrontendPlaceholderLegacyCliEnabledRespectsFilesystemOverrideFalse(): void
    {
        // The direction that matters: an admin who ticks the box in the BE
        // Settings module must not thereby re-open the CLI gate an operator
        // pinned shut on the filesystem.
        $original = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        $GLOBALS['TYPO3_CONF_VARS'] = ['SYS' => ['nrVault' => ['frontendPlaceholderLegacyCli' => false]]];

        $this->typo3Config->method('get')->willReturn(['frontendPlaceholderLegacyCli' => true]);

        try {
            $config = new ExtensionConfiguration($this->typo3Config);
            self::assertFalse($config->isFrontendPlaceholderLegacyCliEnabled());
        } finally {
            if ($original !== null) {
                $GLOBALS['TYPO3_CONF_VARS'] = $original;
            } else {
                unset($GLOBALS['TYPO3_CONF_VARS']);
            }
        }
    }

    #[Test]
    public function isFrontendPlaceholderLegacyCliEnabledRespectsFilesystemOverrideTrue(): void
    {
        // The pin is the authority in both directions, as for every other
        // pinned flag — an operator can also pin the opt-in on.
        $original = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        $GLOBALS['TYPO3_CONF_VARS'] = ['SYS' => ['nrVault' => ['frontendPlaceholderLegacyCli' => true]]];

        $this->typo3Config->method('get')->willReturn(['frontendPlaceholderLegacyCli' => false]);

        try {
            $config = new ExtensionConfiguration($this->typo3Config);
            self::assertTrue($config->isFrontendPlaceholderLegacyCliEnabled());
        } finally {
            if ($original !== null) {
                $GLOBALS['TYPO3_CONF_VARS'] = $original;
            } else {
                unset($GLOBALS['TYPO3_CONF_VARS']);
            }
        }
    }

    #[Test]
    public function isAdminOverrideDisabledReturnsFalseByDefault(): void
    {
        // The admin bypass is on unless a deployment explicitly removes it —
        // an extension update must never silently lock administrators out.
        $this->typo3Config->method('get')->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertFalse($config->isAdminOverrideDisabled());
    }

    #[Test]
    public function isAdminOverrideDisabledReturnsTrueWhenConfigured(): void
    {
        $this->typo3Config->method('get')->willReturn(['disableAdminOverride' => true]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertTrue($config->isAdminOverrideDisabled());
    }

    #[Test]
    public function isAdminOverrideDisabledRespectsFilesystemOverrideTrue(): void
    {
        // The point of the pin: a compromised admin who unticks the box in the
        // BE Settings module must not thereby restore their own bypass.
        $original = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        $GLOBALS['TYPO3_CONF_VARS'] = ['SYS' => ['nrVault' => ['disableAdminOverride' => true]]];

        $this->typo3Config->method('get')->willReturn(['disableAdminOverride' => false]);

        try {
            $config = new ExtensionConfiguration($this->typo3Config);
            self::assertTrue($config->isAdminOverrideDisabled());
        } finally {
            if ($original !== null) {
                $GLOBALS['TYPO3_CONF_VARS'] = $original;
            } else {
                unset($GLOBALS['TYPO3_CONF_VARS']);
            }
        }
    }

    #[Test]
    public function isAdminOverrideDisabledRespectsFilesystemOverrideFalse(): void
    {
        // The pin wins in both directions — it is the authority, not a floor.
        $original = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        $GLOBALS['TYPO3_CONF_VARS'] = ['SYS' => ['nrVault' => ['disableAdminOverride' => false]]];

        $this->typo3Config->method('get')->willReturn(['disableAdminOverride' => true]);

        try {
            $config = new ExtensionConfiguration($this->typo3Config);
            self::assertFalse($config->isAdminOverrideDisabled());
        } finally {
            if ($original !== null) {
                $GLOBALS['TYPO3_CONF_VARS'] = $original;
            } else {
                unset($GLOBALS['TYPO3_CONF_VARS']);
            }
        }
    }

    #[Test]
    public function preferXChaCha20ReturnsFalseByDefault(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertFalse($config->preferXChaCha20());
    }

    #[Test]
    public function preferXChaCha20ReturnsTrueWhenEnabled(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['preferXChaCha20' => true]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertTrue($config->preferXChaCha20());
    }

    #[Test]
    public function getHashiCorpConfigReturnsEmptyConfigByDefault(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);
        $hashiCorpConfig = $config->getHashiCorpConfig();

        self::assertInstanceOf(VaultServerConfig::class, $hashiCorpConfig);
        self::assertSame('', $hashiCorpConfig->address);
        self::assertSame('', $hashiCorpConfig->path);
        self::assertSame('', $hashiCorpConfig->authMethod);
        self::assertSame('', $hashiCorpConfig->token);
    }

    #[Test]
    public function getHashiCorpConfigReturnsConfiguredValues(): void
    {
        $hashicorpConfig = [
            'address' => 'https://vault.example.com',
            'path' => 'secret/data',
            'authMethod' => 'token',
        ];

        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['hashicorp' => $hashicorpConfig]);

        $config = new ExtensionConfiguration($this->typo3Config);
        $result = $config->getHashiCorpConfig();

        self::assertInstanceOf(VaultServerConfig::class, $result);
        self::assertSame('https://vault.example.com', $result->address);
        self::assertSame('secret/data', $result->path);
        self::assertSame('token', $result->authMethod);
    }

    #[Test]
    public function getTransitConfigReadsTheTransitSettingsFromTheHashicorpGroup(): void
    {
        $this->typo3Config->method('get')
            ->willReturn(['hashicorp' => [
                'address' => 'https://vault.example.com:8200',
                'authMethod' => 'token',
                'transitMount' => 'platform/transit',
                'transitKeyName' => 'master-key',
                'transitWrappedKeyPath' => '/secure/wrapped.key',
                'tokenEnvVar' => 'MY_VAULT_TOKEN',
            ]]);

        $result = (new ExtensionConfiguration($this->typo3Config))->getTransitConfig();

        self::assertSame('https://vault.example.com:8200', $result->address);
        self::assertSame('platform/transit', $result->mount);
        self::assertSame('master-key', $result->keyName);
        self::assertSame('/secure/wrapped.key', $result->wrappedKeyPath);
        self::assertSame('MY_VAULT_TOKEN', $result->tokenEnvVar);
        self::assertTrue($result->isComplete());
    }

    #[Test]
    public function getTransitConfigReadsTheTransitSettingsAndKeepsTheVarPathLazy(): void
    {
        // Environment is not initialized in the unit suite, so a configured path
        // must be enough — this also proves the var-path fallback stays lazy. The
        // fallback itself is covered by the functional counterpart of this test.
        $this->typo3Config->method('get')->willReturn(['hashicorp' => [
            'transitWrappedKeyPath' => '/secure/wrapped.key',
        ]]);

        $result = (new ExtensionConfiguration($this->typo3Config))->getTransitConfig();

        self::assertSame('/secure/wrapped.key', $result->wrappedKeyPath);
    }

    #[Test]
    public function getTransitConfigIsIncompleteWithoutAnAddress(): void
    {
        $this->typo3Config->method('get')->willReturn(['hashicorp' => [
            'transitWrappedKeyPath' => '/secure/wrapped.key',
        ]]);

        $result = (new ExtensionConfiguration($this->typo3Config))->getTransitConfig();

        self::assertSame('', $result->address);
        self::assertFalse($result->isComplete());
    }

    #[Test]
    public function getAwsConfigReturnsEmptyConfigByDefault(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);
        $awsConfig = $config->getAwsConfig();

        self::assertInstanceOf(AwsSecretsConfig::class, $awsConfig);
        self::assertSame('', $awsConfig->region);
        self::assertSame('', $awsConfig->secretPrefix);
    }

    #[Test]
    public function getAwsConfigReturnsConfiguredValues(): void
    {
        $awsConfig = [
            'region' => 'eu-west-1',
            'secretPrefix' => 'myapp/',
        ];

        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['aws' => $awsConfig]);

        $config = new ExtensionConfiguration($this->typo3Config);
        $result = $config->getAwsConfig();

        self::assertInstanceOf(AwsSecretsConfig::class, $result);
        self::assertSame('eu-west-1', $result->region);
        self::assertSame('myapp/', $result->secretPrefix);
    }

    #[Test]
    public function handlesNullConfiguration(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(null);

        $config = new ExtensionConfiguration($this->typo3Config);

        // Should use defaults without crashing
        self::assertSame(ExtensionConfiguration::DEFAULT_STORAGE_ADAPTER, $config->getStorageAdapter());
        self::assertSame(ExtensionConfiguration::DEFAULT_MASTER_KEY_PROVIDER, $config->getMasterKeyProvider());
    }

    #[Test]
    public function getStorageAdapterReturnsDefaultWhenValueIsNonString(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['storageAdapter' => 42]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(ExtensionConfiguration::DEFAULT_STORAGE_ADAPTER, $config->getStorageAdapter());
    }

    #[Test]
    public function getMasterKeyProviderReturnsDefaultWhenValueIsNonString(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['masterKeyProvider' => true]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(ExtensionConfiguration::DEFAULT_MASTER_KEY_PROVIDER, $config->getMasterKeyProvider());
    }

    #[Test]
    public function getMasterKeySourceReturnsDefaultWhenNotConfigured(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(ExtensionConfiguration::DEFAULT_MASTER_KEY_SOURCE, $config->getMasterKeySource());
    }

    #[Test]
    public function getMasterKeySourceReturnsDefaultWhenValueIsNonString(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['masterKeySource' => 999]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(ExtensionConfiguration::DEFAULT_MASTER_KEY_SOURCE, $config->getMasterKeySource());
    }

    #[Test]
    public function getAuditLogRetentionReturnsDefaultWhenValueIsNonNumeric(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['auditLogRetention' => 'not-a-number']);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(ExtensionConfiguration::DEFAULT_AUDIT_LOG_RETENTION, $config->getAuditLogRetention());
    }

    #[Test]
    public function getAuditLogRetentionAcceptsNumericString(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['auditLogRetention' => '180']);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(180, $config->getAuditLogRetention());
    }

    #[Test]
    public function getHashiCorpConfigReturnsDefaultWhenValueIsNonArray(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['hashicorp' => 'invalid']);

        $config = new ExtensionConfiguration($this->typo3Config);
        $result = $config->getHashiCorpConfig();

        self::assertInstanceOf(VaultServerConfig::class, $result);
        self::assertSame('', $result->address);
    }

    #[Test]
    public function getAwsConfigReturnsDefaultWhenValueIsNonArray(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['aws' => 'invalid']);

        $config = new ExtensionConfiguration($this->typo3Config);
        $result = $config->getAwsConfig();

        self::assertInstanceOf(AwsSecretsConfig::class, $result);
        self::assertSame('', $result->region);
    }

    #[Test]
    public function getCliAccessGroupsReturnsEmptyArrayWhenNotConfigured(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame([], $config->getCliAccessGroups());
    }

    #[Test]
    public function getAuditHmacEpochReturnsConfiguredValue(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['auditHmacEpoch' => 2]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(2, $config->getAuditHmacEpoch());
    }

    #[Test]
    public function getAuditHmacEpochReturnsDefaultWhenNotConfigured(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(ExtensionConfiguration::DEFAULT_AUDIT_HMAC_EPOCH, $config->getAuditHmacEpoch());
    }

    #[Test]
    public function getAuditHmacEpochReturnsDefaultWhenValueIsNonNumeric(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['auditHmacEpoch' => 'not-a-number']);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(ExtensionConfiguration::DEFAULT_AUDIT_HMAC_EPOCH, $config->getAuditHmacEpoch());
    }

    #[Test]
    public function getAuditHmacEpochAcceptsZeroForLegacyMode(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['auditHmacEpoch' => 0]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(0, $config->getAuditHmacEpoch());
    }

    #[Test]
    public function getCliAccessGroupsFiltersZeroFromEmptyCommaString(): void
    {
        // A comma string with empty values would produce 0s that get filtered
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['cliAccessGroups' => '1,,3']);

        $config = new ExtensionConfiguration($this->typo3Config);
        $result = $config->getCliAccessGroups();

        // array_filter removes 0 values (from empty segment "")
        self::assertContains(1, $result);
        self::assertContains(3, $result);
        self::assertNotContains(0, $result);
    }

    #[Test]
    public function getSecurityProfileReturnsStandardWhenNotConfigured(): void
    {
        $this->typo3Config->method('get')
            ->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(SecurityProfile::Standard, $config->getSecurityProfile());
    }

    #[Test]
    public function getSecurityProfileReturnsStandardForEmptyString(): void
    {
        $this->typo3Config->method('get')
            ->willReturn(['securityProfile' => '']);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(SecurityProfile::Standard, $config->getSecurityProfile());
    }

    #[Test]
    public function getSecurityProfileReturnsHardenedWhenConfigured(): void
    {
        $this->typo3Config->method('get')
            ->willReturn(['securityProfile' => 'hardened']);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(SecurityProfile::Hardened, $config->getSecurityProfile());
    }

    #[Test]
    public function getSecurityProfileThrowsForUnknownProfileInsteadOfDegrading(): void
    {
        // Fail-closed: a typo like "hardned" must never silently become Standard.
        $this->typo3Config->method('get')
            ->willReturn(['securityProfile' => 'hardned']);

        $config = new ExtensionConfiguration($this->typo3Config);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1753900001);

        $config->getSecurityProfile();
    }

    #[Test]
    public function getSecurityProfileFallsBackToStandardForNonStringValue(): void
    {
        $this->typo3Config->method('get')
            ->willReturn(['securityProfile' => 1]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(SecurityProfile::Standard, $config->getSecurityProfile());
    }

    // ------------------------------------------------------------------
    // Audit sinks
    // ------------------------------------------------------------------

    /**
     * External sinks are opt-in: a default installation must not start writing
     * audit copies to the filesystem or the network without being asked.
     */
    /**
     * @param callable(ExtensionConfiguration): bool $read
     */
    #[Test]
    #[DataProvider('auditSinkToggleProvider')]
    public function auditSinkTogglesDefaultToDisabled(callable $read): void
    {
        $this->typo3Config->method('get')->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertFalse($read($config));
    }

    /**
     * The toggles are passed as closures rather than method-name strings: a
     * dynamic `$config->{$name}()` call is invisible to static analysis, so a
     * renamed getter would silently stop being covered.
     *
     * @return iterable<string, array{callable(ExtensionConfiguration): bool}>
     */
    public static function auditSinkToggleProvider(): iterable
    {
        yield 'syslog' => [static fn (ExtensionConfiguration $c): bool => $c->isAuditSinkSyslogEnabled()];
        yield 'file' => [static fn (ExtensionConfiguration $c): bool => $c->isAuditSinkFileEnabled()];
        yield 'webhook' => [static fn (ExtensionConfiguration $c): bool => $c->isAuditSinkWebhookEnabled()];
    }

    /**
     * @param callable(ExtensionConfiguration): bool $read
     */
    #[Test]
    #[DataProvider('auditSinkToggleConfigurationProvider')]
    public function auditSinkTogglesReflectConfiguration(string $key, callable $read, mixed $value, bool $expected): void
    {
        $this->typo3Config->method('get')->willReturn([$key => $value]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame($expected, $read($config));
    }

    /**
     * @return iterable<string, array{string, callable(ExtensionConfiguration): bool, mixed, bool}>
     */
    public static function auditSinkToggleConfigurationProvider(): iterable
    {
        $syslog = static fn (ExtensionConfiguration $c): bool => $c->isAuditSinkSyslogEnabled();
        $file = static fn (ExtensionConfiguration $c): bool => $c->isAuditSinkFileEnabled();
        $webhook = static fn (ExtensionConfiguration $c): bool => $c->isAuditSinkWebhookEnabled();

        // The extension configuration backend stores checkboxes as '1'/'0' strings.
        yield 'syslog on' => ['auditSinkSyslogEnabled', $syslog, '1', true];
        yield 'syslog off' => ['auditSinkSyslogEnabled', $syslog, '0', false];
        yield 'file on' => ['auditSinkFileEnabled', $file, '1', true];
        yield 'file off' => ['auditSinkFileEnabled', $file, '0', false];
        yield 'webhook on' => ['auditSinkWebhookEnabled', $webhook, '1', true];
        yield 'webhook off' => ['auditSinkWebhookEnabled', $webhook, '0', false];
    }

    #[Test]
    public function syslogIdentReturnsConfiguredValue(): void
    {
        $this->typo3Config->method('get')->willReturn(['auditSinkSyslogIdent' => 'vault-prod']);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame('vault-prod', $config->getAuditSinkSyslogIdent());
    }

    /**
     * A blank ident makes every syslog line unattributable, which defeats the
     * point of the sink — so it falls back rather than passing '' to openlog().
     */
    #[Test]
    #[DataProvider('unusableIdentProvider')]
    public function unusableSyslogIdentFallsBackToTheDefault(mixed $value): void
    {
        $this->typo3Config->method('get')->willReturn(['auditSinkSyslogIdent' => $value]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame(
            ExtensionConfiguration::DEFAULT_AUDIT_SINK_SYSLOG_IDENT,
            $config->getAuditSinkSyslogIdent(),
        );
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function unusableIdentProvider(): iterable
    {
        yield 'empty string' => [''];
        yield 'whitespace only' => ['   '];
        yield 'null' => [null];
        yield 'non-string' => [42];
    }

    #[Test]
    public function syslogIdentIsTrimmed(): void
    {
        $this->typo3Config->method('get')->willReturn(['auditSinkSyslogIdent' => "  vault-prod\n"]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame('vault-prod', $config->getAuditSinkSyslogIdent());
    }

    #[Test]
    public function auditSinkFilePathReturnsConfiguredAbsolutePath(): void
    {
        $this->typo3Config->method('get')->willReturn(['auditSinkFilePath' => '/srv/audit/vault.ndjson']);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame('/srv/audit/vault.ndjson', $config->getAuditSinkFilePath());
    }

    /**
     * The default must land outside the public web root, which `<var>/log/` does
     * on every Composer-based installation — the sink refuses to run otherwise.
     */
    #[Test]
    public function auditSinkFilePathDefaultsBelowTheVarLogDirectory(): void
    {
        $this->typo3Config->method('get')->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertStringEndsWith(
            '/log/' . ExtensionConfiguration::DEFAULT_AUDIT_SINK_FILE_BASENAME,
            $config->getAuditSinkFilePath(),
        );
    }

    #[Test]
    #[DataProvider('blankPathProvider')]
    public function blankAuditSinkFilePathFallsBackToTheDefault(mixed $value): void
    {
        $this->typo3Config->method('get')->willReturn(['auditSinkFilePath' => $value]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertStringEndsWith(
            '/log/' . ExtensionConfiguration::DEFAULT_AUDIT_SINK_FILE_BASENAME,
            $config->getAuditSinkFilePath(),
        );
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function blankPathProvider(): iterable
    {
        yield 'empty string' => [''];
        yield 'whitespace only' => ['  '];
        yield 'null' => [null];
        yield 'non-string' => [123];
    }

    #[Test]
    public function auditSinkAnchorPathReturnsConfiguredAbsolutePath(): void
    {
        $this->typo3Config->method('get')->willReturn(['auditSinkAnchorPath' => '/mnt/wormfs/anchor.ndjson']);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame('/mnt/wormfs/anchor.ndjson', $config->getAuditSinkAnchorPath());
    }

    #[Test]
    public function auditSinkAnchorPathDefaultsBelowTheVarLogDirectory(): void
    {
        $this->typo3Config->method('get')->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertStringEndsWith(
            '/log/' . ExtensionConfiguration::DEFAULT_AUDIT_SINK_ANCHOR_BASENAME,
            $config->getAuditSinkAnchorPath(),
        );
    }

    /**
     * The anchor stream is the evidence that survives a table reset, so it must be
     * separately configurable rather than derived from the entry stream's path.
     */
    #[Test]
    public function entryAndAnchorPathsAreIndependentByDefault(): void
    {
        $this->typo3Config->method('get')->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertNotSame($config->getAuditSinkFilePath(), $config->getAuditSinkAnchorPath());
    }

    #[Test]
    public function webhookUrlReturnsConfiguredValueTrimmed(): void
    {
        $this->typo3Config->method('get')->willReturn(['auditSinkWebhookUrl' => '  https://siem.example.com/ingest  ']);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame('https://siem.example.com/ingest', $config->getAuditSinkWebhookUrl());
    }

    #[Test]
    public function webhookUrlDefaultsToEmpty(): void
    {
        $this->typo3Config->method('get')->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame('', $config->getAuditSinkWebhookUrl());
    }

    #[Test]
    public function nonStringWebhookUrlFallsBackToEmpty(): void
    {
        $this->typo3Config->method('get')->willReturn(['auditSinkWebhookUrl' => ['https://x']]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertSame('', $config->getAuditSinkWebhookUrl());
    }
}
