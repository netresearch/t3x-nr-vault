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
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration as Typo3ExtensionConfiguration;

#[CoversClass(ExtensionConfiguration::class)]
#[AllowMockObjectsWithoutExpectations]
final class ExtensionConfigurationTest extends TestCase
{
    private Typo3ExtensionConfiguration&MockObject $typo3Config;

    protected function setUp(): void
    {
        parent::setUp();
        $this->typo3Config = $this->createMock(Typo3ExtensionConfiguration::class);
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
    public function isCacheEnabledReturnsTrueByDefault(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn([]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertTrue($config->isCacheEnabled());
    }

    #[Test]
    public function isCacheEnabledReturnsFalseWhenDisabled(): void
    {
        $this->typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn(['cacheEnabled' => false]);

        $config = new ExtensionConfiguration($this->typo3Config);

        self::assertFalse($config->isCacheEnabled());
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
}
