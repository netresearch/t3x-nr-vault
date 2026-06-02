<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\TCA;

use Netresearch\NrVault\TCA\VaultFieldHelper;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\Test;

final class VaultFieldHelperTest extends TestCase
{
    private const LABEL_API_KEY = 'API Key';

    protected bool $resetSingletonInstances = true;

    #[Test]
    public function getFieldConfigReturnsBasicConfig(): void
    {
        $config = VaultFieldHelper::getFieldConfig();

        self::assertIsArray($config);
        self::assertSame('input', $config['config']['type']);
        self::assertSame('vaultSecret', $config['config']['renderType']);
        self::assertSame(30, $config['config']['size']);
    }

    #[Test]
    public function getFieldConfigAcceptsLabel(): void
    {
        $config = VaultFieldHelper::getFieldConfig(['label' => self::LABEL_API_KEY]);

        self::assertSame(self::LABEL_API_KEY, $config['label']);
    }

    #[Test]
    public function getFieldConfigAcceptsDescription(): void
    {
        $config = VaultFieldHelper::getFieldConfig([
            'description' => 'Your secret API key',
        ]);

        self::assertSame('Your secret API key', $config['description']);
    }

    #[Test]
    public function getFieldConfigAcceptsCustomSize(): void
    {
        $config = VaultFieldHelper::getFieldConfig(['size' => 50]);

        self::assertSame(50, $config['config']['size']);
    }

    #[Test]
    public function getFieldConfigHandlesRequired(): void
    {
        $configRequired = VaultFieldHelper::getFieldConfig(['required' => true]);
        $configOptional = VaultFieldHelper::getFieldConfig(['required' => false]);
        $configDefault = VaultFieldHelper::getFieldConfig();

        self::assertTrue($configRequired['config']['required']);
        self::assertArrayNotHasKey('required', $configOptional['config']);
        self::assertArrayNotHasKey('required', $configDefault['config']);
    }

    #[Test]
    public function getFieldConfigAcceptsPlaceholder(): void
    {
        $config = VaultFieldHelper::getFieldConfig([
            'placeholder' => 'Enter your API key...',
        ]);

        self::assertSame('Enter your API key...', $config['config']['placeholder']);
    }

    #[Test]
    public function getFieldConfigAcceptsDisplayCond(): void
    {
        $config = VaultFieldHelper::getFieldConfig([
            'displayCond' => 'FIELD:type:=:api',
        ]);

        self::assertSame('FIELD:type:=:api', $config['displayCond']);
    }

    #[Test]
    public function getFieldConfigAcceptsL10nMode(): void
    {
        $config = VaultFieldHelper::getFieldConfig([
            'l10n_mode' => 'exclude',
        ]);

        self::assertSame('exclude', $config['l10n_mode']);
    }

    #[Test]
    public function getFieldConfigAcceptsExclude(): void
    {
        $config = VaultFieldHelper::getFieldConfig(['exclude' => true]);

        self::assertTrue($config['exclude']);
    }

    #[Test]
    public function getSecureFieldConfigIncludesDefaults(): void
    {
        $config = VaultFieldHelper::getSecureFieldConfig(self::LABEL_API_KEY);

        self::assertSame(self::LABEL_API_KEY, $config['label']);
        self::assertTrue($config['exclude']);
        self::assertSame('exclude', $config['l10n_mode']);
        self::assertSame('vaultSecret', $config['config']['renderType']);
    }

    #[Test]
    public function getSecureFieldConfigAllowsOverrides(): void
    {
        $config = VaultFieldHelper::getSecureFieldConfig(self::LABEL_API_KEY, [
            'exclude' => false,
            'required' => true,
        ]);

        self::assertFalse($config['exclude']);
        self::assertTrue($config['config']['required']);
    }

    #[Test]
    public function getSqlDefinitionReturnsCorrectSql(): void
    {
        $sql = VaultFieldHelper::getSqlDefinition('api_key');

        self::assertSame("api_key varchar(255) DEFAULT '' NOT NULL", $sql);
    }

    #[Test]
    public function addVaultFieldsAddsFieldsToTca(): void
    {
        $tca = [
            'columns' => [
                'title' => ['label' => 'Title', 'config' => ['type' => 'input']],
            ],
        ];

        $result = VaultFieldHelper::addVaultFields($tca, [
            'api_key' => ['label' => self::LABEL_API_KEY],
            'api_secret' => ['label' => 'API Secret', 'required' => true],
        ]);

        self::assertArrayHasKey('title', $result['columns']);
        self::assertArrayHasKey('api_key', $result['columns']);
        self::assertArrayHasKey('api_secret', $result['columns']);
        self::assertSame('vaultSecret', $result['columns']['api_key']['config']['renderType']);
        self::assertSame('vaultSecret', $result['columns']['api_secret']['config']['renderType']);
    }

    #[Test]
    public function isVaultFieldReturnsTrueForVaultField(): void
    {
        $fieldConfig = [
            'config' => [
                'type' => 'input',
                'renderType' => 'vaultSecret',
            ],
        ];

        self::assertTrue(VaultFieldHelper::isVaultField($fieldConfig));
    }

    #[Test]
    public function isVaultFieldReturnsFalseForOtherFields(): void
    {
        $inputField = ['config' => ['type' => 'input']];
        $textField = ['config' => ['type' => 'text']];
        $passwordField = ['config' => ['type' => 'password']];
        $otherRenderType = ['config' => ['type' => 'input', 'renderType' => 'colorpicker']];

        self::assertFalse(VaultFieldHelper::isVaultField($inputField));
        self::assertFalse(VaultFieldHelper::isVaultField($textField));
        self::assertFalse(VaultFieldHelper::isVaultField($passwordField));
        self::assertFalse(VaultFieldHelper::isVaultField($otherRenderType));
    }
}
