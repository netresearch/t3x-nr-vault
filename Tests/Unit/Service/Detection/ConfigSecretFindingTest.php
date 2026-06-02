<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Detection;

use Netresearch\NrVault\Service\Detection\ConfigSecretFinding;
use Netresearch\NrVault\Service\Detection\SecretFinding;
use Netresearch\NrVault\Service\Detection\Severity;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(ConfigSecretFinding::class)]
final class ConfigSecretFindingTest extends TestCase
{
    private const SYS_KEY_PATH = 'SYS/key';

    private const CUSTOM_MESSAGE = 'Custom message';

    #[Test]
    public function implementsSecretFinding(): void
    {
        $finding = new ConfigSecretFinding(
            path: self::SYS_KEY_PATH,
            severity: Severity::High,
            isLocalConfiguration: true,
        );

        self::assertInstanceOf(SecretFinding::class, $finding);
    }

    #[Test]
    public function constructorSetsProperties(): void
    {
        $finding = new ConfigSecretFinding(
            path: 'EXTENSIONS/my_ext/apiKey',
            severity: Severity::Critical,
            isLocalConfiguration: false,
            patterns: ['API Key'],
            message: self::CUSTOM_MESSAGE,
        );

        self::assertEquals('EXTENSIONS/my_ext/apiKey', $finding->path);
        self::assertEquals(Severity::Critical, $finding->severity);
        self::assertFalse($finding->isLocalConfiguration);
        self::assertEquals(['API Key'], $finding->patterns);
        self::assertEquals(self::CUSTOM_MESSAGE, $finding->message);
    }

    #[Test]
    public function getKeyPrefixesWithConfigForLocalConfiguration(): void
    {
        $finding = new ConfigSecretFinding(
            path: 'SYS/encryptionKey',
            severity: Severity::High,
            isLocalConfiguration: true,
        );

        self::assertEquals('config:SYS/encryptionKey', $finding->getKey());
    }

    #[Test]
    public function getKeyReturnsPathForNonLocalConfiguration(): void
    {
        $finding = new ConfigSecretFinding(
            path: 'EXTENSIONS/my_ext/secret',
            severity: Severity::Medium,
            isLocalConfiguration: false,
        );

        self::assertEquals('EXTENSIONS/my_ext/secret', $finding->getKey());
    }

    #[Test]
    public function getSourceReturnsConfig(): void
    {
        $finding = new ConfigSecretFinding(
            path: 'path',
            severity: Severity::Low,
            isLocalConfiguration: true,
        );

        self::assertEquals('config', $finding->getSource());
    }

    #[Test]
    public function getSeverityReturnsSeverity(): void
    {
        $finding = new ConfigSecretFinding(
            path: 'path',
            severity: Severity::Medium,
            isLocalConfiguration: true,
        );

        self::assertEquals(Severity::Medium, $finding->getSeverity());
    }

    #[Test]
    public function getPatternsReturnsPatterns(): void
    {
        $patterns = ['Pattern 1', 'Pattern 2'];
        $finding = new ConfigSecretFinding(
            path: 'path',
            severity: Severity::Low,
            isLocalConfiguration: true,
            patterns: $patterns,
        );

        self::assertEquals($patterns, $finding->getPatterns());
    }

    #[Test]
    public function patternsDefaultToEmptyArray(): void
    {
        $finding = new ConfigSecretFinding(
            path: 'path',
            severity: Severity::Low,
            isLocalConfiguration: true,
        );

        self::assertEquals([], $finding->getPatterns());
    }

    #[Test]
    public function getDetailsReturnsCustomMessage(): void
    {
        $finding = new ConfigSecretFinding(
            path: 'path',
            severity: Severity::High,
            isLocalConfiguration: true,
            message: 'Found Stripe API key in configuration',
        );

        self::assertEquals('Found Stripe API key in configuration', $finding->getDetails());
    }

    #[Test]
    public function getDetailsReturnsLocalConfigurationForLocalConfig(): void
    {
        $finding = new ConfigSecretFinding(
            path: 'path',
            severity: Severity::High,
            isLocalConfiguration: true,
        );

        self::assertEquals('LocalConfiguration.php', $finding->getDetails());
    }

    #[Test]
    public function getDetailsReturnsExtensionConfigForNonLocalConfig(): void
    {
        $finding = new ConfigSecretFinding(
            path: 'path',
            severity: Severity::High,
            isLocalConfiguration: false,
        );

        self::assertEquals('Extension config', $finding->getDetails());
    }

    #[Test]
    public function jsonSerializeReturnsCorrectStructureForLocalConfig(): void
    {
        $finding = new ConfigSecretFinding(
            path: self::SYS_KEY_PATH,
            severity: Severity::High,
            isLocalConfiguration: true,
            patterns: ['Secret'],
        );

        $json = $finding->jsonSerialize();

        self::assertEquals('LocalConfiguration', $json['source']);
        self::assertEquals(self::SYS_KEY_PATH, $json['path']);
        self::assertEquals('high', $json['severity']);
        self::assertEquals(['Secret'], $json['patterns']);
        self::assertArrayNotHasKey('message', $json);
    }

    #[Test]
    public function jsonSerializeReturnsCorrectStructureForExtensionConfig(): void
    {
        $finding = new ConfigSecretFinding(
            path: 'EXTENSIONS/ext/key',
            severity: Severity::Medium,
            isLocalConfiguration: false,
        );

        $json = $finding->jsonSerialize();

        self::assertEquals('configuration', $json['source']);
    }

    #[Test]
    public function jsonSerializeIncludesMessageWhenSet(): void
    {
        $finding = new ConfigSecretFinding(
            path: 'path',
            severity: Severity::High,
            isLocalConfiguration: true,
            message: self::CUSTOM_MESSAGE,
        );

        $json = $finding->jsonSerialize();

        self::assertArrayHasKey('message', $json);
        self::assertEquals(self::CUSTOM_MESSAGE, $json['message']);
    }

    #[Test]
    public function canBeJsonEncoded(): void
    {
        $finding = new ConfigSecretFinding(
            path: 'test/path',
            severity: Severity::Low,
            isLocalConfiguration: true,
        );

        $json = json_encode($finding);

        self::assertJson($json);
        self::assertStringContainsString('"source":"LocalConfiguration"', $json);
    }
}
