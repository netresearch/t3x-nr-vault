<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Doctor\Check;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Crypto\MasterKeyProviderFactoryInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Service\Doctor\Check\MasterKeyProviderCheck;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Service\VaultHealthServiceInterface;
use Netresearch\NrVault\Service\VaultHealthStatus;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\DoctorFindingTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(MasterKeyProviderCheck::class)]
final class MasterKeyProviderCheckTest extends TestCase
{
    use DoctorFindingTrait;

    /**
     * Key files created by this test, removed in tearDown.
     *
     * Not `$testFilesToDelete`: the testing framework's cleanup only accepts
     * paths under the TYPO3 var path, which no unit test has.
     *
     * @var list<string>
     */
    private array $keyFiles = [];

    protected function tearDown(): void
    {
        foreach ($this->keyFiles as $path) {
            if (is_file($path)) {
                // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
                unlink($path);
            }
        }
        $this->keyFiles = [];

        parent::tearDown();
    }

    #[Test]
    public function appliesToBothProfiles(): void
    {
        $check = $this->check('file');

        self::assertTrue($check->appliesTo(SecurityProfile::Standard));
        self::assertTrue($check->appliesTo(SecurityProfile::Hardened));
    }

    #[Test]
    public function anExplicitExternalProviderWithAWorkingKeyPassesEveryControl(): void
    {
        // 'env' rather than 'file' so no key-file permission control is emitted:
        // this asserts the clean baseline, not the filesystem branch.
        $findings = $this->check('env')->run($this->doctorContext(SecurityProfile::Hardened));

        foreach ($findings as $finding) {
            self::assertTrue(
                $finding->isPass(),
                \sprintf('%s should pass: %s', $finding->id, $finding->summary),
            );
        }
        self::assertSame(
            ['provider.configured', 'provider.known', 'provider.available', 'provider.master_key_readable'],
            $this->findingIds($findings),
        );
    }

    /**
     * The core hardened invariant: the TYPO3 encryption key must not protect
     * vault secrets, because the vault would then share its fate with every
     * other consumer of that key.
     */
    #[Test]
    public function theTypo3ProviderIsCriticalUnderTheHardenedProfile(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Critical,
            $this->check('typo3')->run($this->doctorContext(SecurityProfile::Hardened)),
            'provider.configured',
        );

        self::assertStringContainsString('hardened', $finding->summary);
        self::assertStringContainsString('encryptionKey', $finding->risk);
    }

    /**
     * Under the standard profile the same provider is the documented
     * zero-configuration default — a warning about shared fate, not a defect.
     */
    #[Test]
    public function theTypo3ProviderIsOnlyAWarningUnderTheStandardProfile(): void
    {
        $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check('typo3')->run($this->doctorContext(SecurityProfile::Standard)),
            'provider.configured',
        );
    }

    #[Test]
    public function anEmptyProviderIsCritical(): void
    {
        $this->assertFindingSeverity(
            FindingSeverity::Critical,
            $this->check('')->run($this->doctorContext(SecurityProfile::Standard)),
            'provider.configured',
        );
    }

    /**
     * A provider identifier this installation cannot build — a value from a later
     * release, or from an extension that is not installed here — must be named
     * rather than passed over. The check keeps no allow-list of its own, so the
     * factory stays the single authority on what resolves.
     */
    #[Test]
    public function anUnknownButConfiguredProviderIsCritical(): void
    {
        $factory = self::createStub(MasterKeyProviderFactoryInterface::class);
        $factory->method('create')
            ->willThrowException(ConfigurationException::invalidProvider('transit'));

        $check = new MasterKeyProviderCheck(
            $this->configuration('transit'),
            $factory,
            $this->healthService(true, true, 'transit'),
        );

        $finding = $this->assertFindingSeverity(
            FindingSeverity::Critical,
            $check->run($this->doctorContext(SecurityProfile::Standard)),
            'provider.known',
        );

        self::assertStringContainsString('transit', $finding->summary);
    }

    #[Test]
    public function anUnavailableProviderIsCritical(): void
    {
        $check = new MasterKeyProviderCheck(
            $this->configuration('file'),
            $this->providerFactory(),
            $this->healthService(false, false, 'file'),
        );

        $findings = $check->run($this->doctorContext(SecurityProfile::Standard));

        $this->assertFindingSeverity(FindingSeverity::Critical, $findings, 'provider.available');
        $this->assertFindingSeverity(FindingSeverity::Critical, $findings, 'provider.master_key_readable');
    }

    /**
     * A present-but-unreadable key (truncated file, wrong length) fails the second
     * control while passing the first — the two must not collapse into one.
     */
    #[Test]
    public function aPresentButUnreadableKeyFailsOnlyTheReadabilityControl(): void
    {
        $check = new MasterKeyProviderCheck(
            $this->configuration('env'),
            $this->providerFactory(),
            $this->healthService(true, false, 'env'),
        );

        $findings = $check->run($this->doctorContext(SecurityProfile::Standard));

        self::assertTrue($this->findingById($findings, 'provider.available')->isPass());
        $this->assertFindingSeverity(FindingSeverity::Critical, $findings, 'provider.master_key_readable');
    }

    /**
     * Auto-detection silently running on a different key source than the
     * configuration names is the failure mode that only surfaces later, when the
     * hardened profile removes the fallback and the vault stops booting.
     */
    #[Test]
    public function aResolvedProviderDifferentFromTheConfiguredOneIsAWarning(): void
    {
        $check = new MasterKeyProviderCheck(
            $this->configuration('file'),
            $this->providerFactory(),
            $this->healthService(true, true, 'typo3'),
        );

        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $check->run($this->doctorContext(SecurityProfile::Standard)),
            'provider.available',
        );

        self::assertSame('file', $finding->details['configuredProvider']);
        self::assertSame('typo3', $finding->details['resolvedProvider']);
    }

    #[Test]
    public function noKeyFilePermissionControlIsEmittedForNonFileProviders(): void
    {
        $ids = $this->findingIds($this->check('env')->run($this->doctorContext(SecurityProfile::Standard)));

        self::assertNotContains('provider.key_permissions', $ids);
    }

    #[Test]
    #[DataProvider('groupReadableModeProvider')]
    public function aKeyFileReadableBeyondItsOwnerIsCritical(int $mode): void
    {
        $path = $this->createKeyFile($mode);

        $finding = $this->assertFindingSeverity(
            FindingSeverity::Critical,
            $this->check('file', $path)->run($this->doctorContext(SecurityProfile::Standard)),
            'provider.key_permissions',
        );

        self::assertSame(\sprintf('0%o', $mode), $finding->details['mode']);
        // The path must never reach the finding — the JSON report goes into CI logs.
        self::assertStringNotContainsString($path, $finding->summary . $finding->risk . $finding->remediation);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function groupReadableModeProvider(): iterable
    {
        yield 'group readable' => [0o440];
        yield 'world readable' => [0o444];
        yield 'group writable' => [0o460];
        yield 'world writable' => [0o406];
    }

    #[Test]
    #[DataProvider('ownerOnlyModeProvider')]
    public function anOwnerOnlyKeyFilePasses(int $mode): void
    {
        $finding = $this->findingById(
            $this->check('file', $this->createKeyFile($mode))
                ->run($this->doctorContext(SecurityProfile::Standard)),
            'provider.key_permissions',
        );

        self::assertTrue($finding->isPass(), $finding->summary);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function ownerOnlyModeProvider(): iterable
    {
        yield 'read only' => [0o400];
        yield 'read write' => [0o600];
    }

    #[Test]
    public function aMissingKeyFileIsAWarningRatherThanACrash(): void
    {
        $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check('file', '/nonexistent/nr-vault-test/master.key')
                ->run($this->doctorContext(SecurityProfile::Standard)),
            'provider.key_permissions',
        );
    }

    private function check(string $provider, string $keySource = 'NR_VAULT_MASTER_KEY'): MasterKeyProviderCheck
    {
        return new MasterKeyProviderCheck(
            $this->configuration($provider, $keySource),
            $this->providerFactory(),
            $this->healthService(true, true, $provider),
        );
    }

    private function configuration(
        string $provider,
        string $keySource = 'NR_VAULT_MASTER_KEY',
    ): ExtensionConfigurationInterface {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getMasterKeyProvider')->willReturn($provider);
        $configuration->method('getMasterKeySource')->willReturn($keySource);
        // A path that cannot exist, so the auto-key fallback never picks up a real
        // file from the test host.
        $configuration->method('getAutoKeyPath')->willReturn('/nonexistent/nr-vault-test/auto.key');

        return $configuration;
    }

    private function providerFactory(): MasterKeyProviderFactoryInterface
    {
        $factory = self::createStub(MasterKeyProviderFactoryInterface::class);
        $factory->method('create')->willReturn(self::createStub(MasterKeyProviderInterface::class));

        return $factory;
    }

    private function healthService(
        bool $available,
        bool $working,
        string $resolvedProvider,
    ): VaultHealthServiceInterface {
        $service = self::createStub(VaultHealthServiceInterface::class);
        $service->method('checkHealth')->willReturn(new VaultHealthStatus(
            masterKeyAvailable: $available,
            masterKeyProvider: $resolvedProvider,
            encryptionWorking: $working,
            hasIssues: !$available || !$working,
        ));

        return $service;
    }

    /**
     * A throwaway key file with an exact mode, removed on tearDown.
     */
    private function createKeyFile(int $mode): string
    {
        $path = sys_get_temp_dir() . '/nr-vault-doctor-' . bin2hex(random_bytes(8)) . '.key';
        file_put_contents($path, base64_encode(random_bytes(32)));
        chmod($path, $mode);
        $this->keyFiles[] = $path;

        return $path;
    }
}
