<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Netresearch\NrVault\Command\VaultStoreCommand;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Security\TechnicalActorContextInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

#[CoversClass(VaultStoreCommand::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultStoreCommandTest extends TestCase
{
    private VaultServiceInterface&MockObject $vaultService;

    private ExtensionConfigurationInterface&MockObject $configuration;

    private TechnicalActorContextInterface&MockObject $technicalActorContext;

    private CommandTester $commandTester;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $this->technicalActorContext = $this->createMock(TechnicalActorContextInterface::class);

        $command = $this->createCommand();

        $application = new Application();
        $application->addCommand($command);

        $this->commandTester = new CommandTester($command);
    }

    #[Test]
    public function hasCorrectName(): void
    {
        self::assertSame('vault:store', $this->createCommand()->getName());
    }

    /**
     * Without the flag nothing changes: no actor scope is entered, and the
     * configured UID is irrelevant. Guards against the option silently
     * re-attributing an interactive operator's write.
     */
    #[Test]
    public function storesAsTheCallingActorWhenTheFlagIsAbsent(): void
    {
        $this->configuration->method('getProvisioningBeUserUid')->willReturn(991);
        $this->technicalActorContext->expects($this->never())->method('runAs');
        $this->vaultService->expects($this->once())->method('store');

        $exitCode = $this->commandTester->execute([
            'identifier' => 'openai_api_key',
            '--value' => 'secret-value',
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function storesInsideTheConfiguredActorScopeWithTheFlag(): void
    {
        $this->configuration->method('getProvisioningBeUserUid')->willReturn(991);

        $ranInsideScope = false;
        $this->technicalActorContext
            ->expects($this->once())
            ->method('runAs')
            ->with(991, self::isCallable())
            ->willReturnCallback(static function (int $uid, callable $fn) use (&$ranInsideScope): mixed {
                $ranInsideScope = true;

                return $fn();
            });

        $this->vaultService->expects($this->once())->method('store');

        $exitCode = $this->commandTester->execute([
            'identifier' => 'openai_api_key',
            '--value' => 'secret-value',
            '--as-provisioner' => true,
        ]);

        self::assertSame(0, $exitCode);
        self::assertTrue($ranInsideScope, 'store() ran outside the technical actor scope.');
    }

    /**
     * Fail closed. Writing as the unattributed CLI actor because no provisioning
     * user is configured would silently deliver the opposite of what the flag
     * asks for — an unattributed write where an attributed one was requested.
     */
    #[Test]
    public function refusesTheFlagWhenNoProvisioningActorIsConfigured(): void
    {
        $this->configuration->method('getProvisioningBeUserUid')->willReturn(0);
        $this->technicalActorContext->expects($this->never())->method('runAs');
        $this->vaultService->expects($this->never())->method('store');

        $exitCode = $this->commandTester->execute([
            'identifier' => 'openai_api_key',
            '--value' => 'secret-value',
            '--as-provisioner' => true,
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('provisioningBeUserUid', $this->commandTester->getDisplay());
    }

    #[Test]
    public function storesSecretWithValueOption(): void
    {
        $this->vaultService
            ->expects($this->once())
            ->method('store')
            ->with('my-api-key', 'secret-value-123', []);

        $exitCode = $this->commandTester->execute([
            'identifier' => 'my-api-key',
            '--value' => 'secret-value-123',
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('stored successfully', $this->commandTester->getDisplay());
    }

    #[Test]
    public function storesSecretFromFile(): void
    {
        $root = vfsStream::setup('test');
        vfsStream::newFile('secret.txt')
            ->withContent('file-secret-content')
            ->at($root);

        $this->vaultService
            ->expects($this->once())
            ->method('store')
            ->with('file-secret', 'file-secret-content', []);

        $exitCode = $this->commandTester->execute([
            'identifier' => 'file-secret',
            '--file' => vfsStream::url('test/secret.txt'),
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function failsWhenFileNotFound(): void
    {
        $exitCode = $this->commandTester->execute([
            'identifier' => 'test',
            '--file' => '/nonexistent/file.txt',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('File not found', $this->commandTester->getDisplay());
    }

    #[Test]
    public function failsWhenNoValueProvided(): void
    {
        $exitCode = $this->commandTester->execute(
            ['identifier' => 'test'],
            ['interactive' => false],
        );

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('No secret value provided', $this->commandTester->getDisplay());
    }

    #[Test]
    public function parsesMetadataOptions(): void
    {
        $this->vaultService
            ->expects($this->once())
            ->method('store')
            ->with(
                'metadata-test',
                'secret',
                $this->callback(fn (array $metadata): bool => $metadata['service'] === 'stripe'
                    && $metadata['env'] === 'production'),
            );

        $exitCode = $this->commandTester->execute([
            'identifier' => 'metadata-test',
            '--value' => 'secret',
            '--metadata' => ['service=stripe', 'env=production'],
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function parsesGroupsOption(): void
    {
        $this->vaultService
            ->expects($this->once())
            ->method('store')
            ->with(
                'groups-test',
                'secret',
                $this->callback(fn (array $metadata): bool => isset($metadata['allowed_groups'])
                    && $metadata['allowed_groups'] === [1, 2, 3]),
            );

        $exitCode = $this->commandTester->execute([
            'identifier' => 'groups-test',
            '--value' => 'secret',
            '--groups' => ['1', '2', '3'],
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function handlesVaultException(): void
    {
        $this->vaultService
            ->method('store')
            ->willThrowException(new VaultException('Storage failed'));

        $exitCode = $this->commandTester->execute([
            'identifier' => 'test',
            '--value' => 'secret',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Storage failed', $this->commandTester->getDisplay());
    }

    #[Test]
    public function handlesValidationException(): void
    {
        $this->vaultService
            ->method('store')
            ->willThrowException(ValidationException::invalidIdentifier('bad!identifier', 'contains invalid characters'));

        $exitCode = $this->commandTester->execute([
            'identifier' => 'bad!identifier',
            '--value' => 'secret',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('invalid', $this->commandTester->getDisplay());
    }

    #[Test]
    public function trimsNewlineFromFileContent(): void
    {
        $root = vfsStream::setup('test');
        vfsStream::newFile('secret-with-newline.txt')
            ->withContent("secret-content\n")
            ->at($root);

        $this->vaultService
            ->expects($this->once())
            ->method('store')
            ->with('file-trim-test', "secret-content\n", []);

        $exitCode = $this->commandTester->execute([
            'identifier' => 'file-trim-test',
            '--file' => vfsStream::url('test/secret-with-newline.txt'),
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function ignoresMetadataWithoutEquals(): void
    {
        $this->vaultService
            ->expects($this->once())
            ->method('store')
            ->with(
                'metadata-no-equals',
                'secret',
                $this->callback(fn (array $metadata): bool => $metadata === ['valid' => 'value']),
            );

        $exitCode = $this->commandTester->execute([
            'identifier' => 'metadata-no-equals',
            '--value' => 'secret',
            '--metadata' => ['valid=value', 'invalid-no-equals'],
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function displaysSuccessMessageWithIdentifier(): void
    {
        $exitCode = $this->commandTester->execute([
            'identifier' => 'display-test-id',
            '--value' => 'secret',
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('display-test-id', $this->commandTester->getDisplay());
        self::assertStringContainsString('stored successfully', $this->commandTester->getDisplay());
    }

    #[Test]
    public function handlesEmptyGroupsArray(): void
    {
        $this->vaultService
            ->expects($this->once())
            ->method('store')
            ->with('empty-groups', 'secret', []);

        $exitCode = $this->commandTester->execute([
            'identifier' => 'empty-groups',
            '--value' => 'secret',
            '--groups' => [],
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function parsesSingleGroupCorrectly(): void
    {
        $this->vaultService
            ->expects($this->once())
            ->method('store')
            ->with(
                'single-group',
                'secret',
                $this->callback(fn (array $metadata): bool => isset($metadata['allowed_groups'])
                    && $metadata['allowed_groups'] === [5]),
            );

        $exitCode = $this->commandTester->execute([
            'identifier' => 'single-group',
            '--value' => 'secret',
            '--groups' => ['5'],
        ]);

        self::assertSame(0, $exitCode);
    }

    private function createCommand(): VaultStoreCommand
    {
        return new VaultStoreCommand(
            $this->vaultService,
            $this->configuration,
            $this->technicalActorContext,
        );
    }
}
