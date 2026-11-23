<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use ArrayObject;
use Netresearch\NrVault\Command\VaultStoreCommand;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Domain\Dto\SecretDetails;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Security\TechnicalActorContextInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use RuntimeException;
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

        $this->vaultService          = $this->createMock(VaultServiceInterface::class);
        $this->configuration         = $this->createMock(ExtensionConfigurationInterface::class);
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
            '--value'    => 'secret-value',
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
            'identifier'       => 'openai_api_key',
            '--value'          => 'secret-value',
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
            'identifier'       => 'openai_api_key',
            '--value'          => 'secret-value',
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
            '--value'    => 'secret-value-123',
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
            '--file'     => vfsStream::url('test/secret.txt'),
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function failsWhenFileNotFound(): void
    {
        $exitCode = $this->commandTester->execute([
            'identifier' => 'test',
            '--file'     => '/nonexistent/file.txt',
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

    /**
     * #524: free-form pairs belong under `metadata`, the key the service reads.
     */
    #[Test]
    public function parsesMetadataOptions(): void
    {
        $this->vaultService->method('getMetadata')->willThrowException(SecretNotFoundException::forIdentifier('metadata-test'));
        $this->vaultService
            ->expects($this->once())
            ->method('store')
            ->with(
                'metadata-test',
                'secret',
                ['metadata' => ['service' => 'stripe', 'env' => 'production']],
            );

        $exitCode = $this->commandTester->execute([
            'identifier' => 'metadata-test',
            '--value'    => 'secret',
            '--metadata' => ['service=stripe', 'env=production'],
        ]);

        self::assertSame(0, $exitCode);
    }

    /**
     * #524: groups go under `groups`, the key the service reads.
     */
    #[Test]
    public function parsesGroupsOption(): void
    {
        $this->vaultService
            ->expects($this->once())
            ->method('store')
            ->with('groups-test', 'secret', ['groups' => [1, 2, 3]]);

        $exitCode = $this->commandTester->execute([
            'identifier' => 'groups-test',
            '--value'    => 'secret',
            '--groups'   => ['1', '2', '3'],
        ]);

        self::assertSame(0, $exitCode);
    }

    /**
     * The path the plaintext wipe used to miss.
     *
     * Actor resolution runs before the callback and can fail with something
     * that is not a VaultException, and so can an audit write underneath the
     * store. Neither branch of the old try/catch covered that, so `$value`
     * survived in memory (CWE-316); the wipe now sits in `finally`.
     *
     * What this pins is the path, not the wipe: a zeroed local variable leaves
     * no seam a test can read. It fails if the failure ever stops propagating
     * — which is the assumption `finally` rests on.
     */
    #[Test]
    public function aFailureOutsideTheVaultExceptionHierarchyPropagates(): void
    {
        $this->configuration->method('getProvisioningBeUserUid')->willReturn(991);
        $this->technicalActorContext
            ->method('runAs')
            ->willThrowException(new RuntimeException('actor resolution failed'));

        $this->expectException(RuntimeException::class);

        $this->commandTester->execute([
            'identifier'       => 'openai_api_key',
            '--value'          => 'secret-value',
            '--as-provisioner' => true,
        ]);
    }

    #[Test]
    public function handlesVaultException(): void
    {
        $this->vaultService
            ->method('store')
            ->willThrowException(new VaultException('Storage failed'));

        $exitCode = $this->commandTester->execute([
            'identifier' => 'test',
            '--value'    => 'secret',
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
            '--value'    => 'secret',
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
            '--file'     => vfsStream::url('test/secret-with-newline.txt'),
        ]);

        self::assertSame(0, $exitCode);
    }

    /**
     * A pair without "=" was silently dropped; it is refused now, before the
     * secret value is read (no --value is given and nothing prompts).
     *
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function refusedOptionProvider(): array
    {
        return [
            'metadata without equals'   => [['--metadata' => ['valid=value', 'invalid-no-equals']], 'expected key=value'],
            'metadata with empty key'   => [['--metadata' => ['=value']], 'the key is empty'],
            'groups through metadata'   => [['--metadata' => ['groups=1']], 'use --groups'],
            'frontend flag'             => [['--metadata' => ['frontendAccessible=0']], 'frontend availability'],
            'nested metadata key'       => [['--metadata' => ['metadata=x']], 'key=value pairs directly'],
            'orphan link source'        => [['--metadata' => ['source=tca_field']], 'orphan cleanup'],
            'orphan link uid'           => [['--metadata' => ['uid=7']], 'orphan cleanup'],
            'orphan link table'         => [['--metadata' => ['table=tt_content']], 'orphan cleanup'],
            'orphan link field'         => [['--metadata' => ['field=bodytext']], 'orphan cleanup'],
            'orphan link flexField'     => [['--metadata' => ['flexField=settings.apiKey']], 'orphan cleanup'],
            'expiry that is not a time' => [['--metadata' => ['expiresAt=2026-12-31']], 'expiresAt must be a non-negative integer'],
            'owner that is not a uid'   => [['--metadata' => ['owner=ci']], 'owner must be a non-negative integer'],
            'scope that is not a pid'   => [['--metadata' => ['scopePid=root']], 'scopePid must be a non-negative integer'],
            'comma-separated groups'    => [['--groups' => ['1,2']], 'Invalid --groups value "1,2"'],
            'group zero'                => [['--groups' => ['0']], 'Invalid --groups value "0"'],
            'group name'                => [['--groups' => ['editors']], 'Invalid --groups value "editors"'],
            'group beyond int range'    => [['--groups' => ['99999999999999999999']], 'Invalid --groups value "99999999999999999999"'],
            'group beyond column range' => [['--groups' => ['4294967296']], 'Invalid --groups value "4294967296"'],
            'expiry beyond column range' => [['--metadata' => ['expiresAt=4294967296']], 'expiresAt must be a non-negative integer'],
            'expiry beyond int range'   => [['--metadata' => ['expiresAt=99999999999999999999']], 'expiresAt must be a non-negative integer'],
        ];
    }

    /**
     * @param array<string, mixed> $options
     */
    #[Test]
    #[DataProvider('refusedOptionProvider')]
    public function refusesAnOptionTheServiceWouldMisreadBeforeReadingTheValue(array $options, string $message): void
    {
        $this->vaultService->expects($this->never())->method('store');
        $this->vaultService->expects($this->never())->method('getMetadata');

        $exitCode = $this->commandTester->execute(['identifier' => 'refused'] + $options, ['interactive' => false]);

        self::assertSame(1, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString($message, preg_replace('/\s+/', ' ', $display) ?? $display);
        self::assertStringNotContainsString('No secret value provided', $display, 'the options must be refused before the value is read');
    }

    #[Test]
    public function documentedFieldKeysStayTopLevelOptions(): void
    {
        $this->vaultService->expects($this->never())->method('getMetadata');
        $this->vaultService
            ->expects($this->once())
            ->method('store')
            ->with('fields', 'secret', [
                'description' => 'Stripe production key',
                'context'     => 'payment',
                'expiresAt'   => '1893456000',
                'owner'       => '3',
                'scopePid'    => '12',
            ]);

        $exitCode = $this->commandTester->execute([
            'identifier' => 'fields',
            '--value'    => 'secret',
            '--metadata' => ['description=Stripe production key', 'context=payment', 'expiresAt=1893456000', 'owner=3', 'scopePid=12'],
        ]);

        self::assertSame(0, $exitCode);
    }

    /**
     * The service replaces the metadata map, so the command merges the given
     * pairs into the stored ones.
     */
    #[Test]
    public function mergesFreeFormMetadataIntoTheStoredMap(): void
    {
        $this->vaultService->method('getMetadata')->willReturn($this->details(['team' => 'a', 'note' => 'old']));
        $this->vaultService
            ->expects($this->once())
            ->method('store')
            ->with('merge', 'secret', ['metadata' => ['team' => 'a', 'note' => 'new', 'ticket' => 'OPS-1']]);

        $exitCode = $this->commandTester->execute([
            'identifier' => 'merge',
            '--value'    => 'secret',
            '--metadata' => ['note=new', 'ticket=OPS-1'],
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function aMetadataReadDenialNamesTheWayAround(): void
    {
        $this->vaultService->method('getMetadata')->willThrowException(AccessDeniedException::forIdentifier('merge'));
        $this->vaultService->expects($this->never())->method('store');

        $exitCode = $this->commandTester->execute([
            'identifier' => 'merge',
            '--value'    => 'secret',
            '--metadata' => ['note=new'],
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('leave out --metadata', preg_replace('/\s+/', ' ', $this->commandTester->getDisplay()) ?? '');
    }

    /**
     * The merge read runs as the provisioning actor: outside its scope the
     * plain CLI user would be checked instead (and refused without CLI access).
     */
    #[Test]
    public function theMetadataReadRunsInsideTheProvisionerScope(): void
    {
        $this->configuration->method('getProvisioningBeUserUid')->willReturn(991);
        $scope = new ArrayObject(['active' => false]);
        $this->technicalActorContext
            ->method('runAs')
            ->willReturnCallback(static function (int $uid, callable $fn) use ($scope): mixed {
                $scope['active'] = true;

                try {
                    return $fn();
                } finally {
                    $scope['active'] = false;
                }
            });
        $readInScope = [];
        $this->vaultService
            ->expects($this->once())
            ->method('getMetadata')
            ->willReturnCallback(function () use ($scope, &$readInScope): SecretDetails {
                $readInScope[] = $scope['active'];

                return $this->details(['team' => 'a']);
            });
        $this->vaultService->expects($this->once())->method('store');

        $exitCode = $this->commandTester->execute([
            'identifier'       => 'scoped',
            '--value'          => 'secret',
            '--metadata'       => ['note=x'],
            '--as-provisioner' => true,
        ]);

        self::assertSame(0, $exitCode);
        self::assertSame([true], $readInScope, 'getMetadata() ran outside the technical actor scope.');
    }

    #[Test]
    public function noMetadataIsReadWhenTheProvisionerScopeIsNotEntered(): void
    {
        $this->configuration->method('getProvisioningBeUserUid')->willReturn(991);
        $this->technicalActorContext->method('runAs')->willReturn(null);
        $this->vaultService->expects($this->never())->method('getMetadata');
        $this->vaultService->expects($this->never())->method('store');

        $this->commandTester->execute([
            'identifier'       => 'scoped',
            '--value'          => 'secret',
            '--metadata'       => ['note=x'],
            '--as-provisioner' => true,
        ]);
    }

    #[Test]
    public function repeatedGroupsArePassedOnce(): void
    {
        $this->vaultService
            ->expects($this->once())
            ->method('store')
            ->with('dedup', 'secret', ['groups' => [1, 4]]);

        $exitCode = $this->commandTester->execute([
            'identifier' => 'dedup',
            '--value'    => 'secret',
            '--groups'   => ['1', '4', '1'],
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function displaysSuccessMessageWithIdentifier(): void
    {
        $exitCode = $this->commandTester->execute([
            'identifier' => 'display-test-id',
            '--value'    => 'secret',
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
            '--value'    => 'secret',
            '--groups'   => [],
        ]);

        self::assertSame(0, $exitCode);
    }

    #[Test]
    public function parsesSingleGroupCorrectly(): void
    {
        $this->vaultService
            ->expects($this->once())
            ->method('store')
            ->with('single-group', 'secret', ['groups' => [5]]);

        $exitCode = $this->commandTester->execute([
            'identifier' => 'single-group',
            '--value'    => 'secret',
            '--groups'   => ['5'],
        ]);

        self::assertSame(0, $exitCode);
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function details(array $metadata): SecretDetails
    {
        return new SecretDetails(
            uid: 1,
            identifier: 'merge',
            description: '',
            ownerUid: 1,
            groups: [],
            context: '',
            frontendAccessible: false,
            version: 1,
            createdAt: 0,
            updatedAt: 0,
            expiresAt: null,
            lastRotatedAt: null,
            readCount: 0,
            lastReadAt: null,
            metadata: $metadata,
            scopePid: 0,
        );
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
