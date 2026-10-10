<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Configuration;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use mysqli;
use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Command\VaultRetrieveCommand;
use Netresearch\NrVault\Command\VaultStoreCommand;
use Netresearch\NrVault\Configuration\SiteConfigurationVaultProcessor;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Http\DnsResolverInterface;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Http\VaultHttpClient;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Site\Entity\Site;
use TYPO3\CMS\Core\Site\SiteFinder;
use TYPO3\CMS\Core\Utility\GeneralUtility;

#[CoversClass(SiteConfigurationVaultProcessor::class)]
final class SiteSecretNamespaceTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../Controller/Fixtures/be_users.csv';

    #[Test]
    public function publicCreationResolvesDifferentValuesForTwoSitesAndPreservesReadAudit(): void
    {
        $main = $this->configureSite('main', 1);
        $other = $this->configureSite('other', 2);
        $service = $this->get(VaultServiceInterface::class);
        $service->store('payment_key', 'synthetic-global');
        $this->storeCanonical('site:main:payment_key', 'synthetic-main');
        $this->storeCanonical('site:other:payment_key', 'synthetic-other');
        $processor = new SiteConfigurationVaultProcessor($service, new NullLogger());
        $config = ['key' => '%vault(payment_key)%'];
        self::assertSame(
            ['key' => 'synthetic-main'],
            $processor->processConfiguration($config, $main),
        );
        self::assertSame(
            ['key' => 'synthetic-other'],
            $processor->processConfiguration($config, $other),
        );
        self::assertSame(
            ['key' => 'synthetic-global'],
            $processor->processConfiguration($config),
        );
        self::assertSame(
            'site:main:payment_key',
            $service->getMetadata('site:main:payment_key')->identifier,
        );
        self::assertSame(
            1,
            $this->auditCount(
                'site:main:payment_key',
                AuditAction::Read->value,
                true,
            ),
        );
        self::assertTrue(
            $this->get(AuditLogServiceInterface::class)->verifyHashChain()->valid,
        );
    }

    #[Test]
    public function actualCliCreatesTheCanonicalNamespace(): void
    {
        $this->configureSite('main', 1);
        $tester = new CommandTester($this->get(VaultStoreCommand::class));
        self::assertSame(
            0,
            $tester->execute(
                [
                    'identifier' => 'site:main:cli_key',
                    '--value' => 'synthetic-cli',
                ],
            ),
        );
        self::assertSame(
            'synthetic-cli',
            $this
                ->get(VaultServiceInterface::class)
                ->retrieve('site:main:cli_key'),
        );
    }

    #[Test]
    public function actualBackendDataHandlerCreatesTheCanonicalNamespace(): void
    {
        $this->configureSite('main', 1);
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                'tx_nrvault_secret' => [
                    'NEW1' => [
                        'pid' => 0,
                        'identifier' => 'site:main:backend_key',
                        'secret_input' => 'synthetic-backend',
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();
        self::assertSame(
            'synthetic-backend',
            $this
                ->get(VaultServiceInterface::class)
                ->retrieve('site:main:backend_key'),
            'The actual backend path must create a readable credential.',
        );
        self::assertSame(
            1,
            $this->auditCount(
                'site:main:backend_key',
                AuditAction::Create->value,
                true,
            ),
        );
    }

    #[Test]
    public function unknownSiteIsRefusedBeforeAnySuccessfulCreation(): void
    {
        $service = $this->get(VaultServiceInterface::class);

        try {
            $service->store('site:missing:api_key', 'must-not-be-stored');
            self::fail('A new namespace requires an actual configured site.');
        } catch (ValidationException) {
            self::assertFalse($service->exists('site:missing:api_key'));
        }

        self::assertSame(
            0,
            $this->auditCount(
                'site:missing:api_key',
                AuditAction::Create->value,
                true,
            ),
        );
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                'tx_nrvault_secret' => [
                    'NEW1' => [
                        'pid' => 0,
                        'identifier' => 'site:missing:api_key',
                        'secret_input' => 'must-not-be-stored',
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();
        self::assertSame(
            [],
            $service->list(),
            'Even the value-less DataHandler row must not be inserted.',
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unusableSiteSecrets(): iterable
    {
        yield 'disabled' => ['disabled'];
        yield 'expired' => ['expired'];
        yield 'corrupt ciphertext' => ['corrupt'];
        yield 'malformed envelope' => ['malformed'];
        yield 'denied by actual ACL' => ['denied'];
    }

    #[Test]
    #[DataProvider('unusableSiteSecrets')]
    public function presentUnusableSiteCredentialNeverFallsBackToReadableGlobal(
        string $failure,
    ): void {
        $main = $this->configureSite('main', 1);
        $service = $this->get(VaultServiceInterface::class);
        $service->store('payment_key', 'synthetic-global', ['groups' => [10]]);
        $this->seedExistingNamespace(
            'site:main:payment_key',
            'synthetic-site',
            hidden: $failure === 'disabled',
            expiresAt: $failure === 'expired' ? time() - 60 : 0,
        );
        if ($failure === 'corrupt' || $failure === 'malformed') {
            $this
                ->getConnectionPool()
                ->getConnectionForTable('tx_nrvault_secret')
                ->update(
                    'tx_nrvault_secret',
                    $failure === 'corrupt' ? ['encrypted_value' => 'invalid-ciphertext'] : ['encrypted_dek' => ''],
                    ['identifier' => 'site:main:payment_key'],
                );
        }

        if ($failure === 'denied') {
            $this->setUpBackendUser(3);
        }

        self::assertSame(
            'synthetic-global',
            $service->retrieve('payment_key'),
            'The global credential is independently readable.',
        );
        $processor = new SiteConfigurationVaultProcessor($service, new NullLogger());
        $config = ['key' => '%vault(payment_key)%'];
        self::assertSame(
            $config,
            $processor->processConfiguration($config, $main),
            'An unusable site credential is not absence.',
        );
        if ($failure === 'denied') {
            self::assertSame(
                1,
                $this->auditCount(
                    'site:main:payment_key',
                    AuditAction::AccessDenied->value,
                    false,
                ),
            );
        }
    }

    #[Test]
    public function actuallyMissingSiteCredentialFallsBackToGlobal(): void
    {
        $main = $this->configureSite('main', 1);
        $service = $this->get(VaultServiceInterface::class);
        $service->store('payment_key', 'synthetic-global');

        $processor = new SiteConfigurationVaultProcessor($service, new NullLogger());
        self::assertSame(
            ['key' => 'synthetic-global'],
            $processor->processConfiguration(
                ['key' => '%vault(payment_key)%'],
                $main,
            ),
        );
    }

    #[Test]
    public function existingNamespaceRemainsAdministrableAfterItsSiteIsDeleted(): void
    {
        $this->configureSite('main', 1);
        $this->storeCanonical('site:main:payment_key', 'synthetic-first');
        self::assertTrue(
            GeneralUtility::rmdir(
                $this->instancePath . '/typo3conf/sites/main',
                true,
            ),
        );
        self::assertDirectoryDoesNotExist(
            $this->instancePath . '/typo3conf/sites/main',
        );
        self::assertArrayNotHasKey(
            'main',
            $this->get(SiteFinder::class)->getAllSites(false),
        );
        $service = $this->get(VaultServiceInterface::class);
        $service->store('site:main:payment_key', 'synthetic-updated');
        $service->rotate(
            'site:main:payment_key',
            'synthetic-rotated',
            'Synthetic custody test',
        );
        self::assertSame(
            'synthetic-rotated',
            $service->retrieve('site:main:payment_key'),
        );
        self::assertSame(
            'site:main:payment_key',
            $service->getMetadata('site:main:payment_key')->identifier,
        );
        $service->delete('site:main:payment_key', 'Synthetic custody cleanup');
        self::assertFalse($service->exists('site:main:payment_key'));
    }

    #[Test]
    public function actualDatabaseCollationCannotRenameAnExistingAuthenticatedNamespace(): void
    {
        $this->configureSite('main', 1);
        $this->configureSite('Main', 2);
        $service = $this->get(VaultServiceInterface::class);
        $this->storeCanonical('site:main:api_key', 'synthetic-original');
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_nrvault_secret');
        $alias = $this
            ->get(VaultAdapterInterface::class)
            ->retrieveIncludingDisabled('site:Main:api_key');
        if (getenv('typo3DatabaseDriver') === 'mysqli') {
            self::assertInstanceOf(
                mysqli::class,
                $connection->getNativeConnection(),
            );
            self::assertInstanceOf(Secret::class, $alias);
            self::assertSame('site:main:api_key', $alias->getIdentifier());
            foreach (['store', 'rotate'] as $operation) {
                try {
                    if ($operation === 'store') {
                        $service->store('site:Main:api_key', 'must-not-reseal');
                    } else {
                        $service->rotate('site:Main:api_key', 'must-not-reseal');
                    }

                    self::fail(
                        'A collation alias must not change the authenticated identifier.',
                    );
                } catch (ValidationException $exception) {
                    self::assertStringContainsString(
                        'differently spelled namespace',
                        $exception->getMessage(),
                    );
                }
            }
        } else {
            self::assertInstanceOf(
                PDO::class,
                $connection->getNativeConnection(),
            );
            self::assertNull(
                $alias,
                'The actual SQLite schema compares these identifiers distinctly.',
            );
            $this->storeCanonical('site:Main:api_key', 'synthetic-distinct');
            self::assertSame(
                'synthetic-distinct',
                $service->retrieve('site:Main:api_key'),
            );
        }

        self::assertSame(
            'synthetic-original',
            $service->retrieve('site:main:api_key'),
        );
        self::assertSame(
            'site:main:api_key',
            $service->getMetadata('site:main:api_key')->identifier,
        );
    }

    #[Test]
    public function siteRenamePreservesCustodyAndCliFileExportUnderOriginalIdentifier(): void
    {
        $this->configureSite('main', 1);
        $this->storeCanonical('site:main:payment_key', 'synthetic-original');
        rename(
            $this->instancePath . '/typo3conf/sites/main',
            $this->instancePath . '/typo3conf/sites/renamed',
        );
        $finder = $this->get(SiteFinder::class);
        $finder->getAllSites(false);
        self::assertSame(
            'renamed',
            $finder->getSiteByIdentifier('renamed')->getIdentifier(),
        );
        $service = $this->get(VaultServiceInterface::class);
        $service->store('site:main:payment_key', 'synthetic-updated');
        $service->rotate(
            'site:main:payment_key',
            'synthetic-exported',
            'Synthetic custody test',
        );
        $outputFile = $this->instancePath . '/site-credential-export.txt';
        $tester = new CommandTester($this->get(VaultRetrieveCommand::class));
        self::assertSame(
            0,
            $tester->execute(
                [
                    'identifier' => 'site:main:payment_key',
                    '--output' => $outputFile,
                ],
            ),
        );
        self::assertSame('synthetic-exported', file_get_contents($outputFile));
        self::assertSame(
            'site:main:payment_key',
            $service->getMetadata('site:main:payment_key')->identifier,
        );
        self::assertFalse(
            $service->exists('site:renamed:payment_key'),
            'Site rename does not copy or reseal credentials.',
        );

        try {
            $service->store('site:main:new_key', 'must-not-create');
            self::fail(
                'The old site name cannot establish a new namespace after rename.',
            );
        } catch (ValidationException) {
            self::assertFalse($service->exists('site:main:new_key'));
        }

        $this->storeCanonical('site:renamed:new_key', 'synthetic-new-site');
        self::assertSame(
            'synthetic-new-site',
            $service->retrieve('site:renamed:new_key'),
        );
        $service->delete('site:main:payment_key', 'Synthetic custody cleanup');
        self::assertFalse($service->exists('site:main:payment_key'));
    }

    #[Test]
    public function additionalHttpBodyBindingReadsTheActualEncryptedSiteCredential(): void
    {
        $this->configureSite('main', 1);
        $this->storeCanonical('site:main:api_key', 'synthetic-site-body-value');
        $resolver = new class () implements DnsResolverInterface {
            public function resolve(string $host): array
            {
                return [['ip' => '203.0.113.10']];
            }
        };
        $transport = $this->createMock(ClientInterface::class);
        $transport
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(
                static function (RequestInterface $request): Response {
                    self::assertSame(
                        [
                            'public' => 'kept',
                            'subject_token' => 'synthetic-site-body-value',
                        ],
                        json_decode(
                            (string) $request->getBody(),
                            true,
                            512,
                            JSON_THROW_ON_ERROR,
                        ),
                    );

                    return new Response(200);
                },
            );
        $client = new VaultHttpClient(
            $this->get(VaultServiceInterface::class),
            $this->get(AuditLogServiceInterface::class),
            $transport,
            secureHttpClientFactory: new SecureHttpClientFactory($resolver),
        );
        $response = $client
            ->withAdditionalBodyField('site:main:api_key', 'subject_token')
            ->sendRequest(
                new Request(
                    'POST',
                    'https://api.example.com/token',
                    ['Content-Type' => 'application/json'],
                    '{"public":"kept"}',
                ),
            );
        self::assertSame(200, $response->getStatusCode());
        self::assertSame(
            1,
            $this->auditCount(
                'site:main:api_key',
                AuditAction::Read->value,
                true,
            ),
        );
    }

    /**
     * @return iterable<string,array{string}>
     */
    public static function paddedNamespaceIdentifiers(): iterable
    {
        yield 'leading space' => [' site:main:api_key'];
        yield 'trailing space' => ['site:main:api_key '];
        yield 'trailing control character' => ["site:main:api_key\n"];
        yield 'short name' => ['site:main:ab'];
        yield 'nested delimiter' => ['site:main:api_key:extra'];
        yield 'overlong total' => ['site:main:k' . str_repeat('e', 246)];
    }

    #[Test]
    #[DataProvider('paddedNamespaceIdentifiers')]
    public function backendRefusesNamespaceCorrectionBeforeInsertingAnyRow(
        string $identifier,
    ): void {
        $this->configureSite('main', 1);
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                'tx_nrvault_secret' => [
                    'NEW1' => [
                        'pid' => 0,
                        'identifier' => $identifier,
                        'secret_input' => 'must-not-be-stored',
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();
        self::assertSame(
            [],
            $this->get(VaultServiceInterface::class)->list(),
            'The submitted namespace must be exact, not silently trimmed into another authenticated name.',
        );
    }

    #[Test]
    public function accessToOneSiteCredentialDoesNotGrantTheOtherSitesSameNamedCredential(): void
    {
        $main = $this->configureSite('main', 1);
        $other = $this->configureSite('other', 2);
        $service = $this->get(VaultServiceInterface::class);
        $service->store('payment_key', 'synthetic-global', ['groups' => [10]]);
        $service->store(
            'site:main:payment_key',
            'synthetic-main',
            ['groups' => [10]],
        );
        $service->store('site:other:payment_key', 'synthetic-other');
        $this->setUpBackendUser(3);
        $processor = new SiteConfigurationVaultProcessor($service, new NullLogger());
        $config = ['key' => '%vault(payment_key)%'];
        self::assertSame(
            ['key' => 'synthetic-main'],
            $processor->processConfiguration($config, $main),
        );
        self::assertSame(
            $config,
            $processor->processConfiguration($config, $other),
        );
        $identifiers = array_column($service->list(), 'identifier');
        sort($identifiers, SORT_STRING);
        self::assertSame(['payment_key', 'site:main:payment_key'], $identifiers);
        self::assertSame(
            1,
            $this->auditCount(
                'site:other:payment_key',
                AuditAction::AccessDenied->value,
                false,
            ),
        );
        $deniedMetadata = null;

        try {
            $deniedMetadata = $service->getMetadata('site:other:payment_key');
        } catch (AccessDeniedException) {
        }

        self::assertNull(
            $deniedMetadata,
            'Denied namespaced metadata must not be exposed.',
        );
        $deniedPlaintext = null;

        try {
            $deniedPlaintext = $service->retrieve('site:other:payment_key');
        } catch (AccessDeniedException) {
        }

        self::assertNull(
            $deniedPlaintext,
            'Denied namespaced plaintext must not be exposed.',
        );
        self::assertSame(
            3,
            $this->auditCount(
                'site:other:payment_key',
                AuditAction::AccessDenied->value,
                false,
            ),
        );
    }

    private function configureSite(string $identifier, int $rootPageId): Site
    {
        $path = $this->instancePath . '/typo3conf/sites/' . $identifier;
        GeneralUtility::mkdir_deep($path);
        file_put_contents(
            $path . '/config.yaml',
            'rootPageId: ' . $rootPageId . "\n" . <<<'YAML'
            base: /
            languages:
              - title: English
                enabled: true
                languageId: 0
                base: /
                locale: en_US.UTF-8
                flag: us
            YAML
        );
        $finder = $this->get(SiteFinder::class);
        $finder->getAllSites(false);

        return $finder->getSiteByIdentifier($identifier);
    }

    private function storeCanonical(string $identifier, string $value): void
    {
        $failure = null;

        try {
            $this->get(VaultServiceInterface::class)->store($identifier, $value);
        } catch (ValidationException $exception) {
            $failure = $exception;
        }

        self::assertNull(
            $failure,
            'The supported storage path must accept the canonical namespace.',
        );
    }

    private function seedExistingNamespace(
        string $identifier,
        string $value,
        bool $hidden = false,
        int $expiresAt = 0,
    ): void {
        // Simulate an existing namespaced row from an external adapter or a
        // historic direct write. Resolution is tested independently of the
        // previously broken public namespace-creation path.
        $encrypted = $this
            ->get(EncryptionServiceInterface::class)
            ->encrypt($value, $identifier);
        $this
            ->get(VaultAdapterInterface::class)
            ->store(
                new Secret(
                    identifier: $identifier,
                    encryptedValue: $encrypted->encryptedValue,
                    encryptedDek: $encrypted->encryptedDek,
                    dekNonce: $encrypted->dekNonce,
                    valueNonce: $encrypted->valueNonce,
                    encryptionVersion: $encrypted->encryptionVersion,
                    encryptionAlgorithm: $encrypted->encryptionAlgorithm->value,
                    valueChecksum: $encrypted->valueChecksum,
                    ownerUid: 1,
                    expiresAt: $expiresAt,
                    hidden: $hidden,
                ),
            );
    }

    private function auditCount(
        string $identifier,
        string $action,
        bool $success,
    ): int {
        return $this
            ->getConnectionPool()
            ->getConnectionForTable('tx_nrvault_audit_log')
            ->count(
                '*',
                'tx_nrvault_audit_log',
                [
                    'secret_identifier' => $identifier,
                    'action' => $action,
                    'success' => (int) $success,
                ],
            );
    }
}
