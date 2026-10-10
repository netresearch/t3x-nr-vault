<?php

/* Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Documentation;

use GuzzleHttp\Psr7\Response;
use Netresearch\NrVault\Http\SecretPlacement;
use Netresearch\NrVault\Http\VaultHttpClientInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\RequestInterface;
use ReflectionClass;
use ReflectionMethod;
use RuntimeException;
use Throwable;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Http\RequestFactory;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * The alternative manual services share a class name and are loaded at runtime
 * in separate processes. Keep their guarded reflection lookups as strings;
 * registering both alternatives as one autoloadable PHPStan symbol is misleading.
 *
 * @noRector \Rector\Php55\Rector\String_\StringClassNameToClassConstantRector
 */
#[CoversNothing]
#[RunTestsInSeparateProcesses]
#[PreserveGlobalState(false)]
final class TcaDeepLExampleTest extends FunctionalTestCase
{
    /** @var array<non-empty-string> */
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
        __DIR__ . '/../Fixtures/Extensions/nr_vault_deepl_fixture',
    ];

    #[Test]
    public function literalTcaGeneratesTheSoftDeleteColumnUsedByTheLiteralRepository(): void
    {
        $connection = $this
            ->get(ConnectionPool::class)
            ->getConnectionForTable('tx_mydeeplext_config');
        $table = $connection
            ->createSchemaManager()
            ->introspectSchema()
            ->getTable('tx_mydeeplext_config');
        self::assertTrue(
            $table->hasColumn('deleted'),
            'The literal repository filters deleted=0, so its literal TCA must define soft deletion.',
        );
    }

    #[Test]
    public function literalRepositoryAndServiceBuildTheDocumentedDeepLRequest(): void
    {
        require_once __DIR__ . '/../../../Documentation/Usage/_DeepLConfig.php';
        require_once __DIR__ . '/../../../Documentation/Usage/_ConfigRepository.php';
        require_once __DIR__ . '/../../../Documentation/Usage/_DeepLServiceTca.php';
        $pool = $this->get(ConnectionPool::class);
        $connection = $pool->getConnectionForTable('tx_mydeeplext_config');
        $connection->insert(
            'tx_mydeeplext_config',
            [
                'name' => 'Deleted configuration',
                'api_key' => 'deleted_key',
                'api_url' => 'https://deleted.example/v2',
                'deleted' => 1,
            ],
        );
        $identifier = '01940000-0000-7000-8000-000000000003';
        $connection->insert(
            'tx_mydeeplext_config',
            [
                'name' => 'Active configuration',
                'api_key' => $identifier,
                'api_url' => 'https://api-free.deepl.com/v2',
                'deleted' => 0,
            ],
        );
        $repository = ($this->reflectLiteralClass(
            'MyVendor\MyDeeplExtension\Domain\Repository\ConfigRepository',
        ))->newInstance($pool);
        $http = $this->createMock(
            VaultHttpClientInterface::class,
        );
        $http
            ->expects(self::once())
            ->method('withAuthentication')
            ->with(
                $identifier,
                SecretPlacement::Header,
                ['headerName' => 'Authorization', 'prefix' => 'DeepL-Auth-Key '],
            )
            ->willReturnSelf();
        $http
            ->expects(self::once())
            ->method('withReason')
            ->with('DeepL translation: DE')
            ->willReturnSelf();
        $http
            ->expects(self::once())
            ->method('sendRequest')
            ->with(
                self::callback(
                    static function (
                        RequestInterface $request,
                    ): bool {
                        self::assertSame('POST', $request->getMethod());
                        self::assertSame(
                            'https://api-free.deepl.com/v2/translate',
                            (string) $request->getUri(),
                        );
                        self::assertSame(
                            'application/json',
                            $request->getHeaderLine('Content-Type'),
                        );
                        self::assertSame(
                            ['text' => ['Hello'], 'target_lang' => 'DE'],
                            json_decode(
                                (string) $request->getBody(),
                                true,
                                512,
                                JSON_THROW_ON_ERROR,
                            ),
                        );
                        self::assertFalse($request->hasHeader('Authorization'));

                        return true;
                    },
                ),
            )
            ->willReturn(
                new Response(
                    200,
                    [],
                    '{"translations":[{"text":"Hallo"}]}',
                ),
            );
        $vault = $this->createMock(
            VaultServiceInterface::class,
        );
        $vault->expects(self::once())->method('http')->willReturn($http);
        $service = ($this->reflectLiteralClass(
            'MyVendor\MyDeeplExtension\Service\DeepLService',
        ))->newInstance(
            $vault,
            $this->get(RequestFactory::class),
            $repository,
        );
        self::assertSame(
            'Hallo',
            (new ReflectionMethod($service, 'translate'))->invoke(
                $service,
                'Hello',
                'DE',
            ),
        );
    }

    #[Test]
    public function missingDatabaseConfigurationFailsBeforeHttpDelegation(): void
    {
        require_once __DIR__ . '/../../../Documentation/Usage/_DeepLConfig.php';
        require_once __DIR__ . '/../../../Documentation/Usage/_ConfigRepository.php';
        require_once __DIR__ . '/../../../Documentation/Usage/_DeepLServiceTca.php';
        $repository = ($this->reflectLiteralClass(
            'MyVendor\MyDeeplExtension\Domain\Repository\ConfigRepository',
        ))->newInstance($this->get(ConnectionPool::class));
        $vault = $this->createMock(
            VaultServiceInterface::class,
        );
        $vault->expects(self::never())->method('http');
        $service = ($this->reflectLiteralClass(
            'MyVendor\MyDeeplExtension\Service\DeepLService',
        ))->newInstance(
            $vault,
            $this->get(RequestFactory::class),
            $repository,
        );
        $failure = null;

        try {
            (new ReflectionMethod($service, 'translate'))->invoke(
                $service,
                'Hello',
                'DE',
            );
        } catch (Throwable $caught) {
            $failure = $caught;
        }

        self::assertInstanceOf(RuntimeException::class, $failure);
        self::assertSame('DeepL not configured', $failure->getMessage());
        self::assertSame(1735900001, $failure->getCode());
    }

    /**
     * @return ReflectionClass<object>
     */
    private function reflectLiteralClass(string $name): ReflectionClass
    {
        if (!class_exists($name)) {
            throw new RuntimeException(
                'The literal documentation fixture did not load its class.',
                1735900002,
            );
        }

        return new ReflectionClass($name);
    }
}
