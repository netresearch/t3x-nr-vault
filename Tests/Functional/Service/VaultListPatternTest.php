<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service;

use mysqli;
use Netresearch\NrVault\Command\VaultListCommand;
use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Service\VaultService;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Database\ConnectionPool;

#[CoversClass(VaultService::class)]
#[CoversClass(VaultListCommand::class)]
final class VaultListPatternTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../Controller/Fixtures/be_users.csv';

    /**
     * @param list<string> $expected
     */
    #[Test]
    #[DataProvider('patterns')]
    public function listMatchesIdentifierGlobAgainstTheRealDatabase(
        string $pattern,
        array $expected,
    ): void {
        $service = $this->seedSecrets();
        $actual = array_column($service->list($pattern), 'identifier');
        sort($actual, SORT_STRING);
        self::assertSame($expected, $actual);
        $repository = $this->get(SecretRepositoryInterface::class);
        $filters = new SecretFilters(pattern: $pattern);
        $actual = $repository->findIdentifiers($filters);
        sort($actual, SORT_STRING);
        self::assertSame($expected, $actual);
        $actual = array_map(
            static fn ($secret): string => $secret->getIdentifier(),
            $repository->findAllWithFilters($filters),
        );
        sort($actual, SORT_STRING);
        self::assertSame($expected, $actual);
    }

    /**
     * @return iterable<string, array{string, list<string>}>
     */
    public static function patterns(): iterable
    {
        yield 'trailing star with literal underscore' => ['app_*', ['app_key', 'app_key_extra', 'app_second_token']];
        yield 'no star is exact' => ['app_key', ['app_key']];
        yield 'leading star' => ['*key', ['appXkey', 'app_key', 'billing_key']];
        yield 'middle star' => ['app*key', ['appXkey', 'app_key']];
        yield 'multiple stars' => ['a**p_*key', ['app_key']];
        yield 'star matches all' => [
            '*',
            [
                'appXkey',
                'app_key',
                'app_key_extra',
                'app_second_token',
                'billing_key',
            ],
        ];
        yield 'percent is literal' => ['app%', []];
        yield 'underscore is literal without star' => ['app_key_', []];
        yield 'empty pattern matches nothing' => ['', []];
        yield 'backslash is literal' => ['app\*', []];
        yield 'SQL fragment is literal' => ["app' OR 1=1 --*", []];
    }

    #[Test]
    public function wildcardDoesNotExposeMetadataToAnActorWithoutReadAccess(): void
    {
        $service = $this->seedSecrets();
        self::assertCount(
            5,
            $service->list('*'),
            'Admin counterpart proves the filter has matching records.',
        );
        $this->setUpBackendUser(2);
        self::assertSame([], $service->list('*'));
    }

    #[Test]
    public function cliPatternUsesTheSameRealDatabaseContract(): void
    {
        $service = $this->seedSecrets();
        $tester = new CommandTester(new VaultListCommand($service));
        self::assertSame(
            0,
            $tester->execute(['--pattern' => 'app_*', '--format' => 'json']),
        );
        $decoded = json_decode($tester->getDisplay(), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        self::assertSame(
            ['app_key', 'app_key_extra', 'app_second_token'],
            array_column($decoded, 'identifier'),
        );
    }

    #[Test]
    public function repositoryKeepsPrefixLiteralAndCombinesItWithThePattern(): void
    {
        $this->seedSecrets();
        $repository = $this->get(SecretRepositoryInterface::class);
        self::assertSame(
            ['app_key', 'app_key_extra', 'app_second_token'],
            $repository->findIdentifiers(new SecretFilters(prefix: 'app_')),
        );
        self::assertSame(
            ['app_key'],
            $repository->findIdentifiers(
                new SecretFilters(prefix: 'app_', pattern: '*key'),
            ),
        );
        self::assertSame(
            ['app_key'],
            array_map(
                static fn ($secret): string => $secret->getIdentifier(),
                $repository->findAllWithFilters(
                    new SecretFilters(prefix: 'app_', pattern: '*key'),
                ),
            ),
        );
        self::assertSame(
            [],
            $repository->findIdentifiers(new SecretFilters(prefix: 'app_*')),
        );
    }

    #[Test]
    public function patternDoesNotBypassDisabledAndDeletedRestrictions(): void
    {
        $service = $this->seedSecrets();
        $service->setEnabled('app_key', false, 'Synthetic disabled fixture');
        $service->delete('app_key_extra', 'Synthetic deleted fixture');
        self::assertSame(
            ['app_second_token'],
            array_column($service->list('app_*'), 'identifier'),
        );
        self::assertSame(
            ['app_key', 'app_second_token'],
            array_column(
                $service->list('app_*', includeDisabled: true),
                'identifier',
            ),
        );
    }

    #[Test]
    public function servicePreservesMixedCaseMatchesSelectedByTheDatabase(): void
    {
        $connection = $this
            ->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_secret');
        if (getenv('typo3DatabaseDriver') === 'mysqli') {
            self::assertInstanceOf(
                mysqli::class,
                $connection->getNativeConnection(),
            );
        } else {
            self::assertInstanceOf(
                PDO::class,
                $connection->getNativeConnection(),
            );
        }

        $service = $this->get(VaultServiceInterface::class);
        $service->store('App_Key', 'synthetic-mixed-case');

        $repository = $this->get(SecretRepositoryInterface::class);
        $expected = $repository->findIdentifiers(new SecretFilters(pattern: 'app_*'));
        self::assertSame(
            ['App_Key'],
            $expected,
            'SQLite and the supported MariaDB collation select mixed-case LIKE matches.',
        );
        self::assertSame(
            $expected,
            array_column($service->list('app_*'), 'identifier'),
        );
    }

    private function seedSecrets(): VaultServiceInterface
    {
        $service = $this->get(VaultServiceInterface::class);
        foreach ([
            'app_key',
            'app_key_extra',
            'appXkey',
            'billing_key',
            'app_second_token',
        ] as $identifier) {
            $service->store($identifier, 'synthetic-' . $identifier);
        }

        return $service;
    }
}
