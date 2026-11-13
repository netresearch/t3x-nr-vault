<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Storage\Aws;

use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Throwable;
use TYPO3\CMS\Core\Database\ConnectionPool;

use function is_array;

/**
 * The adapter against a real Secrets Manager emulation, through the real
 * VaultService and database.
 *
 * Setup only; the cases are in {@see AwsSecretsManagerAdapterTest} and
 * {@see AwsSecretsManagerAdapterSafetyTest}.
 */
abstract class AbstractAwsContainerTestCase extends AbstractVaultFunctionalTestCase
{
    protected const KEY_ID_VARIABLE = 'NR_VAULT_AWS_ACCESS_KEY_ID';

    protected const SECRET_VARIABLE = 'NR_VAULT_AWS_SECRET_ACCESS_KEY';

    protected ?string $backendUserFixture = __DIR__ . '/../../Service/Fixtures/be_users.csv';

    protected MotoServer $server;

    /**
     * Boot the server before the first test, so a machine without Docker skips
     * the class instead of failing inside a half-built TYPO3 instance.
     */
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        $ci = getenv('CI');
        if ((!is_string($ci) || $ci === '') && !file_exists('/var/run/docker.sock') && getenv('DOCKER_HOST') === false) {
            self::markTestSkipped('No Docker socket and no DOCKER_HOST: Testcontainers cannot start Moto.');
        }

        MotoServer::shared();
    }

    protected function setUp(): void
    {
        $this->server = MotoServer::shared();

        $this->extensionConfiguration = [
            'auditHmacEpoch' => 1,
            'storageAdapter' => 'aws',
            'aws'            => [
                'region'            => MotoServer::REGION,
                'secretPrefix'      => MotoServer::PREFIX . '/',
                'endpoint'          => $this->server->address,
                'allowInsecureHttp' => '1',
            ],
        ];

        putenv(self::KEY_ID_VARIABLE . '=' . $this->server->keyId);
        putenv(self::SECRET_VARIABLE . '=' . $this->server->secretKey);

        parent::setUp();

        $this->allowHostForSecureClient($this->server->host);
    }

    protected function tearDown(): void
    {
        putenv(self::KEY_ID_VARIABLE);
        putenv(self::SECRET_VARIABLE);

        parent::tearDown();
    }

    /**
     * The exception the action throws; the test fails when it throws nothing.
     *
     * @param callable(): mixed $action
     */
    protected function thrownBy(callable $action): Throwable
    {
        try {
            $action();
        } catch (Throwable $e) {
            return $e;
        }

        self::fail('The operation was expected to throw.');
    }

    /**
     * Change `aws.*` settings before the first service of the test is
     * requested; the configuration object reads them when it is built.
     *
     * @param array<string, mixed> $changes
     */
    protected function changeAwsSettings(array $changes): void
    {
        $confVars = $GLOBALS['TYPO3_CONF_VARS'];
        self::assertIsArray($confVars);
        $extensions = is_array($confVars['EXTENSIONS'] ?? null) ? $confVars['EXTENSIONS'] : [];
        $vault      = is_array($extensions['nr_vault'] ?? null) ? $extensions['nr_vault'] : [];
        $aws        = is_array($vault['aws'] ?? null) ? $vault['aws'] : [];

        $vault['aws']               = array_replace($aws, $changes);
        $extensions['nr_vault']     = $vault;
        $confVars['EXTENSIONS']     = $extensions;
        $GLOBALS['TYPO3_CONF_VARS'] = $confVars;
    }

    protected function newIdentifier(): string
    {
        return 'it_' . bin2hex(random_bytes(6));
    }

    /**
     * @return array<string, mixed>
     */
    protected function row(string $identifier): array
    {
        $row = $this->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_secret')
            ->select(['*'], 'tx_nrvault_secret', ['identifier' => $identifier])
            ->fetchAssociative();

        self::assertIsArray($row, 'the registry row must exist');

        return $row;
    }

    protected function countRows(string $identifier): int
    {
        return (int) $this->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_secret')
            ->count('*', 'tx_nrvault_secret', ['identifier' => $identifier]);
    }

    /**
     * Moto listens on loopback. The secure client refuses that address unless
     * the host is listed literally, the documented opt-in for an internal one.
     */
    protected function allowHostForSecureClient(string $host): void
    {
        $this->setHttpConfiguration(['allowed_hosts' => [$host]]);
    }

    /**
     * @param array<string, mixed> $values
     */
    protected function setHttpConfiguration(array $values): void
    {
        $confVars = $GLOBALS['TYPO3_CONF_VARS'];
        self::assertIsArray($confVars);
        $http = is_array($confVars['HTTP'] ?? null) ? $confVars['HTTP'] : [];

        $confVars['HTTP']           = array_replace($http, $values);
        $GLOBALS['TYPO3_CONF_VARS'] = $confVars;
    }
}
