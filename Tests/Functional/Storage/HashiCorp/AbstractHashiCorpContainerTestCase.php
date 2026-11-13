<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Storage\HashiCorp;

use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Throwable;
use TYPO3\CMS\Core\Database\ConnectionPool;

use function is_array;

/**
 * The adapter against a real Vault, through the real VaultService and database.
 *
 * Setup only; the cases every auth method must pass live in
 * {@see AbstractHashiCorpAuthMethodTestCase}.
 */
abstract class AbstractHashiCorpContainerTestCase extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../../Service/Fixtures/be_users.csv';

    protected VaultDevServer $server;

    /**
     * Boot the server before the first test, so a machine without Docker skips
     * the class instead of failing inside a half-built TYPO3 instance.
     */
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        $ci = getenv('CI');
        if ((!is_string($ci) || $ci === '') && !file_exists('/var/run/docker.sock') && getenv('DOCKER_HOST') === false) {
            self::markTestSkipped('No Docker socket and no DOCKER_HOST: Testcontainers cannot start Vault.');
        }

        VaultDevServer::shared();
    }

    protected function setUp(): void
    {
        $this->server = VaultDevServer::shared();
        $this->prepare($this->server);

        $this->extensionConfiguration = [
            'auditHmacEpoch' => 1,
            'storageAdapter' => 'hashicorp',
            'hashicorp'      => array_merge([
                'address'           => $this->server->address,
                'path'              => 'secret/data/typo3',
                'allowInsecureHttp' => '1',
            ], $this->authSettings($this->server)),
        ];

        parent::setUp();

        $this->allowHostForSecureClient($this->server->host);
    }

    /**
     * The `hashicorp.*` settings that select and feed this auth method.
     *
     * @return array<string, mixed>
     */
    abstract protected function authSettings(VaultDevServer $server): array;

    protected function prepare(VaultDevServer $server): void {}

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
     * Change `hashicorp.*` settings before the first service of the test is
     * requested; the configuration object reads them when it is built.
     *
     * @param array<string, mixed> $changes
     */
    protected function changeHashiCorpSettings(array $changes): void
    {
        $confVars = $GLOBALS['TYPO3_CONF_VARS'];
        self::assertIsArray($confVars);
        $extensions = is_array($confVars['EXTENSIONS'] ?? null) ? $confVars['EXTENSIONS'] : [];
        $vault      = is_array($extensions['nr_vault'] ?? null) ? $extensions['nr_vault'] : [];
        $hashicorp  = is_array($vault['hashicorp'] ?? null) ? $vault['hashicorp'] : [];

        $vault['hashicorp']         = array_replace($hashicorp, $changes);
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

    /**
     * Vault listens on loopback. The secure client refuses that address unless
     * the host is listed literally, the documented opt-in for an internal one.
     */
    protected function allowHostForSecureClient(string $host): void
    {
        $confVars = $GLOBALS['TYPO3_CONF_VARS'];
        self::assertIsArray($confVars);
        $http = is_array($confVars['HTTP'] ?? null) ? $confVars['HTTP'] : [];

        $confVars['HTTP']           = array_replace($http, ['allowed_hosts' => [$host]]);
        $GLOBALS['TYPO3_CONF_VARS'] = $confVars;
    }
}
