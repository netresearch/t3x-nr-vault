<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service;

use Doctrine\DBAL\Platforms\SQLitePlatform;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Real process death must not leave an unaudited, durable mutation.
 */
final class AtomicVaultCrashTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'masterKeyProvider'    => 'file',
        'allowCliAccess'       => true,
        'cliAllowedOperations' => 'secret.use,secret.create,secret.rotate,secret.delete',
        'auditHmacEpoch'       => 3,
    ];

    /** @var list<array{process: resource, pipes: array<int, resource>, signal: string, release: string}> */
    private array $workers = [];

    protected function setUp(): void
    {
        parent::setUp();
        if (!function_exists('proc_open') || !function_exists('posix_kill')) {
            self::markTestSkipped(
                'Process-death regression requires proc_open and POSIX signals.',
            );
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->workers as $worker) {
            if (is_resource($worker['process'])) {
                $status = proc_get_status($worker['process']);
                if ($status['running']) {
                    proc_terminate($worker['process'], 9);
                }

                foreach ($worker['pipes'] as $pipe) {
                    if (is_resource($pipe)) {
                        fclose($pipe);
                    }
                }

                proc_close($worker['process']);
            }
        }

        $this->workers = [];
        parent::tearDown();
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function mutationProvider(): iterable
    {
        yield 'creation' => ['store'];
        yield 'rotation' => ['rotate'];
        yield 'deletion' => ['delete'];
    }

    #[Test]
    #[DataProvider('mutationProvider')]
    public function processKilledAfterMutationBeforeAuditCommitLeavesOriginalState(
        string $operation,
    ): void {
        $identifier = 'atomic_crash_' . $operation;
        if ($operation !== 'store') {
            $this
                ->get(VaultServiceInterface::class)
                ->store($identifier, 'synthetic-before');
        }

        $before     = $this->secretRow($identifier);
        $auditCount = $this->successfulAuditCount($identifier);

        $worker = $this->startWorker($identifier, $operation, 'crash');
        $this->waitForSignal($worker, '.audit', $operation);
        $status = $this->waitForExit($worker);
        self::assertTrue(
            $status['signaled'],
            'The worker must die by signal, not by a bootstrap error.',
        );
        self::assertSame(9, $status['termsig']);

        self::assertSame($before, $this->secretRow($identifier));
        self::assertSame($auditCount, $this->successfulAuditCount($identifier));
        self::assertTrue(
            $this->get(AuditLogServiceInterface::class)->verifyHashChain()->valid,
        );
    }

    #[Test]
    public function competingRotationCommitsAfterAnotherWriterIsKilled(): void
    {
        $identifier = 'atomic_competing_crash';
        $this
            ->get(VaultServiceInterface::class)
            ->store($identifier, 'synthetic-before');
        $before = $this
            ->get(SecretRepositoryInterface::class)
            ->findByIdentifier($identifier);
        self::assertNotNull($before);
        $auditCount = $this->successfulAuditCount($identifier);

        $first = $this->startWorker($identifier, 'rotate', 'pause-crash');
        $this->waitForSignal($first, '.audit', 'rotate');
        $second = $this->startWorker($identifier, 'rotate', 'success');
        $this->waitForSignal($second, '.started', 'rotate');
        if ($this
            ->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_secret')
            ->getDatabasePlatform() instanceof SQLitePlatform) {
            $this->waitForSignal($second, '.busy', 'rotate');
        }

        file_put_contents($first['release'], 'release');

        $firstStatus = $this->waitForExit($first);
        self::assertTrue($firstStatus['signaled']);
        self::assertSame(9, $firstStatus['termsig']);
        $secondStatus = $this->waitForExit($second);
        self::assertSame(
            0,
            $secondStatus['exitcode'],
            $this->workerOutput($second),
        );
        self::assertFileExists($second['signal'] . '.completed');

        $after = $this
            ->get(SecretRepositoryInterface::class)
            ->findByIdentifier($identifier);
        self::assertNotNull($after);
        self::assertSame($before->getVersion() + 1, $after->getVersion());
        self::assertSame(
            'synthetic-success',
            $this
                ->get(EncryptionServiceInterface::class)
                ->decrypt(
                    $after->getEncryptedValue() ?? '',
                    $after->getEncryptedDek(),
                    $after->getDekNonce(),
                    $after->getValueNonce(),
                    $identifier,
                    $after->getEncryptionVersion(),
                    $after->getEncryptionAlgorithm(),
                ),
        );
        self::assertSame(
            $auditCount + 1,
            $this->successfulAuditCount($identifier),
        );
        self::assertTrue(
            $this->get(AuditLogServiceInterface::class)->verifyHashChain()->valid,
        );
    }

    /**
     * @return array<string, mixed>|false
     */
    private function secretRow(string $identifier): array|false
    {
        return $this
            ->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_secret')
            ->select(['*'], 'tx_nrvault_secret', ['identifier' => $identifier])
            ->fetchAssociative();
    }

    private function successfulAuditCount(string $identifier): int
    {
        return (int) $this
            ->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_audit_log')
            ->count(
                '*',
                'tx_nrvault_audit_log',
                ['secret_identifier' => $identifier, 'success' => 1],
            );
    }

    /**
     * @return array{process: resource, pipes: array<int, resource>, signal: string, release: string}
     */
    private function startWorker(
        string $identifier,
        string $operation,
        string $mode,
    ): array {
        $globalConfiguration = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        self::assertIsArray($globalConfiguration);
        $databaseConfiguration = $globalConfiguration['DB'] ?? null;
        self::assertIsArray($databaseConfiguration);
        $extensions = $globalConfiguration['EXTENSIONS'] ?? null;
        self::assertIsArray($extensions);
        $extension = $extensions['nr_vault'] ?? null;
        self::assertIsArray($extension);
        $signal            = $this->instancePath . '/atomic-worker-' . bin2hex(random_bytes(6));
        $configurationFile = $signal . '.json';
        $configuration     = [
            'autoload'    => dirname(__DIR__, 3) . '/.Build/vendor/autoload.php',
            'environment' => [
                'project' => Environment::getProjectPath(),
                'public'  => Environment::getPublicPath(),
                'var'     => Environment::getVarPath(),
                'config'  => Environment::getConfigPath(),
            ],
            'database'   => $databaseConfiguration,
            'extension'  => $extension,
            'identifier' => $identifier,
            'operation'  => $operation,
            'mode'       => $mode,
            'signal'     => $signal,
            'release'    => $signal . '.release',
            'atomic'     => getenv('NR_VAULT_TEST_LEGACY') !== '1',
        ];
        file_put_contents(
            $configurationFile,
            json_encode($configuration, JSON_THROW_ON_ERROR),
        );
        chmod($configurationFile, 0o600);
        // nosemgrep: netresearch.php.lang.security.exec-use.exec-use - argv array, no shell; fixed PHP_BINARY and worker path, test-generated isolated configuration path
        $process = proc_open(
            [
                PHP_BINARY,
                __DIR__ . '/Fixtures/atomic-vault-worker.php',
                $configurationFile,
            ],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
        );
        self::assertIsResource($process);
        fclose($pipes[0]);
        unset($pipes[0]);
        foreach ($pipes as $pipe) {
            stream_set_blocking($pipe, false);
        }

        $worker = [
            'process' => $process,
            'pipes'   => $pipes,
            'signal'  => $signal,
            'release' => $signal . '.release',
        ];
        $this->workers[] = $worker;

        return $worker;
    }

    /**
     * @param array{process: resource, pipes: array<int, resource>, signal: string, release: string} $worker
     */
    private function waitForSignal(
        array $worker,
        string $suffix,
        string $expected,
    ): void {
        $deadline = microtime(true) + 10;
        do {
            clearstatcache(true, $worker['signal'] . $suffix);
            if (is_file($worker['signal'] . $suffix)) {
                self::assertSame(
                    $expected,
                    file_get_contents($worker['signal'] . $suffix),
                );

                return;
            }

            $status = proc_get_status($worker['process']);
            if (!$status['running']) {
                self::fail(
                    'Worker stopped before its barrier: ' . $this->workerOutput($worker),
                );
            }

            usleep(10000);
        } while (microtime(true) < $deadline);

        self::fail(
            'Worker never reached the expected barrier: ' . $this->workerOutput($worker),
        );
    }

    /**
     * @param array{process: resource, pipes: array<int, resource>, signal: string, release: string} $worker
     *
     * @return array{command: string, pid: int, running: bool, signaled: bool, stopped: bool, exitcode: int, termsig: int, stopsig: int}
     */
    private function waitForExit(array $worker): array
    {
        $deadline = microtime(true) + 10;
        do {
            $status = proc_get_status($worker['process']);
            if (!$status['running']) {
                $this
                    ->get(ConnectionPool::class)
                    ->getConnectionForTable('tx_nrvault_secret')
                    ->close();

                return $status;
            }

            usleep(10000);
        } while (microtime(true) < $deadline);

        self::fail(
            'Worker did not finish within the deadline: ' . $this->workerOutput($worker),
        );
    }

    /**
     * @param array{process: resource, pipes: array<int, resource>, signal: string, release: string} $worker
     */
    private function workerOutput(array $worker): string
    {
        $output = '';
        foreach ($worker['pipes'] as $pipe) {
            $output .= stream_get_contents($pipe);
        }

        return $output;
    }
}
