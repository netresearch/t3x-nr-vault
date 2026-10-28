<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use Doctrine\DBAL\Platforms\SQLitePlatform;
use Netresearch\NrVault\Adapter\LocalEncryptionAdapter;
use Netresearch\NrVault\Audit\AuditChainAnchorStore;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\VaultMutationTransaction;
use Netresearch\NrVault\Configuration\ExtensionConfiguration;
use Netresearch\NrVault\Crypto\EncryptionService;
use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Domain\Repository\SecretRepository;
use Netresearch\NrVault\Http\VaultHttpClientFactoryInterface;
use Netresearch\NrVault\Http\VaultHttpClientInterface;
use Netresearch\NrVault\Security\AccessControlService;
use Netresearch\NrVault\Service\VaultService;
use Netresearch\NrVault\Service\VaultServiceInterface;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration as CoreExtensionConfiguration;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\TestingFramework\Core\Testbase;

/**
 * Infrastructure failure in the isolated crash-test worker.
 */
final class AtomicVaultWorkerFailure extends RuntimeException {}

$arguments = $_SERVER['argv'] ?? null;
if (!is_array($arguments) || !is_string($arguments[1] ?? null)) {
    throw new InvalidArgumentException(
        'Expected the isolated test configuration path.',
        8996905505,
    );
}

/** @var array{autoload: string, environment: array{project: string, public: string, var: string, config: string}, database: array<string, mixed>, extension: array<string, mixed>, identifier: string, operation: string, mode: string, signal: string, release: string, atomic: bool} $settings */
$settings = json_decode(
    (string) file_get_contents($arguments[1]),
    true,
    512,
    JSON_THROW_ON_ERROR,
);
require_once $settings['autoload'];

/**
 * Publish a barrier file atomically, so the parent never reads it half-written.
 */
function atomicVaultSignal(string $path, string $content): void
{
    file_put_contents($path . '.tmp', $content);
    rename($path . '.tmp', $path);
}

try {
    $testbase = new Testbase();
    $testbase->setTypo3TestingContext();
    if ($settings['environment']['project'] === '') {
        throw new InvalidArgumentException(
            'The isolated test instance path must not be empty.',
            1793189001,
        );
    }

    $testbase->setUpBasicTypo3Bootstrap($settings['environment']['project']);
    $configurationValues = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
    if (!is_array($configurationValues)) {
        throw new AtomicVaultWorkerFailure(
            'The isolated TYPO3 configuration was not initialized.',
            8330214822,
        );
    }

    $GLOBALS['TYPO3_CONF_VARS'] = array_replace_recursive(
        $configurationValues,
        [
            'DB'         => $settings['database'],
            'EXTENSIONS' => ['nr_vault' => $settings['extension']],
        ],
    );
    $configuration = new ExtensionConfiguration(new CoreExtensionConfiguration());
    $pool          = new ConnectionPool();
    if ($pool->getConnectionForTable('tx_nrvault_secret')->getDatabasePlatform() instanceof SQLitePlatform) {
        $pool
            ->getConnectionForTable('tx_nrvault_secret')
            ->executeStatement('PRAGMA busy_timeout=50');
    }

    $keyProvider      = new FileMasterKeyProvider($configuration);
    $access           = new AccessControlService($configuration, $pool);
    $auditKeyProvider = new class ($keyProvider, $settings, $pool) implements MasterKeyProviderInterface {
        private bool $reached = false;

        /**
         * @param array{mode: string, signal: string, release: string, operation: string, identifier: string} $settings
         */
        public function __construct(
            private readonly MasterKeyProviderInterface $inner,
            private readonly array $settings,
            private readonly ConnectionPool $pool,
        ) {}

        public function getIdentifier(): string
        {
            return $this->inner->getIdentifier();
        }

        public function isAvailable(): bool
        {
            return $this->inner->isAvailable();
        }

        public function storeMasterKey(
            #[SensitiveParameter]
            string $key,
        ): void {
            $this->inner->storeMasterKey($key);
        }

        public function generateMasterKey(): string
        {
            return $this->inner->generateMasterKey();
        }

        public static function clearCachedKey(): void
        {
            FileMasterKeyProvider::clearCachedKey();
        }

        public function getMasterKey(): string
        {
            if (!$this->reached && $this->settings['mode'] !== 'success') {
                $this->reached = true;
                $this->recordMutationEvidence();
                atomicVaultSignal(
                    $this->settings['signal'] . '.audit',
                    $this->settings['operation'],
                );
                if ($this->settings['mode'] === 'pause-crash') {
                    $deadline = microtime(true) + 10;
                    while (!is_file($this->settings['release'])) {
                        if (microtime(true) >= $deadline) {
                            throw new AtomicVaultWorkerFailure(
                                'Test barrier timed out.',
                                4873682939,
                            );
                        }

                        clearstatcache(true, $this->settings['release']);
                        usleep(10000);
                    }
                }

                $pid = getmypid();
                if ($pid === false) {
                    throw new AtomicVaultWorkerFailure(
                        'Worker process id is unavailable.',
                        5129470785,
                    );
                }

                posix_kill($pid, 9);

                throw new AtomicVaultWorkerFailure(
                    'SIGKILL did not terminate the worker.',
                    3877558119,
                );
            }

            return $this->inner->getMasterKey();
        }

        /**
         * What this process's open transaction sees right before the kill:
         * the parent proves the mutation had been written.
         */
        private function recordMutationEvidence(): void
        {
            $row = $this->pool
                ->getConnectionForTable('tx_nrvault_secret')
                ->select(['version'], 'tx_nrvault_secret', ['identifier' => $this->settings['identifier']])
                ->fetchAssociative();
            atomicVaultSignal(
                $this->settings['signal'] . '.evidence',
                json_encode(
                    [
                        'exists'  => $row !== false,
                        'version' => $row !== false && is_numeric($row['version'] ?? null) ? (int) $row['version'] : null,
                    ],
                    JSON_THROW_ON_ERROR,
                ),
            );
        }
    };
    $httpFactory = new class implements VaultHttpClientFactoryInterface {
        public function create(
            VaultServiceInterface $vaultService,
        ): VaultHttpClientInterface {
            throw new LogicException('The process regression must never use HTTP.', 6329957518);
        }
    };
    $transaction = $settings['atomic'] && class_exists(VaultMutationTransaction::class) ? new VaultMutationTransaction($pool) : null;
    $audit       = $transaction instanceof VaultMutationTransaction ? new AuditLogService(
        $pool,
        $access,
        $auditKeyProvider,
        $configuration,
        new AuditChainAnchorStore($pool, $keyProvider, $configuration),
        mutationTransaction: $transaction,
    ) : new AuditLogService(
        $pool,
        $access,
        $auditKeyProvider,
        $configuration,
        new AuditChainAnchorStore($pool, $keyProvider, $configuration),
    );
    $adapter    = new LocalEncryptionAdapter(new SecretRepository($pool));
    $encryption = new EncryptionService($keyProvider, $configuration);
    $vault      = $transaction instanceof VaultMutationTransaction ? new VaultService(
        $adapter,
        $encryption,
        $access,
        $audit,
        $configuration,
        $httpFactory,
        mutationTransaction: $transaction,
    ) : new VaultService(
        $adapter,
        $encryption,
        $access,
        $audit,
        $configuration,
        $httpFactory,
    );
    atomicVaultSignal($settings['signal'] . '.started', $settings['operation']);
    $deadline = microtime(true) + 8;
    while (true) {
        try {
            match ($settings['operation']) {
                'store' => $vault->store(
                    $settings['identifier'],
                    'synthetic-' . $settings['mode'],
                ),
                'rotate' => $vault->rotate(
                    $settings['identifier'],
                    'synthetic-' . $settings['mode'],
                ),
                'delete' => $vault->delete($settings['identifier']),
                default  => throw new LogicException('Unknown test mutation.', 1595025539),
            };
            atomicVaultSignal(
                $settings['signal'] . '.completed',
                $settings['operation'],
            );
            exit(0);
        } catch (Throwable $exception) {
            // SQLite may reject a competing snapshot rather than wait for the
            // other writer. Retry only this documented lock-conflict outcome.
            $busy = false;
            for ($cause = $exception; $cause instanceof Throwable; $cause = $cause->getPrevious()) {
                if (preg_match(
                    '/database (?:table )?is locked|SQLITE_BUSY/i',
                    $cause->getMessage(),
                ) === 1) {
                    $busy = true;
                }
            }

            if (!$busy || $settings['mode'] !== 'success' || microtime(true) >= $deadline) {
                throw $exception;
            }

            atomicVaultSignal(
                $settings['signal'] . '.busy',
                $settings['operation'],
            );

            usleep(10000);
        }
    }
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class . ': ' . $exception->getMessage() . "\n");
    exit(17);
}
