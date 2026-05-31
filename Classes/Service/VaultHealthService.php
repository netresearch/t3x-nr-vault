<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service;

use Netresearch\NrVault\Crypto\MasterKeyProviderFactoryInterface;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Read-only health probe for the master-key / encryption subsystem.
 *
 * Services may depend on Crypto; controllers must not (ARCHITECTURE-2). This
 * service therefore owns the master-key liveness check that previously lived
 * in {@see \Netresearch\NrVault\Controller\OverviewController}.
 *
 * Per SEC-INJECTION-LEAK-2 it never returns raw exception messages (which can
 * carry the master-key file path): failures are logged via PSR-3 and the
 * caller only learns the booleans + provider identifier.
 */
final readonly class VaultHealthService implements VaultHealthServiceInterface
{
    public function __construct(
        private MasterKeyProviderFactoryInterface $masterKeyProviderFactory,
        private LoggerInterface $logger,
    ) {}

    public function checkHealth(): VaultHealthStatus
    {
        $masterKeyAvailable = false;
        $masterKeyProvider = '';
        $encryptionWorking = false;
        $hasIssues = false;

        try {
            $provider = $this->masterKeyProviderFactory->getAvailableProvider();
            $masterKeyProvider = $provider->getIdentifier();

            if ($provider->isAvailable()) {
                $masterKeyAvailable = true;

                // Can we actually derive/read the master key?
                try {
                    $key = $provider->getMasterKey();
                    if ($key === '') {
                        $hasIssues = true;
                        $this->logger->warning(
                            'Vault health check: master key provider returned an empty key.',
                            ['provider' => $masterKeyProvider],
                        );
                    } else {
                        $encryptionWorking = true;
                        sodium_memzero($key);
                    }
                } catch (Throwable $e) {
                    $hasIssues = true;
                    // Detail (may include a key file path) goes to the log only.
                    $this->logger->warning(
                        'Vault health check: master key could not be read.',
                        ['provider' => $masterKeyProvider, 'exception' => $e->getMessage()],
                    );
                }
            } else {
                $hasIssues = true;
                $this->logger->warning(
                    'Vault health check: master key provider is configured but not available.',
                    ['provider' => $masterKeyProvider],
                );
            }
        } catch (Throwable $e) {
            $hasIssues = true;
            $this->logger->warning(
                'Vault health check: no master key provider available.',
                ['exception' => $e->getMessage()],
            );
        }

        return new VaultHealthStatus(
            masterKeyAvailable: $masterKeyAvailable,
            masterKeyProvider: $masterKeyProvider,
            encryptionWorking: $encryptionWorking,
            hasIssues: $hasIssues,
        );
    }
}
