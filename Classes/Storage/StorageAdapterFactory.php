<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage;

use Netresearch\NrVault\Adapter\HashiCorpAdapter;
use Netresearch\NrVault\Adapter\LocalEncryptionAdapter;
use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\ConfigurationException;

/**
 * Selects the storage adapter named by the `storageAdapter` setting.
 *
 * `local` is the default and the fallback for `aws`, which is declared but not
 * yet implemented. An unknown value is refused rather than treated as `local`:
 * a typo must not decide where secrets are stored.
 *
 * A consuming extension that binds its own adapter to
 * {@see VaultAdapterInterface} in its Services.yaml replaces this factory's
 * result, as before.
 */
final readonly class StorageAdapterFactory
{
    public function __construct(
        private ExtensionConfigurationInterface $configuration,
        private LocalEncryptionAdapter $local,
        private HashiCorpAdapter $hashicorp,
    ) {}

    /**
     * @throws ConfigurationException For a value that names no adapter
     */
    public function create(): VaultAdapterInterface
    {
        return match ($this->configuration->getStorageAdapter()) {
            'local', 'aws'               => $this->local,
            HashiCorpAdapter::IDENTIFIER => $this->hashicorp,
            default                      => throw ConfigurationException::invalidAdapter($this->configuration->getStorageAdapter()),
        };
    }
}
