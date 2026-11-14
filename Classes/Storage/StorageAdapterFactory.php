<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage;

use Netresearch\NrVault\Adapter\AwsSecretsManagerAdapter;
use Netresearch\NrVault\Adapter\HashiCorpAdapter;
use Netresearch\NrVault\Adapter\LocalEncryptionAdapter;
use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\ConfigurationException;

/**
 * Selects the storage adapter named by the `storageAdapter` setting.
 *
 * `local` is the default. `aws` never falls back to it: without the AWS SDK or
 * with an incomplete configuration the adapter fails with a configuration error
 * when it is used. An unknown value is refused rather than treated as `local`:
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
        private AwsSecretsManagerAdapter $aws,
    ) {}

    /**
     * @throws ConfigurationException For a value that names no adapter
     */
    public function create(): VaultAdapterInterface
    {
        return match ($this->configuration->getStorageAdapter()) {
            'local'                              => $this->local,
            HashiCorpAdapter::IDENTIFIER         => $this->hashicorp,
            AwsSecretsManagerAdapter::IDENTIFIER => $this->aws,
            default                              => throw ConfigurationException::invalidAdapter($this->configuration->getStorageAdapter()),
        };
    }
}
