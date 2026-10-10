<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

use MyVendor\MyDeeplExtension\Service\DeepLService;
use Netresearch\NrVault\Service\VaultService;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

return static function (
    ContainerConfigurator $containerConfigurator,
    ContainerBuilder $containerBuilder,
): void {
    $source = (new ReflectionClass(VaultService::class))->getFileName();
    if ($source === false) {
        throw new RuntimeException(
            'The vault service must have a source file for the documentation fixture.',
            1735900001,
        );
    }

    $documentation = dirname($source, 3) . '/Documentation/Usage';
    require_once $documentation . '/_DeepLServiceVault.php';
    // Compile the manual's exact service registration, without supplying its dependencies.
    (new YamlFileLoader($containerBuilder, new FileLocator()))->load(
        $documentation . '/_DeepLServices.yaml',
    );
    // Only visibility changes for retrieval by the functional test.
    $containerBuilder->getDefinition(DeepLService::class)->setPublic(true);
};
