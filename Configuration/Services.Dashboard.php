<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use Netresearch\NrVault\Widgets\AdminOnlyBarChartWidget;
use Netresearch\NrVault\Widgets\AdminOnlyNumberWithIconWidget;
use Netresearch\NrVault\Widgets\DataProvider\ActiveSecretCountDataProvider;
use Netresearch\NrVault\Widgets\DataProvider\AuditActivityDataProvider;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use TYPO3\CMS\Dashboard\Widgets\AdminOnlyWidgetInterface;
use TYPO3\CMS\Dashboard\Widgets\BarChartWidget;
use TYPO3\CMS\Dashboard\Widgets\NumberWithIconWidget;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Dashboard widget registration for nr-vault.
 *
 * Imported conditionally from Configuration/Services.php only when
 * typo3/cms-dashboard is installed. This is a PHP config file (not YAML)
 * because TYPO3 loads Configuration/Services.php with a standalone Symfony
 * PhpFileLoader that has no YAML loader in its resolver, so a `.yaml` import
 * cannot be resolved from there.
 *
 * Vault statistics are admin-scoped (matching the vault backend module's
 * 'access' => 'admin') and must not be assignable to non-admin backend
 * users. On TYPO3 v14 the AdminOnly* widget subclasses enforce this via
 * AdminOnlyWidgetInterface; the interface does not exist in v13.4 (added in
 * v14), so v13 falls back to the plain core widget classes — there, widgets
 * are invisible to non-admins anyway unless a group explicitly grants them
 * in its access list.
 */
return static function (ContainerConfigurator $containerConfigurator): void {
    $services = $containerConfigurator->services();

    $services->defaults()
        ->autowire()
        ->autoconfigure()
        ->private();

    $adminOnlySupported = interface_exists(AdminOnlyWidgetInterface::class);
    $numberWidgetClass = $adminOnlySupported ? AdminOnlyNumberWithIconWidget::class : NumberWithIconWidget::class;
    $barWidgetClass = $adminOnlySupported ? AdminOnlyBarChartWidget::class : BarChartWidget::class;

    $services->set(ActiveSecretCountDataProvider::class);
    $services->set(AuditActivityDataProvider::class);

    $services->set('dashboard.widget.nrvault.secrets', $numberWidgetClass)
        ->arg('$dataProvider', service(ActiveSecretCountDataProvider::class))
        ->arg('$options', [
            'icon' => 'vault-secret',
            'title' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_dashboard.xlf:widget.secrets.title',
            'subtitle' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_dashboard.xlf:widget.secrets.subtitle',
        ])
        ->tag('dashboard.widget', [
            'identifier' => 'nrvault-secrets',
            'groupNames' => 'nrvault',
            'title' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_dashboard.xlf:widget.secrets.title',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_dashboard.xlf:widget.secrets.description',
            'iconIdentifier' => 'vault-secret',
            'height' => 'small',
            'width' => 'small',
        ]);

    $services->set('dashboard.widget.nrvault.audit_activity', $barWidgetClass)
        ->arg('$dataProvider', service(AuditActivityDataProvider::class))
        ->tag('dashboard.widget', [
            'identifier' => 'nrvault-audit-activity',
            'groupNames' => 'nrvault',
            'title' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_dashboard.xlf:widget.audit_activity.title',
            'description' => 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_dashboard.xlf:widget.audit_activity.description',
            'iconIdentifier' => 'module-vault',
            'height' => 'medium',
            'width' => 'medium',
        ]);
};
