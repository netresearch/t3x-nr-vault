<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Controller;

use Netresearch\NrVault\Domain\Dto\StaleSecret;
use Netresearch\NrVault\Service\Analytics\VaultAnalyticsServiceInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Backend\Attribute\AsController;
use TYPO3\CMS\Backend\Routing\UriBuilder as BackendUriBuilder;
use TYPO3\CMS\Backend\Template\ModuleTemplateFactory;

/**
 * Backend module controller for the vault usage-analytics submodule.
 */
#[AsController]
final readonly class AnalyticsController
{
    private const MODULE_NAME = 'admin_vault_analytics';

    /** Allowed usage windows in days. */
    private const WINDOWS = [30, 90, 180, 365];

    private const DEFAULT_WINDOW = 90;

    public function __construct(
        private ModuleTemplateFactory $moduleTemplateFactory,
        private VaultAnalyticsServiceInterface $analyticsService,
        private BackendUriBuilder $backendUriBuilder,
    ) {}

    public function indexAction(ServerRequestInterface $request): ResponseInterface
    {
        $moduleTemplate = $this->moduleTemplateFactory->create($request);
        $moduleTemplate->makeDocHeaderModuleMenu();

        $window = $this->resolveWindow($request);
        $stats = $this->analyticsService->getUsageStats($window);
        $candidates = $this->analyticsService->getRedactionCandidates($window);

        $moduleTemplate->assignMultiple([
            'stats' => $stats,
            'candidateCount' => \count($candidates),
            'candidates' => array_map($this->toRow(...), $candidates),
            'window' => $window,
            'windowOptions' => $this->buildWindowOptions($window),
        ]);

        return $moduleTemplate->renderResponse('Analytics/Index');
    }

    private function resolveWindow(ServerRequestInterface $request): int
    {
        $raw = $request->getQueryParams()['window'] ?? null;
        $value = is_numeric($raw) ? (int) $raw : self::DEFAULT_WINDOW;

        return \in_array($value, self::WINDOWS, true) ? $value : self::DEFAULT_WINDOW;
    }

    /**
     * @return array{uid: int, identifier: string, context: string, adapter: string, lastReadAt: int|null, automatedReads: int, manualReveals: int, ageDays: int, severity: string, rules: list<array{key: string, severity: string}>, editUrl: string}
     */
    private function toRow(StaleSecret $secret): array
    {
        $rules = [];
        foreach ($secret->rules as $rule) {
            $rules[] = ['key' => $rule->value, 'severity' => $rule->severity()];
        }

        return [
            'uid' => $secret->uid,
            'identifier' => $secret->identifier,
            'context' => $secret->context,
            'adapter' => $secret->adapter,
            'lastReadAt' => $secret->lastReadAt,
            'automatedReads' => $secret->automatedReads,
            'manualReveals' => $secret->manualReveals,
            'ageDays' => $secret->ageDays,
            'severity' => $secret->highestSeverity(),
            'rules' => $rules,
            'editUrl' => (string) $this->backendUriBuilder->buildUriFromRoute('record_edit', [
                'edit' => ['tx_nrvault_secret' => [$secret->uid => 'edit']],
                'returnUrl' => (string) $this->backendUriBuilder->buildUriFromRoute(self::MODULE_NAME),
            ]),
        ];
    }

    /**
     * @return list<array{days: int, url: string, active: bool}>
     */
    private function buildWindowOptions(int $active): array
    {
        $options = [];
        foreach (self::WINDOWS as $days) {
            $options[] = [
                'days' => $days,
                'url' => (string) $this->backendUriBuilder->buildUriFromRoute(self::MODULE_NAME, ['window' => $days]),
                'active' => $days === $active,
            ];
        }

        return $options;
    }
}
