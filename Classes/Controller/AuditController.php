<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Controller;

use DateTimeImmutable;
use Exception;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\AuditLogFilter;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Utility\CsvFormulaSanitizer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Backend\Attribute\AsController;
use TYPO3\CMS\Backend\Routing\UriBuilder;
use TYPO3\CMS\Backend\Template\Components\ButtonBar;
use TYPO3\CMS\Backend\Template\ModuleTemplate;
use TYPO3\CMS\Backend\Template\ModuleTemplateFactory;
use TYPO3\CMS\Core\Http\JsonResponse;
use TYPO3\CMS\Core\Http\Response;
use TYPO3\CMS\Core\Imaging\IconFactory;
use TYPO3\CMS\Core\Imaging\IconSize;
use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Page\PageRenderer;

/**
 * Backend module controller for audit log management.
 */
#[AsController]
final readonly class AuditController
{
    private const MODULE_NAME = 'admin_vault_audit';

    private const LL_PREFIX = 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:';

    private const LL_TABS_TAB = self::LL_PREFIX . 'mlang_tabs_tab';

    public function __construct(
        private ModuleTemplateFactory $moduleTemplateFactory,
        private IconFactory $iconFactory,
        private PageRenderer $pageRenderer,
        private AuditLogServiceInterface $auditLogService,
        private UriBuilder $uriBuilder,
        private ModuleAccessGuard $accessGuard,
    ) {}

    /**
     * Display audit log.
     */
    public function listAction(ServerRequestInterface $request): ResponseInterface
    {
        if (!$this->accessGuard->isGranted(VaultPermission::AuditView)) {
            return $this->accessGuard->deniedResponse($request, VaultPermission::AuditView);
        }

        $moduleTemplate = $this->moduleTemplateFactory->create($request);
        $moduleTemplate->makeDocHeaderModuleMenu();
        /** @phpstan-ignore function.alreadyNarrowedType (v14-only method, not available in v13) */
        if (method_exists($moduleTemplate->getDocHeaderComponent(), 'setShortcutContext')) {
            $moduleTemplate->getDocHeaderComponent()->setShortcutContext(
                routeIdentifier: self::MODULE_NAME,
                displayName: $this->getLanguageService()->sL(self::LL_TABS_TAB)
                    . ' - '
                    . $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:audit.title'),
            );
        }

        $this->addDocHeaderButtons($moduleTemplate);

        // Get filter parameters from POST body (filter form uses POST to avoid iframe issues)
        $body = $request->getParsedBody();
        $bodyArray = \is_array($body) ? $body : [];
        $queryParams = $request->getQueryParams();

        // Merge POST body with query params (POST takes precedence for filters)
        /** @var array<string, mixed> $filterParams */
        $filterParams = array_merge($queryParams, $bodyArray);
        $filterData = $this->buildAuditFilters($filterParams);
        $filter = $filterData['filter'];
        $formData = $filterData['form'];

        $pageVal = $filterParams['page'] ?? 1;
        $page = max(1, is_numeric($pageVal) ? (int) $pageVal : 1);
        $limit = 50;
        $offset = ($page - 1) * $limit;

        $entries = $this->auditLogService->query($filter, $limit, $offset);
        $totalCount = $this->auditLogService->count($filter);
        $totalPages = (int) ceil($totalCount / $limit);

        // Format entries and group by date
        $formattedEntries = [];
        $groupedEntries = [];
        foreach ($entries as $entry) {
            $date = date('Y-m-d', $entry->crdate);
            $formatted = [
                'uid' => $entry->uid,
                'timestamp' => date('Y-m-d H:i:s', $entry->crdate),
                'date' => $date,
                'time' => date('H:i:s', $entry->crdate),
                'secretIdentifier' => $entry->secretIdentifier,
                'action' => $entry->action,
                'actionBadgeClass' => $this->getActionBadgeClass($entry->action),
                'success' => $entry->success,
                'errorMessage' => $entry->errorMessage,
                'reason' => $entry->reason ?? '',
                'actorUsername' => $entry->actorUsername,
                'actorType' => $entry->actorType,
                'ipAddress' => $entry->ipAddress,
                'entryHash' => $entry->entryHash,
                'entryHashShort' => substr($entry->entryHash, 0, 8) . '...',
            ];
            $formattedEntries[] = $formatted;
            $groupedEntries[$date][] = $formatted;
        }

        $this->pageRenderer->addCssFile('EXT:nr_vault/Resources/Public/Css/backend.css');

        // Build pagination URLs with filter parameters preserved
        $baseFilterParams = array_filter([
            'secretIdentifier' => $formData['secretIdentifier'],
            'filterAction' => $formData['action'],
            'success' => $formData['success'],
            'since' => $formData['since'],
            'until' => $formData['until'],
        ], static fn (string $v): bool => $v !== '');

        $pagination = [
            'first' => (string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME, array_merge($baseFilterParams, ['page' => 1])),
            'prev' => (string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME, array_merge($baseFilterParams, ['page' => max(1, $page - 1)])),
            'current' => (string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME, array_merge($baseFilterParams, ['page' => $page])),
            'next' => (string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME, array_merge($baseFilterParams, ['page' => min($totalPages, $page + 1)])),
            'last' => (string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME, array_merge($baseFilterParams, ['page' => $totalPages])),
        ];

        $moduleTemplate->assignMultiple([
            'entries' => $formattedEntries,
            'groupedEntries' => $groupedEntries,
            'totalCount' => $totalCount,
            'currentPage' => $page,
            'totalPages' => $totalPages,
            'filters' => ['_form' => $formData],
            'pagination' => $pagination,
            'canExport' => $this->accessGuard->isGranted(VaultPermission::AuditExport),
            // Derive the action-filter list from the AuditAction enum so the UI
            // can never drift from the actions actually written to the chain
            // (the previous hard-coded list silently omitted master_key_* and
            // oauth_* actions).
            'actions' => array_map(static fn (AuditAction $action): string => $action->value, AuditAction::cases()),
        ]);

        $moduleTemplate->setTitle(
            $this->getLanguageService()->sL(self::LL_TABS_TAB)
            . ' - '
            . $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:audit.title'),
        );

        return $moduleTemplate->renderResponse('Audit/List');
    }

    /**
     * Verify hash chain integrity.
     */
    public function verifyChainAction(ServerRequestInterface $request): ResponseInterface
    {
        // Verification is a read of the chain, so it shares `audit.view` with
        // the listing. Replaces the previous silent redirect-on-non-admin with
        // an explicit 403 that names the missing permission.
        if (!$this->accessGuard->isGranted(VaultPermission::AuditView)) {
            return $this->accessGuard->deniedResponse($request, VaultPermission::AuditView);
        }

        $moduleTemplate = $this->moduleTemplateFactory->create($request);
        $moduleTemplate->makeDocHeaderModuleMenu();

        $buttonBar = $moduleTemplate->getDocHeaderComponent()->getButtonBar();
        $backButton = $buttonBar->makeLinkButton()
            ->setIcon($this->iconFactory->getIcon('actions-view-go-back', IconSize::SMALL))
            ->setTitle($this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:action.back'))
            ->setHref((string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME));
        $buttonBar->addButton($backButton, ButtonBar::BUTTON_POSITION_LEFT, 1);

        $this->pageRenderer->addCssFile('EXT:nr_vault/Resources/Public/Css/backend.css');

        $result = $this->auditLogService->verifyHashChain();

        $moduleTemplate->assignMultiple([
            'valid' => $result->valid,
            'errors' => $result->errors,
            'warnings' => $result->warnings,
            'anchorStatus' => $result->anchorStatus->value,
            'message' => $result->isValid()
                ? $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:audit.chain_valid')
                : $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:audit.chain_invalid'),
        ]);

        $moduleTemplate->setTitle(
            $this->getLanguageService()->sL(self::LL_TABS_TAB)
            . ' - '
            . $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:audit.verify_chain'),
        );

        return $moduleTemplate->renderResponse('Audit/VerifyChain');
    }

    /**
     * Export audit logs.
     */
    public function exportAction(ServerRequestInterface $request): ResponseInterface
    {
        // Export needs its own permission: the downloaded copy leaves the
        // tamper-evident storage behind (no hash chain, no retention, no
        // access control), which `audit.view` deliberately does not cover.
        if (!$this->accessGuard->isGranted(VaultPermission::AuditExport)) {
            /** @phpstan-ignore new.internalClass, method.internalClass */
            return new JsonResponse(['success' => false, 'error' => 'Access denied'], 403);
        }

        $queryParams = $request->getQueryParams();
        $formatVal = $queryParams['format'] ?? 'json';
        $format = \is_string($formatVal) ? $formatVal : 'json';

        /** @var array<string, mixed> $queryParams */
        $filterData = $this->buildAuditFilters($queryParams);

        $entries = $this->auditLogService->export($filterData['filter']);

        if ($format === 'csv') {
            return $this->exportAsCsv($entries);
        }

        // JSON: AuditLogEntry implements JsonSerializable, encode directly
        /** @phpstan-ignore new.internalClass, method.internalClass */
        $response = new Response();
        /** @phpstan-ignore method.internalClass */
        $response->getBody()->write(json_encode($entries, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));

        /** @phpstan-ignore-next-line method.internalClass */
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Content-Disposition', 'attachment; filename="vault-audit-' . date('Y-m-d') . '.json"');
    }

    /**
     * Build audit log filter and form data from request parameters.
     *
     * @param array<string, mixed> $queryParams
     *
     * @return array{filter: ?AuditLogFilter, form: array<string, string>}
     */
    private function buildAuditFilters(array $queryParams): array
    {
        $formData = $this->buildAuditFormData($queryParams);

        // Parse dates
        $since = $this->parseFilterDate($queryParams['since'] ?? '');
        $until = $this->parseFilterDate($queryParams['until'] ?? '');

        // Parse success filter
        $success = null;
        $successValue = $queryParams['success'] ?? '';
        if (\is_string($successValue) && $successValue !== '') {
            $success = (bool) (int) $successValue;
        }

        $secretIdentifierVal = $queryParams['secretIdentifier'] ?? '';
        $actionVal = $queryParams['filterAction'] ?? '';
        $actorUidVal = $queryParams['actorUid'] ?? '';

        $filter = new AuditLogFilter(
            secretIdentifier: \is_string($secretIdentifierVal) && $secretIdentifierVal !== '' ? $secretIdentifierVal : null,
            action: \is_string($actionVal) && $actionVal !== '' ? $actionVal : null,
            actorUid: is_numeric($actorUidVal) ? (int) $actorUidVal : null,
            success: $success,
            since: $since,
            until: $until,
        );

        return [
            'filter' => $filter->isEmpty() ? null : $filter,
            'form' => $formData,
        ];
    }

    /**
     * Build form values for repopulation (always strings for form fields).
     *
     * @param array<string, mixed> $queryParams
     *
     * @return array<string, string>
     */
    private function buildAuditFormData(array $queryParams): array
    {
        $secretIdVal = $queryParams['secretIdentifier'] ?? '';
        $filterActionVal = $queryParams['filterAction'] ?? '';
        $successFormVal = $queryParams['success'] ?? '';
        $sinceFormVal = $queryParams['since'] ?? '';
        $untilFormVal = $queryParams['until'] ?? '';

        return [
            'secretIdentifier' => \is_string($secretIdVal) ? $secretIdVal : '',
            'action' => \is_string($filterActionVal) ? $filterActionVal : '',
            'success' => \is_string($successFormVal) || \is_int($successFormVal) ? (string) $successFormVal : '',
            'since' => \is_string($sinceFormVal) ? $sinceFormVal : '',
            'until' => \is_string($untilFormVal) ? $untilFormVal : '',
        ];
    }

    /**
     * Parse a date filter value; malformed or empty input yields null so the
     * filter is simply not applied. The form re-renders the raw value so the
     * user can correct it.
     */
    private function parseFilterDate(mixed $value): ?DateTimeImmutable
    {
        if (\is_string($value) && $value !== '') {
            try {
                return new DateTimeImmutable($value);
            } catch (Exception) {
                // Malformed date input from the user — fall through to null.
            }
        }

        return null;
    }

    /**
     * @param list<AuditLogEntry> $entries
     */
    private function exportAsCsv(array $entries): ResponseInterface
    {
        /** @phpstan-ignore new.internalClass, method.internalClass */
        $response = new Response();
        $output = fopen('php://temp', 'r+');

        if ($output === false) {
            /** @phpstan-ignore method.internalClass */
            $response->getBody()->write('Failed to create output stream');

            /** @phpstan-ignore-next-line method.internalClass */
            return $response->withHeader('Content-Type', 'text/plain');
        }

        if ($entries === []) {
            fwrite($output, "No data\n");
        } else {
            $first = $entries[0]->jsonSerialize();
            // escape: '' selects strict RFC-4180 output: enclosures are always
            // doubled. PHP's legacy escape character ('\\') suppresses that
            // doubling after a backslash, which lets attacker-controlled audit
            // data (request id, user agent, reason) terminate its own quoted
            // cell and synthesize new cells whose first byte
            // CsvFormulaSanitizer never inspected (CWE-1236).
            fputcsv($output, array_keys($first), escape: '');

            foreach ($entries as $entry) {
                $row = $entry->jsonSerialize();
                if (\is_array($row['context'])) {
                    $row['context'] = json_encode($row['context']);
                }
                /** @var array<int, bool|float|int|string|null> $values */
                $values = array_values($row);
                fputcsv($output, CsvFormulaSanitizer::neutralizeRow($values), escape: '');
            }
        }

        rewind($output);
        $csv = stream_get_contents($output);
        fclose($output);

        /** @phpstan-ignore method.internalClass */
        $response->getBody()->write(\is_string($csv) ? $csv : '');

        /** @phpstan-ignore-next-line method.internalClass */
        return $response
            ->withHeader('Content-Type', 'text/csv')
            ->withHeader('Content-Disposition', 'attachment; filename="vault-audit-' . date('Y-m-d') . '.csv"');
    }

    private function addDocHeaderButtons(ModuleTemplate $moduleTemplate): void
    {
        $buttonBar = $moduleTemplate->getDocHeaderComponent()->getButtonBar();
        $lang = $this->getLanguageService();

        // The buttons follow the same permissions the actions enforce, so the
        // UI never offers an operation that would answer 403.
        if ($this->accessGuard->isGranted(VaultPermission::AuditView)) {
            // Verify Chain button
            $verifyButton = $buttonBar->makeLinkButton()
                ->setHref((string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME . '.verifyChain'))
                ->setTitle($lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:audit.verify_chain'))
                ->setIcon($this->iconFactory->getIcon('actions-check', IconSize::SMALL));
            $buttonBar->addButton($verifyButton, ButtonBar::BUTTON_POSITION_LEFT, 1);
        }

        if ($this->accessGuard->isGranted(VaultPermission::AuditExport)) {
            // Export JSON button
            $exportJsonButton = $buttonBar->makeLinkButton()
                ->setHref((string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME . '.export', ['format' => 'json']))
                ->setTitle($lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:audit.export') . ' JSON')
                ->setIcon($this->iconFactory->getIcon('actions-download', IconSize::SMALL));
            $buttonBar->addButton($exportJsonButton, ButtonBar::BUTTON_POSITION_LEFT, 2);

            // Export CSV button
            $exportCsvButton = $buttonBar->makeLinkButton()
                ->setHref((string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME . '.export', ['format' => 'csv']))
                ->setTitle($lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:audit.export') . ' CSV')
                ->setIcon($this->iconFactory->getIcon('actions-document-export-csv', IconSize::SMALL));
            $buttonBar->addButton($exportCsvButton, ButtonBar::BUTTON_POSITION_LEFT, 3);
        }

        // Note: Reload button is automatically added by TYPO3's DocHeaderComponent
    }

    private function getActionBadgeClass(string $action): string
    {
        return match ($action) {
            'create' => 'success',
            'read' => 'info',
            'update' => 'warning',
            'delete' => 'danger',
            'rotate' => 'info',
            'access_denied' => 'danger',
            // A break-glass activation is the most review-worthy row in the
            // log; it must not blend into the grey default.
            'break_glass_activated' => 'danger',
            'break_glass_deactivated' => 'success',
            default => 'secondary',
        };
    }

    private function getLanguageService(): LanguageService
    {
        \assert($GLOBALS['LANG'] instanceof LanguageService);

        return $GLOBALS['LANG'];
    }
}
