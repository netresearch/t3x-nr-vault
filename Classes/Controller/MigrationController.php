<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Controller;

use Doctrine\DBAL\Exception as DbalException;
use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Schema\Table;
use Exception;
use Netresearch\NrVault\Domain\Dto\MigrationResult;
use Netresearch\NrVault\Service\SecretDetectionService;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Utility\IdentifierValidator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Backend\Attribute\AsController;
use TYPO3\CMS\Backend\Routing\UriBuilder;
use TYPO3\CMS\Backend\Template\Components\ButtonBar;
use TYPO3\CMS\Backend\Template\ModuleTemplate;
use TYPO3\CMS\Backend\Template\ModuleTemplateFactory;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Http\RedirectResponse;
use TYPO3\CMS\Core\Imaging\IconFactory;
use TYPO3\CMS\Core\Imaging\IconSize;
use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Messaging\FlashMessage;
use TYPO3\CMS\Core\Messaging\FlashMessageService;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;

/**
 * Backend module controller for secret migration wizard.
 *
 * Provides a wizard interface for migrating plaintext secrets to the vault:
 * 1. Scan - Detect plaintext secrets in database and configuration
 * 2. Review - Review detected secrets and select which to migrate
 * 3. Configure - Set migration options (identifier pattern, ownership)
 * 4. Execute - Perform the migration
 * 5. Verify - Confirm migration success
 */
#[AsController]
final readonly class MigrationController
{
    private const MODULE_NAME = 'admin_vault_migration';

    /**
     * Allowed actions for this controller.
     *
     * @var list<string>
     */
    private const ALLOWED_ACTIONS = ['index', 'scan', 'review', 'configure', 'execute', 'verify'];

    private const LL_PREFIX = 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:';

    private const LL_TABS_TAB = self::LL_PREFIX . 'mlang_tabs_tab';

    public function __construct(
        private ModuleTemplateFactory $moduleTemplateFactory,
        private SecretDetectionService $detectionService,
        private VaultServiceInterface $vaultService,
        private ConnectionPool $connectionPool,
        private UriBuilder $uriBuilder,
        private FlashMessageService $flashMessageService,
        private IconFactory $iconFactory,
    ) {}

    /**
     * Main entry point - dispatches to action methods based on ?action= query param.
     */
    public function handleRequest(ServerRequestInterface $request): ResponseInterface
    {
        $queryParams = $request->getQueryParams();
        $action = $queryParams['action'] ?? 'index';

        // Validate action
        if (!\in_array($action, self::ALLOWED_ACTIONS, true)) {
            $action = 'index';
        }

        return match ($action) {
            'scan' => $this->scanAction($request),
            'review' => $this->reviewAction($request),
            'configure' => $this->configureAction($request),
            'execute' => $this->executeAction($request),
            'verify' => $this->verifyAction($request),
            default => $this->indexAction($request),
        };
    }

    /**
     * Index action - shows intro page with "Start Scan" button.
     *
     * The scan is not run automatically to avoid slow page loads.
     */
    private function indexAction(ServerRequestInterface $request): ResponseInterface
    {
        $moduleTemplate = $this->moduleTemplateFactory->create($request);
        $moduleTemplate->makeDocHeaderModuleMenu();
        /** @phpstan-ignore function.alreadyNarrowedType (v14-only method, not available in v13) */
        if (method_exists($moduleTemplate->getDocHeaderComponent(), 'setShortcutContext')) {
            $moduleTemplate->getDocHeaderComponent()->setShortcutContext(
                routeIdentifier: self::MODULE_NAME,
                displayName: $this->getLanguageService()->sL(self::LL_TABS_TAB)
                    . ' - '
                    . $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:migration.title'),
            );
        }

        $moduleTemplate->setTitle(
            $this->getLanguageService()->sL(self::LL_TABS_TAB)
            . ' - '
            . $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:migration.title'),
        );

        return $moduleTemplate->renderResponse('Migration/Index');
    }

    /**
     * Step 1: Scan for plaintext secrets (explicitly triggered).
     */
    private function scanAction(ServerRequestInterface $request): ResponseInterface
    {
        $moduleTemplate = $this->moduleTemplateFactory->create($request);
        $moduleTemplate->makeDocHeaderModuleMenu();
        $this->addBackButton($moduleTemplate, 'index');

        $moduleTemplate->setTitle(
            $this->getLanguageService()->sL(self::LL_TABS_TAB)
            . ' - '
            . $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:migration.scan'),
        );

        // Perform the scan
        $secrets = $this->detectionService->scan();
        $groupedSecrets = $this->detectionService->getDetectedSecretsBySeverity();
        $totalCount = $this->detectionService->getDetectedSecretsCount();

        // Count by source
        $databaseCount = 0;
        $configCount = 0;
        foreach ($secrets as $secret) {
            if ($secret->getSource() === 'database') {
                ++$databaseCount;
            } else {
                ++$configCount;
            }
        }

        $moduleTemplate->assignMultiple([
            'secrets' => $secrets,
            'groupedSecrets' => $groupedSecrets,
            'totalCount' => $totalCount,
            'databaseCount' => $databaseCount,
            'configCount' => $configCount,
        ]);

        return $moduleTemplate->renderResponse('Migration/Scan');
    }

    /**
     * Step 2: Review detected secrets and select which to migrate.
     */
    private function reviewAction(ServerRequestInterface $request): ResponseInterface
    {
        $moduleTemplate = $this->moduleTemplateFactory->create($request);
        $moduleTemplate->makeDocHeaderModuleMenu();
        $this->addBackButton($moduleTemplate, 'scan');

        $moduleTemplate->setTitle(
            $this->getLanguageService()->sL(self::LL_TABS_TAB)
            . ' - '
            . $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:migration.review'),
        );

        $queryParams = $request->getQueryParams();
        $sourceFilter = $queryParams['source'] ?? 'all';
        $severityFilter = $queryParams['severity'] ?? 'all';

        // Get previously scanned secrets
        $secrets = $this->detectionService->scan();

        // Filter secrets
        $filteredSecrets = [];
        foreach ($secrets as $key => $secret) {
            if ($sourceFilter !== 'all' && $secret->getSource() !== $sourceFilter) {
                continue;
            }
            if ($severityFilter !== 'all' && $secret->getSeverity()->value !== $severityFilter) {
                continue;
            }

            // Only database secrets can be migrated via wizard
            if ($secret->getSource() === 'database') {
                $filteredSecrets[$key] = $secret;
            }
        }

        $moduleTemplate->assignMultiple([
            'secrets' => $filteredSecrets,
            'sourceFilter' => $sourceFilter,
            'severityFilter' => $severityFilter,
        ]);

        return $moduleTemplate->renderResponse('Migration/Review');
    }

    /**
     * Step 3: Configure migration options.
     */
    private function configureAction(ServerRequestInterface $request): ResponseInterface
    {
        $moduleTemplate = $this->moduleTemplateFactory->create($request);
        $moduleTemplate->makeDocHeaderModuleMenu();
        $this->addBackButton($moduleTemplate, 'review');

        $moduleTemplate->setTitle(
            $this->getLanguageService()->sL(self::LL_TABS_TAB)
            . ' - '
            . $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:migration.configure'),
        );

        $parsedBody = $request->getParsedBody();
        $parsedBodyArray = \is_array($parsedBody) ? $parsedBody : [];
        $selectedSecrets = $parsedBodyArray['selected'] ?? [];

        $lang = $this->getLanguageService();

        if (!\is_array($selectedSecrets) || $selectedSecrets === []) {
            $this->addFlashMessage(
                $lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:migration.noSecretsSelected'),
                $lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:migration.selectionRequired'),
                ContextualFeedbackSeverity::WARNING,
            );

            /** @phpstan-ignore new.internalClass, method.internalClass */
            return new RedirectResponse($this->buildUri('review'));
        }

        // Parse selected secrets (format: "table.column")
        $migrations = [];
        foreach ($selectedSecrets as $key) {
            $keyString = \is_string($key) || is_numeric($key) ? (string) $key : '';
            if (preg_match('/^database:([^.]+)\.([^.]+)$/', $keyString, $matches)) {
                $table = $matches[1];
                $column = $matches[2];
                $migrations[] = [
                    'key' => $key,
                    'table' => $table,
                    'column' => $column,
                    'identifierPattern' => "{$table}__{$column}__{{uid}}",
                ];
            }
        }

        $moduleTemplate->assignMultiple([
            'migrations' => $migrations,
        ]);

        return $moduleTemplate->renderResponse('Migration/Configure');
    }

    /**
     * Step 4: Execute the migration.
     */
    private function executeAction(ServerRequestInterface $request): ResponseInterface
    {
        $parsedBody = $request->getParsedBody();
        $parsedBodyArray = \is_array($parsedBody) ? $parsedBody : [];
        $migrationsRaw = $parsedBodyArray['migrations'] ?? [];
        $migrations = \is_array($migrationsRaw) ? $migrationsRaw : [];
        $clearOriginalsValue = $parsedBodyArray['clearOriginals'] ?? false;
        $clearOriginals = (\is_string($clearOriginalsValue) || \is_int($clearOriginalsValue)) && (bool) $clearOriginalsValue;

        $guardResponse = $this->validateMigrationsRequest($migrations);
        if ($guardResponse instanceof ResponseInterface) {
            return $guardResponse;
        }

        $results = [];
        $totalMigrated = 0;
        $totalFailed = 0;

        foreach ($migrations as $migration) {
            $result = $this->processMigrationEntry($migration);
            if (!$result instanceof MigrationResult) {
                continue;
            }
            $results[] = $result->toArray();
            $totalMigrated += $result->migrated;
            $totalFailed += $result->failed;
        }

        $this->storeMigrationResults($results, $totalMigrated, $totalFailed, $clearOriginals);

        /** @phpstan-ignore new.internalClass, method.internalClass */
        return new RedirectResponse($this->buildUri('verify'));
    }

    /**
     * Validate that migrations were configured; returns a redirect response when invalid, null otherwise.
     *
     * @param array<mixed> $migrations
     */
    private function validateMigrationsRequest(array $migrations): ?ResponseInterface
    {
        if ($migrations !== []) {
            return null;
        }

        $lang = $this->getLanguageService();
        $this->addFlashMessage(
            $lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:migration.noMigrationsConfigured'),
            $lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:migration.configurationRequired'),
            ContextualFeedbackSeverity::ERROR,
        );

        /** @phpstan-ignore new.internalClass, method.internalClass */
        return new RedirectResponse($this->buildUri('scan'));
    }

    /**
     * Process a single migration entry; returns the migration result, or null when the entry is skipped.
     */
    private function processMigrationEntry(mixed $migration): ?MigrationResult
    {
        if (!\is_array($migration)) {
            return null;
        }
        $tableVal = $migration['table'] ?? '';
        $table = \is_string($tableVal) ? $tableVal : '';
        $columnVal = $migration['column'] ?? '';
        $column = \is_string($columnVal) ? $columnVal : '';
        $identifierPatternVal = $migration['identifierPattern'] ?? '';
        $identifierPattern = \is_string($identifierPatternVal) ? $identifierPatternVal : '';
        if ($table === '') {
            return null;
        }
        if ($column === '') {
            return null;
        }
        if ($identifierPattern === '') {
            return null;
        }

        try {
            return $this->migrateColumn($table, $column, $identifierPattern);
        } catch (Exception $e) {
            return MigrationResult::error($table, $column, $e->getMessage());
        }
    }

    /**
     * Store migration results in the backend user session for the verify step.
     *
     * @param list<array<string, mixed>> $results
     */
    private function storeMigrationResults(
        array $results,
        int $totalMigrated,
        int $totalFailed,
        bool $clearOriginals,
    ): void {
        $beUser = $GLOBALS['BE_USER'] ?? null;
        if (\is_object($beUser) && method_exists($beUser, 'setAndSaveSessionData')) {
            $beUser->setAndSaveSessionData('vault_migration_results', [
                'results' => $results,
                'totalMigrated' => $totalMigrated,
                'totalFailed' => $totalFailed,
                'clearOriginals' => $clearOriginals,
            ]);
        }
    }

    /**
     * Step 5: Verify migration results.
     */
    private function verifyAction(ServerRequestInterface $request): ResponseInterface
    {
        $moduleTemplate = $this->moduleTemplateFactory->create($request);
        $moduleTemplate->makeDocHeaderModuleMenu();
        $this->addBackButton($moduleTemplate, 'index');

        $moduleTemplate->setTitle(
            $this->getLanguageService()->sL(self::LL_TABS_TAB)
            . ' - '
            . $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:migration.verify'),
        );

        // Get results from session
        $beUser = $GLOBALS['BE_USER'] ?? null;
        $sessionData = [];
        if (\is_object($beUser) && method_exists($beUser, 'getSessionData')) {
            $sessionDataRaw = $beUser->getSessionData('vault_migration_results');
            $sessionData = \is_array($sessionDataRaw) ? $sessionDataRaw : [];
        }

        $results = \is_array($sessionData['results'] ?? null) ? $sessionData['results'] : [];
        $totalMigratedVal = $sessionData['totalMigrated'] ?? 0;
        $totalMigrated = is_numeric($totalMigratedVal) ? (int) $totalMigratedVal : 0;
        $totalFailedVal = $sessionData['totalFailed'] ?? 0;
        $totalFailed = is_numeric($totalFailedVal) ? (int) $totalFailedVal : 0;
        $clearOriginalsVal = $sessionData['clearOriginals'] ?? false;
        $clearOriginals = \is_bool($clearOriginalsVal) ? $clearOriginalsVal : (bool) $clearOriginalsVal;

        // Clear session data
        if (\is_object($beUser) && method_exists($beUser, 'setAndSaveSessionData')) {
            $beUser->setAndSaveSessionData('vault_migration_results', null);
        }

        $lang = $this->getLanguageService();

        if ($totalMigrated > 0) {
            $this->addFlashMessage(
                \sprintf($lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:migration.success'), $totalMigrated),
                $lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:migration.complete'),
                ContextualFeedbackSeverity::OK,
            );
        }

        if ($totalFailed > 0) {
            $this->addFlashMessage(
                \sprintf($lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:migration.failed'), $totalFailed),
                $lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:migration.errors'),
                ContextualFeedbackSeverity::WARNING,
            );
        }

        $moduleTemplate->assignMultiple([
            'results' => $results,
            'totalMigrated' => $totalMigrated,
            'totalFailed' => $totalFailed,
            'clearOriginals' => $clearOriginals,
        ]);

        return $moduleTemplate->renderResponse('Migration/Verify');
    }

    /**
     * Migrate a single database column to the vault.
     */
    private function migrateColumn(
        string $table,
        string $column,
        string $identifierPattern,
    ): MigrationResult {
        $migrated = 0;
        $failed = 0;
        $skipped = 0;

        // Validate table and column names against database schema to prevent SQL injection
        try {
            $schemaManager = $this->connectionPool
                ->getConnectionByName(ConnectionPool::DEFAULT_CONNECTION_NAME)
                ->createSchemaManager();
            $tableNames = array_map(
                static fn (Table $t): string => $t->getName(), /** @phpstan-ignore method.internalClass */
                $schemaManager->listTables(),
            );
            if (!\in_array($table, $tableNames, true)) {
                return MigrationResult::error($table, $column, 'Invalid table name');
            }

            $columns = array_map(
                static fn (Column $col): string => $col->getName(), /** @phpstan-ignore method.internalClass */
                $schemaManager->listTableColumns($table),
            );
            if (!\in_array($column, $columns, true)) {
                return MigrationResult::error($table, $column, 'Invalid column name');
            }
        } catch (DbalException $e) {
            return MigrationResult::error($table, $column, 'Schema validation failed');
        }

        try {
            $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
            $rows = $queryBuilder
                ->select('uid', $column)
                ->from($table)
                ->where(
                    $queryBuilder->expr()->isNotNull($column),
                    $queryBuilder->expr()->neq($column, $queryBuilder->createNamedParameter('')),
                )
                ->executeQuery()
                ->fetchAllAssociative();

            foreach ($rows as $row) {
                $uidVal = $row['uid'] ?? 0;
                $uid = is_numeric($uidVal) ? (int) $uidVal : 0;
                $valueVal = $row[$column] ?? '';
                $value = \is_string($valueVal) ? $valueVal : '';

                // Skip if already looks like a vault identifier
                if (IdentifierValidator::looksLikeVaultIdentifier($value)) {
                    ++$skipped;
                    continue;
                }

                // Generate identifier from pattern
                $identifier = str_replace('{uid}', (string) $uid, $identifierPattern);

                try {
                    // Store in vault
                    $this->vaultService->store($identifier, $value, [
                        'source' => 'migration',
                        'originalTable' => $table,
                        'originalColumn' => $column,
                        'originalUid' => $uid,
                    ]);

                    // Update database with vault identifier
                    $updateBuilder = $this->connectionPool->getQueryBuilderForTable($table);
                    $updateBuilder
                        ->update($table)
                        ->set($column, $identifier)
                        ->where($updateBuilder->expr()->eq('uid', $uid))
                        ->executeStatement();

                    ++$migrated;

                    // Clear original if requested (update already done above with identifier)
                    // The column now contains the vault identifier, not the original value
                } catch (Exception) {
                    ++$failed;
                }
            }
        } catch (DbalException $e) {
            return MigrationResult::error($table, $column, $e->getMessage());
        }

        return MigrationResult::withFailures($table, $column, $migrated, $failed, $skipped);
    }

    /**
     * Build a URI for a migration action.
     *
     * Uses query param based routing like TYPO3 core modules (styleguide, reactions).
     */
    private function buildUri(string $action): string
    {
        return (string) $this->uriBuilder->buildUriFromRoute(
            self::MODULE_NAME,
            $action === 'scan' ? [] : ['action' => $action],
        );
    }

    /**
     * Add a flash message.
     */
    private function addFlashMessage(
        string $message,
        string $title,
        ContextualFeedbackSeverity $severity,
    ): void {
        $flashMessage = new FlashMessage($message, $title, $severity, true);
        $this->flashMessageService
            ->getMessageQueueByIdentifier()
            ->addMessage($flashMessage);
    }

    private function getLanguageService(): LanguageService
    {
        \assert($GLOBALS['LANG'] instanceof LanguageService);

        return $GLOBALS['LANG'];
    }

    /**
     * Add a back button to the DocHeader.
     */
    private function addBackButton(
        ModuleTemplate $moduleTemplate,
        string $targetAction,
    ): void {
        $buttonBar = $moduleTemplate->getDocHeaderComponent()->getButtonBar();
        $backButton = $buttonBar->makeLinkButton()
            ->setIcon($this->iconFactory->getIcon('actions-view-go-back', IconSize::SMALL))
            ->setTitle($this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:action.back'))
            ->setHref($this->buildUri($targetAction));
        $buttonBar->addButton($backButton, ButtonBar::BUTTON_POSITION_LEFT, 1);
    }
}
