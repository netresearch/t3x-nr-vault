<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Controller;

use Exception;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\GenericContext;
use Netresearch\NrVault\Domain\Dto\SecretMetadata;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Backend\Attribute\AsController;
use TYPO3\CMS\Backend\Routing\UriBuilder;
use TYPO3\CMS\Backend\Template\Components\ButtonBar;
use TYPO3\CMS\Backend\Template\ModuleTemplate;
use TYPO3\CMS\Backend\Template\ModuleTemplateFactory;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Http\JsonResponse;
use TYPO3\CMS\Core\Http\RedirectResponse;
use TYPO3\CMS\Core\Imaging\IconFactory;
use TYPO3\CMS\Core\Imaging\IconSize;
use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Messaging\FlashMessage;
use TYPO3\CMS\Core\Messaging\FlashMessageService;
use TYPO3\CMS\Core\Page\PageRenderer;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;

/**
 * Backend module controller for secrets management.
 */
#[AsController]
final readonly class SecretsController
{
    private const MODULE_NAME = 'admin_vault_secrets';

    private const DATE_FORMAT = 'Y-m-d H:i:s';

    private const LL_PREFIX = 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:';

    private const LL_NO_IDENTIFIER = self::LL_PREFIX . 'secrets.noIdentifier';

    private const LL_NOT_FOUND = self::LL_PREFIX . 'secrets.notFound';

    public function __construct(
        private ModuleTemplateFactory $moduleTemplateFactory,
        private IconFactory $iconFactory,
        private PageRenderer $pageRenderer,
        private VaultServiceInterface $vaultService,
        private UriBuilder $uriBuilder,
        private FlashMessageService $flashMessageService,
        private ConnectionPool $connectionPool,
        private AuditLogServiceInterface $auditLogService,
    ) {}

    /**
     * List all secrets (default action).
     */
    public function listAction(ServerRequestInterface $request): ResponseInterface
    {
        $moduleTemplate = $this->moduleTemplateFactory->create($request);
        $moduleTemplate->makeDocHeaderModuleMenu();
        /** @phpstan-ignore function.alreadyNarrowedType (v14-only method, not available in v13) */
        if (method_exists($moduleTemplate->getDocHeaderComponent(), 'setShortcutContext')) {
            $moduleTemplate->getDocHeaderComponent()->setShortcutContext(
                routeIdentifier: self::MODULE_NAME,
                displayName: $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:mlang_tabs_tab')
                    . ' - '
                    . $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:secrets.title'),
            );
        }

        $this->addDocHeaderButtons($moduleTemplate);

        // Get filter parameters from POST body (filter form uses POST to avoid iframe issues)
        $bodyRaw = $request->getParsedBody();
        $body = \is_array($bodyRaw) ? $bodyRaw : [];
        $identifierVal = $body['identifier'] ?? '';
        $statusVal = $body['status'] ?? '';
        $ownerVal = $body['owner'] ?? 0;
        $filters = [
            'identifier' => \is_string($identifierVal) ? trim($identifierVal) : '',
            'status' => \is_string($statusVal) ? $statusVal : '',
            'owner' => is_numeric($ownerVal) ? (int) $ownerVal : 0,
        ];

        $secrets = $this->vaultService->list();
        $userCache = $this->getUsernameCache($secrets);

        // Get unique owners for filter dropdown
        $ownerOptions = $this->getOwnerOptions($secrets, $userCache);

        $formattedSecrets = [];
        foreach ($secrets as $secret) {
            // Apply filters
            if ($filters['identifier'] !== '' && stripos($secret->identifier, $filters['identifier']) === false) {
                continue;
            }
            // Status filter not applicable - secrets don't have hidden state
            if ($filters['owner'] > 0 && $secret->ownerUid !== $filters['owner']) {
                continue;
            }

            $ownerUid = $secret->ownerUid;
            $formattedSecrets[] = [
                'identifier' => $secret->identifier,
                'owner_uid' => $ownerUid,
                'owner_name' => $userCache[$ownerUid] ?? 'User #' . $ownerUid,
                'created' => date(self::DATE_FORMAT, $secret->createdAt),
                'updated' => date(self::DATE_FORMAT, $secret->updatedAt),
                'read_count' => $secret->readCount,
                'last_read' => $secret->lastReadAt !== null ? date(self::DATE_FORMAT, $secret->lastReadAt) : '-',
                'description' => $secret->description,
                'hidden' => false,
            ];
        }

        $this->pageRenderer->addCssFile('EXT:nr_vault/Resources/Public/Css/backend.css');

        $moduleTemplate->assignMultiple([
            'secrets' => $formattedSecrets,
            'totalCount' => \count($formattedSecrets),
            'isAdmin' => $this->isAdmin(),
            'filters' => $filters,
            'ownerOptions' => $ownerOptions,
        ]);

        $moduleTemplate->setTitle(
            $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:mlang_tabs_tab')
            . ' - '
            . $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:secrets.title'),
        );

        return $moduleTemplate->renderResponse('Secrets/List');
    }

    /**
     * Redirect to FormEngine for creating a new secret.
     */
    public function createAction(): ResponseInterface
    {
        // Redirect to FormEngine for native TYPO3 editing experience
        $editUrl = $this->uriBuilder->buildUriFromRoute('record_edit', [
            'edit' => [
                'tx_nrvault_secret' => [
                    0 => 'new',
                ],
            ],
            'returnUrl' => (string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME),
        ]);

        /** @phpstan-ignore new.internalClass, method.internalClass */
        return new RedirectResponse((string) $editUrl);
    }

    /**
     * Show edit secret form.
     */
    public function editAction(ServerRequestInterface $request): ResponseInterface
    {
        $queryParams = $request->getQueryParams();
        $identifierVal = $queryParams['identifier'] ?? '';
        $identifier = \is_string($identifierVal) ? $identifierVal : '';

        $lang = $this->getLanguageService();

        if ($identifier === '') {
            $this->addFlashMessage(
                $lang->sL(self::LL_NO_IDENTIFIER),
                ContextualFeedbackSeverity::ERROR,
            );

            /** @phpstan-ignore new.internalClass, method.internalClass */
            return new RedirectResponse(
                (string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME),
            );
        }

        try {
            $metadata = $this->vaultService->getMetadata($identifier);
        } catch (SecretNotFoundException) {
            $this->addFlashMessage(
                \sprintf($lang->sL(self::LL_NOT_FOUND), $identifier),
                ContextualFeedbackSeverity::ERROR,
            );

            /** @phpstan-ignore new.internalClass, method.internalClass */
            return new RedirectResponse(
                (string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME),
            );
        }

        $uid = $metadata->uid;
        if ($uid === 0) {
            $this->addFlashMessage(
                $lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:secrets.uidNotFound'),
                ContextualFeedbackSeverity::ERROR,
            );

            /** @phpstan-ignore new.internalClass, method.internalClass */
            return new RedirectResponse(
                (string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME),
            );
        }

        // Redirect to FormEngine for native TYPO3 editing experience
        $editUrl = $this->uriBuilder->buildUriFromRoute('record_edit', [
            'edit' => [
                'tx_nrvault_secret' => [
                    $uid => 'edit',
                ],
            ],
            'returnUrl' => (string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME),
        ]);

        /** @phpstan-ignore new.internalClass, method.internalClass */
        return new RedirectResponse((string) $editUrl);
    }

    /**
     * Toggle secret enabled/disabled state.
     *
     * Supports both AJAX (returns JSON) and regular form submissions (redirects).
     */
    public function toggleAction(ServerRequestInterface $request): ResponseInterface
    {
        $bodyRaw = $request->getParsedBody();
        $body = \is_array($bodyRaw) ? $bodyRaw : [];
        $identifierVal = $body['identifier'] ?? '';
        $identifier = \is_string($identifierVal) ? $identifierVal : '';
        $isAjax = $this->isAjaxRequest($request);

        $lang = $this->getLanguageService();

        if ($identifier === '') {
            if ($isAjax) {
                /** @phpstan-ignore new.internalClass, method.internalClass */
                return new JsonResponse(['success' => false, 'error' => 'No secret identifier provided'], 400);
            }
            $this->addFlashMessage(
                $lang->sL(self::LL_NO_IDENTIFIER),
                ContextualFeedbackSeverity::ERROR,
            );

            /** @phpstan-ignore new.internalClass, method.internalClass */
            return new RedirectResponse(
                (string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME),
            );
        }

        try {
            // Get current state - remove restrictions to find hidden records
            $queryBuilder = $this->connectionPool->getQueryBuilderForTable('tx_nrvault_secret');
            $queryBuilder->getRestrictions()->removeAll();
            $current = $queryBuilder
                ->select('hidden')
                ->from('tx_nrvault_secret')
                ->where(
                    $queryBuilder->expr()->eq('identifier', $queryBuilder->createNamedParameter($identifier)),
                    $queryBuilder->expr()->eq('deleted', 0),
                )
                ->executeQuery()
                ->fetchAssociative();

            if ($current === false) {
                throw new SecretNotFoundException('Secret not found: ' . $identifier, 7409034110);
            }

            // Toggle the hidden state
            $newState = $current['hidden'] ? 0 : 1;
            $action = $newState !== 0 ? 'disable' : 'enable';
            $queryBuilder = $this->connectionPool->getQueryBuilderForTable('tx_nrvault_secret');
            $queryBuilder->getRestrictions()->removeAll();
            $queryBuilder
                ->update('tx_nrvault_secret')
                ->set('hidden', $newState)
                ->set('tstamp', time())
                ->where(
                    $queryBuilder->expr()->eq('identifier', $queryBuilder->createNamedParameter($identifier)),
                    $queryBuilder->expr()->eq('deleted', 0),
                )
                ->executeStatement();

            // Log the enable/disable action to audit log
            $this->auditLogService->log(
                $identifier,
                'update',
                true,
                null,
                $action === 'disable' ? 'Secret disabled' : 'Secret enabled',
                null,
                null,
                new GenericContext(['action' => $action, 'hidden' => $newState]),
            );

            $message = $newState !== 0
                ? $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:secrets.disabled.success')
                : $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:secrets.enabled.success');

            if ($isAjax) {
                /** @phpstan-ignore new.internalClass, method.internalClass */
                return new JsonResponse([
                    'success' => true,
                    'hidden' => (bool) $newState,
                    'message' => $message,
                ]);
            }

            $this->addFlashMessage($message, ContextualFeedbackSeverity::OK);
        } catch (SecretNotFoundException) {
            $this->auditLogService->log($identifier, 'update', false, 'Secret not found');
            if ($isAjax) {
                /** @phpstan-ignore new.internalClass, method.internalClass */
                return new JsonResponse(['success' => false, 'error' => 'Secret not found'], 404);
            }
            $this->addFlashMessage(
                \sprintf($lang->sL(self::LL_NOT_FOUND), $identifier),
                ContextualFeedbackSeverity::ERROR,
            );
        } catch (Exception $e) {
            $this->auditLogService->log($identifier, 'update', false, $e->getMessage());
            if ($isAjax) {
                /** @phpstan-ignore new.internalClass, method.internalClass */
                return new JsonResponse(['success' => false, 'error' => 'An internal error occurred'], 500);
            }
            $this->addFlashMessage(
                \sprintf($lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:secrets.error'), $e->getMessage()),
                ContextualFeedbackSeverity::ERROR,
            );
        }

        /** @phpstan-ignore new.internalClass, method.internalClass */
        return new RedirectResponse(
            (string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME),
        );
    }

    /**
     * Delete a secret.
     */
    public function deleteAction(ServerRequestInterface $request): ResponseInterface
    {
        $bodyRaw = $request->getParsedBody();
        $body = \is_array($bodyRaw) ? $bodyRaw : [];
        $identifierVal = $body['identifier'] ?? '';
        $identifier = \is_string($identifierVal) ? $identifierVal : '';
        $reasonVal = $body['reason'] ?? '';
        $reason = \is_string($reasonVal) ? trim($reasonVal) : '';

        $lang = $this->getLanguageService();

        if ($identifier === '') {
            $this->addFlashMessage(
                $lang->sL(self::LL_NO_IDENTIFIER),
                ContextualFeedbackSeverity::ERROR,
            );

            /** @phpstan-ignore new.internalClass, method.internalClass */
            return new RedirectResponse(
                (string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME),
            );
        }

        try {
            $this->vaultService->delete($identifier, $reason);

            $this->addFlashMessage(
                $lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:secrets.delete.success'),
                ContextualFeedbackSeverity::OK,
            );
        } catch (SecretNotFoundException) {
            $this->addFlashMessage(
                \sprintf($lang->sL(self::LL_NOT_FOUND), $identifier),
                ContextualFeedbackSeverity::ERROR,
            );
        } catch (AccessDeniedException) {
            $this->addFlashMessage(
                $lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:secrets.accessDenied'),
                ContextualFeedbackSeverity::ERROR,
            );
        } catch (Exception $e) {
            $this->addFlashMessage(
                \sprintf($lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:secrets.error'), $e->getMessage()),
                ContextualFeedbackSeverity::ERROR,
            );
        }

        /** @phpstan-ignore new.internalClass, method.internalClass */
        return new RedirectResponse(
            (string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME),
        );
    }

    /**
     * Check if the request is an AJAX request.
     */
    private function isAjaxRequest(ServerRequestInterface $request): bool
    {
        $acceptHeader = $request->getHeaderLine('Accept');

        return str_contains($acceptHeader, 'application/json')
            || $request->getHeaderLine('X-Requested-With') === 'XMLHttpRequest';
    }

    private function addDocHeaderButtons(ModuleTemplate $moduleTemplate): void
    {
        $buttonBar = $moduleTemplate->getDocHeaderComponent()->getButtonBar();
        $lang = $this->getLanguageService();

        // Create Secret button
        $createButton = $buttonBar->makeLinkButton()
            ->setHref((string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME . '.create'))
            ->setTitle($lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:secrets.create'))
            ->setShowLabelText(true)
            ->setIcon($this->iconFactory->getIcon('actions-add', IconSize::SMALL));
        $buttonBar->addButton($createButton, ButtonBar::BUTTON_POSITION_LEFT, 1);

        // Note: Reload button is automatically added by TYPO3's DocHeaderComponent
    }

    private function addFlashMessage(string $message, ContextualFeedbackSeverity $severity): void
    {
        $flashMessage = new FlashMessage($message, '', $severity, true);
        $this->flashMessageService->getMessageQueueByIdentifier()->addMessage($flashMessage);
    }

    private function isAdmin(): bool
    {
        $backendUser = $GLOBALS['BE_USER'] ?? null;
        if (!\is_object($backendUser) || !method_exists($backendUser, 'isAdmin')) {
            return false;
        }

        return (bool) $backendUser->isAdmin();
    }

    private function getLanguageService(): LanguageService
    {
        \assert($GLOBALS['LANG'] instanceof LanguageService);

        return $GLOBALS['LANG'];
    }

    /**
     * Build a cache of user IDs to usernames.
     *
     * @param list<SecretMetadata> $secrets
     *
     * @return array<int, string>
     */
    private function getUsernameCache(array $secrets): array
    {
        $userIds = array_unique(array_filter(array_map(
            static fn (SecretMetadata $s): int => $s->ownerUid,
            $secrets,
        )));

        if ($userIds === []) {
            return [];
        }

        $queryBuilder = $this->connectionPool->getQueryBuilderForTable('be_users');
        $result = $queryBuilder
            ->select('uid', 'username', 'realName')
            ->from('be_users')
            ->where(
                $queryBuilder->expr()->in('uid', $userIds),
            )
            ->executeQuery();

        $cache = [];
        while ($row = $result->fetchAssociative()) {
            $realName = $row['realName'] ?? '';
            $username = $row['username'] ?? '';
            $displayName = '';
            if (\is_string($realName) && $realName !== '') {
                $displayName = $realName;
            } elseif (\is_string($username)) {
                $displayName = $username;
            }
            $uidVal = $row['uid'] ?? 0;
            $cache[is_numeric($uidVal) ? (int) $uidVal : 0] = $displayName;
        }

        return $cache;
    }

    /**
     * Get unique owner options for the filter dropdown.
     *
     * @param list<SecretMetadata> $secrets
     * @param array<int, string> $userCache
     *
     * @return array<array{uid: int, name: string}>
     */
    private function getOwnerOptions(array $secrets, array $userCache): array
    {
        $ownerIds = array_unique(array_filter(array_map(
            static fn (SecretMetadata $s): int => $s->ownerUid,
            $secrets,
        )));
        $options = [];
        foreach ($ownerIds as $uid) {
            $options[] = [
                'uid' => $uid,
                'name' => $userCache[$uid] ?? 'User #' . $uid,
            ];
        }
        usort($options, static fn (array $a, array $b): int => strcasecmp($a['name'], $b['name']));

        return $options;
    }
}
