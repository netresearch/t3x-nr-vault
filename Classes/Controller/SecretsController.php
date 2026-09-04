<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Controller;

use Exception;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Domain\Dto\SecretMetadata;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Security\VaultPermission;
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
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;
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
        private ModuleAccessGuard $accessGuard,
        private BreakGlassBannerProvider $breakGlassBanner,
        private SecretRepositoryInterface $secretRepository,
        private LanguageServiceFactory $languageServiceFactory,
    ) {}

    /**
     * List all secrets (default action).
     *
     * Entering the module needs ANY secret-handling permission; the mutating
     * actions below assert their own. `VaultService::list()` still filters the
     * listing down to the secrets the actor may read per-secret.
     */
    public function listAction(ServerRequestInterface $request): ResponseInterface
    {
        if (!$this->accessGuard->isAnyGranted(...VaultPermission::secretOperations())) {
            return $this->accessGuard->deniedResponse($request, VaultPermission::SecretUse);
        }

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

        // Disabled secrets are listed too. They are the only surface from
        // which one can be re-enabled — the toggle renders per listed row —
        // so omitting them made disabling a one-way door. The row carries a
        // "Disabled" badge and the status filter narrows to either state.
        $secrets = $this->vaultService->list(includeDisabled: true);
        $userCache = $this->getUsernameCache($secrets);

        // Get unique owners for filter dropdown
        $ownerOptions = $this->getOwnerOptions($secrets, $userCache);

        $formattedSecrets = [];
        foreach ($secrets as $secret) {
            // Apply filters
            if ($filters['identifier'] !== '' && stripos($secret->identifier, $filters['identifier']) === false) {
                continue;
            }

            if ($filters['status'] === 'active' && !$secret->enabled) {
                continue;
            }

            if ($filters['status'] === 'disabled' && $secret->enabled) {
                continue;
            }

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
                'hidden' => !$secret->enabled,
            ];
        }

        $this->pageRenderer->addCssFile('EXT:nr_vault/Resources/Public/Css/backend.css');
        // Expose JS UI labels to TYPO3.lang for the SecretsList ESM module
        // (delete/reveal/rotate dialogs, clipboard + error toasts).
        $this->pageRenderer->addInlineLanguageLabelFile('EXT:nr_vault/Resources/Private/Language/locallang_js.xlf');

        $moduleTemplate->assignMultiple([
            'secrets' => $formattedSecrets,
            'totalCount' => \count($formattedSecrets),
            'filters' => $filters,
            'ownerOptions' => $ownerOptions,
            // Per-action flags so the row actions mirror what the endpoints
            // enforce — a rendered button never leads to a 403.
            'canReveal' => $this->accessGuard->isGranted(VaultPermission::SecretReveal),
            'canRotate' => $this->accessGuard->isGranted(VaultPermission::SecretRotate),
            'canDelete' => $this->accessGuard->isGranted(VaultPermission::SecretDelete),
            'canManagePolicy' => $this->accessGuard->isGranted(VaultPermission::SecretManagePolicy),
            'breakGlass' => $this->breakGlassBanner->forView(),
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
    public function createAction(ServerRequestInterface $request): ResponseInterface
    {
        if (!$this->accessGuard->isGranted(VaultPermission::SecretCreate)) {
            return $this->accessGuard->deniedResponse($request, VaultPermission::SecretCreate);
        }

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
     *
     * Editing hands the record to FormEngine, whose form includes the
     * `allowed_groups` / `write_groups` tiers — i.e. the secret's access
     * policy. That makes `secret.manage_policy` the permission this entry
     * point needs, not a plain write permission.
     */
    public function editAction(ServerRequestInterface $request): ResponseInterface
    {
        if (!$this->accessGuard->isGranted(VaultPermission::SecretManagePolicy)) {
            return $this->accessGuard->deniedResponse($request, VaultPermission::SecretManagePolicy);
        }

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
     * The mutation itself belongs to `VaultService::setEnabled()`, which owns
     * the permission gates, the audit entry and its compensating rollback.
     * What is left here is HTTP: resolving which state the button asks for,
     * and answering in JSON or with a flash message plus redirect.
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

        // Enabling/disabling a secret changes its availability to every
        // consumer, so it belongs to policy management rather than to editing
        // a value. The service asserts this again — this gate exists so the
        // module answers with its own 403 page instead of an exception.
        if (!$this->accessGuard->isGranted(VaultPermission::SecretManagePolicy)) {
            if ($isAjax) {
                /** @phpstan-ignore new.internalClass, method.internalClass */
                return new JsonResponse(['success' => false, 'error' => 'Access denied'], 403);
            }

            return $this->accessGuard->deniedResponse($request, VaultPermission::SecretManagePolicy);
        }

        $lang = $this->getLanguageService();

        if ($identifier === '') {
            return $this->toggleMissingIdentifierResponse($isAjax, $lang);
        }

        // Holding secret.manage_policy says the actor may manage policy at
        // all; it does not say WHICH secrets. Without this second, per-secret
        // gate any holder could disable every colleague's secret. The lookup
        // must see disabled records too — otherwise the gate would silently
        // not apply to exactly the secrets this action re-enables.
        $secret = $this->secretRepository->findByIdentifierIncludingDisabled($identifier);
        if ($secret instanceof Secret && !$this->accessGuard->canWrite($secret)) {
            $this->auditLogService->log(
                $identifier,
                AuditAction::AccessDenied->value,
                false,
                'Toggle access denied',
            );

            if ($isAjax) {
                /** @phpstan-ignore new.internalClass, method.internalClass */
                return new JsonResponse(['success' => false, 'error' => 'Access denied'], 403);
            }

            return $this->accessGuard->deniedForSecretResponse($request);
        }

        // The button toggles, the service sets: read the current state here
        // and ask for its opposite. A secret that cannot be found is left to
        // the service's not-found path, so both callers see one behaviour.
        $enable = !$secret instanceof Secret || $secret->isHidden();

        try {
            return $this->applyEnabledState($identifier, $enable, $isAjax);
        } catch (SecretNotFoundException) {
            if ($isAjax) {
                /** @phpstan-ignore new.internalClass, method.internalClass */
                return new JsonResponse(['success' => false, 'error' => 'Secret not found'], 404);
            }

            $this->addFlashMessage(
                \sprintf($lang->sL(self::LL_NOT_FOUND), $identifier),
                ContextualFeedbackSeverity::ERROR,
            );
        } catch (Exception $e) {
            // Deliberately no audit write here. The failure this catch most
            // has to survive is an audit-store outage, and the previous
            // version's log() call would have thrown a SECOND time out of the
            // handler — leaving the request with no response at all, no flash
            // message, and the availability already flipped. Every outcome the
            // service considers auditable it has already audited itself: the
            // denial as `access_denied`, the change as `metadata_update`, and
            // a failed audit write is compensated rather than logged again.
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
        // Per-secret deletion rights (owner/admin/maintainer, no group tier)
        // are still asserted by VaultService::delete() on top of this.
        if (!$this->accessGuard->isGranted(VaultPermission::SecretDelete)) {
            return $this->accessGuard->deniedResponse($request, VaultPermission::SecretDelete);
        }

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
     * Build the response for a toggle request that lacks a secret identifier.
     */
    private function toggleMissingIdentifierResponse(bool $isAjax, LanguageService $lang): ResponseInterface
    {
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

    /**
     * Apply the requested availability through the vault service and turn the
     * outcome into the response shape the caller asked for.
     *
     * The service is what mutates, audits and — on a failed audit write —
     * rolls back; anything it throws propagates to `toggleAction()`'s handlers
     * so a change that could not be audited never reports success.
     */
    private function applyEnabledState(string $identifier, bool $enable, bool $isAjax): ResponseInterface
    {
        $this->vaultService->setEnabled($identifier, $enable);

        $message = $this->getLanguageService()->sL(
            $enable
                ? 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:secrets.enabled.success'
                : 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:secrets.disabled.success',
        );

        if ($isAjax) {
            // `hidden` stays the wire name: the ESM module and the E2E specs
            // read it, and renaming the field is not part of this change.
            /** @phpstan-ignore new.internalClass, method.internalClass */
            return new JsonResponse([
                'success' => true,
                'hidden' => !$enable,
                'message' => $message,
            ]);
        }

        $this->addFlashMessage($message, ContextualFeedbackSeverity::OK);

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

        // Create Secret button — only for actors createAction() would admit.
        if ($this->accessGuard->isGranted(VaultPermission::SecretCreate)) {
            $createButton = $buttonBar->makeLinkButton()
                ->setHref((string) $this->uriBuilder->buildUriFromRoute(self::MODULE_NAME . '.create'))
                ->setTitle($lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:secrets.create'))
                ->setShowLabelText(true)
                ->setIcon($this->iconFactory->getIcon('actions-add', IconSize::SMALL));
            $buttonBar->addButton($createButton, ButtonBar::BUTTON_POSITION_LEFT, 1);
        }

        // Note: Reload button is automatically added by TYPO3's DocHeaderComponent
    }

    private function addFlashMessage(string $message, ContextualFeedbackSeverity $severity): void
    {
        $flashMessage = new FlashMessage($message, '', $severity, true);
        $this->flashMessageService->getMessageQueueByIdentifier()->addMessage($flashMessage);
    }

    private function getLanguageService(): LanguageService
    {
        return $this->languageServiceFactory->create();
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
