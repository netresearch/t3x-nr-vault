<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

use DateTimeImmutable;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\GenericContext;
use Netresearch\NrVault\Event\BreakGlassActivatedEvent;
use Netresearch\NrVault\Event\BreakGlassDeactivatedEvent;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\ValidationException;
use Psr\EventDispatcher\EventDispatcherInterface;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;

/**
 * Opens and closes break-glass windows.
 *
 * Everything that makes break-glass accountable lives here — the activation
 * policy, the mandatory justification, the TTL clamp, the audit row and the
 * PSR-14 event. {@see BreakGlassState} only stores bytes.
 */
final readonly class BreakGlassService implements BreakGlassServiceInterface
{
    /**
     * Pseudo-identifier for the audit rows. Break-glass is not about one
     * secret — it is about all of them — so it follows the `__master_key__`
     * convention already established by `vault:rotate-master-key`.
     */
    public const AUDIT_PSEUDO_IDENTIFIER = '__break_glass__';

    public function __construct(
        private BreakGlassState $state,
        private AccessControlServiceInterface $accessControlService,
        private AuditLogServiceInterface $auditLogService,
        private EventDispatcherInterface $eventDispatcher,
    ) {}

    public function activate(string $reason, int $minutes = self::DEFAULT_TTL_MINUTES): BreakGlassSession
    {
        $reason = $this->requireReason($reason, 'break-glass activation');
        $this->assertMayOperate('activation');

        $ttlMinutes = $this->clampTtl($minutes);
        $now = new DateTimeImmutable();
        $session = new BreakGlassSession(
            activatedByUid: $this->accessControlService->getCurrentActorUid(),
            activatedByUsername: $this->accessControlService->getCurrentActorUsername(),
            reason: $reason,
            activatedAt: $now,
            expiresAt: $now->setTimestamp($now->getTimestamp() + ($ttlMinutes * 60)),
        );

        // Audit BEFORE granting the power. The two stores cannot be written
        // atomically, so the order decides which half-failure is possible: this
        // one can leave an audit row for a window that never opened (visible,
        // harmless — the operator simply has no bypass and retries), while the
        // reverse could leave a window OPEN with no evidence, which is the one
        // outcome break-glass exists to make impossible. `log()` throws on
        // failure, so a failed audit write aborts activation.
        $this->auditLogService->log(
            self::AUDIT_PSEUDO_IDENTIFIER,
            AuditAction::BreakGlassActivated->value,
            true,
            null,
            $reason,
            null,
            null,
            new GenericContext([
                'actorUid' => $session->activatedByUid,
                'actorUsername' => $session->activatedByUsername,
                'expiresAt' => $session->expiresAt->getTimestamp(),
                'ttlMinutes' => $ttlMinutes,
            ]),
        );

        $this->state->store($session);

        $this->eventDispatcher->dispatch(new BreakGlassActivatedEvent(
            $session->activatedByUid,
            $session->activatedByUsername,
            $reason,
            $session->expiresAt,
        ));

        return $session;
    }

    public function deactivate(string $reason): void
    {
        $reason = $this->requireReason($reason, 'break-glass deactivation');
        $this->assertMayOperate('deactivation');

        $session = $this->state->getActiveSession();
        if (!$session instanceof BreakGlassSession) {
            // Already closed (explicitly or by expiry). Clear any expired
            // leftover so the registry does not accumulate dead entries, then
            // stay silent: no audit row may imply a window that was not open.
            $this->state->clear();

            return;
        }

        // Revoke BEFORE logging, for the mirror-image reason: an audit row
        // claiming the window is closed while it is still open would be a lie
        // in the direction that matters.
        $this->state->clear();

        $this->auditLogService->log(
            self::AUDIT_PSEUDO_IDENTIFIER,
            AuditAction::BreakGlassDeactivated->value,
            true,
            null,
            $reason,
            null,
            null,
            new GenericContext([
                'actorUid' => $this->accessControlService->getCurrentActorUid(),
                'actorUsername' => $this->accessControlService->getCurrentActorUsername(),
                'activatedByUid' => $session->activatedByUid,
                'activatedByUsername' => $session->activatedByUsername,
                'activationReason' => $session->reason,
                'expiresAt' => $session->expiresAt->getTimestamp(),
            ]),
        );

        $this->eventDispatcher->dispatch(new BreakGlassDeactivatedEvent(
            $this->accessControlService->getCurrentActorUid(),
            $this->accessControlService->getCurrentActorUsername(),
            $reason,
            $session->expiresAt,
        ));
    }

    public function getActiveSession(): ?BreakGlassSession
    {
        return $this->state->getActiveSession();
    }

    public function isActive(): bool
    {
        return $this->state->isActive();
    }

    /**
     * Only a real backend administrator or a real CLI operator may open or
     * close a window.
     *
     * "Real" means the TYPO3 `isAdmin()` / `isSystemMaintainer()` flag on a live
     * session — read here directly rather than through
     * {@see AccessControlServiceInterface::isCurrentActorAdmin()}, which now
     * reports whether the admin BYPASS is active and answers false in exactly
     * the situation break-glass exists to escape.
     *
     * A `TechnicalActorContext::runAs()` scope is deliberately NOT sufficient,
     * even for an actor whose snapshot carries the admin flag: `runAs()` is not
     * an authentication boundary (any code with DI access can open a scope), so
     * accepting it would let arbitrary extension code mint its own bypass with
     * a synthetic justification. Such a scope reports actor type `technical`,
     * which reaches neither branch below.
     *
     * @throws AccessDeniedException
     */
    private function assertMayOperate(string $operation): void
    {
        // A shell on the host is already root-equivalent with respect to the
        // vault (the master key and settings.php are both reachable), so CLI is
        // trusted here and deliberately NOT gated on `allowCliAccess`: that
        // switch governs whether unattended jobs may read secrets, a different
        // question from whether an operator at a terminal may declare an
        // emergency.
        if ($this->accessControlService->getCurrentActorType() === 'cli') {
            return;
        }

        $backendUser = $GLOBALS['BE_USER'] ?? null;
        if (!$backendUser instanceof BackendUserAuthentication) {
            throw AccessDeniedException::breakGlassRequiresAdmin($operation);
        }

        // Defence-in-depth, mirroring AccessControlService: a stale session for
        // a disabled account must not reach this.
        /** @phpstan-ignore property.internal */
        $userRecord = $backendUser->user;
        /** @var array<string, mixed> $userRecordTyped */
        $userRecordTyped = \is_array($userRecord) ? $userRecord : [];
        $disable = $userRecordTyped['disable'] ?? 0;
        if (is_numeric($disable) && (int) $disable !== 0) {
            throw AccessDeniedException::breakGlassRequiresAdmin($operation);
        }

        if ($backendUser->isAdmin() || $backendUser->isSystemMaintainer()) {
            return;
        }

        throw AccessDeniedException::breakGlassRequiresAdmin($operation);
    }

    /**
     * @throws ValidationException
     */
    private function requireReason(string $reason, string $operation): string
    {
        $trimmed = trim($reason);
        if ($trimmed === '') {
            throw ValidationException::missingReason($operation);
        }

        return $trimmed;
    }

    /**
     * Clamp rather than reject: a fat-fingered `--minutes 600` during an
     * incident should yield the one-hour ceiling, not an error the operator has
     * to re-read under pressure. The ceiling is what carries the security
     * property, and clamping enforces it either way.
     */
    private function clampTtl(int $minutes): int
    {
        return min(self::MAX_TTL_MINUTES, max(self::MIN_TTL_MINUTES, $minutes));
    }
}
