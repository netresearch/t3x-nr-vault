<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Domain\Model\Secret;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Authentication\CommandLineUserAuthentication;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Http\ApplicationType;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Access control service implementation.
 */
final class AccessControlService implements AccessControlServiceInterface
{
    /**
     * Least-privilege permission tiers (ADR-005). READ is the broadest
     * (read-tier groups + write-tier groups), WRITE is narrower (write-tier
     * groups only), DELETE is the most restrictive (owner/admin/maintainer
     * only — no group tier).
     */
    private const PERMISSION_READ = 'read';

    private const PERMISSION_WRITE = 'write';

    private const PERMISSION_DELETE = 'delete';

    /**
     * Namespace of the TYPO3 custom permission options that carry the
     * operation permissions. Must match the `customPermOptions` key
     * registered in `ext_localconf.php`.
     */
    private const PERM_OPTION_GROUP = 'tx_nrvault';

    /**
     * Per-request cache of group UIDs that actually exist in the be_groups table.
     * Reset only for the lifetime of the service instance.
     *
     * @var list<int>|null
     */
    private ?array $existingGroupIdsCache = null;

    public function __construct(
        private readonly ExtensionConfigurationInterface $configuration,
        private readonly ?ConnectionPool $connectionPool = null,
        private readonly ?TechnicalActorContextInterface $technicalActorContext = null,
        /**
         * Read-only view of the break-glass window (never the full service —
         * see {@see BreakGlassStateInterface} for the DI-cycle reason).
         * Optional so the ~40 unit tests that construct this service with a
         * configuration mock alone keep working: absent state means "no window
         * open", which is the fail-closed answer.
         */
        private readonly ?BreakGlassStateInterface $breakGlassState = null,
    ) {}

    public function canRead(Secret $secret): bool
    {
        return $this->hasAccess($secret, self::PERMISSION_READ);
    }

    public function canWrite(Secret $secret): bool
    {
        return $this->hasAccess($secret, self::PERMISSION_WRITE);
    }

    public function canDelete(Secret $secret): bool
    {
        return $this->hasAccess($secret, self::PERMISSION_DELETE);
    }

    public function canCreate(): bool
    {
        // An active technical actor was validated as a real, enabled backend
        // user when its runAs() scope was established — same outcome as the
        // authenticated-BE-user branch below (any enabled user can create).
        if ($this->getTechnicalActor() instanceof TechnicalActor) {
            return true;
        }

        $backendUser = $this->getBackendUser();

        // An unauthenticated CommandLineUserAuthentication (messenger worker,
        // scheduler CLI run) must not pass as a backend user — the CLI access
        // configuration decides. See hasAccess() for the full rationale.
        if ($this->isUnauthenticatedCommandLineUser($backendUser)) {
            return $this->configuration->isCliAccessAllowed();
        }

        // Backend user takes precedence
        if ($backendUser instanceof BackendUserAuthentication) {
            // Defence-in-depth: disabled users must not create secrets,
            // even if a stale session is still active.
            return !($this->isBackendUserDisabled($backendUser));
            // Any authenticated backend user can create
        }

        // CLI check (only when no backend user)
        if ($this->isRealCliContext()) {
            return $this->configuration->isCliAccessAllowed();
        }

        // No backend user and not CLI
        return false;
    }

    public function isGranted(VaultPermission $permission): bool
    {
        // An active TechnicalActorContext::runAs() scope supersedes every
        // ambient branch below — same precedence as hasAccess().
        $technicalActor = $this->getTechnicalActor();
        if ($technicalActor instanceof TechnicalActor) {
            return $this->hasTechnicalActorGrant($technicalActor, $permission);
        }

        // A FRONTEND request never carries operation permissions, no matter
        // what $GLOBALS['BE_USER'] holds: TYPO3 populates that global for any
        // visitor with a valid backend session, and frontend output is shared
        // (page cache) with anonymous visitors. Frontend reads stay governed
        // exclusively by the secret's own `frontend_accessible` flag.
        if ($this->isFrontendRequest()) {
            return false;
        }

        $backendUser = $this->getBackendUser();

        // The trusted CLI operator: the TYPO3 CLI bootstrap places an
        // UNAUTHENTICATED CommandLineUserAuthentication in $GLOBALS['BE_USER']
        // (CommandApplication::run() never logs the `_cli_` user in), so there
        // is no user record and no group that could carry a custom permission
        // option. The vault's own CLI trust switch decides instead — narrowed
        // to the cliAllowedOperations allowlist, because "anyone with a shell"
        // must not implicitly hold reveal/delete/audit-export/master-key
        // powers just because deployment automation needs store/rotate.
        if ($this->isUnauthenticatedCommandLineUser($backendUser)) {
            return $this->cliOperationGranted($permission);
        }

        if ($backendUser instanceof BackendUserAuthentication) {
            // Defence-in-depth: a disabled user must not hold any operation
            // permission, even if a stale session reaches this layer.
            if ($this->isBackendUserDisabled($backendUser)) {
                return false;
            }

            if ($this->adminBypassActive($this->isPrivilegedBackendUser($backendUser))) {
                return true;
            }

            return $this->hasCustomPermissionOption($backendUser, $permission);
        }

        // No backend user at all: grant only in a real CLI context (no
        // BE_USER global was ever created — same trusted-operator rule as
        // above). Any other unattributable actor fails closed.
        return $this->isRealCliContext() && $this->cliOperationGranted($permission);
    }

    public function isCurrentActorAdmin(): bool
    {
        $technicalActor = $this->getTechnicalActor();
        if ($technicalActor instanceof TechnicalActor) {
            return $this->adminBypassActive($technicalActor->admin);
        }

        $backendUser = $this->getBackendUser();
        if (!$backendUser instanceof BackendUserAuthentication) {
            return false;
        }

        if ($this->isBackendUserDisabled($backendUser)) {
            return false;
        }

        // Every caller of this method uses it as an authorization bypass — the
        // privileged-column policy in `SecretTcaHook`, the `secret.use`
        // exemption and the owner_uid / frontend_accessible coercions in
        // `VaultService`. So it must answer "does the admin bypass apply",
        // not the raw role: a disabled override that still let admins claim
        // ownership of any secret and read plaintext without `secret.use`
        // would be disabled in name only.
        return $this->adminBypassActive($backendUser->isAdmin());
    }

    public function getCurrentActorUid(): int
    {
        $technicalActor = $this->getTechnicalActor();
        if ($technicalActor instanceof TechnicalActor) {
            return $technicalActor->uid;
        }

        $backendUser = $this->getBackendUser();
        if (!$backendUser instanceof BackendUserAuthentication) {
            return 0;
        }

        /** @phpstan-ignore property.internal */
        $userRecord = $backendUser->user;
        /** @var array<string, mixed> $userRecordTyped */
        $userRecordTyped = \is_array($userRecord) ? $userRecord : [];

        return \is_int($userRecordTyped['uid'] ?? null) ? $userRecordTyped['uid'] : 0;
    }

    public function getCurrentActorType(): string
    {
        // The technical actor supersedes even CLI detection: a runAs() scope
        // typically runs INSIDE a CLI worker, and the audit log must record
        // the named technical identity — not the anonymous CLI operator.
        if ($this->getTechnicalActor() instanceof TechnicalActor) {
            return 'technical';
        }

        // CLI detection must run BEFORE the backend-user check: the TYPO3 CLI
        // bootstrap (console commands, messenger workers) sets
        // $GLOBALS['BE_USER'] to a CommandLineUserAuthentication instance —
        // which extends BackendUserAuthentication — so a backend-user-first
        // order misclassified every CLI/worker access as 'backend'.
        if ($this->isRealCliContext()) {
            return 'cli';
        }

        if (\defined('TYPO3_cliMode') && \constant('TYPO3_cliMode') === true) {
            return 'cli';
        }

        $backendUser = $this->getBackendUser();

        // A CommandLineUserAuthentication BE user only ever exists in CLI
        // context — classify it as 'cli' even when SAPI detection is
        // suppressed (e.g. under PHPUnit, where isRealCliContext() is guarded).
        if ($backendUser instanceof CommandLineUserAuthentication) {
            return 'cli';
        }

        if ($backendUser instanceof BackendUserAuthentication) {
            return 'backend';
        }

        return 'api';
    }

    public function getCurrentActorUsername(): string
    {
        $technicalActor = $this->getTechnicalActor();
        if ($technicalActor instanceof TechnicalActor) {
            return $technicalActor->username;
        }

        $backendUser = $this->getBackendUser();
        if ($backendUser instanceof BackendUserAuthentication) {
            /** @phpstan-ignore property.internal */
            $userRecord = $backendUser->user;
            /** @var array<string, mixed> $userRecordTyped */
            $userRecordTyped = \is_array($userRecord) ? $userRecord : [];

            return \is_string($userRecordTyped['username'] ?? null) ? $userRecordTyped['username'] : 'Unknown';
        }

        // No backend user - check context
        if ($this->isRealCliContext()) {
            return 'CLI';
        }

        return 'Anonymous';
    }

    public function getCurrentUserGroups(): array
    {
        $technicalActor = $this->getTechnicalActor();
        if ($technicalActor instanceof TechnicalActor) {
            return $technicalActor->groupIds;
        }

        $backendUser = $this->getBackendUser();
        if (!$backendUser instanceof BackendUserAuthentication) {
            return [];
        }

        /** @phpstan-ignore nullCoalesce.property */
        $groups = $backendUser->userGroupsUID ?? [];

        /** @var list<int> $result */
        $result = [];
        foreach ($groups as $groupId) {
            $normalised = 0;
            if (\is_int($groupId)) {
                $normalised = $groupId;
            } elseif (is_numeric($groupId)) {
                $normalised = (int) $groupId;
            }

            $result[] = $normalised;
        }

        return $result;
    }

    /**
     * Filter a list of group UIDs to only those that actually exist in be_groups.
     *
     * Stale group UIDs (deleted groups still referenced in a user session)
     * must not grant access. This is a defence-in-depth measure on top of
     * TYPO3's own session handling.
     *
     * The result is cached per request (per service instance) to avoid
     * repeated lookups on hot paths.
     *
     * @param int[] $groupIds
     *
     * @return list<int>
     */
    public function filterExistingGroupIds(array $groupIds): array
    {
        if ($groupIds === []) {
            return [];
        }

        $existing = $this->loadExistingGroupIds();
        if ($existing === null) {
            // No DB available (e.g. unit tests, CLI bootstrap): fail CLOSED
            // rather than open. The caller can still fall back to the
            // owner/admin checks which do not require this lookup.
            return [];
        }

        return array_values(array_intersect($groupIds, $existing));
    }

    /**
     * The unattributed CLI actor's operation grant: the CLI trust switch AND
     * the cliAllowedOperations allowlist must both hold. The per-secret tiers
     * (hasCliAccess) stay governed by allowCliAccess/cliAccessGroups alone —
     * this narrows only the OPERATION dimension.
     */
    private function cliOperationGranted(VaultPermission $permission): bool
    {
        return $this->configuration->isCliAccessAllowed()
            && \in_array($permission->value, $this->configuration->getCliAllowedOperations(), true);
    }

    /**
     * Detect if we're in an actual CLI context (not PHPUnit tests).
     */
    private function isRealCliContext(): bool
    {
        // PHPUnit sets this constant
        if (\defined('PHPUNIT_COMPOSER_INSTALL') || \defined('__PHPUNIT_PHAR__')) {
            return false;
        }

        return PHP_SAPI === 'cli';
    }

    /**
     * Check access to a secret for a given permission tier.
     *
     * @param self::PERMISSION_* $permission
     */
    private function hasAccess(Secret $secret, string $permission): bool
    {
        // An active TechnicalActorContext::runAs() scope supersedes every
        // ambient branch below (the unauthenticated CLI placeholder, a
        // hypothetical $GLOBALS['BE_USER'], the frontend fallback): the
        // caller explicitly asked to be evaluated as that named backend
        // user. Without an active scope this is a no-op and the ambient
        // behaviour is unchanged.
        $technicalActor = $this->getTechnicalActor();
        if ($technicalActor instanceof TechnicalActor) {
            return $this->hasTechnicalActorAccess($technicalActor, $secret, $permission);
        }

        // A FRONTEND request never takes the backend-user branch below, no
        // matter what $GLOBALS['BE_USER'] happens to hold: TYPO3's frontend
        // BackendUserAuthenticator middleware populates that global for ANY
        // visitor who carries a valid backend session, so branching on its
        // mere presence evaluates an ambient backend identity for a request
        // whose output is shared (page cache) with anonymous visitors. The
        // request's application type decides instead — in the frontend only
        // the explicit `frontend_accessible` READ gate applies, exactly as
        // for an anonymous visitor.
        if ($this->isFrontendRequest()) {
            return $this->hasFrontendAccess($secret, $permission);
        }

        $backendUser = $this->getBackendUser();

        // An UNAUTHENTICATED CommandLineUserAuthentication must not take the
        // backend-user precedence branch: the TYPO3 CLI bootstrap
        // (CommandApplication::run() — console commands, Symfony Messenger
        // workers, scheduler runs) places one in $GLOBALS['BE_USER'] "not
        // logged in yet", i.e. without a user record. Treating it as a
        // backend user both shadows the configured CLI access rules (every
        // group/admin/maintainer check fails on the empty record) AND lets
        // its default uid 0 match ownerUid=0 secrets via the owner check.
        // A CommandLineUserAuthentication only ever exists in CLI context
        // (its constructor throws otherwise — see also getCurrentActorType()),
        // so the CLI access rules apply directly. An AUTHENTICATED CLI user
        // (after Bootstrap::initializeBackendAuthentication()) keeps its
        // user-based access semantics below.
        if ($this->isUnauthenticatedCommandLineUser($backendUser)) {
            return $this->hasCliAccess($secret, $permission);
        }

        // Backend user takes precedence
        if ($backendUser instanceof BackendUserAuthentication) {
            return $this->hasBackendUserAccess($backendUser, $secret, $permission);
        }

        // CLI access control (only when no backend user)
        if ($this->isRealCliContext()) {
            return $this->hasCliAccess($secret, $permission);
        }

        // No backend user and not CLI: fall back to the frontend gate.
        return $this->hasFrontendAccess($secret, $permission);
    }

    /**
     * Frontend access for secrets explicitly marked as frontend_accessible.
     * This allows TypoScript and other frontend contexts to resolve vault
     * placeholders. Frontend is READ-ONLY — write/delete are never granted
     * without a backend, CLI or technical actor.
     *
     * @param self::PERMISSION_* $permission
     */
    private function hasFrontendAccess(Secret $secret, string $permission): bool
    {
        if ($permission !== self::PERMISSION_READ) {
            return false;
        }

        return $secret->isFrontendAccessible();
    }

    /**
     * Is the current request a TYPO3 *frontend* request?
     *
     * The request's `applicationType` attribute is core's only authoritative
     * answer (`ApplicationType::fromRequest()`). It is read from
     * `$GLOBALS['TYPO3_REQUEST']` — the fallback core documents for library
     * code that does not receive the PSR-7 request — because this service is
     * called from hooks, listeners and commands that cannot hand one down.
     *
     * Returns false whenever the application type cannot be established:
     * no request at all (CLI, Symfony Messenger worker, scheduler, install
     * tool bootstrap, unit tests) or a request that carries no valid
     * `applicationType` attribute. Those callers keep exactly the behaviour
     * they have today; only a request positively identified as frontend is
     * routed to the frontend gate.
     */
    private function isFrontendRequest(): bool
    {
        $request = $GLOBALS['TYPO3_REQUEST'] ?? null;
        if (!$request instanceof ServerRequestInterface) {
            return false;
        }

        try {
            return ApplicationType::fromRequest($request)->isFrontend();
        } catch (Throwable) {
            // fromRequest() throws when the request was not created by a
            // TYPO3 frontend / backend / install application.
            return false;
        }
    }

    /**
     * Check access for the trusted CLI operator (no authenticated backend
     * user) against the CLI access configuration.
     *
     * @param self::PERMISSION_* $permission
     */
    private function hasCliAccess(Secret $secret, string $permission): bool
    {
        if (!$this->configuration->isCliAccessAllowed()) {
            return false;
        }

        // Check CLI access groups if configured
        $cliAccessGroups = $this->configuration->getCliAccessGroups();
        if ($cliAccessGroups !== []) {
            // The trusted CLI operator is scoped to the configured
            // groups. The applicable secret-group set widens with the
            // permission tier: read may match read- OR write-tier
            // groups, write only write-tier groups, delete has no group
            // tier at all (owner/admin/maintainer-only — none of which a
            // CLI actor is — so group-restricted CLI cannot delete).
            $secretGroups = $this->secretGroupsForPermission($secret, $permission);

            return array_intersect($secretGroups, $cliAccessGroups) !== [];
        }

        // CLI allowed and no group restrictions: trusted operator gets
        // the requested tier.
        return true;
    }

    /**
     * Detect the unauthenticated CommandLineUserAuthentication placeholder
     * that the TYPO3 CLI bootstrap puts into $GLOBALS['BE_USER'] before any
     * authentication happens (console commands, Symfony Messenger workers,
     * scheduler runs). It carries no user record (uid), so no user-based
     * access semantics can apply — CLI access rules must be used instead.
     * Once authenticate() / Bootstrap::initializeBackendAuthentication() has
     * loaded the `_cli_` user record, this returns false and the user-based
     * semantics take over.
     */
    private function isUnauthenticatedCommandLineUser(?BackendUserAuthentication $backendUser): bool
    {
        if (!$backendUser instanceof CommandLineUserAuthentication) {
            return false;
        }

        /** @phpstan-ignore property.internal */
        $userRecord = $backendUser->user;
        /** @var array<string, mixed> $userRecordTyped */
        $userRecordTyped = \is_array($userRecord) ? $userRecord : [];
        $uid = $userRecordTyped['uid'] ?? null;

        if (\is_int($uid)) {
            return $uid <= 0;
        }

        if (is_numeric($uid)) {
            return (int) $uid <= 0;
        }

        // No usable uid at all: not authenticated.
        return true;
    }

    /**
     * Check access for a validated technical actor — the SAME user-based
     * semantics an authenticated backend user gets in
     * `hasBackendUserAccess()`, evaluated against the actor's snapshot:
     *
     * - admin → full access to every tier (this also covers the system
     *   maintainer, because `isSystemMaintainer()` implies the admin flag);
     * - owner → full access to every tier;
     * - group tier per ADR-005, with the same stale-group filtering.
     *
     * No disabled-user re-check: `TechnicalActorContext::runAs()` refuses
     * deleted/disabled/time-restricted users before the scope starts.
     *
     * @param self::PERMISSION_* $permission
     */
    private function hasTechnicalActorAccess(
        TechnicalActor $actor,
        Secret $secret,
        string $permission,
    ): bool {
        if ($this->adminBypassActive($actor->admin)) {
            return true;
        }

        if ($secret->getOwnerUid() === $actor->uid) {
            return true;
        }

        $secretGroups = $this->secretGroupsForPermission($secret, $permission);
        if ($secretGroups !== []) {
            $userGroups = $this->filterExistingGroupIds($actor->groupIds);

            if (array_intersect($secretGroups, $userGroups) !== []) {
                return true;
            }
        }

        return false;
    }

    /**
     * Operation permissions for a validated technical actor.
     *
     * A technical actor is a snapshot of a real backend user, but it has no
     * live session and `runAs()` is explicitly NOT an authentication boundary
     * (any code with DI access can open a scope). A NON-admin technical actor
     * therefore holds exactly what its provisioned backend groups grant via
     * the `tx_nrvault` custom permission options — the same carrier an
     * interactive user's grants come from, resolved here directly from
     * `be_groups` because a technical actor has no authenticated
     * `BackendUserAuthentication` whose `groupData` could be consulted.
     *
     * The one implicit grant is `SecretUse`: headless consumption is the
     * entire purpose of a technical actor, and gating it on a group-level
     * custom permission option would break every existing `runAs()` caller
     * while adding nothing — the per-secret tier already decides which
     * secrets the actor may read.
     */
    private function hasTechnicalActorGrant(TechnicalActor $actor, VaultPermission $permission): bool
    {
        if ($this->adminBypassActive($actor->admin)) {
            return true;
        }

        if ($permission === VaultPermission::SecretUse) {
            return true;
        }

        return $this->technicalActorGroupsGrant($actor, $permission);
    }

    /**
     * Does any of the technical actor's (already subgroup-expanded) groups
     * carry the `tx_nrvault:<permission>` custom permission option?
     *
     * Fail-closed: no ConnectionPool wired (bare unit-test construction) or
     * no groups means no grant.
     */
    private function technicalActorGroupsGrant(TechnicalActor $actor, VaultPermission $permission): bool
    {
        if (!$this->connectionPool instanceof ConnectionPool) {
            return false;
        }

        $groupIds = $this->filterExistingGroupIds($actor->groupIds);
        if ($groupIds === []) {
            return false;
        }

        try {
            $queryBuilder = $this->connectionPool->getQueryBuilderForTable('be_groups');
            $rows = $queryBuilder
                ->select('custom_options')
                ->from('be_groups')
                ->where(
                    $queryBuilder->expr()->in(
                        'uid',
                        $queryBuilder->createNamedParameter($groupIds, Connection::PARAM_INT_ARRAY),
                    ),
                )
                ->executeQuery()
                ->fetchAllAssociative();
        } catch (Throwable) {
            // Fail closed on any database error.
            return false;
        }

        foreach ($rows as $row) {
            $options = $row['custom_options'] ?? null;
            if (!\is_string($options)) {
                continue;
            }

            if ($options === '') {
                continue;
            }

            if (GeneralUtility::inList($options, self::PERM_OPTION_GROUP . ':' . $permission->value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * THE seam for "admins and system maintainers may do anything".
     *
     * Every such decision in this class flows through here — the operation
     * permissions in `isGranted()`, the per-secret tiers in
     * `hasBackendUserAccess()`, their technical-actor counterparts, and the
     * privileged-column / interactive-use exemptions callers reach via
     * `isCurrentActorAdmin()`. Never inline `isAdmin()` in a caller: an
     * override that is only half-disabled is worse than one that is not
     * disabled at all, because the deployment believes it is protected.
     *
     * Three gates, in the order that keeps the default path cheap and total:
     *
     * 1. Not privileged at all → no bypass, nothing else matters.
     * 2. `disableAdminOverride` off (the default) → bypass, and we never even
     *    resolve the security profile. This deliberately keeps
     *    `getSecurityProfile()` — which THROWS on an unknown profile string —
     *    off the hot path of every existing installation.
     * 3. Profile is Standard → bypass anyway. The flag is inert outside the
     *    Hardened profile ON PURPOSE: setting it alone, without the rest of the
     *    hardened policy (external master-key provider, no TYPO3-key fallback),
     *    is far more likely to be a misunderstanding than a decision, and its
     *    failure mode is locking every administrator out of the vault. Hardened
     *    is the explicit statement "I have read the fail-closed contract".
     *    A `vault:doctor`-style check can surface the mismatch by pairing
     *    `isAdminOverrideDisabled()` with `getSecurityProfile()`.
     * 4. Hardened AND disabled → bypass only inside an open break-glass
     *    window. No window, or no state seam wired at all → no bypass.
     */
    private function adminBypassActive(bool $actorIsPrivileged): bool
    {
        if (!$actorIsPrivileged) {
            return false;
        }

        if (!$this->configuration->isAdminOverrideDisabled()) {
            return true;
        }

        if (!$this->configuration->getSecurityProfile()->isHardened()) {
            return true;
        }

        return $this->breakGlassState?->isActive() ?? false;
    }

    /**
     * Does one of the user's groups carry this custom permission option?
     *
     * Deliberately NOT `BackendUserAuthentication::check()`, even though that is
     * the documented API for custom permission options. Core's implementation is
     *
     *     isset($this->groupData[$type])
     *         && ($this->isAdmin() || GeneralUtility::inList(...))
     *
     * — an unconditional `true` for any admin. Routing the grant lookup through
     * it would hand the override straight back to the privileged user whose
     * bypass {@see self::adminBypassActive()} just decided to withhold, leaving
     * `disableAdminOverride` effective on the per-secret tiers and inert on the
     * operation permissions: disabled in name only, which is worse than not
     * disabled, because the deployment believes it is protected.
     *
     * What remains is exactly the list core evaluates for a non-admin, minus the
     * short-circuit — so a non-admin's result is unchanged, and an admin without
     * the override is treated like any other user: they hold what their groups
     * were granted, and nothing more.
     */
    private function hasCustomPermissionOption(
        BackendUserAuthentication $backendUser,
        VaultPermission $permission,
    ): bool {
        /** @phpstan-ignore property.internal */
        $granted = $backendUser->groupData['custom_options'] ?? null;

        if (!\is_string($granted) || $granted === '') {
            return false;
        }

        return GeneralUtility::inList(
            $granted,
            self::PERM_OPTION_GROUP . ':' . $permission->value,
        );
    }

    /**
     * Does this backend user carry the admin / system-maintainer role?
     *
     * `isSystemMaintainer()` is checked explicitly even though it implies the
     * admin flag in core, mirroring `hasBackendUserAccess()`. This answers the
     * ROLE question only — whether the role currently grants a bypass is
     * {@see self::adminBypassActive()}.
     */
    private function isPrivilegedBackendUser(BackendUserAuthentication $backendUser): bool
    {
        if ($backendUser->isAdmin()) {
            return true;
        }

        return $backendUser->isSystemMaintainer();
    }

    private function getTechnicalActor(): ?TechnicalActor
    {
        return $this->technicalActorContext?->getCurrentActor();
    }

    /**
     * Check if backend user has access to a secret for a permission tier.
     *
     * @param self::PERMISSION_* $permission
     */
    private function hasBackendUserAccess(
        BackendUserAuthentication $backendUser,
        Secret $secret,
        string $permission,
    ): bool {
        // BUG FIX: Defence-in-depth — disabled users must be rejected even if
        // their BE_USER session somehow reaches this layer. TYPO3 core normally
        // blocks disabled users earlier, but the vault MUST NOT rely on that
        // alone.
        if ($this->isBackendUserDisabled($backendUser)) {
            return false;
        }

        // Admin / system-maintainer access — full access to every tier, unless
        // the override is disabled (hardened profile) and no break-glass window
        // is open. Routed through the shared seam so a disabled override really
        // removes the global bypass instead of only the operation permissions:
        // an "admin" who still reads every colleague's secret is not restricted.
        if ($this->adminBypassActive($this->isPrivilegedBackendUser($backendUser))) {
            return true;
        }

        // Owner access — full access to every tier (read/write/delete).
        /** @phpstan-ignore property.internal */
        $userRecord = $backendUser->user;
        /** @var array<string, mixed> $userRecordTyped */
        $userRecordTyped = \is_array($userRecord) ? $userRecord : [];
        $currentUserUid = \is_int($userRecordTyped['uid'] ?? null) ? $userRecordTyped['uid'] : 0;
        if ($secret->getOwnerUid() === $currentUserUid) {
            return true;
        }

        // Group access — the applicable secret-group set depends on the tier
        // (least-privilege split, ADR-005). DELETE has no group tier, so the
        // applicable set is empty and group members can never delete.
        $secretGroups = $this->secretGroupsForPermission($secret, $permission);
        if ($secretGroups !== []) {
            // BUG FIX: Filter out stale / deleted group UIDs before the
            // intersection check. A deleted group whose UID is still in the
            // user session must NOT grant access to a secret that lists it.
            $userGroups = $this->filterExistingGroupIds($this->getCurrentUserGroups());

            if (array_intersect($secretGroups, $userGroups) !== []) {
                return true;
            }
        }

        return false;
    }

    /**
     * Resolve which secret group UIDs grant the requested permission tier:
     *
     * - READ:   read-tier (`allowedGroups`) ∪ write-tier (`writeGroups`)
     *           — a write-tier member can always read.
     * - WRITE:  write-tier (`writeGroups`) only.
     * - DELETE: no group tier — deletion is owner/admin/maintainer-only.
     *
     * @param self::PERMISSION_* $permission
     *
     * @return int[]
     */
    private function secretGroupsForPermission(Secret $secret, string $permission): array
    {
        return match ($permission) {
            self::PERMISSION_READ => array_values(array_unique(array_merge(
                $secret->getAllowedGroups(),
                $secret->getWriteGroups(),
            ))),
            self::PERMISSION_WRITE => $secret->getWriteGroups(),
            self::PERMISSION_DELETE => [],
        };
    }

    /**
     * Read the `disable` flag from a backend user record.
     *
     * TYPO3 stores `be_users.disable` as a 0/1 integer (DataHandler casts
     * string "1" from form submissions to int 1). Any non-zero value
     * therefore indicates a disabled user. A missing key is treated as
     * "not disabled" to preserve existing behaviour for tests that do not
     * set the flag.
     */
    private function isBackendUserDisabled(BackendUserAuthentication $backendUser): bool
    {
        /** @phpstan-ignore property.internal */
        $userRecord = $backendUser->user;
        /** @var array<string, mixed> $userRecordTyped */
        $userRecordTyped = \is_array($userRecord) ? $userRecord : [];

        $disable = $userRecordTyped['disable'] ?? 0;
        if (\is_int($disable)) {
            return $disable !== 0;
        }

        if (is_numeric($disable)) {
            return (int) $disable !== 0;
        }

        return false;
    }

    /**
     * Load the set of existing be_groups UIDs from the database.
     *
     * Returns null when the connection pool is not available (unit tests,
     * CLI bootstrap without DB). Cached per service instance.
     *
     * @return list<int>|null
     */
    private function loadExistingGroupIds(): ?array
    {
        if ($this->existingGroupIdsCache !== null) {
            return $this->existingGroupIdsCache;
        }

        if (!$this->connectionPool instanceof ConnectionPool) {
            return null;
        }

        try {
            $queryBuilder = $this->connectionPool
                ->getQueryBuilderForTable('be_groups');
            $queryBuilder->getRestrictions()->removeAll();

            $rows = $queryBuilder
                ->select('uid')
                ->from('be_groups')
                ->where(
                    $queryBuilder->expr()->eq(
                        'deleted',
                        $queryBuilder->createNamedParameter(0, Connection::PARAM_INT),
                    ),
                )
                ->executeQuery()
                ->fetchAllAssociative();
        } catch (Throwable) {
            // DB query failed (schema missing, permissions, etc.) — fail
            // closed: treat all group IDs as stale.
            return $this->existingGroupIdsCache = [];
        }

        /** @var list<int> $uids */
        $uids = [];
        foreach ($rows as $row) {
            $uid = $row['uid'] ?? null;
            if (\is_int($uid)) {
                $uids[] = $uid;
            } elseif (is_numeric($uid)) {
                $uids[] = (int) $uid;
            }
        }

        return $this->existingGroupIdsCache = $uids;
    }

    private function getBackendUser(): ?BackendUserAuthentication
    {
        $beUser = $GLOBALS['BE_USER'] ?? null;

        return $beUser instanceof BackendUserAuthentication ? $beUser : null;
    }
}
