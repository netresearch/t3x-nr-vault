<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

use Netresearch\NrVault\Exception\TechnicalActorException;
use TYPO3\CMS\Core\Authentication\GroupResolver;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Technical actor context implementation.
 *
 * State is a plain per-service-instance stack: with TYPO3's shared DI
 * services that means per-request (web) or per-process (CLI worker).
 * Scopes are strictly LIFO via try/finally; the stack is NOT keyed per
 * fiber — concurrent fibers sharing one instance would observe each
 * other's actor, so `runAs()` scopes must not span fiber suspension
 * points.
 */
final class TechnicalActorContext implements TechnicalActorContextInterface
{
    /** @var list<TechnicalActor> */
    private array $actorStack = [];

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        // GroupResolver is what BackendUserAuthentication::fetchGroupData()
        // itself uses; no non-internal API reproduces core's group semantics.
        // @phpstan-ignore parameter.internalClass, property.internalClass
        private readonly GroupResolver $groupResolver,
    ) {}

    public function runAs(int $beUserUid, callable $fn): mixed
    {
        $actor = $this->resolveActor($beUserUid);

        $this->actorStack[] = $actor;

        try {
            return $fn();
        } finally {
            array_pop($this->actorStack);
        }
    }

    public function getCurrentActor(): ?TechnicalActor
    {
        return $this->actorStack === [] ? null : $this->actorStack[array_key_last($this->actorStack)];
    }

    /**
     * Load and validate the be_users record for the requested actor.
     *
     * Mirrors the enable-column semantics of a real backend login
     * (`deleted`, `disable`, `starttime`, `endtime`): a user who could not
     * authenticate interactively must not be usable as a technical actor
     * either. Fail-closed — every rejection throws before the caller's
     * callable runs.
     *
     * @param positive-int $beUserUid
     *
     * @throws TechnicalActorException
     */
    private function resolveActor(int $beUserUid): TechnicalActor
    {
        if ($beUserUid <= 0) {
            throw TechnicalActorException::invalidUid($beUserUid);
        }

        $record = $this->loadUserRecord($beUserUid);
        if ($record === null) {
            throw TechnicalActorException::userNotFound($beUserUid);
        }

        if ($this->toInt($record['disable'] ?? 0) !== 0) {
            throw TechnicalActorException::userDisabled($beUserUid);
        }

        $now = time();
        $starttime = $this->toInt($record['starttime'] ?? 0);
        $endtime = $this->toInt($record['endtime'] ?? 0);
        if ($starttime > $now || ($endtime !== 0 && $endtime <= $now)) {
            throw TechnicalActorException::userNotActive($beUserUid);
        }

        $username = $record['username'] ?? '';

        return new TechnicalActor(
            uid: $beUserUid,
            username: \is_string($username) ? $username : '',
            admin: $this->toInt($record['admin'] ?? 0) !== 0,
            groupIds: $this->resolveGroupIds($record),
        );
    }

    /**
     * Fetch the raw, non-deleted be_users row.
     *
     * Restrictions are removed deliberately: the enable columns are
     * evaluated explicitly in `resolveActor()` so each rejection carries a
     * distinct, typed exception instead of a generic "not found".
     *
     * @return array<string, mixed>|null
     */
    private function loadUserRecord(int $beUserUid): ?array
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable('be_users');
        $queryBuilder->getRestrictions()->removeAll();

        $row = $queryBuilder
            ->select('*')
            ->from('be_users')
            ->where(
                $queryBuilder->expr()->eq(
                    'uid',
                    $queryBuilder->createNamedParameter($beUserUid, Connection::PARAM_INT),
                ),
                $queryBuilder->expr()->eq(
                    'deleted',
                    $queryBuilder->createNamedParameter(0, Connection::PARAM_INT),
                ),
            )
            ->executeQuery()
            ->fetchAssociative();

        if (!\is_array($row)) {
            return null;
        }

        /** @var array<string, mixed> $row */
        return $row;
    }

    /**
     * Resolve the actor's be_groups uids exactly as a real backend login
     * would (subgroup expansion, enable-column filtering, PSR-14
     * AfterGroupsResolvedEvent).
     *
     * @param array<string, mixed> $userRecord
     *
     * @return list<int>
     */
    private function resolveGroupIds(array $userRecord): array
    {
        // GroupResolver is what BackendUserAuthentication::fetchGroupData()
        // itself uses; there is no non-internal API that reproduces core's
        // group semantics (subgroup recursion + restrictions + event).
        // @phpstan-ignore method.internalClass (no non-internal alternative exists)
        $groups = $this->groupResolver->resolveGroupsForUser($userRecord, 'be_groups');

        $groupIds = [];
        foreach ($groups as $group) {
            $uid = \is_array($group) ? ($group['uid'] ?? null) : null;
            if (\is_int($uid)) {
                $groupIds[] = $uid;
            } elseif (is_numeric($uid)) {
                $groupIds[] = (int) $uid;
            }
        }

        return $groupIds;
    }

    private function toInt(mixed $value): int
    {
        if (\is_int($value)) {
            return $value;
        }

        return is_numeric($value) ? (int) $value : 0;
    }
}
