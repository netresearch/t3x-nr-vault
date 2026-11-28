<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Task;

use Netresearch\NrVault\Hook\RecordLinkFactory;
use Netresearch\NrVault\Service\OrphanReferenceChecker;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Task\OrphanCleanupTask;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\TestingFramework\Core\Functional\Framework\DataHandling\ActionService;

use function json_decode;

/**
 * A secret entered while editing a workspace version, then published.
 *
 * Publishing copies the version's values onto the live uid and hard-deletes
 * the version row (EXT:workspaces `version_swap()`). A record link naming the
 * version uid would therefore point at a missing row while the live record
 * holds the secret, and the orphan cleanup would delete a secret in use
 * (#565). The link names the live uid instead, and the cleanup also keeps any
 * secret another row still holds.
 */
#[CoversClass(RecordLinkFactory::class)]
#[CoversClass(OrphanReferenceChecker::class)]
#[CoversClass(OrphanCleanupTask::class)]
final class WorkspacePublishOrphanCleanupTest extends AbstractVaultFunctionalTestCase
{
    private const TABLE = 'tx_nrvaulttest_versioned';

    private const WORKSPACE = 1;

    /** @var list<string> */
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
        __DIR__ . '/../Fixtures/Extensions/nr_vault_test',
    ];

    /** @var list<string> */
    protected array $coreExtensionsToLoad = ['backend', 'frontend', 'scheduler', 'workspaces'];

    protected ?string $backendUserFixture = __DIR__ . '/../Hook/Fixtures/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 1,
    ];

    protected function setUp(): void
    {
        parent::setUp();

        $this->importCSVDataSet(__DIR__ . '/../Hook/Fixtures/pages.csv');
        $this->importCSVDataSet(__DIR__ . '/Fixtures/sys_workspace.csv');
    }

    #[Test]
    public function aSecretEnteredOnAWorkspaceVersionSurvivesPublishingAndOrphanCleanup(): void
    {
        $actionService = new ActionService();
        $vaultService  = $this->get(VaultServiceInterface::class);
        $plaintext     = 'workspace-' . bin2hex(random_bytes(8));

        // A live record without a secret.
        $created     = $actionService->createNewRecord(self::TABLE, 1, ['title' => 'Live record']);
        $createdUids = $created[self::TABLE] ?? null;
        self::assertIsArray($createdUids);
        $liveUid = $createdUids[0] ?? null;
        self::assertIsInt($liveUid);

        // In the workspace: the first save creates the version, the second
        // edits that version directly, as the backend form does once a
        // version exists.
        $GLOBALS['BE_USER']->setWorkspace(self::WORKSPACE);
        $actionService->modifyRecord(self::TABLE, $liveUid, ['title' => 'Workspace record']);
        $versionUid = $this->versionUidOf($liveUid);
        $actionService->modifyRecord(self::TABLE, $versionUid, ['api_key' => $plaintext]);

        $identifier = $this->fieldOf($versionUid);
        self::assertTrue($vaultService->exists($identifier), 'The secret entered on the version must be stored');
        self::assertSame($liveUid, $this->storedMetadata($identifier)['uid'] ?? null, 'The record link must name the live uid, never the version uid');

        $actionService->publishRecord(self::TABLE, $liveUid);
        $GLOBALS['BE_USER']->setWorkspace(0);

        self::assertFalse($this->rowExists($versionUid), 'Publishing must have removed the version row');
        self::assertSame($identifier, $this->fieldOf($liveUid), 'The live record must hold the published secret');

        $this->getConnectionPool()->getConnectionForTable('tx_nrvault_secret')->update(
            'tx_nrvault_secret',
            ['crdate' => time() - 86400],
            [],
        );
        $task = new OrphanCleanupTask($this->get(ConnectionPool::class), $vaultService);
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);
        self::assertTrue($task->execute());

        self::assertSame($plaintext, $vaultService->retrieve($identifier), 'Orphan cleanup must not delete the published secret');
    }

    private function versionUidOf(int $liveUid): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        $uid = $queryBuilder
            ->select('uid')
            ->from(self::TABLE)
            ->where(
                $queryBuilder->expr()->eq('t3ver_oid', $queryBuilder->createNamedParameter($liveUid, Connection::PARAM_INT)),
                $queryBuilder->expr()->eq('t3ver_wsid', $queryBuilder->createNamedParameter(self::WORKSPACE, Connection::PARAM_INT)),
            )
            ->executeQuery()
            ->fetchOne();
        self::assertNotFalse($uid, 'The first workspace save must have created a version');

        return (int) $uid;
    }

    private function fieldOf(int $uid): string
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        $value = $queryBuilder
            ->select('api_key')
            ->from(self::TABLE)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();
        self::assertIsString($value);
        self::assertNotSame('', $value);

        return $value;
    }

    private function rowExists(int $uid): bool
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        return (int) $queryBuilder
            ->count('uid')
            ->from(self::TABLE)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne() > 0;
    }

    /**
     * @return array<string, mixed>
     */
    private function storedMetadata(string $identifier): array
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable('tx_nrvault_secret');
        $queryBuilder->getRestrictions()->removeAll();

        $raw = $queryBuilder
            ->select('metadata')
            ->from('tx_nrvault_secret')
            ->where($queryBuilder->expr()->eq('identifier', $queryBuilder->createNamedParameter($identifier)))
            ->executeQuery()
            ->fetchOne();
        self::assertIsString($raw);

        $metadata = json_decode($raw, true);
        self::assertIsArray($metadata);

        $typed = [];
        foreach ($metadata as $key => $value) {
            $typed[(string) $key] = $value;
        }

        return $typed;
    }
}
