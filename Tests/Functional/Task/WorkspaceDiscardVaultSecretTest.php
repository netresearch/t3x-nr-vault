<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Task;

use Netresearch\NrVault\Hook\DataHandlerHook;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\TestingFramework\Core\Functional\Framework\DataHandling\ActionService;

/**
 * Discarding a workspace version removes its row without DataHandler's delete
 * command, so the record-delete hook never runs and a secret entered on the
 * version would stay behind. The discard hook deletes such a secret once the
 * version is gone, and only when no other row holds it (#565).
 */
#[CoversClass(DataHandlerHook::class)]
final class WorkspaceDiscardVaultSecretTest extends AbstractVaultFunctionalTestCase
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
    public function discardingAVersionDeletesTheSecretOnlyItHeld(): void
    {
        $actionService = new ActionService();
        $vaultService  = $this->get(VaultServiceInterface::class);

        [$liveUid, $versionUid] = $this->createVersion($actionService);
        $actionService->modifyRecord(self::TABLE, $versionUid, ['api_key' => 'discarded-' . bin2hex(random_bytes(8))]);
        $identifier = $this->fieldOf($versionUid);
        self::assertTrue($vaultService->exists($identifier), 'The secret entered on the version must be stored');

        $actionService->clearWorkspaceRecord(self::TABLE, $liveUid);

        self::assertFalse($this->rowExists($versionUid), 'Discarding must have removed the version row');
        self::assertFalse($vaultService->exists($identifier), 'The secret only the discarded version held must be deleted');
    }

    /**
     * A version created from a live record that already has a secret holds
     * the live record's identifier. Discarding the version must not delete
     * the secret the live record still uses.
     */
    #[Test]
    public function discardingAVersionKeepsASecretTheLiveRecordHolds(): void
    {
        $actionService = new ActionService();
        $vaultService  = $this->get(VaultServiceInterface::class);
        $plaintext     = 'live-' . bin2hex(random_bytes(8));

        $created     = $actionService->createNewRecord(self::TABLE, 1, ['title' => 'Live record', 'api_key' => $plaintext]);
        $createdUids = $created[self::TABLE] ?? null;
        self::assertIsArray($createdUids);
        $liveUid = $createdUids[0] ?? null;
        self::assertIsInt($liveUid);
        $identifier = $this->fieldOf($liveUid);

        $GLOBALS['BE_USER']->setWorkspace(self::WORKSPACE);
        $actionService->modifyRecord(self::TABLE, $liveUid, ['title' => 'Workspace record']);
        $versionUid = $this->versionUidOf($liveUid);
        self::assertSame($identifier, $this->fieldOf($versionUid), 'The version shares the live identifier');

        $actionService->clearWorkspaceRecord(self::TABLE, $liveUid);
        $GLOBALS['BE_USER']->setWorkspace(0);

        self::assertFalse($this->rowExists($versionUid));
        self::assertSame($plaintext, $vaultService->retrieve($identifier), 'The live record keeps its secret');
    }

    /**
     * The hook runs before core's access checks. A discard core refuses
     * leaves the version, and its secret, in place.
     */
    #[Test]
    public function aDiscardOutsideTheVersionsWorkspaceKeepsTheSecret(): void
    {
        $actionService = new ActionService();
        $vaultService  = $this->get(VaultServiceInterface::class);

        [, $versionUid] = $this->createVersion($actionService);
        $actionService->modifyRecord(self::TABLE, $versionUid, ['api_key' => 'refused-' . bin2hex(random_bytes(8))]);
        $identifier = $this->fieldOf($versionUid);

        // Back in live: core refuses to discard ("Different workspace").
        $GLOBALS['BE_USER']->setWorkspace(0);
        $actionService->clearWorkspaceRecord(self::TABLE, $versionUid);

        self::assertTrue($this->rowExists($versionUid), 'Core must have refused the discard');
        self::assertTrue($vaultService->exists($identifier), 'A version that was not discarded keeps its secret');
    }

    /**
     * A live record without a secret, and its workspace version.
     *
     * @return array{int, int} live uid, version uid
     */
    private function createVersion(ActionService $actionService): array
    {
        $created     = $actionService->createNewRecord(self::TABLE, 1, ['title' => 'Live record']);
        $createdUids = $created[self::TABLE] ?? null;
        self::assertIsArray($createdUids);
        $liveUid = $createdUids[0] ?? null;
        self::assertIsInt($liveUid);

        $GLOBALS['BE_USER']->setWorkspace(self::WORKSPACE);
        $actionService->modifyRecord(self::TABLE, $liveUid, ['title' => 'Workspace record']);

        return [$liveUid, $this->versionUidOf($liveUid)];
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
}
