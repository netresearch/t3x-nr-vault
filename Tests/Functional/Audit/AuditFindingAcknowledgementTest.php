<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Audit;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use Netresearch\NrVault\Audit\Acknowledgement\AcknowledgementOutcome;
use Netresearch\NrVault\Audit\Acknowledgement\AcknowledgementStatus;
use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingAcknowledger;
use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingAcknowledgerInterface;
use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingItem;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditIntegrityReport;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\GenericContext;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Traits\AuditSinkSandboxTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Acknowledging integrity findings (ADR-055).
 *
 * The acknowledgement is an overlay on the verification report and must never
 * reach the raw hash-chain pass that guards the re-seal paths: every test that
 * acknowledges something also asks `verifyHashChain()` and
 * `verifyChainForReseal()`, which have to keep refusing the broken chain.
 */
#[CoversClass(AuditFindingAcknowledger::class)]
final class AuditFindingAcknowledgementTest extends AbstractVaultFunctionalTestCase
{
    use AuditSinkSandboxTrait;

    private const TABLE = AuditLogService::TABLE_NAME;

    protected ?string $backendUserFixture = __DIR__ . '/../Command/Fixtures/be_users_audit_permission.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'masterKeyProvider' => 'file',
        'auditHmacEpoch'    => 3,
    ];

    protected function setUp(): void
    {
        $this->extensionConfiguration = $this->prepareAuditSinkSandbox($this->extensionConfiguration);

        parent::setUp();
    }

    protected function tearDown(): void
    {
        $this->cleanUpAuditSinkSandbox();

        parent::tearDown();
    }

    #[Test]
    public function aTamperedRowStaysOpenUntilAnAdministratorAcknowledgesIt(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);

        $before = $this->inspect();
        self::assertFalse($before->isValid());
        self::assertSame('HASH_MISMATCH', $before->getReasonCodes()[0]);
        self::assertCount(1, $before->getOpenItems());

        $outcome = $this->acknowledge($before);

        self::assertSame(AcknowledgementStatus::Acknowledged, $outcome->status);

        $after = $this->inspect();
        self::assertTrue($after->isValid(), 'the acknowledged finding no longer fails the check');
        self::assertSame([], $after->findings);
        self::assertCount(1, $after->getAcknowledgedItems());
        self::assertGreaterThan(5, $after->getAcknowledgedItems()[0]->acknowledgedBy);
    }

    /**
     * The acknowledgement must not reach the raw pass: re-sealing a chain that is
     * still broken would launder the tampering into a valid chain.
     */
    #[Test]
    public function theRawChainPassAndTheResealGuardKeepRefusingTheAcknowledgedChain(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);
        $this->acknowledge($this->inspect());

        $auditService = $this->get(AuditLogServiceInterface::class);

        self::assertFalse($auditService->verifyHashChain()->isValid());
        self::assertSame([5], array_keys($auditService->verifyHashChain()->errors), 'only the flagged row fails; the acknowledgement row verifies');
        self::assertNotNull($auditService->verifyChainForReseal(), 'a re-seal must still be refused');
    }

    #[Test]
    public function aNewTamperAfterTheAcknowledgementFailsAgain(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);
        $this->acknowledge($this->inspect());
        self::assertTrue($this->inspect()->isValid(), 'precondition');

        $this->tamperRow(3);

        $report = $this->inspect();
        self::assertFalse($report->isValid());
        self::assertSame(3, $report->getOpenItems()[0]->rangeStart);
        self::assertCount(1, $report->getAcknowledgedItems(), 'the earlier acknowledgement still stands');
    }

    #[Test]
    public function editingAnAcknowledgedRowAgainReopensIt(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);
        $this->acknowledge($this->inspect());

        $this->getConnection()->update(self::TABLE, ['reason' => 'edited a second time'], ['uid' => 5]);

        $report = $this->inspect();
        self::assertFalse($report->isValid());
        self::assertSame(5, $report->getOpenItems()[0]->rangeStart);
    }

    #[Test]
    public function aRowWrittenAfterTheAcknowledgementIsNotCovered(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);
        $this->acknowledge($this->inspect());

        // A fresh row that fails its own hash, written after the acknowledgement.
        $this->get(AuditLogServiceInterface::class)->log('later', 'read', true, null, 'after');
        $uid = $this->maxUid();
        $this->getConnection()->update(self::TABLE, ['reason' => 'rewritten'], ['uid' => $uid]);

        $report = $this->inspect();
        self::assertFalse($report->isValid());
        self::assertSame($uid, $report->getOpenItems()[0]->rangeStart);
    }

    #[Test]
    public function anAcknowledgementForAStaleViewIsRefused(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);
        $displayed = AuditFindingItem::fingerprint($this->inspect()->getOpenItems());

        // Another finding appears after the administrator was shown the page.
        $this->tamperRow(3);

        $outcome = $this->get(AuditFindingAcknowledgerInterface::class)
            ->acknowledge($displayed, 'looked fine', '', 0);

        self::assertSame(AcknowledgementStatus::Stale, $outcome->status);
        self::assertSame(0, $this->acknowledgementRowCount());
        self::assertCount(2, $this->inspect()->getOpenItems());
    }

    #[Test]
    public function aNonAdministratorIsRefused(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);
        $displayed = AuditFindingItem::fingerprint($this->inspect()->getOpenItems());

        // audit_viewer holds audit.view through a group but is no administrator.
        $this->setUpBackendUser(3);

        $outcome = $this->get(AuditFindingAcknowledgerInterface::class)
            ->acknowledge($displayed, 'not allowed', '', 0);

        self::assertSame(AcknowledgementStatus::NotPermitted, $outcome->status);
        self::assertSame(0, $this->acknowledgementRowCount());
    }

    #[Test]
    public function aMissingReasonIsRefused(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);
        $displayed = AuditFindingItem::fingerprint($this->inspect()->getOpenItems());

        $outcome = $this->get(AuditFindingAcknowledgerInterface::class)->acknowledge($displayed, "  \n ", '', 0);

        self::assertSame(AcknowledgementStatus::ReasonInvalid, $outcome->status);
        self::assertSame(0, $this->acknowledgementRowCount());
    }

    #[Test]
    public function aCleanChainHasNothingToAcknowledge(): void
    {
        $this->writeEntries(4);

        $outcome = $this->get(AuditFindingAcknowledgerInterface::class)
            ->acknowledge(AuditFindingItem::fingerprint([]), 'nothing', '', 0);

        self::assertSame(AcknowledgementStatus::NothingToAcknowledge, $outcome->status);
        self::assertSame(0, $this->acknowledgementRowCount());
    }

    #[Test]
    public function repeatingAnAcknowledgementChangesNothing(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);
        $displayed    = AuditFindingItem::fingerprint($this->inspect()->getOpenItems());
        $acknowledger = $this->get(AuditFindingAcknowledgerInterface::class);

        self::assertTrue($acknowledger->acknowledge($displayed, 'first', '', 0)->isAcknowledged());
        $second = $acknowledger->acknowledge($displayed, 'second', '', 0);

        self::assertSame(AcknowledgementStatus::NothingToAcknowledge, $second->status);
        self::assertSame(1, $this->acknowledgementRowCount());
    }

    /**
     * The acknowledgement is itself a chained row: its hash verifies, it sits
     * directly after the tip it recorded, and it carries the acting administrator,
     * the reason, the ticket and the finding set.
     */
    #[Test]
    public function theAcknowledgementRowIsChainedAndRecordsWhoWhyAndWhat(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);
        $report    = $this->inspect();
        $displayed = AuditFindingItem::fingerprint($report->getOpenItems());
        $tipBefore = $this->get(AuditLogServiceInterface::class)->getLatestHash();

        $this->get(AuditFindingAcknowledgerInterface::class)
            ->acknowledge($displayed, 'restored from backup on 2026-11-12', 'OPS-1', 7);

        $row = $this->getConnection()->createQueryBuilder()
            ->select('*')->from(self::TABLE)
            ->where('action = :a')->setParameter('a', AuditAction::AuditFindingsAcknowledged->value)
            ->executeQuery()->fetchAssociative();

        self::assertIsArray($row);
        self::assertSame($tipBefore, $row['previous_hash'], 'chained directly after the old tip');
        self::assertSame('admin', $row['actor_username']);
        self::assertSame('restored from backup on 2026-11-12', $row['reason']);
        self::assertGreaterThanOrEqual(3, (int) $row['hmac_key_epoch']);
        self::assertArrayNotHasKey((int) $row['uid'], $this->get(AuditLogServiceInterface::class)->verifyHashChain()->errors);

        $context = json_decode(is_string($row['context']) ? $row['context'] : '', true);
        self::assertIsArray($context);
        self::assertSame($tipBefore, $context['tipHash']);
        self::assertSame('OPS-1', $context['ticket']);
        self::assertSame(7, $context['originalUserUid']);
        self::assertSame('HASH_MISMATCH', $context['codes']);
        self::assertSame($report->getOpenItems()[0]->key, $context['findings']);
    }

    #[Test]
    public function anAcknowledgementThatFailsItsOwnHashIsIgnored(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);
        $this->acknowledge($this->inspect());

        $ackUid = $this->maxUid();
        $this->getConnection()->update(self::TABLE, ['reason' => 'edited acknowledgement'], ['uid' => $ackUid]);

        $report = $this->inspect();
        self::assertFalse($report->isValid(), 'a tampered acknowledgement proves nothing');
        self::assertSame(5, $report->getOpenItems()[0]->rangeStart);
    }

    #[Test]
    public function aForgedAcknowledgementRowIsIgnored(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);
        $key = $this->inspect()->getOpenItems()[0]->key;

        // A database-write attacker appends a row that claims to acknowledge the
        // finding, without the HMAC key.
        $connection = $this->getConnection();
        $connection->insert(self::TABLE, [
            'pid'               => 0,
            'secret_identifier' => '__audit_findings__',
            'action'            => AuditAction::AuditFindingsAcknowledged->value,
            'success'           => 1,
            'reason'            => 'forged',
            'actor_uid'         => 1,
            'actor_type'        => 'backend',
            'actor_username'    => 'admin',
            'previous_hash'     => $this->get(AuditLogServiceInterface::class)->getLatestHash() ?? '',
            'entry_hash'        => str_repeat('a', 64),
            'hmac_key_epoch'    => 3,
            'crdate'            => time(),
            'context'           => json_encode(['findings' => $key, 'tipHash' => $this->get(AuditLogServiceInterface::class)->getLatestHash() ?? ''], JSON_THROW_ON_ERROR),
        ]);

        $report = $this->inspect();
        self::assertFalse($report->isValid());
        self::assertNotSame([], array_filter($report->getOpenItems(), static fn (AuditFindingItem $i): bool => $i->rangeStart === 5), 'the forged row did not acknowledge row 5');
    }

    /**
     * A correctly sealed acknowledgement row that was not chained directly after
     * the tip it recorded is what a row slipping in between verification and
     * write looks like. It must not cover anything.
     */
    #[Test]
    public function anAcknowledgementNotChainedDirectlyAfterItsRecordedTipIsIgnored(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);
        $key = $this->inspect()->getOpenItems()[0]->key;

        $this->get(AuditLogServiceInterface::class)->log(
            '__audit_findings__',
            AuditAction::AuditFindingsAcknowledged->value,
            true,
            null,
            'recorded an older tip',
            null,
            null,
            GenericContext::fromArray(findings: $key, tipHash: str_repeat('b', 64)),
        );

        self::assertFalse($this->inspect()->isValid());

        // The same row bound to the real tip is honoured: the binding, not the
        // action type, is what counts.
        $this->get(AuditLogServiceInterface::class)->log(
            '__audit_findings__',
            AuditAction::AuditFindingsAcknowledged->value,
            true,
            null,
            'recorded the real tip',
            null,
            null,
            GenericContext::fromArray(findings: $key, tipHash: $this->get(AuditLogServiceInterface::class)->getLatestHash() ?? ''),
        );

        self::assertTrue($this->inspect()->isValid());
    }

    #[Test]
    public function aUidGapAndItsBrokenSuccessorAreReportedAndCanBeAcknowledged(): void
    {
        $this->writeEntries(8);
        $this->getConnection()->delete(self::TABLE, ['uid' => 4]);

        $before = $this->inspect();
        self::assertContains('UID_GAP', $before->getReasonCodes());

        self::assertTrue($this->acknowledge($before)->isAcknowledged());

        $after = $this->inspect();
        self::assertTrue($after->isValid());
        self::assertFalse($this->get(AuditLogServiceInterface::class)->verifyHashChain()->isValid());

        // The gap is bound to the row after it: editing that row again reopens
        // the UID_GAP finding itself, not only the hash finding on the row.
        $this->getConnection()->update(self::TABLE, ['reason' => 'edited after the acknowledgement'], ['uid' => 5]);

        $reopened = array_map(
            static fn (AuditFindingItem $item): string => $item->reason->value,
            $this->inspect()->getOpenItems(),
        );
        self::assertContains('UID_GAP', $reopened);
    }

    #[Test]
    public function aTableResetAgainstTheExternalAnchorCanBeAcknowledgedAndANewAnchorDoesNotRaiseItAgain(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $service      = $this->get(ChainTipAnchorServiceInterface::class);

        $this->writeEntries(5);
        $service->publish($service->capture());

        $this->truncateAuditTable();
        $this->getConnectionPool()->getConnectionForTable('sys_registry')
            ->delete('sys_registry', ['entry_namespace' => 'tx_nrvault_audit_anchor']);
        $auditService->log('rebuilt', 'create', true);
        $auditService->log('rebuilt', 'read', true);

        $before = $service->inspect();
        self::assertContains('TABLE_RESET', $before->getReasonCodes());

        $outcome = $this->acknowledge($before);
        self::assertSame(AcknowledgementStatus::Acknowledged, $outcome->status);
        self::assertSame(1, $outcome->anchorsPublished, 'the new verified segment is anchored');

        $after = $service->inspect();
        self::assertTrue($after->isValid());
        self::assertSame([], $after->findings);
    }

    #[Test]
    public function anAcknowledgedTableResetReopensWhenTheChainChangesAgain(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $service      = $this->get(ChainTipAnchorServiceInterface::class);

        $this->writeEntries(5);
        $service->publish($service->capture());
        $this->truncateAuditTable();
        $this->getConnectionPool()->getConnectionForTable('sys_registry')
            ->delete('sys_registry', ['entry_namespace' => 'tx_nrvault_audit_anchor']);
        $auditService->log('rebuilt', 'create', true);
        $this->acknowledge($service->inspect());

        // The rebuilt chain is wiped a second time: the new anchor no longer matches.
        $this->truncateAuditTable();
        $this->getConnectionPool()->getConnectionForTable('sys_registry')
            ->delete('sys_registry', ['entry_namespace' => 'tx_nrvault_audit_anchor']);
        $auditService->log('second_reset', 'create', true);
        $auditService->log('second_reset', 'read', true);

        self::assertFalse($service->inspect()->isValid());
    }

    /**
     * An external-anchor finding is resolved by anchoring, not covered: when the
     * old anchor is back in force (replayed, or no new anchor was kept), the same
     * finding is open again instead of inheriting the earlier acknowledgement.
     */
    #[Test]
    public function aReplayedOldAnchorReopensAnAcknowledgedTableReset(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $service      = $this->get(ChainTipAnchorServiceInterface::class);

        $this->writeEntries(5);
        $service->publish($service->capture());
        // The anchor as it was published some time ago, before the restore.
        $oldAnchorFile = '';
        foreach (explode("\n", trim((string) file_get_contents($this->auditSinkAnchorPath))) as $line) {
            $record = json_decode($line, true);
            if (is_array($record) && is_array($record['anchor'] ?? null)) {
                $record['anchor']['timestamp'] = (int) $record['anchor']['timestamp'] - 3600;
                $oldAnchorFile .= json_encode($record, JSON_THROW_ON_ERROR) . "\n";
            }
        }

        self::assertNotSame('', $oldAnchorFile);
        file_put_contents($this->auditSinkAnchorPath, $oldAnchorFile);

        $this->truncateAuditTable();
        $this->getConnectionPool()->getConnectionForTable('sys_registry')
            ->delete('sys_registry', ['entry_namespace' => 'tx_nrvault_audit_anchor']);
        $auditService->log('rebuilt', 'create', true);
        self::assertTrue($this->acknowledge($service->inspect())->isAcknowledged());
        self::assertTrue($service->inspect()->isValid(), 'precondition: resolved by the fresh anchor');

        // Only the old anchor is left in force again, and the chain is as short as
        // before: a second incident of the same kind against the same anchor.
        file_put_contents($this->auditSinkAnchorPath, $oldAnchorFile);

        $report = $service->inspect();
        self::assertFalse($report->isValid());
        self::assertContains('TABLE_RESET', $report->getReasonCodes());
        self::assertSame([], $report->getAcknowledgedItems());
    }

    /**
     * The acknowledgement is bound to the chain prefix it was written after:
     * once the row at the tip it recorded is gone, the external-anchor finding is
     * open again, although the acknowledgement row itself is still there.
     */
    #[Test]
    public function aTableResetReopensWhenTheRecordedTipRowIsRemoved(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $service      = $this->get(ChainTipAnchorServiceInterface::class);

        $this->writeEntries(5);
        $service->publish($service->capture());
        $this->truncateAuditTable();
        $this->getConnectionPool()->getConnectionForTable('sys_registry')
            ->delete('sys_registry', ['entry_namespace' => 'tx_nrvault_audit_anchor']);
        $auditService->log('rebuilt', 'create', true);
        self::assertTrue($this->acknowledge($service->inspect())->isAcknowledged());
        self::assertTrue($service->inspect()->isValid(), 'precondition');

        // Row 1 was the tip the acknowledgement was chained after.
        $this->getConnection()->delete(self::TABLE, ['uid' => 1]);

        $open = array_map(
            static fn (AuditFindingItem $item): string => $item->reason->value,
            $service->inspect()->getOpenItems(),
        );
        self::assertContains('TABLE_RESET', $open);
    }

    /**
     * The in-database anchor is re-armed by the acknowledgement; damaging it a
     * second time, with the same symptom, is a new incident.
     */
    #[Test]
    public function aSecondDamageToTheInDatabaseAnchorFailsAgain(): void
    {
        $this->writeEntries(6);
        $this->damageInDatabaseAnchor();
        $first = $this->inspect();
        self::assertFalse($first->isValid());

        self::assertTrue($this->acknowledge($first)->isAcknowledged());
        self::assertTrue($this->inspect()->isValid(), 'precondition: re-armed and acknowledged');

        $this->damageInDatabaseAnchor();

        self::assertFalse($this->inspect()->isValid(), 'the same symptom a second time is a new incident');
    }

    private function damageInDatabaseAnchor(): void
    {
        $this->getConnectionPool()->getConnectionForTable('sys_registry')->update(
            'sys_registry',
            ['entry_value' => 'garbage'],
            ['entry_namespace' => 'tx_nrvault_audit_anchor', 'entry_key' => 'auditChainTip'],
            ['entry_value' => Connection::PARAM_LOB],
        );
    }

    private function inspect(): AuditIntegrityReport
    {
        return $this->get(ChainTipAnchorServiceInterface::class)->inspect();
    }

    private function acknowledge(AuditIntegrityReport $report): AcknowledgementOutcome
    {
        return $this->get(AuditFindingAcknowledgerInterface::class)->acknowledge(
            AuditFindingItem::fingerprint($report->getOpenItems()),
            'reviewed the evidence export',
            '',
            0,
        );
    }

    private function writeEntries(int $count): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        for ($i = 0; $i < $count; ++$i) {
            $auditService->log('ack-' . $i, 'read', true, null, 'acknowledgement test');
        }
    }

    private function tamperRow(int $uid): void
    {
        $this->getConnection()->update(self::TABLE, ['reason' => 'edited after the fact'], ['uid' => $uid]);
    }

    private function maxUid(): int
    {
        return (int) $this->getConnection()->createQueryBuilder()
            ->selectLiteral('MAX(uid)')->from(self::TABLE)->executeQuery()->fetchOne();
    }

    private function acknowledgementRowCount(): int
    {
        return (int) $this->getConnection()->createQueryBuilder()
            ->count('uid')->from(self::TABLE)
            ->where('action = :a')->setParameter('a', AuditAction::AuditFindingsAcknowledged->value)
            ->executeQuery()->fetchOne();
    }

    private function getConnection(): Connection
    {
        return $this->get(ConnectionPool::class)->getConnectionForTable(self::TABLE);
    }

    private function truncateAuditTable(): void
    {
        $connection = $this->getConnection();
        $connection->executeStatement('DELETE FROM ' . self::TABLE);

        $platform = $connection->getDatabasePlatform();
        if ($platform instanceof SQLitePlatform) {
            $connection->executeStatement("DELETE FROM sqlite_sequence WHERE name = '" . self::TABLE . "'");
        } elseif ($platform instanceof PostgreSQLPlatform) {
            $connection->executeStatement("SELECT setval(pg_get_serial_sequence('" . self::TABLE . "', 'uid'), 1, false)");
        }
    }
}
