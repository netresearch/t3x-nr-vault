<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Audit;

use Doctrine\DBAL\Platforms\SQLitePlatform;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorService;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Traits\AuditSinkSandboxTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Functional tests for external chain-tip anchoring.
 *
 * The scenario that matters, and that no in-database check can catch: an attacker
 * with DELETE rights truncates `tx_nrvault_audit_log` and lets the service build a
 * fresh chain from uid 1. That chain verifies perfectly against itself — there is
 * nothing left inside the database to contradict it. Only an anchor published
 * earlier, outside the database, can reveal it.
 *
 * These tests run the real sink stack (the NDJSON file sink writing to a real
 * temp path), so the anchor is genuinely round-tripped through the filesystem
 * rather than through a stub.
 */
#[CoversClass(ChainTipAnchorService::class)]
final class ChainTipAnchorServiceTest extends AbstractVaultFunctionalTestCase
{
    use AuditSinkSandboxTrait;

    protected ?string $backendUserFixture = __DIR__ . '/../../Functional/Service/Fixtures/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'masterKeyProvider' => 'file',
        'auditHmacEpoch' => 3,
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
    public function captureReadsTheCurrentChainTip(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $auditService->log('anchor_test_secret', 'create', true);
        $auditService->log('anchor_test_secret', 'read', true);

        $anchor = $this->getAnchorService()->capture();

        self::assertSame(2, $anchor->sequence);
        self::assertSame($auditService->getLatestHash(), $anchor->chainTip);
        self::assertSame(3, $anchor->hmacEpoch);
        self::assertFalse($anchor->isEmpty());
    }

    #[Test]
    public function captureOnAnEmptyChainYieldsAnEmptyAnchor(): void
    {
        $anchor = $this->getAnchorService()->capture();

        self::assertSame(0, $anchor->sequence);
        self::assertSame('', $anchor->chainTip);
        self::assertTrue($anchor->isEmpty());
    }

    #[Test]
    public function publishWritesTheAnchorToTheFileSink(): void
    {
        $this->get(AuditLogServiceInterface::class)->log('anchor_test_secret', 'create', true);

        $service = $this->getAnchorService();
        $accepted = $service->publish($service->capture());

        self::assertSame(1, $accepted);
        self::assertFileExists($this->auditSinkAnchorPath);
    }

    #[Test]
    public function anIntactChainVerifiesAgainstItsAnchor(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $auditService->log('anchor_test_secret', 'create', true);
        $auditService->log('anchor_test_secret', 'read', true);

        $service = $this->getAnchorService();
        $service->publish($service->capture());

        // The chain keeps growing after the anchor — that is normal and must not
        // be mistaken for tampering.
        $auditService->log('anchor_test_secret', 'read', true);

        $report = $service->verify();

        self::assertTrue($report->isValid(), 'findings: ' . implode(',', $report->getReasonCodes()));
        self::assertTrue($report->chainValid);
        self::assertInstanceOf(ChainTipAnchor::class, $report->anchor);
        self::assertSame(2, $report->anchor->sequence);
        self::assertSame(3, $report->currentSequence);
    }

    /**
     * THE case this whole subsystem exists for: truncate the table, re-seed a
     * shorter chain. The new chain is internally valid, so `verifyHashChain()`
     * alone reports success — the anchor is what catches it.
     */
    #[Test]
    public function fullTableResetIsDetectedAsTableReset(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $service = $this->getAnchorService();

        // Build a chain of five entries and anchor it.
        for ($i = 0; $i < 5; $i++) {
            $auditService->log('anchor_test_secret', 'read', true);
        }
        $anchor = $service->capture();
        $service->publish($anchor);
        self::assertSame(5, $anchor->sequence);

        // Wipe the table and re-seed a SHORTER chain from uid 1.
        $this->truncateAuditTable();
        $auditService->log('attacker_seeded', 'create', true);
        $auditService->log('attacker_seeded', 'read', true);

        // The rebuilt chain is internally consistent — this is exactly why the
        // in-database check cannot see the reset.
        self::assertTrue(
            $auditService->verifyHashChain()->isValid(),
            'the rebuilt chain verifies against itself, which is the premise of this test',
        );

        $report = $service->verify();

        self::assertFalse($report->isValid());
        self::assertTrue($report->hasReason(AuditIntegrityReason::TableReset));
        self::assertTrue($report->hasTamperEvidence());
        self::assertContains('TABLE_RESET', $report->getReasonCodes());
        self::assertSame(2, $report->currentSequence);
    }

    /**
     * A reset that re-seeds MORE rows than were anchored cannot be caught by the
     * length check, so the hash at the anchored sequence has to be compared too.
     */
    #[Test]
    public function tableResetIsDetectedEvenWhenTheRebuiltChainIsLonger(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $service = $this->getAnchorService();

        for ($i = 0; $i < 3; $i++) {
            $auditService->log('anchor_test_secret', 'read', true);
        }
        $anchor = $service->capture();
        $service->publish($anchor);

        $this->truncateAuditTable();
        for ($i = 0; $i < 6; $i++) {
            $auditService->log('attacker_seeded', 'read', true);
        }

        $report = $service->verify();

        self::assertGreaterThan($anchor->sequence, $report->currentSequence, 'the new chain is longer');
        self::assertTrue($report->hasReason(AuditIntegrityReason::TableReset));
    }

    /**
     * Deleting the anchored row while leaving later rows in place shows up as a
     * missing row at the anchored sequence, not just as a uid gap.
     */
    #[Test]
    public function deletingTheAnchoredRowIsDetected(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $service = $this->getAnchorService();

        for ($i = 0; $i < 4; $i++) {
            $auditService->log('anchor_test_secret', 'read', true);
        }
        $anchor = $service->capture();
        $service->publish($anchor);

        // Remove the anchored row but keep the chain longer than the anchor by
        // appending a new entry.
        $connection = $this->getAuditConnection();
        $connection->delete(AuditLogService::TABLE_NAME, ['uid' => $anchor->sequence]);
        $auditService->log('anchor_test_secret', 'read', true);

        $report = $service->verify();

        self::assertTrue($report->hasReason(AuditIntegrityReason::TableReset));
    }

    /**
     * A row deleted from the middle leaves a uid gap the chain check itself
     * detects. The report must classify it as UID_GAP rather than folding it into
     * a generic hash error, so an operator can tell deletion from forgery.
     */
    #[Test]
    public function deletedMiddleRowIsClassifiedAsUidGap(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);

        for ($i = 0; $i < 4; $i++) {
            $auditService->log('anchor_test_secret', 'read', true);
        }

        $this->getAuditConnection()->delete(AuditLogService::TABLE_NAME, ['uid' => 2]);

        $report = $this->getAnchorService()->verify();

        self::assertTrue($report->hasReason(AuditIntegrityReason::UidGap));
        self::assertFalse($report->chainValid);
    }

    /**
     * A rewritten payload breaks the row's own hash. That must surface as
     * HASH_MISMATCH — distinct from a reset, because the remedy differs.
     */
    #[Test]
    public function tamperedRowIsClassifiedAsHashMismatch(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $auditService->log('anchor_test_secret', 'create', true);
        $auditService->log('anchor_test_secret', 'read', true);

        $this->getAuditConnection()->update(
            AuditLogService::TABLE_NAME,
            ['secret_identifier' => 'rewritten_by_attacker'],
            ['uid' => 1],
        );

        $report = $this->getAnchorService()->verify();

        self::assertTrue($report->hasReason(AuditIntegrityReason::HashMismatch));
        self::assertTrue($report->hasTamperEvidence());
    }

    /**
     * Relabelling every row down to keyless epoch-0 lets an attacker re-sign the
     * chain without the HMAC key. The anchor witnesses the epoch that was really
     * in force, so the downgrade is detectable even after a full re-sign.
     */
    #[Test]
    public function epochDowngradeBelowTheAnchoredEpochIsDetected(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $auditService->log('anchor_test_secret', 'create', true);
        $auditService->log('anchor_test_secret', 'read', true);

        $service = $this->getAnchorService();
        $anchor = $service->capture();
        $service->publish($anchor);
        self::assertSame(3, $anchor->hmacEpoch);

        $connection = $this->getAuditConnection();
        $connection->update(AuditLogService::TABLE_NAME, ['hmac_key_epoch' => 0], ['uid' => $anchor->sequence]);

        $report = $service->verify();

        self::assertTrue($report->hasReason(AuditIntegrityReason::EpochDowngrade));
    }

    /**
     * Without a baseline there is nothing to compare against. Under the standard
     * profile that is not an error (sinks are opt-in), but the report must say so
     * rather than implying the chain was checked against external evidence.
     */
    #[Test]
    public function verificationWithoutAnyAnchorReportsNoAnchor(): void
    {
        $this->get(AuditLogServiceInterface::class)->log('anchor_test_secret', 'create', true);

        $report = $this->getAnchorService()->verify();

        self::assertNull($report->anchor);
        self::assertTrue($report->isValid(), 'standard profile treats a missing anchor as acceptable');
    }

    /**
     * The hardened profile requires external evidence, so a missing anchor is a
     * finding there — a vault under audit must not silently lose reset detection.
     */
    #[Test]
    public function hardenedProfileWithoutAnAnchorReportsNoExternalSink(): void
    {
        $this->switchToHardenedProfile();

        $this->get(AuditLogServiceInterface::class)->log('anchor_test_secret', 'create', true);

        $report = $this->getAnchorService()->verify();

        self::assertTrue($report->hasReason(AuditIntegrityReason::NoExternalSink));
        self::assertFalse($report->hasTamperEvidence(), 'a configuration gap is not tamper evidence');
    }

    #[Test]
    public function hardenedProfileWithAnAnchorHasNoSinkFinding(): void
    {
        $this->switchToHardenedProfile();

        $this->get(AuditLogServiceInterface::class)->log('anchor_test_secret', 'create', true);

        $service = $this->getAnchorService();
        $service->publish($service->capture());

        $report = $service->verify();

        self::assertFalse($report->hasReason(AuditIntegrityReason::NoExternalSink));
        self::assertTrue($report->isValid(), 'findings: ' . implode(',', $report->getReasonCodes()));
    }

    #[Test]
    public function theFileSinkIsReportedAsAnExternalAuditSink(): void
    {
        $registry = $this->get(AuditSinkRegistryInterface::class);

        self::assertTrue($registry->hasExternalAuditSink());
        self::assertContains('file', $registry->getEnabledSinkIdentifiers());
    }

    /**
     * The audit write path must fan out to the sinks. Without this, anchoring
     * works but the entry stream stays empty and nobody notices.
     */
    #[Test]
    public function auditWritesReachTheExternalSink(): void
    {
        $this->get(AuditLogServiceInterface::class)->log('anchor_test_secret', 'create', true);

        self::assertFileExists($this->auditSinkEntryPath);

        $contents = file_get_contents($this->auditSinkEntryPath);
        self::assertIsString($contents);
        self::assertStringContainsString('anchor_test_secret', $contents);
    }

    /**
     * A later anchor with a HIGHER sequence must become the baseline, so the blind
     * window shrinks with every run.
     */
    #[Test]
    public function theHighestPublishedAnchorBecomesTheBaseline(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $service = $this->getAnchorService();

        $auditService->log('anchor_test_secret', 'create', true);
        $service->publish($service->capture());

        for ($i = 0; $i < 3; $i++) {
            $auditService->log('anchor_test_secret', 'read', true);
        }
        $service->publish($service->capture());

        $report = $service->verify();

        self::assertInstanceOf(ChainTipAnchor::class, $report->anchor);
        self::assertSame(4, $report->anchor->sequence);
    }

    /**
     * Flip the running instance to the hardened profile.
     *
     * Written through a typed local because `$GLOBALS` is `mixed` to static
     * analysis, so chained offset writes on it cannot be verified.
     */
    private function switchToHardenedProfile(): void
    {
        $confVars = \is_array($GLOBALS['TYPO3_CONF_VARS'] ?? null) ? $GLOBALS['TYPO3_CONF_VARS'] : [];
        $extensions = \is_array($confVars['EXTENSIONS'] ?? null) ? $confVars['EXTENSIONS'] : [];
        $nrVault = \is_array($extensions['nr_vault'] ?? null) ? $extensions['nr_vault'] : [];

        $nrVault['securityProfile'] = 'hardened';
        $extensions['nr_vault'] = $nrVault;
        $confVars['EXTENSIONS'] = $extensions;
        $GLOBALS['TYPO3_CONF_VARS'] = $confVars;
    }

    private function getAnchorService(): ChainTipAnchorServiceInterface
    {
        return $this->get(ChainTipAnchorServiceInterface::class);
    }

    private function getAuditConnection(): Connection
    {
        return $this->get(ConnectionPool::class)->getConnectionForTable(AuditLogService::TABLE_NAME);
    }

    /**
     * Emulate the attack: remove every row so the next write starts a fresh
     * chain. `DELETE` plus an explicit sqlite sequence reset rather than
     * `TRUNCATE`, because the testing framework runs on SQLite here and the
     * auto-increment counter must also go back to 1 for the rebuilt chain to
     * reuse the anchored uid.
     */
    private function truncateAuditTable(): void
    {
        $connection = $this->getAuditConnection();
        $connection->executeStatement('DELETE FROM ' . AuditLogService::TABLE_NAME);

        $platform = $connection->getDatabasePlatform();
        if ($platform instanceof SQLitePlatform) {
            $connection->executeStatement(
                "DELETE FROM sqlite_sequence WHERE name = '" . AuditLogService::TABLE_NAME . "'",
            );

            return;
        }

        $connection->executeStatement('ALTER TABLE ' . AuditLogService::TABLE_NAME . ' AUTO_INCREMENT = 1');
    }
}
