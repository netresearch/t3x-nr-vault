<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Command;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditChainAnchorStore;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\Export\AuditChainExport;
use Netresearch\NrVault\Audit\Export\AuditChainExporter;
use Netresearch\NrVault\Audit\Export\AuditExportVerification;
use Netresearch\NrVault\Audit\Export\DatabaseStoredAuditChain;
use Netresearch\NrVault\Audit\GenericContext;
use Netresearch\NrVault\Command\VaultAuditCommand;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Database\ConnectionPool;

use function count;
use function is_array;

/**
 * `vault:audit --export` as evidence: complete by default, refused when an
 * explicit --limit would cut it, and verifiable offline across HMAC epochs.
 */
#[CoversClass(VaultAuditCommand::class)]
#[CoversClass(AuditChainExporter::class)]
#[CoversClass(AuditChainExport::class)]
#[CoversClass(AuditExportVerification::class)]
#[CoversClass(DatabaseStoredAuditChain::class)]
final class VaultAuditCommandExportTest extends AbstractVaultFunctionalTestCase
{
    private const ADMIN = 1;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_audit_permission.csv';

    protected ?int $backendUserUid = null;

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 3,
    ];

    /** @var list<string> */
    private array $files = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpBackendUser(self::ADMIN);
    }

    protected function tearDown(): void
    {
        foreach ($this->files as $file) {
            if (file_exists($file)) {
                // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
                unlink($file);
            }
        }

        parent::tearDown();
    }

    /**
     * Rows written at epoch 2 and then at epoch 3 export with their epoch, and
     * the export re-verifies from the file alone. The values include the
     * characters an encoder could rewrite: slashes, non-ASCII text, a leading
     * formula character.
     */
    #[Test]
    public function anExportSpanningTwoEpochsCarriesTheEpochAndVerifies(): void
    {
        $this->seedTwoEpochs();
        $file = $this->exportFile();

        $tester = $this->executeAudit(['--export' => $file]);
        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());

        $rows   = $this->readRows($file);
        $epochs = array_unique(array_column($rows, 'hmac_key_epoch'));
        sort($epochs);
        self::assertSame([2, 3], $epochs);
        // `context` is the stored JSON string, verbatim, not a re-encoding.
        self::assertIsString($rows[0]['context']);
        $context = json_decode($rows[0]['context'], true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($context);
        self::assertSame('ünïcode/päth "quoted"', $context['note']);

        $verify = $this->executeAudit(['--verify-export' => $file]);
        self::assertSame(Command::SUCCESS, $verify->getStatusCode(), $verify->getDisplay());
        self::assertStringContainsString('Export verified', $this->normalize($verify));
        self::assertStringContainsString('Whole chain yes', $this->normalize($verify));
    }

    /**
     * Cutting the tail and rewriting the header to match leaves a consistent
     * file; the installation still stores the cut row, so the file is never
     * reported as the whole chain.
     */
    #[Test]
    public function aTailCutWithARewrittenHeaderIsNotTheWholeChain(): void
    {
        $this->seedTwoEpochs();
        $file = $this->exportFile();
        $this->executeAudit(['--export' => $file]);

        $document = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($document);
        self::assertIsArray($document['export']);
        $rows                          = array_slice($this->readRows($file), 0, -1);
        $last                          = $rows[count($rows) - 1];
        $document['rows']              = $rows;
        $document['export']['count']   = count($rows);
        $document['export']['total']   = count($rows);
        $document['export']['lastUid'] = $last['uid'];
        $document['export']['tipUid']  = $last['uid'];
        file_put_contents($file, json_encode($document, JSON_THROW_ON_ERROR));

        $verify = $this->executeAudit(['--verify-export' => $file]);

        self::assertStringContainsString('Whole chain not confirmed', $this->normalize($verify));
        self::assertStringContainsString('stores 1 entry after uid', $this->normalize($verify));
        self::assertStringNotContainsString('links to its predecessor', $this->normalize($verify));
    }

    #[Test]
    public function anExportWithOneAlteredFieldFailsVerification(): void
    {
        $this->seedTwoEpochs();
        $file = $this->exportFile();
        $this->executeAudit(['--export' => $file]);

        $document = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($document);
        $rows = $this->readRows($file);
        // An epoch-3 row: rows below the configured epoch are compared with
        // the stored row first, this one reaches the hash check.
        self::assertSame(3, $rows[2]['hmac_key_epoch']);
        $rows[2]['success'] = $rows[2]['success'] === 1 ? 0 : 1;
        $document['rows']   = $rows;
        file_put_contents($file, json_encode($document, JSON_THROW_ON_ERROR));

        $verify = $this->executeAudit(['--verify-export' => $file]);

        self::assertSame(Command::FAILURE, $verify->getStatusCode());
        self::assertStringContainsString('entry hash does not match', $this->normalize($verify));
        // Genesis, tip and the stored tip row are all intact, so every
        // whole-chain condition holds; the error alone withholds the verdict.
        self::assertMatchesRegularExpression('/Whole chain\s+not confirmed/', $this->normalize($verify));
    }

    /**
     * Whoever edits an export can relabel a keyed row as keyless epoch 0 and
     * recompute its SHA-256 without the key. A one-row filtered export has no
     * neighbour to break, so only the installation's own floor can catch it.
     */
    #[Test]
    public function aKeyedRowRewrittenAsKeylessEpochZeroFailsVerification(): void
    {
        $this->seedTwoEpochs();
        $file   = $this->exportFile();
        $tester = $this->executeAudit(['--export' => $file, '--identifier' => 'export_epoch_3']);
        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());

        $document = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($document);
        $rows = $this->readRows($file);
        self::assertCount(1, $rows);
        $row                   = $rows[0];
        $row['hmac_key_epoch'] = 0;
        self::assertIsString($row['previous_hash']);
        /** @var array<string, mixed> $row */
        $row['entry_hash'] = AuditLogService::calculateEntryHash($row, $row['previous_hash'], '');
        $document['rows']  = [$row];
        file_put_contents($file, json_encode($document, JSON_THROW_ON_ERROR));

        $verify = $this->executeAudit(['--verify-export' => $file]);

        self::assertSame(Command::FAILURE, $verify->getStatusCode());
        self::assertStringContainsString('is exported at epoch 0', $this->normalize($verify));
    }

    /**
     * Legacy epoch-0 rows left from before HMAC was switched on carry no key.
     * In a file that does not claim the whole chain, removing one and
     * recomputing the keyless hashes of its neighbours must still fail: each
     * keyless row has to match the row the installation stores.
     */
    #[Test]
    public function rewrittenLegacyKeylessRowsInAPartialFileFailVerification(): void
    {
        $this->seedEpochs([0, 0, 0, 3, 3]);
        $file = $this->exportFile();
        $this->executeAudit(['--export' => $file]);

        $document = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($document);
        self::assertIsArray($document['export']);
        $rows = $this->readRows($file);
        unset($rows[2]);
        $rows                         = array_values($rows);
        $rows[0]['secret_identifier'] = 'forged';
        $previous                     = '';
        foreach ([0, 1] as $i) {
            /** @var array<string, mixed> $row */
            $row                  = $rows[$i];
            $row['previous_hash'] = $previous;
            $row['entry_hash']    = AuditLogService::calculateEntryHash($row, $previous, '');
            $previous             = $row['entry_hash'];
            $rows[$i]             = $row;
        }

        $document['rows']                    = $rows;
        $document['export']['chainComplete'] = false;
        $document['export']['count']         = count($rows);
        file_put_contents($file, json_encode($document, JSON_THROW_ON_ERROR));

        $verify = $this->executeAudit(['--verify-export' => $file]);

        self::assertSame(Command::FAILURE, $verify->getStatusCode());
        self::assertStringContainsString('differs from the row this installation stores', $this->normalize($verify));
    }

    /**
     * Epoch 2 does not bind the actor columns, so the row hash still matches
     * after actor_username is edited. Rows below epoch 3 are therefore compared
     * column by column with the stored row.
     */
    #[Test]
    public function anEditedColumnThatEpochTwoLeavesUnboundFailsVerification(): void
    {
        $this->seedTwoEpochs();
        $file = $this->exportFile();
        $this->executeAudit(['--export' => $file, '--identifier' => 'export_epoch_0']);

        $document = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($document);
        $rows = $this->readRows($file);
        self::assertSame(2, $rows[0]['hmac_key_epoch']);
        $rows[0]['actor_username'] = 'someone_else';
        $document['rows']          = $rows;
        file_put_contents($file, json_encode($document, JSON_THROW_ON_ERROR));

        $verify = $this->executeAudit(['--verify-export' => $file]);

        self::assertSame(Command::FAILURE, $verify->getStatusCode());
        self::assertStringContainsString('differs from the row this installation stores', $this->normalize($verify));
    }

    /**
     * A uid gap next to keyless rows is a note, not an error, once the
     * installation signs with HMAC: every keyless row has been confirmed
     * against the stored row, so the gap is in the stored chain too.
     */
    #[Test]
    public function aGapNextToConfirmedKeylessRowsVerifiesAsTheWholeChain(): void
    {
        $this->insertChain([[1, 0], [2, 0], [4, 3]]);

        $file = $this->exportFile();
        self::assertSame(Command::SUCCESS, $this->executeAudit(['--export' => $file])->getStatusCode());

        $verify = $this->executeAudit(['--verify-export' => $file]);

        self::assertSame(Command::SUCCESS, $verify->getStatusCode(), $this->normalize($verify));
        self::assertStringContainsString('uid 3 to 3 are not in the chain', $this->normalize($verify));
        self::assertMatchesRegularExpression('/Whole chain\s+yes/', $this->normalize($verify));
    }

    /**
     * The other half of the gap rule: removing a confirmed keyless row from a
     * file that claims the whole chain still breaks the link across it.
     */
    #[Test]
    public function aConfirmedKeylessRowRemovedFromTheWholeChainFailsVerification(): void
    {
        $this->insertChain([[1, 0], [2, 0], [3, 3]]);
        $file = $this->exportFile();
        self::assertSame(Command::SUCCESS, $this->executeAudit(['--export' => $file])->getStatusCode());

        $document = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($document);
        self::assertIsArray($document['export']);
        $rows = $this->readRows($file);
        unset($rows[1]);
        $document['rows']            = array_values($rows);
        $document['export']['count'] = 2;
        file_put_contents($file, json_encode($document, JSON_THROW_ON_ERROR));

        $verify = $this->executeAudit(['--verify-export' => $file]);

        self::assertSame(Command::FAILURE, $verify->getStatusCode());
        self::assertStringContainsString('uid 3 does not link to uid 1', $this->normalize($verify));
    }

    /**
     * A legitimate export re-serialised with sorted keys (jq -S, sort_keys)
     * holds the same rows and still verifies.
     */
    #[Test]
    public function anExportWithSortedKeysStillVerifies(): void
    {
        $this->seedTwoEpochs();
        $file = $this->exportFile();
        $this->executeAudit(['--export' => $file]);

        $document = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($document);
        $rows = $this->readRows($file);
        foreach ($rows as &$row) {
            ksort($row);
        }

        unset($row);
        $document['rows'] = $rows;
        file_put_contents($file, json_encode($document, JSON_THROW_ON_ERROR));

        $verify = $this->executeAudit(['--verify-export' => $file]);

        self::assertSame(Command::SUCCESS, $verify->getStatusCode(), $this->normalize($verify));
    }

    /**
     * The honest counterpart: a filtered export of legacy rows only verifies,
     * because each keyless row matches the stored one.
     */
    #[Test]
    public function aFilteredExportOfLegacyKeylessRowsVerifies(): void
    {
        $this->seedEpochs([0, 0, 0, 3, 3]);
        $file   = $this->exportFile();
        $tester = $this->executeAudit(['--export' => $file, '--identifier' => 'export_epoch_1']);
        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());

        $verify = $this->executeAudit(['--verify-export' => $file]);

        self::assertSame(Command::SUCCESS, $verify->getStatusCode(), $verify->getDisplay());
    }

    /**
     * The listing shows 50 entries by default; an export must not inherit that.
     */
    #[Test]
    public function aDefaultExportContainsEveryRowBeyondTheListingDefault(): void
    {
        $audit = $this->get(AuditLogServiceInterface::class);
        for ($i = 0; $i < 60; ++$i) {
            $audit->log('export_many_' . $i, AuditAction::Read->value, true);
        }

        $file   = $this->exportFile();
        $tester = $this->executeAudit(['--export' => $file]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $rows = $this->readRows($file);
        self::assertCount($this->countAuditRows(), $rows);
        self::assertGreaterThanOrEqual(60, count($rows));
    }

    #[Test]
    public function anExplicitLimitBelowTheTotalIsRefusedWithoutAllowPartial(): void
    {
        $audit = $this->get(AuditLogServiceInterface::class);
        for ($i = 0; $i < 8; ++$i) {
            $audit->log('export_limit_' . $i, AuditAction::Read->value, true);
        }

        $file   = $this->exportFile();
        $tester = $this->executeAudit(['--export' => $file, '--limit' => '5']);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertStringContainsString('Refusing a partial export', $this->normalize($tester));
        self::assertFileDoesNotExist($file);
    }

    #[Test]
    public function allowPartialWritesTheNewestRowsMarkedTruncated(): void
    {
        $audit = $this->get(AuditLogServiceInterface::class);
        for ($i = 0; $i < 8; ++$i) {
            $audit->log('export_partial_' . $i, AuditAction::Read->value, true);
        }

        $file   = $this->exportFile();
        $tester = $this->executeAudit(['--export' => $file, '-l' => '5', '--allow-partial' => true]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $document = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($document);
        self::assertIsArray($document['export']);
        self::assertTrue($document['export']['truncated']);
        self::assertFalse($document['export']['chainComplete']);
        self::assertSame(5, $document['export']['count']);
        self::assertSame($this->countAuditRows(), $document['export']['total']);
        $rows = $this->readRows($file);
        self::assertCount(5, $rows);
        self::assertSame($this->maxAuditUid(), $rows[4]['uid']);
    }

    /**
     * Writes a chain with the given uids and epochs straight into the table.
     *
     * @param list<array{int, int}> $uidsAndEpochs
     */
    private function insertChain(array $uidsAndEpochs): void
    {
        $hmacKey    = AuditLogService::deriveHmacKey($this->get(MasterKeyProviderInterface::class));
        $connection = $this->get(ConnectionPool::class)->getConnectionForTable('tx_nrvault_audit_log');
        $previous   = '';
        foreach ($uidsAndEpochs as $index => [$uid, $epoch]) {
            $row = [
                'uid'               => $uid,
                'secret_identifier' => 'chain_' . $index,
                'action'            => 'read',
                'success'           => 1,
                'actor_uid'         => 1,
                'crdate'            => 1704067200 + $index,
                'context'           => '{}',
                'reason'            => '',
                'hmac_key_epoch'    => $epoch,
                'previous_hash'     => $previous,
            ];
            $row['entry_hash'] = AuditLogService::calculateEntryHash($row, $previous, $epoch === 0 ? '' : $hmacKey);
            $previous          = $row['entry_hash'];
            $connection->insert('tx_nrvault_audit_log', AuditChainExporter::exportRow($row));
        }
    }

    /**
     * Two epochs written by two service instances: epoch 2 first, then the
     * configured epoch 3.
     */
    private function seedTwoEpochs(): void
    {
        $this->seedEpochs([2, 2, 3, 3]);
    }

    /**
     * One row per given epoch, each written by a service configured at it.
     *
     * @param list<int> $epochs
     */
    private function seedEpochs(array $epochs): void
    {
        foreach ($epochs as $i => $epoch) {
            $configuration = self::createStub(ExtensionConfigurationInterface::class);
            $configuration->method('getAuditHmacEpoch')->willReturn($epoch);
            $configuration->method('isAuditAnchorRequired')->willReturn(false);
            $configuration->method('isAuditReadsEnabled')->willReturn(true);

            $service = new AuditLogService(
                $this->get(ConnectionPool::class),
                $this->get(AccessControlServiceInterface::class),
                $this->get(MasterKeyProviderInterface::class),
                $configuration,
                new AuditChainAnchorStore(
                    $this->get(ConnectionPool::class),
                    $this->get(MasterKeyProviderInterface::class),
                    $configuration,
                ),
            );
            $service->log(
                'export_epoch_' . $i,
                AuditAction::Read->value,
                $i % 2 === 0,
                null,
                '=SUM(1+1) reason',
                null,
                null,
                new GenericContext(['note' => 'ünïcode/päth "quoted"']),
            );
        }
    }

    private function exportFile(): string
    {
        $file          = $this->instancePath . '/audit-export-' . bin2hex(random_bytes(4)) . '.json';
        $this->files[] = $file;

        return $file;
    }

    /**
     * @return list<array<mixed>>
     */
    private function readRows(string $file): array
    {
        $document = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($document);
        self::assertIsArray($document['rows'] ?? null);

        return array_values(array_filter($document['rows'], is_array(...)));
    }

    /**
     * @param array<string, string|bool> $arguments
     */
    private function executeAudit(array $arguments): CommandTester
    {
        $tester = new CommandTester($this->get(VaultAuditCommand::class));
        $tester->execute($arguments);

        return $tester;
    }

    private function countAuditRows(): int
    {
        return (int) $this->get(ConnectionPool::class)->getConnectionForTable('tx_nrvault_audit_log')
            ->count('uid', 'tx_nrvault_audit_log', []);
    }

    private function maxAuditUid(): int
    {
        $queryBuilder = $this->get(ConnectionPool::class)->getConnectionForTable('tx_nrvault_audit_log')->createQueryBuilder();

        return (int) $queryBuilder->selectLiteral('MAX(uid)')->from('tx_nrvault_audit_log')->executeQuery()->fetchOne();
    }

    private function normalize(CommandTester $tester): string
    {
        return (string) preg_replace('/\s+/', ' ', $tester->getDisplay());
    }
}
