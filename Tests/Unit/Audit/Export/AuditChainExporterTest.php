<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Export;

use Netresearch\NrVault\Audit\Anchor\AnchorReaderInterface;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\Export\AuditChainExporter;
use Netresearch\NrVault\Audit\Export\AuditExportVerification;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Re-verification of an export document is fail-closed: it reads as valid
 * only when every declared row was checked and nothing failed.
 */
#[CoversClass(AuditChainExporter::class)]
#[CoversClass(AuditExportVerification::class)]
final class AuditChainExporterTest extends TestCase
{
    private const MASTER_KEY = '0123456789abcdef0123456789abcdef';

    #[Test]
    public function aWholeChainAcrossTwoEpochsVerifies(): void
    {
        $result = $this->exporter()->verify($this->document($this->chain([0, 0, 3, 3])));

        self::assertSame([], $result->errors);
        self::assertTrue($result->isValid());
        self::assertSame(4, $result->rowsChecked);
        self::assertSame([0 => 2, 3 => 2], $result->epochCounts);
    }

    #[Test]
    public function anEmptyExportIsNotValid(): void
    {
        $result = $this->exporter()->verify($this->document([]));

        self::assertFalse($result->isValid());
    }

    #[Test]
    public function aRowRemovedFromTheMiddleIsNotValid(): void
    {
        $rows = $this->chain([0, 0, 0, 0]);
        unset($rows[1]);

        $result = $this->exporter()->verify($this->document(array_values($rows), declaredCount: 3, firstUid: 1, lastUid: 4));

        self::assertFalse($result->isValid());
        self::assertNotSame([], $result->errors);
    }

    #[Test]
    public function aHeaderDeclaringMoreRowsThanTheDocumentHoldsIsNotValid(): void
    {
        $result = $this->exporter()->verify($this->document($this->chain([0, 0]), declaredCount: 3));

        self::assertFalse($result->isValid());
    }

    #[Test]
    public function anAlteredFieldIsNotValid(): void
    {
        $rows              = $this->chain([3, 3]);
        $rows[1]['action'] = 'delete';

        $result = $this->exporter()->verify($this->document($rows));

        self::assertFalse($result->isValid());
        self::assertStringContainsString('uid 2: entry hash does not match', implode("\n", $result->errors));
    }

    /**
     * Without the master key, rows at epoch 1 and above are not checked, and
     * an export that was only partly checked never reads as valid.
     */
    #[Test]
    public function rowsThatCouldNotBeCheckedMakeTheExportInvalid(): void
    {
        $provider = self::createStub(MasterKeyProviderInterface::class);
        $provider->method('getMasterKey')->willThrowException(new RuntimeException('no key'));
        $exporter = new AuditChainExporter(self::createStub(ConnectionPool::class), $provider, $this->legacyConfiguration(), self::createStub(AnchorReaderInterface::class));

        $result = $exporter->verify($this->document($this->chain([0, 3])));

        self::assertFalse($result->isValid());
        self::assertSame(1, $result->rowsChecked);
    }

    /**
     * A decrease of the epoch between two exported rows is a downgrade even in
     * a filtered or truncated export: a real chain never goes back.
     */
    #[Test]
    public function aPartialExportWithAnEpochDecreaseIsNotValid(): void
    {
        $rows                                = $this->chain([3, 2]);
        $document                            = $this->document($rows);
        $document['export']['chainComplete'] = false;
        $document['export']['truncated']     = true;

        $result = $this->exporter()->verify($document);

        self::assertFalse($result->isValid());
        self::assertStringContainsString('epoch downgrade 3 -> 2', implode("\n", $result->errors));
    }

    /**
     * Cutting the head and rewriting the header to match leaves a consistent
     * file; it still does not start the chain, so it is never "whole chain".
     */
    #[Test]
    public function aHeadCutWithARewrittenHeaderIsNotTheWholeChain(): void
    {
        $rows                         = array_values(array_slice($this->chain([0, 0, 0, 0]), 1));
        $document                     = $this->document($rows);
        $document['export']['tipUid'] = 4;

        $result = $this->exporter()->verify($document);

        self::assertFalse($result->chainComplete);
        self::assertStringContainsString('does not start the chain', implode("\n", $result->notes));
    }

    /**
     * A value the writer never produces is refused rather than coerced:
     * otherwise the file could carry content no hash covers.
     *
     * @return iterable<string, array{string, mixed}>
     */
    public static function foreignValueProvider(): iterable
    {
        yield 'array where a string was hashed' => ['reason', ['approved by CISO']];
        yield 'integer where a string was hashed' => ['ip_address', 10];
        yield 'truthy success' => ['success', 7];
        yield 'unknown column' => ['approved_by', 'CISO'];
    }

    #[DataProvider('foreignValueProvider')]
    #[Test]
    public function aValueTheWriterNeverProducesIsNotValid(string $column, mixed $value): void
    {
        $rows             = $this->chain([3, 3]);
        $rows[1][$column] = $value;

        $result = $this->exporter()->verify($this->document($rows));

        self::assertFalse($result->isValid());
    }

    /**
     * A rolled-back insert skips a uid. The link across the gap is intact, so
     * no row was removed, and the export still verifies.
     */
    #[Test]
    public function aUidGapWithAnIntactLinkStillVerifies(): void
    {
        $result = $this->exporter()->verify($this->document($this->chain([3, 3, 3], [1, 2, 4])));

        self::assertSame([], $result->errors);
        self::assertTrue($result->isValid());
        self::assertStringContainsString('uid 3 to 3 are not in the chain', implode("\n", $result->notes));
    }

    /**
     * The anchor is taken on a row that exists. A complete-looking export that
     * lacks the anchored uid (removed, with the neighbours renumbered around
     * it) is an error, whatever the file claims.
     */
    #[Test]
    public function anExportLackingTheAnchoredRowIsNotValid(): void
    {
        $rows   = $this->chain([0, 0, 0], [1, 2, 4]);
        $anchor = new ChainTipAnchor(sequence: 3, chainTip: str_repeat('a', 64), timestamp: 1704067200, hmacEpoch: 0);

        $result = $this->exporterWithAnchor($anchor)->verify($this->document($rows));

        self::assertFalse($result->isValid());
        self::assertFalse($result->chainComplete);
        self::assertStringContainsString('anchor was taken at uid 3, which this export lacks', implode("\n", $result->errors));
    }

    /**
     * The anchor check reads the same verified rows as the hash check: an
     * exported row at the anchored uid whose hash differs from the anchor is
     * never confirmed as the whole chain.
     */
    #[Test]
    public function aRowDifferingFromTheAnchorIsNotTheWholeChain(): void
    {
        $rows   = $this->chain([0, 0, 0]);
        $anchor = new ChainTipAnchor(sequence: 2, chainTip: str_repeat('b', 64), timestamp: 1704067200, hmacEpoch: 0);

        $result = $this->exporterWithAnchor($anchor)->verify($this->document($rows));

        self::assertFalse($result->chainComplete);
        self::assertStringContainsString('uid 2 differs from the external anchor', implode("\n", $result->notes));
    }

    #[Test]
    public function aForeignDocumentIsNotValid(): void
    {
        $document                     = $this->document($this->chain([0]));
        $document['export']['format'] = 'something-else';

        self::assertFalse($this->exporter()->verify($document)->isValid());
    }

    /**
     * Configured at keyless epoch 0, so the verifier needs no database to
     * know which rows may be keyless. The floor itself is pinned by the
     * functional suite.
     */
    private function legacyConfiguration(): ExtensionConfigurationInterface
    {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getAuditHmacEpoch')->willReturn(0);

        return $configuration;
    }

    private function exporter(): AuditChainExporter
    {
        $provider = self::createStub(MasterKeyProviderInterface::class);
        $provider->method('getMasterKey')->willReturnCallback(static fn (): string => self::MASTER_KEY);

        return new AuditChainExporter(self::createStub(ConnectionPool::class), $provider, $this->legacyConfiguration(), self::createStub(AnchorReaderInterface::class));
    }

    private function exporterWithAnchor(ChainTipAnchor $anchor): AuditChainExporter
    {
        $provider = self::createStub(MasterKeyProviderInterface::class);
        $provider->method('getMasterKey')->willReturnCallback(static fn (): string => self::MASTER_KEY);
        $reader = self::createStub(AnchorReaderInterface::class);
        $reader->method('isAvailable')->willReturn(true);
        $reader->method('readLatestAnchor')->willReturn($anchor);

        return new AuditChainExporter(self::createStub(ConnectionPool::class), $provider, $this->legacyConfiguration(), $reader);
    }

    /**
     * A correctly linked chain, one row per given epoch, uid 1 upwards.
     *
     * @param list<int>      $epochs
     * @param list<int>|null $uids   default 1 upwards
     *
     * @return list<array<string, int|string>>
     */
    private function chain(array $epochs, ?array $uids = null): array
    {
        $hmacKey  = AuditLogService::deriveHmacKeyFromMasterKey(self::MASTER_KEY);
        $previous = '';
        $rows     = [];
        foreach ($epochs as $index => $epoch) {
            $row = [
                'uid'               => $uids[$index] ?? $index + 1,
                'secret_identifier' => 'secret_' . $index,
                'action'            => 'read',
                'success'           => 1,
                'actor_uid'         => 1,
                'crdate'            => 1704067200 + $index,
                'context'           => '{"note":"ü\/x"}',
                'reason'            => '=SUM(1+1)',
                'hmac_key_epoch'    => $epoch,
                'previous_hash'     => $previous,
            ];
            $row['entry_hash'] = AuditLogService::calculateEntryHash($row, $previous, $hmacKey);
            $previous          = $row['entry_hash'];
            $rows[]            = AuditChainExporter::exportRow($row);
        }

        return $rows;
    }

    /**
     * @param list<array<string, mixed>> $rows
     *
     * @return array<string, mixed>
     */
    private function document(array $rows, ?int $declaredCount = null, ?int $firstUid = null, ?int $lastUid = null): array
    {
        return [
            'export' => [
                'format'        => AuditChainExporter::FORMAT,
                'version'       => AuditChainExporter::FORMAT_VERSION,
                'count'         => $declaredCount ?? count($rows),
                'firstUid'      => $firstUid ?? ($rows === [] ? 0 : $rows[0]['uid']),
                'lastUid'       => $lastUid ?? ($rows === [] ? 0 : $rows[count($rows) - 1]['uid']),
                'tipUid'        => $rows === [] ? 0 : $rows[count($rows) - 1]['uid'],
                'chainComplete' => true,
                'truncated'     => false,
            ],
            'rows' => $rows,
        ];
    }
}
