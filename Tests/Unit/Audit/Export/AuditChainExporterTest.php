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
use Netresearch\NrVault\Audit\Export\StoredAuditChainInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Throwable;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Re-verification of an export document is fail-closed: it reads as valid
 * only when every declared row was checked and nothing failed. The stored
 * chain is an in-memory stand-in, so every branch that consults the
 * installation is reached here, not only in the functional suite.
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
        self::assertSame(4, $result->declaredCount);
        self::assertSame([0 => 2, 3 => 2], $result->epochCounts);
        self::assertSame(1, $result->firstUid);
        self::assertSame(4, $result->lastUid);
    }

    /**
     * The stored chain holds the same rows and nothing newer: the export is
     * confirmed as the whole chain.
     */
    #[Test]
    public function anExportMatchingTheStoredChainIsTheWholeChain(): void
    {
        $rows = $this->chain([3, 3, 3]);

        $result = $this->exporter(3, $this->stored($rows))->verify($this->document($rows));

        self::assertSame([], $result->errors);
        self::assertTrue($result->chainComplete);
        self::assertSame([], $result->notes);
    }

    #[Test]
    public function anEmptyExportIsNotValid(): void
    {
        $result = $this->exporter()->verify($this->document([]));

        self::assertFalse($result->isValid());
        self::assertStringContainsString('holds no rows', implode("\n", $result->errors));
    }

    #[Test]
    public function aDocumentWithoutRowsIsNotValid(): void
    {
        $document = $this->document($this->chain([3]));
        unset($document['rows']);

        $result = $this->exporter()->verify($document);

        self::assertFalse($result->isValid());
        self::assertSame(0, $result->rowsChecked);
        self::assertSame(-1, $result->declaredCount);
        self::assertSame(['The document has no "rows" list.'], $result->errors);
        self::assertFalse($result->chainComplete);
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
        self::assertSame(['The metadata declares 3 row(s), the document holds 2.'], $result->errors);
    }

    /**
     * Missing metadata never matches real rows: the declared bounds default to
     * values no row carries, and the defaults are named in the errors.
     */
    #[Test]
    public function missingMetadataBoundsAreReportedWithTheirDefaults(): void
    {
        $rows     = $this->chain([3, 3]);
        $document = $this->document($rows);
        unset($document['export']['firstUid'], $document['export']['lastUid'], $document['export']['count']);

        $result = $this->exporter()->verify($document);

        self::assertSame(-1, $result->declaredCount);
        self::assertSame(0, $result->firstUid);
        self::assertSame(0, $result->lastUid);
        self::assertSame([
            'The metadata declares -1 row(s), the document holds 2.',
            'The metadata declares first uid 0, the first row is uid 1.',
            'The metadata declares last uid 0, the last row is uid 2.',
        ], $result->errors);
    }

    #[Test]
    public function aMissingTipUidIsNeverTheDeclaredTip(): void
    {
        $rows     = $this->chain([3, 3]);
        $document = $this->document($rows);
        unset($document['export']['tipUid']);

        $result = $this->exporter(3, $this->stored($rows))->verify($document);

        self::assertTrue($result->isValid());
        self::assertFalse($result->chainComplete);
        self::assertSame(['The export ends at uid 2, not at its declared tip uid -1.'], $result->notes);
    }

    /**
     * Only a literal `true` is a claim: anything else reads as "not
     * claimed", which never yields the whole chain.
     *
     * @return iterable<string, array{mixed}>
     */
    public static function nonTrueClaimProvider(): iterable
    {
        yield 'integer 1' => [1];
        yield 'string "true"' => ['true'];
        yield 'missing' => [null];
    }

    #[DataProvider('nonTrueClaimProvider')]
    #[Test]
    public function onlyALiteralTrueClaimsTheWholeChain(mixed $claim): void
    {
        $rows                                = $this->chain([3, 3]);
        $document                            = $this->document($rows);
        $document['export']['chainComplete'] = $claim;
        $document['export']['truncated']     = $claim;

        $result = $this->exporter(3, $this->stored($rows))->verify($document);

        self::assertTrue($result->isValid());
        self::assertFalse($result->chainComplete);
        self::assertFalse($result->truncated);
    }

    #[Test]
    public function aTruncatedFlagIsEchoed(): void
    {
        $document                        = $this->document($this->chain([3]));
        $document['export']['truncated'] = true;

        self::assertTrue($this->exporter()->verify($document)->truncated);
    }

    #[Test]
    public function anAlteredFieldIsNotValid(): void
    {
        $rows              = $this->chain([3, 3]);
        $rows[1]['action'] = 'delete';

        $result = $this->exporter()->verify($this->document($rows));

        self::assertFalse($result->isValid());
        self::assertSame(2, $result->rowsChecked);
        self::assertStringContainsString('uid 2: entry hash does not match', implode("\n", $result->errors));
    }

    /**
     * Without the master key, rows at epoch 1 and above are not checked, and
     * an export that was only partly checked never reads as valid. The key
     * failure is reported once, each unchecked row by itself.
     */
    #[Test]
    public function rowsThatCouldNotBeCheckedMakeTheExportInvalid(): void
    {
        $provider = self::createStub(MasterKeyProviderInterface::class);
        $provider->method('getMasterKey')->willThrowException(new RuntimeException('no key'));

        $result = $this->exporter(provider: $provider)->verify($this->document($this->chain([0, 3, 3])));

        self::assertFalse($result->isValid());
        self::assertSame(1, $result->rowsChecked);
        self::assertSame([
            'The master key is not available, so rows at HMAC epoch 1 and above cannot be checked: no key',
            'uid 2 was not checked: its HMAC epoch needs the master key.',
            'uid 3 was not checked: its HMAC epoch needs the master key.',
        ], $result->errors);
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
        self::assertSame([2 => 1, 3 => 1], $result->epochCounts);
        self::assertStringContainsString('uid 2: HMAC key epoch downgrade 3 -> 2.', implode("\n", $result->errors));
    }

    #[Test]
    public function rowsOutOfUidOrderAreNotValid(): void
    {
        $rows = $this->chain([3, 3]);

        $result = $this->exporter()->verify($this->document([$rows[1], $rows[0]], firstUid: 2, lastUid: 1));

        self::assertFalse($result->isValid());
        self::assertSame(['uid 1 follows uid 2: rows are not in ascending uid order.'], $result->errors);
    }

    #[Test]
    public function aRepeatedUidIsNotValid(): void
    {
        $rows = $this->chain([3]);

        $result = $this->exporter()->verify($this->document([$rows[0], $rows[0]], firstUid: 1, lastUid: 1));

        self::assertSame(['uid 1 follows uid 1: rows are not in ascending uid order.'], $result->errors);
    }

    #[Test]
    public function aRowWithSuccessZeroIsAValidRow(): void
    {
        $row            = $this->chain([3])[0];
        $row['success'] = 0;
        $rows           = [$this->rehash($row, '')];

        $result = $this->exporter(3, $this->stored($rows))->verify($this->document($rows));

        self::assertSame([], $result->errors);
        self::assertTrue($result->chainComplete);
    }

    /**
     * Keyless rows need no key: an export of epoch-0 rows verifies where the
     * master key is not available.
     */
    #[Test]
    public function keylessRowsDoNotNeedTheMasterKey(): void
    {
        $provider = self::createStub(MasterKeyProviderInterface::class);
        $provider->method('getMasterKey')->willThrowException(new RuntimeException('no key'));

        $result = $this->exporter(provider: $provider)->verify($this->document($this->chain([0, 0])));

        self::assertSame([], $result->errors);
        self::assertSame(2, $result->rowsChecked);
    }

    /**
     * Cutting the head and rewriting the header to match leaves a consistent
     * file; it still does not start the chain, so it is never "whole chain".
     */
    #[Test]
    public function aHeadCutWithARewrittenHeaderIsNotTheWholeChain(): void
    {
        $chain    = $this->chain([3, 3, 3, 3]);
        $rows     = array_values(array_slice($chain, 1));
        $document = $this->document($rows);

        $result = $this->exporter(3, $this->stored($chain))->verify($document);

        self::assertTrue($result->isValid());
        self::assertFalse($result->chainComplete);
        self::assertSame(['The first row does not start the chain (its previous_hash is not empty).'], $result->notes);
    }

    /**
     * A tail cut with a rewritten header still ends where the file says, but
     * the installation stores newer rows.
     *
     * @return iterable<string, array{int, string}>
     */
    public static function newerRowsProvider(): iterable
    {
        yield 'one newer row' => [1, 'This installation stores 1 entry after uid 2.'];
        yield 'two newer rows' => [2, 'This installation stores 2 entries after uid 2.'];
    }

    #[DataProvider('newerRowsProvider')]
    #[Test]
    public function newerStoredRowsMeanTheExportIsNotTheWholeChain(int $newer, string $note): void
    {
        $chain = $this->chain(array_fill(0, 2 + $newer, 3));
        $rows  = array_slice($chain, 0, 2);

        $result = $this->exporter(3, $this->stored($chain))->verify($this->document($rows));

        self::assertTrue($result->isValid());
        self::assertFalse($result->chainComplete);
        self::assertSame([$note], $result->notes);
    }

    #[Test]
    public function aTipTheInstallationDoesNotStoreIsNotTheWholeChain(): void
    {
        $rows = $this->chain([3, 3]);

        $result = $this->exporter(3, $this->stored([$rows[0]]))->verify($this->document($rows));

        self::assertTrue($result->isValid());
        self::assertFalse($result->chainComplete);
        self::assertSame(['This installation does not store uid 2, so the end of the export cannot be confirmed.'], $result->notes);
    }

    /**
     * A re-sealed stored chain (rotation or migration) is not an error, but
     * the export is no longer confirmed as the whole chain.
     */
    #[Test]
    public function aTipThatDiffersFromTheStoredRowIsNotTheWholeChain(): void
    {
        $rows                    = $this->chain([3, 3]);
        $stored                  = $rows;
        $stored[1]['entry_hash'] = str_repeat('c', 64);

        $result = $this->exporter(3, $this->stored($stored))->verify($this->document($rows));

        self::assertTrue($result->isValid());
        self::assertFalse($result->chainComplete);
        self::assertSame([
            'uid 2 carries a different entry hash than the row this installation stores '
                . "(re-sealed since the export, or not this installation's chain).",
        ], $result->notes);
    }

    #[Test]
    public function anUnreachableInstallationIsNotTheWholeChain(): void
    {
        $rows = $this->chain([3, 3]);

        $result = $this->exporter(3, $this->stored($rows, new RuntimeException('database down')))->verify($this->document($rows));

        self::assertTrue($result->isValid());
        self::assertFalse($result->chainComplete);
        self::assertSame(['The installation could not be consulted: database down'], $result->notes);
    }

    /**
     * A value the writer never produces is refused rather than coerced:
     * otherwise the file could carry content no hash covers.
     *
     * @return iterable<string, array{string, mixed, string}>
     */
    public static function foreignValueProvider(): iterable
    {
        yield 'array where a string was hashed' => ['reason', ['approved by CISO'], 'Row 1 has a array in "reason", where the export writes string.'];
        yield 'integer where a string was hashed' => ['ip_address', 10, 'Row 1 has a int in "ip_address", where the export writes string.'];
        yield 'string where an integer was hashed' => ['actor_uid', '1', 'Row 1 has a string in "actor_uid", where the export writes int.'];
        yield 'truthy success' => ['success', 7, 'Row 1 has a "success" other than 0 or 1.'];
        yield 'unknown column' => ['approved_by', 'CISO', 'Row 1 carries the unknown column(s) approved_by.'];
    }

    #[DataProvider('foreignValueProvider')]
    #[Test]
    public function aValueTheWriterNeverProducesIsNotValid(string $column, mixed $value, string $error): void
    {
        $rows             = $this->chain([3, 3]);
        $rows[1][$column] = $value;

        $result = $this->exporter()->verify($this->document($rows));

        self::assertFalse($result->isValid());
        self::assertSame(1, $result->rowsChecked);
        self::assertSame([$error], $result->errors);
    }

    #[Test]
    public function aRowLackingAColumnIsNotValid(): void
    {
        $rows = $this->chain([3, 3]);
        unset($rows[1]['action'], $rows[1]['reason']);

        $result = $this->exporter()->verify($this->document($rows));

        self::assertSame(['Row 1 lacks the column(s) action, reason.'], $result->errors);
    }

    /**
     * A row that is not an object is refused, and the row after it is not
     * treated as its neighbour.
     */
    #[Test]
    public function aRowThatIsNotAnObjectIsRefused(): void
    {
        $rows = $this->chain([3, 3, 3]);

        $result = $this->exporter()->verify($this->document([$rows[0], 'x', $rows[2]], firstUid: 1, lastUid: 3));

        self::assertSame(2, $result->rowsChecked);
        self::assertSame(['Row 1 is not an object.'], $result->errors);
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
        self::assertContains('uid 3 to 3 are not in the chain; the link across them is intact.', $result->notes);
    }

    /**
     * A gap whose link is broken is an error, never also "intact".
     */
    #[Test]
    public function aGapWithABrokenLinkIsAnErrorAndNotAnIntactGap(): void
    {
        $chain = $this->chain([3, 3, 3, 3]);

        $result = $this->exporter()->verify($this->document([$chain[0], $chain[1], $chain[3]], firstUid: 1, lastUid: 4));

        self::assertFalse($result->isValid());
        self::assertSame(['uid 4 does not link to uid 2: previous_hash differs from its entry_hash.'], $result->errors);
        self::assertStringNotContainsString('not in the chain', implode("\n", $result->notes));
    }

    /**
     * In a file that does not claim the whole chain, only adjacent uids are
     * neighbours: a gap there is the selection, not a finding.
     */
    #[Test]
    public function aPartialFileChecksOnlyAdjacentUids(): void
    {
        $chain                               = $this->chain([3, 3, 3, 3]);
        $document                            = $this->document([$chain[0], $chain[1], $chain[3]], firstUid: 1, lastUid: 4);
        $document['export']['chainComplete'] = false;

        $result = $this->exporter()->verify($document);

        self::assertSame([], $result->errors);
        self::assertStringNotContainsString('not in the chain', implode("\n", $result->notes));
    }

    #[Test]
    public function aPartialFileStillChecksTheLinkBetweenAdjacentUids(): void
    {
        $rows                                = $this->chain([3, 3]);
        $other                               = $this->chain([3, 3]);
        $other[1]['secret_identifier']       = 'other';
        $document                            = $this->document([$rows[0], $this->rehash($other[1], str_repeat('d', 64))]);
        $document['export']['chainComplete'] = false;

        $result = $this->exporter()->verify($document);

        self::assertSame(['uid 2 does not link to uid 1: previous_hash differs from its entry_hash.'], $result->errors);
    }

    /**
     * The anchor is taken on a row that exists. A complete-looking export that
     * lacks the anchored uid (removed, with the neighbours renumbered around
     * it) is an error, whatever the file claims.
     */
    #[Test]
    public function anExportLackingTheAnchoredRowIsNotValid(): void
    {
        $rows   = $this->chain([3, 3, 3], [1, 2, 4]);
        $anchor = new ChainTipAnchor(sequence: 3, chainTip: str_repeat('a', 64), timestamp: 1704067200, hmacEpoch: 3);

        $result = $this->exporter(anchor: $this->anchor($anchor))->verify($this->document($rows));

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
        $rows   = $this->chain([3, 3, 3]);
        $anchor = new ChainTipAnchor(sequence: 2, chainTip: str_repeat('b', 64), timestamp: 1704067200, hmacEpoch: 3);

        $result = $this->exporter(3, $this->stored($rows), $this->anchor($anchor))->verify($this->document($rows));

        self::assertTrue($result->isValid());
        self::assertFalse($result->chainComplete);
        self::assertSame([
            'uid 2 differs from the external anchor taken at that uid '
                . "(re-sealed since the anchor, or not this installation's chain).",
        ], $result->notes);
    }

    #[Test]
    public function aRowMatchingTheAnchorIsTheWholeChain(): void
    {
        $rows   = $this->chain([3, 3, 3]);
        $anchor = new ChainTipAnchor(sequence: 2, chainTip: (string) $rows[1]['entry_hash'], timestamp: 1704067200, hmacEpoch: 3);

        $result = $this->exporter(3, $this->stored($rows), $this->anchor($anchor))->verify($this->document($rows));

        self::assertTrue($result->chainComplete);
        self::assertSame([], $result->notes);
    }

    #[Test]
    public function anAnchorBeyondTheExportIsNotTheWholeChain(): void
    {
        $rows   = $this->chain([3, 3]);
        $anchor = new ChainTipAnchor(sequence: 3, chainTip: str_repeat('a', 64), timestamp: 1704067200, hmacEpoch: 3);

        $result = $this->exporter(3, $this->stored($rows), $this->anchor($anchor))->verify($this->document($rows));

        self::assertTrue($result->isValid());
        self::assertFalse($result->chainComplete);
        self::assertSame(['The newest external anchor is at uid 3, beyond the end of the export.'], $result->notes);
    }

    #[Test]
    public function anAnchorAtTheTipIsWithinTheExport(): void
    {
        $rows   = $this->chain([3, 3]);
        $anchor = new ChainTipAnchor(sequence: 2, chainTip: (string) $rows[1]['entry_hash'], timestamp: 1704067200, hmacEpoch: 3);

        $result = $this->exporter(3, $this->stored($rows), $this->anchor($anchor))->verify($this->document($rows));

        self::assertTrue($result->chainComplete);
    }

    #[Test]
    public function anUnreadableAnchorIsNotTheWholeChain(): void
    {
        $rows   = $this->chain([3, 3]);
        $reader = self::createStub(AnchorReaderInterface::class);
        $reader->method('isAvailable')->willReturn(true);
        $reader->method('readLatestAnchor')->willThrowException(new RuntimeException('sink down'));

        $result = $this->exporter(3, $this->stored($rows), $reader)->verify($this->document($rows));

        self::assertTrue($result->isValid());
        self::assertFalse($result->chainComplete);
        self::assertSame(['The external anchor could not be read: sink down'], $result->notes);
    }

    #[Test]
    public function anUnavailableAnchorReaderIsNotConsulted(): void
    {
        $rows   = $this->chain([3, 3]);
        $reader = $this->createMock(AnchorReaderInterface::class);
        $reader->method('isAvailable')->willReturn(false);
        $reader->expects(self::never())->method('readLatestAnchor');

        $result = $this->exporter(3, $this->stored($rows), $reader)->verify($this->document($rows));

        self::assertTrue($result->chainComplete);
    }

    /**
     * Keyless rows can be recomputed by anyone, so a link across a gap proves
     * nothing there: removing the row between two epoch-0 rows and recomputing
     * the unkeyed hashes must not pass as a rolled-back insert.
     */
    #[Test]
    public function aGapBetweenKeylessRowsIsNotValid(): void
    {
        $result = $this->exporter()->verify($this->document($this->chain([0, 0, 0], [1, 2, 4])));

        self::assertFalse($result->isValid());
        self::assertSame(['uid 3 to 3 are not in the export, next to a keyless row whose link can be recomputed.'], $result->errors);
    }

    /**
     * One keyless side is enough: the keyless row's hash can be recomputed.
     */
    #[Test]
    public function aGapWithOneKeylessNeighbourIsNotValidAtEpochZero(): void
    {
        $result = $this->exporter()->verify($this->document($this->chain([0, 3], [1, 3])));

        self::assertSame(['uid 2 to 2 are not in the export, next to a keyless row whose link can be recomputed.'], $result->errors);
    }

    /**
     * With HMAC on, every keyless row is confirmed against the stored row, so
     * a gap next to one is listed like a gap between keyed rows.
     */
    #[Test]
    public function aGapNextToConfirmedKeylessRowsIsListedAtEpochThree(): void
    {
        $rows = $this->chain([0, 0, 3], [1, 2, 4]);

        $result = $this->exporter(3, $this->stored($rows))->verify($this->document($rows));

        self::assertSame([], $result->errors);
        self::assertTrue($result->chainComplete);
        self::assertSame(['uid 3 to 3 are not in the chain; the link across them is intact.'], $result->notes);
    }

    #[Test]
    public function rowsBelowEpochThreeListTheColumnsTheirHashLeavesUnbound(): void
    {
        $rows   = $this->chain([1, 2, 3]);
        $result = $this->exporter(stored: $this->stored($rows))->verify($this->document($rows));

        self::assertSame([
            'Rows at epoch 0 and 1 bind only uid, secret_identifier, action, actor_uid, crdate and previous_hash; '
                . 'their other columns are not covered by the hash.',
            'Rows at epoch 2 do not bind hmac_key_epoch, actor_type, actor_username, actor_role and request_id.',
        ], $result->notes);
    }

    /**
     * @return iterable<string, array{list<int>, list<string>}>
     */
    public static function unboundColumnNoteProvider(): iterable
    {
        $identity = 'Rows at epoch 0 and 1 bind only uid, secret_identifier, action, actor_uid, crdate and previous_hash; '
            . 'their other columns are not covered by the hash.';
        $forensic = 'Rows at epoch 2 do not bind hmac_key_epoch, actor_type, actor_username, actor_role and request_id.';

        yield 'epoch 0 only' => [[0], [$identity]];
        yield 'epoch 1 only' => [[1], [$identity]];
        yield 'epoch 2 only' => [[2], [$forensic]];
        yield 'epoch 3 only' => [[3], []];
    }

    /**
     * @param list<int>    $epochs
     * @param list<string> $notes
     */
    #[DataProvider('unboundColumnNoteProvider')]
    #[Test]
    public function eachEpochListsOnlyTheColumnsItLeavesUnbound(array $epochs, array $notes): void
    {
        $rows   = $this->chain($epochs);
        $result = $this->exporter(stored: $this->stored($rows))->verify($this->document($rows));

        self::assertSame([], $result->errors);
        self::assertSame($notes, $result->notes);
    }

    /**
     * Rows compared with the stored row column by column are covered in every
     * column, so no unbound-column note is listed for them.
     */
    #[Test]
    public function confirmedRowsListNoUnboundColumns(): void
    {
        $rows = $this->chain([0, 1, 2, 3]);

        $result = $this->exporter(3, $this->stored($rows))->verify($this->document($rows));

        self::assertSame([], $result->errors);
        self::assertTrue($result->chainComplete);
        self::assertSame([], $result->notes);
    }

    /**
     * With HMAC on, a row below epoch 3 is confirmed against the stored chain.
     * When the stored chain cannot be read, the row is refused, not waved
     * through, and it is not counted as checked.
     */
    #[Test]
    public function aRowBelowEpochThreeIsRefusedWhenTheStoredChainCannotBeRead(): void
    {
        $rows = $this->chain([0, 3]);

        $result = $this->exporter(3, $this->stored($rows, new RuntimeException('database down')))->verify($this->document($rows));

        self::assertFalse($result->isValid());
        self::assertSame(1, $result->rowsChecked);
        self::assertContains('The stored chain could not be consulted: database down', $result->notes);
        self::assertSame([
            'uid 1 is exported at epoch 0 and differs from the row this installation stores (or it stores none at that uid); '
                . 'with HMAC at epoch 3, a row below epoch 3 is only confirmed by the stored chain.',
        ], $result->errors);
    }

    /**
     * Installations set up while the default was epoch 1 or 2 still run
     * there. Their rows at the configured epoch leave columns out of the
     * hash, so they too are confirmed against the stored chain.
     *
     * @return iterable<string, array{int}>
     */
    public static function configuredEpochProvider(): iterable
    {
        yield 'configured at 1' => [1];
        yield 'configured at 2' => [2];
        yield 'configured at 3' => [3];
    }

    #[DataProvider('configuredEpochProvider')]
    #[Test]
    public function anUnboundColumnEditedBelowEpochThreeIsNotValid(int $configured): void
    {
        $rows                      = $this->chain([2, 2]);
        $stored                    = $rows;
        $rows[0]['actor_username'] = 'someone_else';

        $result = $this->exporter($configured, $this->stored($stored))->verify($this->document($rows));

        self::assertFalse($result->isValid());
        self::assertStringContainsString('uid 1 is exported at epoch 2 and differs', implode("\n", $result->errors));
    }

    #[Test]
    public function aRowTheInstallationDoesNotStoreIsNotValid(): void
    {
        $rows = $this->chain([2, 3]);

        $result = $this->exporter(3, $this->stored([$rows[1]]))->verify($this->document($rows));

        self::assertFalse($result->isValid());
        self::assertStringContainsString('uid 1 is exported at epoch 2 and differs', implode("\n", $result->errors));
    }

    /**
     * A file re-serialised with sorted keys holds the same rows.
     */
    #[Test]
    public function keyOrderDoesNotMatterForTheStoredRowComparison(): void
    {
        $rows   = $this->chain([2, 3]);
        $sorted = $rows;
        ksort($sorted[0]);

        $result = $this->exporter(3, $this->stored($rows))->verify($this->document($sorted));

        self::assertSame([], $result->errors);
    }

    /**
     * The writer replaces invalid UTF-8 (JSON_INVALID_UTF8_SUBSTITUTE), and so
     * does the hash at epoch 2 and above; the stored value is compared the way
     * the file carries it.
     */
    #[Test]
    public function invalidUtf8InAStoredRowIsComparedAsWritten(): void
    {
        $stored = $this->chain([2, 3], reason: "bad \xff byte");
        $file   = $this->chain([2, 3], reason: "bad \u{FFFD} byte");

        $result = $this->exporter(3, $this->stored($stored))->verify($this->document($file));

        self::assertSame([], $result->errors);
        self::assertTrue($result->chainComplete);
    }

    #[Test]
    public function aForeignDocumentIsNotValid(): void
    {
        $document                     = $this->document($this->chain([0]));
        $document['export']['format'] = 'something-else';

        self::assertSame(['Not a nr-vault-audit-chain-export document of version 1.'], $this->exporter()->verify($document)->errors);
    }

    #[Test]
    public function aDocumentOfAnotherVersionIsNotValid(): void
    {
        $document                      = $this->document($this->chain([0]));
        $document['export']['version'] = 2;

        self::assertFalse($this->exporter()->verify($document)->isValid());
    }

    /**
     * @return iterable<string, array{int, int, list<string>, bool}>
     */
    public static function verificationProvider(): iterable
    {
        yield 'every declared row checked' => [1, 1, [], true];
        yield 'nothing checked' => [0, 0, [], false];
        yield 'fewer checked than declared' => [1, 2, [], false];
        yield 'an error' => [1, 1, ['x'], false];
    }

    /**
     * @param list<string> $errors
     */
    #[DataProvider('verificationProvider')]
    #[Test]
    public function aVerificationIsValidOnlyWhenEveryDeclaredRowWasCheckedAndNothingFailed(int $checked, int $declared, array $errors, bool $valid): void
    {
        $verification = new AuditExportVerification($checked, $declared, $errors, [], false, false, 1, 1);

        self::assertSame($valid, $verification->isValid());
    }

    /**
     * @param ?StoredAuditChainInterface $stored the installation's chain; an empty one when null
     */
    private function exporter(
        int $configuredEpoch = 0,
        ?StoredAuditChainInterface $stored = null,
        ?AnchorReaderInterface $anchor = null,
        ?MasterKeyProviderInterface $provider = null,
    ): AuditChainExporter {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getAuditHmacEpoch')->willReturn($configuredEpoch);
        if (!$provider instanceof MasterKeyProviderInterface) {
            $provider = self::createStub(MasterKeyProviderInterface::class);
            $provider->method('getMasterKey')->willReturnCallback(static fn (): string => self::MASTER_KEY);
        }

        return new AuditChainExporter(
            self::createStub(ConnectionPool::class),
            $provider,
            $configuration,
            $anchor ?? self::createStub(AnchorReaderInterface::class),
            $stored ?? $this->stored([]),
        );
    }

    private function anchor(ChainTipAnchor $anchor): AnchorReaderInterface
    {
        $reader = self::createStub(AnchorReaderInterface::class);
        $reader->method('isAvailable')->willReturn(true);
        $reader->method('readLatestAnchor')->willReturn($anchor);

        return $reader;
    }

    /**
     * The installation's chain, held in memory.
     *
     * @param list<array<string, int|string>> $rows
     */
    private function stored(array $rows, ?Throwable $failure = null): StoredAuditChainInterface
    {
        return new class ($rows, $failure) implements StoredAuditChainInterface {
            /**
             * @param list<array<string, int|string>> $rows
             */
            public function __construct(
                private readonly array $rows,
                private readonly ?Throwable $failure,
            ) {}

            public function exportRowAt(int $uid): ?array
            {
                $this->failIfConfigured();
                foreach ($this->rows as $row) {
                    if ($row['uid'] === $uid) {
                        return $row;
                    }
                }

                return null;
            }

            public function entryHashAt(int $uid): ?string
            {
                $row = $this->exportRowAt($uid);

                return $row === null ? null : (string) $row['entry_hash'];
            }

            public function countAfter(int $uid): int
            {
                $this->failIfConfigured();

                return count(array_filter($this->rows, static fn (array $row): bool => $row['uid'] > $uid));
            }

            private function failIfConfigured(): void
            {
                if ($this->failure instanceof Throwable) {
                    throw $this->failure;
                }
            }
        };
    }

    /**
     * A correctly linked chain, one row per given epoch, uid 1 upwards.
     *
     * @param list<int>      $epochs
     * @param list<int>|null $uids   default 1 upwards
     *
     * @return list<array<string, int|string>>
     */
    private function chain(array $epochs, ?array $uids = null, string $reason = '=SUM(1+1)'): array
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
                'reason'            => $reason,
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
     * The row with a new previous_hash and a matching entry hash.
     *
     * @param array<string, int|string> $row
     *
     * @return array<string, int|string>
     */
    private function rehash(array $row, string $previousHash): array
    {
        $row['previous_hash'] = $previousHash;
        $row['entry_hash']    = AuditLogService::calculateEntryHash(
            $row,
            $previousHash,
            AuditLogService::deriveHmacKeyFromMasterKey(self::MASTER_KEY),
        );

        return $row;
    }

    /**
     * @param list<mixed> $rows
     *
     * @return array<string, mixed>
     */
    private function document(array $rows, ?int $declaredCount = null, ?int $firstUid = null, ?int $lastUid = null): array
    {
        $first = $rows[0] ?? null;
        $last  = $rows === [] ? null : $rows[count($rows) - 1];

        return [
            'export' => [
                'format'        => AuditChainExporter::FORMAT,
                'version'       => AuditChainExporter::FORMAT_VERSION,
                'count'         => $declaredCount ?? count($rows),
                'firstUid'      => $firstUid ?? (is_array($first) ? $first['uid'] : 0),
                'lastUid'       => $lastUid ?? (is_array($last) ? $last['uid'] : 0),
                'tipUid'        => $lastUid ?? (is_array($last) ? $last['uid'] : 0),
                'chainComplete' => true,
                'truncated'     => false,
            ],
            'rows' => $rows,
        ];
    }
}
