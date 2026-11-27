<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Domain\Dto;

use Netresearch\NrVault\Domain\Dto\OrphanReference;
use Netresearch\NrVault\Domain\Dto\SecretRecordLink;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(SecretRecordLink::class)]
#[CoversClass(OrphanReference::class)]
final class SecretRecordLinkTest extends TestCase
{
    #[Test]
    public function forFieldBuildsTheLinkTheCleanupReads(): void
    {
        $metadata = SecretRecordLink::forField('tca_field', 'tx_table', 'api_key', 7, ['copied_from' => 'x']);

        self::assertSame(
            ['source' => 'tca_field', 'table' => 'tx_table', 'field' => 'api_key', 'uid' => 7, 'copied_from' => 'x'],
            $metadata,
        );
        self::assertEquals(new OrphanReference('tx_table', 'api_key', 7), SecretRecordLink::referenceFrom($metadata));
    }

    #[Test]
    public function forFlexFieldBuildsAFlexFormLink(): void
    {
        $metadata = SecretRecordLink::forFlexField('flexform_field', 'tt_content', 'pi_flexform', 3, ['sheet' => 'sDEF']);

        self::assertSame(
            ['source' => 'flexform_field', 'table' => 'tt_content', 'flexField' => 'pi_flexform', 'uid' => 3, 'sheet' => 'sDEF'],
            $metadata,
        );
        self::assertEquals(new OrphanReference('tt_content', 'pi_flexform', 3, true), SecretRecordLink::referenceFrom($metadata));
    }

    /**
     * The identifier of a FlexForm-sourced secret sits inside the column's
     * XML, whichever key names the column.
     */
    #[Test]
    #[DataProvider('flexFormSourceProvider')]
    public function aFlexFormSourceIsAFlexFormLinkUnderTheFieldKey(string $source): void
    {
        $reference = SecretRecordLink::referenceFrom(['source' => $source, 'table' => 'tt_content', 'field' => 'pi_flexform', 'uid' => 3]);

        self::assertEquals(new OrphanReference('tt_content', 'pi_flexform', 3, true), $reference);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function flexFormSourceProvider(): iterable
    {
        yield 'flexform_field' => ['flexform_field'];
        yield 'flexform_record_copy' => ['flexform_record_copy'];
    }

    #[Test]
    public function aPlainSourceUnderTheFieldKeyIsAValueLink(): void
    {
        self::assertEquals(
            new OrphanReference('tx_table', 'api_key', 3, false),
            SecretRecordLink::referenceFrom(['source' => 'tca_field', 'table' => 'tx_table', 'field' => 'api_key', 'uid' => 3]),
        );
    }

    #[Test]
    public function theLinkCannotOverrideTheCoreKeysThroughExtra(): void
    {
        $metadata = SecretRecordLink::forField('tca_field', 'tx_table', 'api_key', 7, ['uid' => 99, 'table' => 'other']);

        self::assertSame(7, $metadata['uid']);
        self::assertSame('tx_table', $metadata['table']);
    }

    /**
     * @param array<string, mixed> $metadata
     */
    #[Test]
    #[DataProvider('nonCandidateProvider')]
    public function referenceFromRejectsNonCandidates(array $metadata): void
    {
        self::assertNull(SecretRecordLink::referenceFrom($metadata));
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function nonCandidateProvider(): iterable
    {
        yield 'no metadata' => [[]];
        yield 'foreign source' => [['source' => 'manual', 'table' => 't', 'field' => 'f', 'uid' => 1]];
        yield 'no table' => [['source' => 'tca_field', 'field' => 'f', 'uid' => 1]];
        yield 'empty table' => [['source' => 'tca_field', 'table' => '', 'field' => 'f', 'uid' => 1]];
        yield 'zero uid' => [['source' => 'tca_field', 'table' => 't', 'field' => 'f', 'uid' => 0]];
        yield 'non-numeric uid' => [['source' => 'tca_field', 'table' => 't', 'field' => 'f', 'uid' => 'x']];
        yield 'top-level keys of the old shape' => [['originalTable' => 't', 'originalColumn' => 'f', 'originalUid' => 1, 'source' => 'migration']];
    }

    #[Test]
    public function everyCleanupSourceIsACandidate(): void
    {
        foreach (['tca_field', 'record_copy', 'flexform_field', 'flexform_record_copy', 'migration'] as $source) {
            self::assertInstanceOf(
                OrphanReference::class,
                SecretRecordLink::referenceFrom(['source' => $source, 'table' => 't', 'field' => 'f', 'uid' => '5']),
                $source,
            );
        }
    }
}
