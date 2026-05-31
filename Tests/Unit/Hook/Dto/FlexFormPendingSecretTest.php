<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Hook\Dto;

use Netresearch\NrVault\Hook\Dto\FlexFormPendingSecret;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(FlexFormPendingSecret::class)]
final class FlexFormPendingSecretTest extends TestCase
{
    #[Test]
    public function constructorSetsAllProperties(): void
    {
        $subject = new FlexFormPendingSecret(
            flexField: 'pi_flexform',
            sheet: 'sDEF',
            fieldPath: 'settings.apiKey',
            value: 'mysecret',
            identifier: 'app/api-key',
            originalChecksum: 'abc123',
            isNew: false,
        );

        self::assertSame('pi_flexform', $subject->flexField);
        self::assertSame('sDEF', $subject->sheet);
        self::assertSame('settings.apiKey', $subject->fieldPath);
        self::assertSame('mysecret', $subject->value);
        self::assertSame('app/api-key', $subject->identifier);
        self::assertSame('abc123', $subject->originalChecksum);
        self::assertFalse($subject->isNew);
    }

    #[Test]
    public function createNewSetsIsNewTrueAndEmptyChecksum(): void
    {
        $subject = FlexFormPendingSecret::createNew(
            flexField: 'pi_flexform',
            sheet: 'sDEF',
            fieldPath: 'settings.token',
            value: 'tokenvalue',
            identifier: 'svc/token',
        );

        self::assertSame('pi_flexform', $subject->flexField);
        self::assertSame('sDEF', $subject->sheet);
        self::assertSame('settings.token', $subject->fieldPath);
        self::assertSame('tokenvalue', $subject->value);
        self::assertSame('svc/token', $subject->identifier);
        self::assertSame('', $subject->originalChecksum);
        self::assertTrue($subject->isNew);
    }

    #[Test]
    public function createUpdateSetsIsNewFalseAndChecksum(): void
    {
        $subject = FlexFormPendingSecret::createUpdate(
            flexField: 'tx_myext_pi1',
            sheet: 'sMain',
            fieldPath: 'settings.apiSecret',
            value: 'updatedvalue',
            identifier: 'myext/secret',
            originalChecksum: 'oldchecksum',
        );

        self::assertSame('tx_myext_pi1', $subject->flexField);
        self::assertSame('sMain', $subject->sheet);
        self::assertSame('settings.apiSecret', $subject->fieldPath);
        self::assertSame('updatedvalue', $subject->value);
        self::assertSame('myext/secret', $subject->identifier);
        self::assertSame('oldchecksum', $subject->originalChecksum);
        self::assertFalse($subject->isNew);
    }

    #[Test]
    #[DataProvider('getFullPathProvider')]
    public function getFullPathReturnsCorrectFormat(
        string $flexField,
        string $sheet,
        string $fieldPath,
        string $expected,
    ): void {
        $subject = new FlexFormPendingSecret($flexField, $sheet, $fieldPath, 'val', 'id', '', false);

        self::assertSame($expected, $subject->getFullPath());
    }

    public static function getFullPathProvider(): iterable
    {
        yield 'standard DEF sheet' => [
            'pi_flexform', 'sDEF', 'settings.apiKey',
            'pi_flexform/sDEF/settings.apiKey',
        ];
        yield 'custom sheet' => [
            'tx_ext_config', 'sAPI', 'credentials.secret',
            'tx_ext_config/sAPI/credentials.secret',
        ];
        yield 'nested field path' => [
            'flexform_col', 'sGeneral', 'group.sub.field',
            'flexform_col/sGeneral/group.sub.field',
        ];
        yield 'empty values' => [
            '', '', '',
            '//',
        ];
    }

    #[Test]
    public function getFullPathContainsAllThreeSegments(): void
    {
        $subject = new FlexFormPendingSecret('field', 'sheet', 'path', 'val', 'id', '', false);
        $fullPath = $subject->getFullPath();

        self::assertStringContainsString('field', $fullPath);
        self::assertStringContainsString('sheet', $fullPath);
        self::assertStringContainsString('path', $fullPath);
    }

    #[Test]
    public function getFullPathUsesSlashAsSeparator(): void
    {
        $subject = new FlexFormPendingSecret('f', 's', 'p', 'val', 'id', '', false);

        self::assertSame('f/s/p', $subject->getFullPath());
    }

    #[Test]
    #[DataProvider('hasChangedProvider')]
    public function hasChangedReturnsCorrectResult(
        string $originalChecksum,
        string $currentChecksum,
        bool $expected,
    ): void {
        $subject = new FlexFormPendingSecret('f', 's', 'p', 'val', 'id', $originalChecksum, false);

        self::assertSame($expected, $subject->hasChanged($currentChecksum));
    }

    public static function hasChangedProvider(): iterable
    {
        yield 'different checksums => changed' => ['original', 'different', true];
        yield 'same checksums => not changed' => ['identical', 'identical', false];
        yield 'empty original, non-empty current => changed' => ['', 'newchecksum', true];
        yield 'both empty => not changed' => ['', '', false];
    }

    #[Test]
    public function hasChangedReturnsFalseWhenChecksumMatches(): void
    {
        $checksum = 'sha256:abc123';
        $subject = FlexFormPendingSecret::createUpdate('f', 's', 'p', 'val', 'id', $checksum);

        self::assertFalse($subject->hasChanged($checksum));
    }

    #[Test]
    public function hasChangedReturnsTrueWhenChecksumDiffers(): void
    {
        $subject = FlexFormPendingSecret::createUpdate('f', 's', 'p', 'val', 'id', 'old');

        self::assertTrue($subject->hasChanged('new'));
    }

    #[Test]
    public function createNewAlwaysHasChangedForNonEmptyCurrentChecksum(): void
    {
        $subject = FlexFormPendingSecret::createNew('f', 's', 'p', 'val', 'id');

        self::assertTrue($subject->hasChanged('anychecksum'));
    }

    #[Test]
    public function toArrayReturnsCorrectStructure(): void
    {
        $subject = new FlexFormPendingSecret(
            flexField: 'pi_flexform',
            sheet: 'sDEF',
            fieldPath: 'settings.token',
            value: 'mytoken',
            identifier: 'app/token',
            originalChecksum: 'checksum123',
            isNew: false,
        );

        self::assertSame([
            'flexField' => 'pi_flexform',
            'sheet' => 'sDEF',
            'fieldPath' => 'settings.token',
            'value' => '[REDACTED]',
            'identifier' => 'app/token',
            'originalChecksum' => 'checksum123',
            'isNew' => false,
        ], $subject->toArray());
    }

    #[Test]
    public function toArrayForNewSecretHasEmptyChecksumAndIsNewTrue(): void
    {
        $subject = FlexFormPendingSecret::createNew('f', 's', 'p', 'val', 'id');
        $array = $subject->toArray();

        self::assertSame('', $array['originalChecksum']);
        self::assertTrue($array['isNew']);
    }

    #[Test]
    public function toArrayForUpdatedSecretHasIsNewFalse(): void
    {
        $subject = FlexFormPendingSecret::createUpdate('f', 's', 'p', 'val', 'id', 'chk');

        self::assertFalse($subject->toArray()['isNew']);
    }

    #[Test]
    public function toArrayContainsExactlySevenKeys(): void
    {
        $subject = FlexFormPendingSecret::createNew('f', 's', 'p', 'val', 'id');

        self::assertCount(7, $subject->toArray());
    }
}
