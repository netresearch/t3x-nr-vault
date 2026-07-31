<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use Netresearch\NrVault\Audit\HashChainVerificationResult;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(HashChainVerificationResult::class)]
final class HashChainVerificationResultTest extends TestCase
{
    #[Test]
    public function constructorSetsValidAndErrors(): void
    {
        $errors = [1 => 'Hash mismatch', 5 => 'Missing entry'];
        $subject = new HashChainVerificationResult(valid: false, errors: $errors);

        self::assertFalse($subject->valid);
        self::assertSame($errors, $subject->errors);
    }

    #[Test]
    public function constructorErrorsDefaultToEmptyArray(): void
    {
        $subject = new HashChainVerificationResult(valid: true);

        self::assertSame([], $subject->errors);
    }

    #[Test]
    public function validFactoryCreatesSuccessfulResult(): void
    {
        $subject = HashChainVerificationResult::valid();

        self::assertTrue($subject->valid);
        self::assertSame([], $subject->errors);
    }

    #[Test]
    public function invalidFactoryCreatesFailedResultWithErrors(): void
    {
        $errors = [3 => 'Chain broken', 7 => 'Invalid hash'];
        $subject = HashChainVerificationResult::invalid($errors);

        self::assertFalse($subject->valid);
        self::assertSame($errors, $subject->errors);
    }

    #[Test]
    public function invalidFactoryWithEmptyErrorsCreatesInvalidResult(): void
    {
        // invalid() can be called with an empty array (unusual but valid)
        $subject = HashChainVerificationResult::invalid([]);

        self::assertFalse($subject->valid);
        self::assertSame([], $subject->errors);
    }

    #[Test]
    public function isValidReturnsTrueForValidResult(): void
    {
        $subject = HashChainVerificationResult::valid();

        self::assertTrue($subject->isValid());
    }

    #[Test]
    public function isValidReturnsFalseForInvalidResult(): void
    {
        $subject = HashChainVerificationResult::invalid([1 => 'error']);

        self::assertFalse($subject->isValid());
    }

    #[Test]
    public function isValidMirrorsValidProperty(): void
    {
        $trueResult = new HashChainVerificationResult(valid: true);
        $falseResult = new HashChainVerificationResult(valid: false);

        self::assertSame($trueResult->valid, $trueResult->isValid());
        self::assertSame($falseResult->valid, $falseResult->isValid());
    }

    #[Test]
    public function getErrorCountReturnsZeroForValidResult(): void
    {
        $subject = HashChainVerificationResult::valid();

        self::assertSame(0, $subject->getErrorCount());
    }

    #[Test]
    public function getErrorCountReturnsCorrectCountForInvalidResult(): void
    {
        $errors = [1 => 'err1', 5 => 'err2', 9 => 'err3'];
        $subject = HashChainVerificationResult::invalid($errors);

        self::assertSame(3, $subject->getErrorCount());
    }

    #[Test]
    public function getErrorCountReturnsOneForSingleError(): void
    {
        $subject = HashChainVerificationResult::invalid([42 => 'hash mismatch']);

        self::assertSame(1, $subject->getErrorCount());
    }

    #[Test]
    public function toArrayReturnsCorrectStructureForValidResult(): void
    {
        $subject = HashChainVerificationResult::valid();

        self::assertSame([
            'valid' => true,
            'errors' => [],
            'warnings' => [],
            'missingUids' => [],
            'missingUidCount' => 0,
            'anchorStatus' => 'notChecked',
        ], $subject->toArray());
    }

    #[Test]
    public function toArrayReturnsCorrectStructureForInvalidResult(): void
    {
        $errors = [2 => 'Chain broken at entry 2', 8 => 'Entry 8 missing'];
        $subject = HashChainVerificationResult::invalid($errors);

        self::assertSame([
            'valid' => false,
            'errors' => $errors,
            'warnings' => [],
            'missingUids' => [],
            'missingUidCount' => 0,
            'anchorStatus' => 'notChecked',
        ], $subject->toArray());
    }

    #[Test]
    public function toArrayContainsExactlySixKeys(): void
    {
        $subject = HashChainVerificationResult::valid();

        // Schema: valid, errors, warnings, missingUids, missingUidCount,
        // anchorStatus. missingUidCount was added alongside the enumeration cap
        // so large gaps (mass purges) do not explode the missingUids array —
        // callers can still detect the gap scale without holding N entries.
        // anchorStatus reports the tip-anchor check, which is what detects a
        // tail truncation or a full wipe the row walk cannot see.
        self::assertCount(6, $subject->toArray());
    }

    #[Test]
    public function constructorWarningsDefaultToEmptyArray(): void
    {
        $subject = new HashChainVerificationResult(valid: true);

        self::assertSame([], $subject->warnings);
    }

    #[Test]
    public function validFactoryAcceptsWarnings(): void
    {
        $warnings = [5 => 'HMAC key epoch boundary: 0 -> 1'];
        $subject = HashChainVerificationResult::valid($warnings);

        self::assertTrue($subject->valid);
        self::assertSame([], $subject->errors);
        self::assertSame($warnings, $subject->warnings);
    }

    #[Test]
    public function invalidFactoryAcceptsWarnings(): void
    {
        $errors = [3 => 'Chain broken'];
        $warnings = [2 => 'Epoch boundary'];
        $subject = HashChainVerificationResult::invalid($errors, $warnings);

        self::assertFalse($subject->valid);
        self::assertSame($errors, $subject->errors);
        self::assertSame($warnings, $subject->warnings);
    }

    #[Test]
    public function getWarningCountReturnsZeroForNoWarnings(): void
    {
        $subject = HashChainVerificationResult::valid();

        self::assertSame(0, $subject->getWarningCount());
    }

    #[Test]
    public function getWarningCountReturnsCorrectCount(): void
    {
        $warnings = [1 => 'warn1', 5 => 'warn2'];
        $subject = HashChainVerificationResult::valid($warnings);

        self::assertSame(2, $subject->getWarningCount());
    }

    #[Test]
    public function toArrayIncludesWarnings(): void
    {
        $warnings = [10 => 'epoch change'];
        $subject = HashChainVerificationResult::valid($warnings);

        $array = $subject->toArray();
        self::assertSame($warnings, $array['warnings']);
    }

    #[Test]
    public function missingUidsDefaultsToEmpty(): void
    {
        $subject = HashChainVerificationResult::valid();

        self::assertSame([], $subject->missingUids);
        self::assertFalse($subject->hasMissingUids());
    }

    #[Test]
    public function missingUidsReportedInValidResult(): void
    {
        $subject = HashChainVerificationResult::valid([], [7]);

        self::assertSame([7], $subject->missingUids);
        self::assertTrue($subject->hasMissingUids());
    }

    #[Test]
    public function missingUidsReportedInInvalidResult(): void
    {
        $subject = HashChainVerificationResult::invalid([8 => 'gap detected'], [], [7]);

        self::assertFalse($subject->isValid());
        self::assertSame([7], $subject->missingUids);
    }

    #[Test]
    public function toArrayIncludesMissingUids(): void
    {
        $subject = HashChainVerificationResult::valid([], [4, 5, 6]);

        $array = $subject->toArray();
        self::assertSame([4, 5, 6], $array['missingUids']);
    }
}
