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
            'epochCounts' => [],
            'minEpoch' => null,
            'maxEpoch' => null,
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
            'epochCounts' => [],
            'minEpoch' => null,
            'maxEpoch' => null,
        ], $subject->toArray());
    }

    #[Test]
    public function toArrayContainsExactlyNineKeys(): void
    {
        $subject = HashChainVerificationResult::valid();

        // Schema: valid, errors, warnings, missingUids, missingUidCount,
        // anchorStatus, epochCounts, minEpoch, maxEpoch. missingUidCount was
        // added alongside the enumeration cap so large gaps (mass purges) do not
        // explode the missingUids array — callers can still detect the gap scale
        // without holding N entries. anchorStatus reports the tip-anchor check,
        // which is what detects a tail truncation or a full wipe the row walk
        // cannot see. epochCounts and its two derived bounds answer the question
        // `valid` cannot: whether every stored row is signed at the configured
        // epoch, or only the newest ones are.
        self::assertCount(9, $subject->toArray());
    }

    /**
     * The distribution is what separates "the chain is valid" from "the whole
     * chain is signed at the configured epoch". A chain left at epoch 1 by a
     * stalled migration verifies perfectly and still leaves `success` and the
     * attribution fields outside the MAC.
     */
    #[Test]
    public function theEpochDistributionExposesItsBoundsAndWhetherItIsMixed(): void
    {
        $subject = HashChainVerificationResult::valid(
            epochCounts: [1 => 40, 2 => 5, 3 => 900],
        );

        self::assertSame([1 => 40, 2 => 5, 3 => 900], $subject->epochCounts);
        self::assertSame(1, $subject->getMinEpoch());
        self::assertSame(3, $subject->getMaxEpoch());
        self::assertTrue($subject->hasMixedEpochs());
    }

    /**
     * A fully migrated chain is one epoch across the board — min equals max and
     * nothing is mixed, so a caller can act on the bounds alone.
     */
    #[Test]
    public function aSingleEpochChainIsNotReportedAsMixed(): void
    {
        $subject = HashChainVerificationResult::valid(epochCounts: [3 => 120]);

        self::assertSame(3, $subject->getMinEpoch());
        self::assertSame(3, $subject->getMaxEpoch());
        self::assertFalse($subject->hasMixedEpochs());
    }

    /**
     * An empty range has no epoch at all — null, never 0, which is a real epoch
     * meaning "keyless" and the opposite of "nothing to say".
     */
    #[Test]
    public function anEmptyRangeReportsNoEpochBoundsRatherThanZero(): void
    {
        $subject = HashChainVerificationResult::valid();

        self::assertSame([], $subject->epochCounts);
        self::assertNull($subject->getMinEpoch());
        self::assertNull($subject->getMaxEpoch());
        self::assertFalse($subject->hasMixedEpochs());
    }

    /**
     * The bounds are derived from the keys, not from insertion order, so a
     * caller that hands in an unordered map still gets the right answer.
     */
    #[Test]
    public function theEpochBoundsDoNotDependOnInsertionOrder(): void
    {
        $subject = HashChainVerificationResult::invalid(
            [7 => 'Entry hash mismatch - possible tampering'],
            epochCounts: [3 => 10, 0 => 2, 2 => 4],
        );

        self::assertSame(0, $subject->getMinEpoch());
        self::assertSame(3, $subject->getMaxEpoch());
    }

    /**
     * An invalid chain still reports its distribution — a downgraded chain is
     * exactly the case where an operator needs to see which epochs are present.
     */
    #[Test]
    public function theInvalidFactoryCarriesTheDistributionThroughToArray(): void
    {
        $subject = HashChainVerificationResult::invalid(
            [0 => 'HMAC key epoch downgrade detected'],
            epochCounts: [0 => 900],
        );

        $array = $subject->toArray();

        self::assertSame([0 => 900], $array['epochCounts']);
        self::assertSame(0, $array['minEpoch']);
        self::assertSame(0, $array['maxEpoch']);
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
