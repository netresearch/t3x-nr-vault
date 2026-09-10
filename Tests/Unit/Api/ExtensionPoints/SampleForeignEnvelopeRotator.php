<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api\ExtensionPoints;

use Netresearch\NrVault\Crypto\EnvelopeRotationContext;
use Netresearch\NrVault\Crypto\ForeignEnvelopeRotatorInterface;

/**
 * A foreign-envelope rotator written the way a consuming extension writes
 * one: against the published interface only. It owns no rows, which is a
 * legal state for a consumer that has not sealed anything yet.
 */
final class SampleForeignEnvelopeRotator implements ForeignEnvelopeRotatorInterface
{
    public function getIdentifier(): string
    {
        return 'sample: sealed payloads';
    }

    /**
     * @return list<string>
     */
    public function getTables(): array
    {
        return ['tx_sample_payload'];
    }

    public function countEnvelopes(): int
    {
        return 0;
    }

    public function rewrapAll(EnvelopeRotationContext $context): int
    {
        return 0;
    }
}
