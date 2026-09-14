<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\Classes\Doctor;

use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\ReadinessCheckInterface;

/**
 * A `vault:doctor` control contributed by a consuming extension. It names the
 * profile it was evaluated against, so the test can tell a real run through
 * the doctor from a hand-built call.
 */
final class ConsumerReadinessCheck implements ReadinessCheckInterface
{
    public const FINDING_ID = 'consumer_fixture.integration';

    public function getId(): string
    {
        return 'consumer_fixture';
    }

    public function appliesTo(SecurityProfile $profile): bool
    {
        return true;
    }

    /**
     * @return list<Finding>
     */
    public function run(DoctorContext $context): array
    {
        return [
            Finding::pass(
                self::FINDING_ID,
                \sprintf('The consumer fixture integration is wired (profile: %s).', $context->profile->value),
            ),
        ];
    }
}
