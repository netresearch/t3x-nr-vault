<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api\ExtensionPoints;

use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\ReadinessCheckInterface;

/**
 * A readiness check written the way a consuming extension writes one:
 * against the published interface only. It covers no control yet, which the
 * contract allows.
 */
final class SampleReadinessCheck implements ReadinessCheckInterface
{
    public function getId(): string
    {
        return 'sample';
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
        return [];
    }
}
