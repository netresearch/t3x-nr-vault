<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Command;

use Netresearch\NrVault\Command\VaultStoreCommand;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

/**
 * Positive control for {@see VaultStoreCommandCliDefaultAllowlistTest}: with
 * `secret.manage_policy` in the CLI allowlist the group change applies.
 */
#[CoversClass(VaultStoreCommand::class)]
final class VaultStoreCommandCliManagePolicyTest extends AbstractVaultStoreCommandCliTestCase
{
    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch'       => 1,
        'allowCliAccess'       => true,
        'cliAllowedOperations' => 'secret.use,secret.create,secret.rotate,secret.manage_policy',
    ];

    #[Test]
    public function changingTheGroupsOfAnExistingSecretAppliesWithManagePolicy(): void
    {
        [$exitCode, $display, $groups] = $this->changeGroupsAsCliUser();

        self::assertSame(0, $exitCode, $display);
        self::assertSame([3], $groups);
    }
}
