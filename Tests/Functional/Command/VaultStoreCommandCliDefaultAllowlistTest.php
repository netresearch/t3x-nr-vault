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
 * #524: now that `--groups` reaches the service, changing the group tiers of
 * an existing secret is a policy change and needs `secret.manage_policy`,
 * which the default CLI allowlist does not hold.
 */
#[CoversClass(VaultStoreCommand::class)]
final class VaultStoreCommandCliDefaultAllowlistTest extends AbstractVaultStoreCommandCliTestCase
{
    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 1,
        'allowCliAccess' => true,
    ];

    #[Test]
    public function changingTheGroupsOfAnExistingSecretIsDeniedWithoutManagePolicy(): void
    {
        [$exitCode, $display, $groups] = $this->changeGroupsAsCliUser();

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('secret.manage_policy', $display);
        self::assertSame([1], $groups);
    }
}
