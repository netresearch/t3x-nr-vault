<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Command;

use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Command\VaultStoreCommand;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Authentication\CommandLineUserAuthentication;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * `vault:store --groups` on an existing secret, run as the plain TYPO3 CLI
 * user: `CommandApplication` puts an unauthenticated
 * `CommandLineUserAuthentication` into `$GLOBALS['BE_USER']`, and the CLI
 * holds the operations listed in `cliAllowedOperations`. ExtensionConfiguration
 * is read once per class, so each allowlist needs its own class.
 */
abstract class AbstractVaultStoreCommandCliTestCase extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../Fixtures/Users/be_users.csv';

    /**
     * Creates a secret with group 1 as the CLI user, then runs
     * `vault:store <id> --groups 3` over it.
     *
     * @return array{0: int, 1: string, 2: list<int>} Exit code, output, groups read back
     */
    protected function changeGroupsAsCliUser(): array
    {
        $GLOBALS['BE_USER'] = GeneralUtility::makeInstance(CommandLineUserAuthentication::class);
        $identifier         = 'cli_groups_' . bin2hex(random_bytes(4));
        $vaultService       = $this->get(VaultServiceInterface::class);
        $tester             = new CommandTester($this->get(VaultStoreCommand::class));

        $created = $tester->execute(['identifier' => $identifier, '--value' => 'first', '--groups' => ['1']]);
        self::assertSame(0, $created, $tester->getDisplay());

        $exitCode = $tester->execute(['identifier' => $identifier, '--value' => 'second', '--groups' => ['3']]);
        $display  = $tester->getDisplay();
        $groups   = $vaultService->getMetadata($identifier)->groups;
        sort($groups);

        self::assertTrue(
            $this->get(AuditLogServiceInterface::class)->verifyHashChain()->isValid(),
            'the audit chain must verify after the store commands',
        );

        return [$exitCode, (string) preg_replace('/\s+/', ' ', $display), $groups];
    }
}
