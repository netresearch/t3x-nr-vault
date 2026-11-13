<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Storage\HashiCorp;

/**
 * Token auth: the extension holds a Vault token with the extension's policy.
 */
final class HashiCorpTokenAuthTest extends AbstractHashiCorpAuthMethodTestCase
{
    protected function authSettings(VaultDevServer $server): array
    {
        return [
            'authMethod' => 'token',
            'token'      => $server->limitedToken(),
            // Nothing is exported under this name, so the stored token is what runs.
            'tokenEnvVar' => 'NR_VAULT_TEST_UNSET_VAULT_TOKEN',
        ];
    }

    protected function refreshesAfterRevocation(): bool
    {
        return false;
    }
}
