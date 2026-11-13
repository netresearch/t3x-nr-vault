<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Storage\HashiCorp;

/**
 * AppRole auth: role id in the configuration, secret id in the environment.
 */
final class HashiCorpAppRoleAuthTest extends AbstractHashiCorpAuthMethodTestCase
{
    private const SECRET_ID_ENV = 'NR_VAULT_TEST_APPROLE_SECRET_ID';

    protected function tearDown(): void
    {
        putenv(self::SECRET_ID_ENV);

        parent::tearDown();
    }

    protected function prepare(VaultDevServer $server): void
    {
        putenv(self::SECRET_ID_ENV . '=' . $server->newAppRoleSecretId());
    }

    protected function authSettings(VaultDevServer $server): array
    {
        return [
            'authMethod'     => 'approle',
            'roleId'         => $server->appRoleId(),
            'secretIdEnvVar' => self::SECRET_ID_ENV,
        ];
    }

    protected function refreshesAfterRevocation(): bool
    {
        return true;
    }
}
