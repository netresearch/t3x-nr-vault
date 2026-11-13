<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Storage\HashiCorp;

/**
 * Kubernetes auth: the pod's service account token, reviewed by the cluster API.
 *
 * The cluster API is a stub that vouches for one service account; the login,
 * the role binding to that account and the policy are Vault's own.
 */
final class HashiCorpKubernetesAuthTest extends AbstractHashiCorpAuthMethodTestCase
{
    private string $jwtPath = '';

    protected function tearDown(): void
    {
        if ($this->jwtPath !== '' && file_exists($this->jwtPath)) {
            // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned temp file
            unlink($this->jwtPath);
        }

        parent::tearDown();
    }

    protected function prepare(VaultDevServer $server): void
    {
        $this->jwtPath = sys_get_temp_dir() . '/nr-vault-test-sa-' . bin2hex(random_bytes(6));
        file_put_contents($this->jwtPath, $server->serviceAccountJwt() . "\n");
    }

    protected function authSettings(VaultDevServer $server): array
    {
        return [
            'authMethod'        => 'kubernetes',
            'kubernetesRole'    => 'typo3',
            'kubernetesJwtPath' => $this->jwtPath,
        ];
    }

    protected function refreshesAfterRevocation(): bool
    {
        return true;
    }
}
