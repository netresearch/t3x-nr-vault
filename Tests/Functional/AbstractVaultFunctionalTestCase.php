<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional;

use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * Shared base for nr-vault functional tests.
 *
 * Centralises the repetitive master-key lifecycle that appeared verbatim in
 * ~17 test files (~30 LOC each):
 *
 *  - generates a per-test sodium master key,
 *  - writes it to `instancePath/master.key` with mode 0600,
 *  - seeds `$GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault']` so
 *    `FileMasterKeyProvider` picks it up,
 *  - optionally imports a backend-user fixture and logs the user in,
 *  - clears the `FileMasterKeyProvider` cache, zeros the key bytes and
 *    unlinks the file on tearDown.
 *
 * Subclasses customise behaviour via protected properties:
 *  - `$backendUserFixture` — CSV fixture path (absolute), or null to skip.
 *  - `$backendUserUid` — UID to log in; null to skip `setUpBackendUser()`.
 *  - `$extensionConfiguration` — merged into the nr_vault config array.
 *
 * Tests that need a non-standard master-key path or want to opt out of the
 * master-key lifecycle should extend `FunctionalTestCase` directly.
 */
abstract class AbstractVaultFunctionalTestCase extends FunctionalTestCase
{
    /** @var list<string> */
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
    ];

    /** @var list<string> */
    protected array $coreExtensionsToLoad = [
        'backend',
    ];

    /**
     * Absolute path to a CSV fixture loaded via `importCSVDataSet()` in setUp.
     * Null disables the import.
     */
    protected ?string $backendUserFixture = null;

    /** Backend user UID to set up via `setUpBackendUser()`. Null skips login. */
    protected ?int $backendUserUid = 1;

    /**
     * Extra keys merged into `$GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault']`.
     *
     * @var array<string, mixed>
     */
    protected array $extensionConfiguration = [];

    /**
     * Resolved path of the test-local master key file.
     * Initialised in `setUp()` — `null` until then.
     */
    protected ?string $masterKeyPath = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->masterKeyPath = $this->instancePath . '/master.key';
        $masterKey = sodium_crypto_secretbox_keygen();
        file_put_contents($this->masterKeyPath, $masterKey);
        chmod($this->masterKeyPath, 0o600);

        if (!isset($GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']) || !\is_array($GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS'])) {
            $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS'] = [];
        }

        $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault'] = array_merge(
            [
                'masterKeySource' => $this->masterKeyPath,
                'autoKeyPath' => $this->masterKeyPath,
                'enableCache' => false,
            ],
            $this->extensionConfiguration,
        );

        if ($this->backendUserFixture !== null) {
            $this->importCSVDataSet($this->backendUserFixture);
        }

        if ($this->backendUserUid !== null) {
            $this->setUpBackendUser($this->backendUserUid);
        }
    }

    protected function tearDown(): void
    {
        FileMasterKeyProvider::clearCachedKey();

        if ($this->masterKeyPath !== null && file_exists($this->masterKeyPath)) {
            $content = file_get_contents($this->masterKeyPath);
            if ($content !== false) {
                sodium_memzero($content);
            }

            // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
            unlink($this->masterKeyPath);
        }

        parent::tearDown();
    }

    /**
     * Generate a UUID v7 for use as a per-test secret identifier.
     *
     * Extracted from ~9 duplicated copies across the functional suite.
     */
    protected function generateUuidV7(): string
    {
        $timestamp = (int) (microtime(true) * 1000);
        $timestampHex = str_pad(dechex($timestamp), 12, '0', STR_PAD_LEFT);
        $randomBytes = random_bytes(10);
        $randomHex = bin2hex($randomBytes);

        return \sprintf(
            '%s-%s-7%s-%s%s-%s',
            substr($timestampHex, 0, 8),
            substr($timestampHex, 8, 4),
            substr($randomHex, 0, 3),
            dechex(8 + random_int(0, 3)),
            substr($randomHex, 3, 3),
            substr($randomHex, 6, 12),
        );
    }
}
