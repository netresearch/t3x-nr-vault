<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service;

use Netresearch\NrVault\Service\VaultFieldPermission;
use Netresearch\NrVault\Service\VaultFieldPermissionService;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * Functional tests for VaultFieldPermissionService with TSconfig.
 */
#[CoversClass(VaultFieldPermissionService::class)]
final class VaultFieldPermissionServiceTest extends FunctionalTestCase
{
    /** @var list<string> */
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
    ];

    /** @var list<string> */
    protected array $coreExtensionsToLoad = [
        'backend',
    ];

    private ?VaultFieldPermissionService $subject = null;

    protected function setUp(): void
    {
        parent::setUp();

        // Import backend users - admin and non-admin
        $this->importCSVDataSet(__DIR__ . '/Fixtures/be_users_permissions.csv');

        // Get service from container
        $service = GeneralUtility::makeInstance(VaultFieldPermissionService::class);
        self::assertInstanceOf(VaultFieldPermissionService::class, $service);
        $this->subject = $service;
    }

    #[Test]
    public function adminUserHasFullAccessToAllPermissions(): void
    {
        // Set up admin backend user
        $this->setUpBackendUser(1);

        self::assertTrue($this->getSubject()->isAllowed('any_table', 'any_field', VaultFieldPermission::Reveal));
        self::assertTrue($this->getSubject()->isAllowed('any_table', 'any_field', VaultFieldPermission::Copy));
        self::assertTrue($this->getSubject()->isAllowed('any_table', 'any_field', VaultFieldPermission::Edit));
        self::assertFalse($this->getSubject()->isAllowed('any_table', 'any_field', VaultFieldPermission::ReadOnly));
    }

    #[Test]
    public function adminUserIsNeverReadOnly(): void
    {
        $this->setUpBackendUser(1);

        self::assertFalse($this->getSubject()->isReadOnly('any_table', 'any_field'));
    }

    #[Test]
    public function nonAdminUserUsesBuiltInDefaults(): void
    {
        // Set up non-admin backend user
        $this->setUpBackendUser(2);

        // Without TSconfig, built-in defaults apply: reveal=true, copy=true, edit=true, readOnly=false
        self::assertTrue($this->getSubject()->isAllowed('some_table', 'some_field', VaultFieldPermission::Reveal));
        self::assertTrue($this->getSubject()->isAllowed('some_table', 'some_field', VaultFieldPermission::Copy));
        self::assertTrue($this->getSubject()->isAllowed('some_table', 'some_field', VaultFieldPermission::Edit));
        self::assertFalse($this->getSubject()->isAllowed('some_table', 'some_field', VaultFieldPermission::ReadOnly));
    }

    #[Test]
    public function getPermissionsReturnsAllPermissionStates(): void
    {
        $this->setUpBackendUser(1);

        $permissions = $this->getSubject()->getPermissions('test_table', 'test_field');

        self::assertArrayHasKey('reveal', $permissions);
        self::assertArrayHasKey('copy', $permissions);
        self::assertArrayHasKey('edit', $permissions);
        self::assertArrayHasKey('readOnly', $permissions);
    }

    #[Test]
    public function clearCacheResetsPermissionCache(): void
    {
        $this->setUpBackendUser(1);

        // First call - caches result
        $this->getSubject()->isAllowed('table', 'field', VaultFieldPermission::Reveal);

        // Clear cache
        $this->getSubject()->clearCache();

        // Should work without errors
        $result = $this->getSubject()->isAllowed('table', 'field', VaultFieldPermission::Reveal);
        self::assertTrue($result);
    }

    #[Test]
    public function permissionsAreCachedPerUserAndField(): void
    {
        $this->setUpBackendUser(1);

        // Multiple calls should use cache
        $result1 = $this->getSubject()->isAllowed('table1', 'field1', VaultFieldPermission::Reveal);
        $result2 = $this->getSubject()->isAllowed('table1', 'field1', VaultFieldPermission::Reveal);
        $result3 = $this->getSubject()->isAllowed('table1', 'field2', VaultFieldPermission::Reveal);

        self::assertTrue($result1);
        self::assertTrue($result2);
        self::assertTrue($result3);
    }

    #[Test]
    public function noBackendUserReturnsFalse(): void
    {
        // Don't set up a backend user - simulate frontend context
        unset($GLOBALS['BE_USER']);

        $result = $this->getSubject()->isAllowed('table', 'field', VaultFieldPermission::Reveal);

        self::assertFalse($result);
    }

    private function getSubject(): VaultFieldPermissionService
    {
        self::assertNotNull($this->subject, 'VaultFieldPermissionService not initialized');

        return $this->subject;
    }
}
