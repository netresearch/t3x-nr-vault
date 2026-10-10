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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Cache\CacheManager;
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
        $this->configureUser(2, 'page.vault.permissions.default.reveal = 0');
        self::assertFalse(
            $this
                ->getSubject()
                ->isAllowed('table', 'field', VaultFieldPermission::Reveal),
        );

        $this->configureUser(2, 'page.vault.permissions.default.reveal = 1');
        self::assertFalse(
            $this
                ->getSubject()
                ->isAllowed('table', 'field', VaultFieldPermission::Reveal),
        );
        $this->getSubject()->clearCache();
        self::assertTrue(
            $this
                ->getSubject()
                ->isAllowed('table', 'field', VaultFieldPermission::Reveal),
        );
    }

    #[Test]
    public function permissionsAreCachedPerUserAndField(): void
    {
        $this->configureUser(
            2,
            "page.vault.permissions.table.field1.reveal = 0\npage.vault.permissions.table.field2.reveal = 1",
        );
        self::assertFalse(
            $this
                ->getSubject()
                ->isAllowed('table', 'field1', VaultFieldPermission::Reveal),
        );
        self::assertTrue(
            $this
                ->getSubject()
                ->isAllowed('table', 'field2', VaultFieldPermission::Reveal),
        );

        $this->configureUser(
            3,
            'page.vault.permissions.table.field1.reveal = 1',
        );
        self::assertTrue(
            $this
                ->getSubject()
                ->isAllowed('table', 'field1', VaultFieldPermission::Reveal),
        );
        $this->configureUser(
            2,
            'page.vault.permissions.table.field1.reveal = 1',
        );
        self::assertFalse(
            $this
                ->getSubject()
                ->isAllowed('table', 'field1', VaultFieldPermission::Reveal),
        );
    }

    #[Test]
    public function noBackendUserReturnsFalse(): void
    {
        // Don't set up a backend user - simulate frontend context
        unset($GLOBALS['BE_USER']);

        $result = $this->getSubject()->isAllowed('table', 'field', VaultFieldPermission::Reveal);

        self::assertFalse($result);
    }

    #[Test]
    #[DataProvider('configurationPrecedence')]
    public function realUserTsConfigControlsPublicPermission(
        string $config,
        VaultFieldPermission $permission,
        bool $expected,
    ): void {
        $this->configureUser(2, $config);

        self::assertSame(
            $expected,
            $this->getSubject()->isAllowed('table', 'field', $permission),
        );
    }

    /**
     * @return iterable<string, array{string, VaultFieldPermission, bool}>
     */
    public static function configurationPrecedence(): iterable
    {
        yield 'global false overrides built-in true' => [
            'page.vault.permissions.default.reveal = 0',
            VaultFieldPermission::Reveal,
            false,
        ];
        yield 'table true overrides global false' => [
            "page.vault.permissions.default.reveal = 0\npage.vault.permissions.table.default.reveal = 1",
            VaultFieldPermission::Reveal,
            true,
        ];
        yield 'table false overrides global true' => [
            "page.vault.permissions.default.reveal = 1\npage.vault.permissions.table.default.reveal = 0",
            VaultFieldPermission::Reveal,
            false,
        ];
        yield 'field false overrides table and global true' => [
            "page.vault.permissions.default.reveal = 1\npage.vault.permissions.table.default.reveal = 1\npage.vault.permissions.table.field.reveal = 0",
            VaultFieldPermission::Reveal,
            false,
        ];
        yield 'field true overrides table and global false' => [
            "page.vault.permissions.default.reveal = 0\npage.vault.permissions.table.default.reveal = 0\npage.vault.permissions.table.field.reveal = 1",
            VaultFieldPermission::Reveal,
            true,
        ];
        yield 'configured readonly overrides built-in false' => [
            'page.vault.permissions.table.field.readOnly = yes',
            VaultFieldPermission::ReadOnly,
            true,
        ];
    }

    #[Test]
    public function realTsConfigSeparatesPermissionsAndTables(): void
    {
        $this->configureUser(
            2,
            "page.vault.permissions.table.field.reveal = 0\npage.vault.permissions.table.field.copy = 1\npage.vault.permissions.table.field.edit = 0\npage.vault.permissions.table.field.readOnly = 1\npage.vault.permissions.other.field.reveal = 1",
        );

        self::assertSame(
            [
                'reveal' => false,
                'copy' => true,
                'edit' => false,
                'readOnly' => true,
            ],
            $this->getSubject()->getPermissions('table', 'field'),
        );
        self::assertTrue($this->getSubject()->isReadOnly('table', 'field'));
        self::assertTrue(
            $this
                ->getSubject()
                ->isAllowed('other', 'field', VaultFieldPermission::Reveal),
        );
    }

    #[Test]
    public function administratorsIgnoreRestrictiveTsConfigAndAreNeverReadOnly(): void
    {
        $this->configureUser(
            1,
            "page.vault.permissions.default.reveal = 0\npage.vault.permissions.default.copy = 0\npage.vault.permissions.default.edit = 0\npage.vault.permissions.default.readOnly = 1",
        );

        self::assertSame(
            [
                'reveal' => true,
                'copy' => true,
                'edit' => true,
                'readOnly' => false,
            ],
            $this->getSubject()->getPermissions('table', 'field'),
        );
    }

    private function getSubject(): VaultFieldPermissionService
    {
        self::assertNotNull($this->subject, 'VaultFieldPermissionService not initialized');

        return $this->subject;
    }

    private function configureUser(int $uid, string $config): void
    {
        $this
            ->getConnectionPool()
            ->getConnectionForTable('be_users')
            ->update('be_users', ['TSconfig' => $config], ['uid' => $uid]);
        GeneralUtility::makeInstance(CacheManager::class)
            ->getCache('runtime')
            ->flush();
        $this->setUpBackendUser($uid);
    }
}
