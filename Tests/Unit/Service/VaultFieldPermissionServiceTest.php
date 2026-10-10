<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service;

use Netresearch\NrVault\Service\VaultFieldPermission;
use Netresearch\NrVault\Service\VaultFieldPermissionService;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;
use stdClass;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;

#[CoversClass(VaultFieldPermissionService::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultFieldPermissionServiceTest extends TestCase
{
    private VaultFieldPermissionService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new VaultFieldPermissionService();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($GLOBALS['BE_USER']);
    }

    #[Test]
    public function returnsFalseWhenNoBackendUser(): void
    {
        $result = $this->service->isAllowed('tx_table', 'field', VaultFieldPermission::Reveal);

        self::assertFalse($result);
    }

    #[Test]
    public function adminHasFullAccessExceptReadOnly(): void
    {
        $backendUser = $this->createMockBackendUser(isAdmin: true);

        self::assertTrue($this->service->isAllowed('any_table', 'any_field', VaultFieldPermission::Reveal, $backendUser));
        self::assertTrue($this->service->isAllowed('any_table', 'any_field', VaultFieldPermission::Copy, $backendUser));
        self::assertTrue($this->service->isAllowed('any_table', 'any_field', VaultFieldPermission::Edit, $backendUser));
        self::assertFalse($this->service->isAllowed('any_table', 'any_field', VaultFieldPermission::ReadOnly, $backendUser));
    }

    #[Test]
    public function getPermissionsReturnsAllPermissions(): void
    {
        $backendUser = $this->createMockBackendUser(isAdmin: true);

        $permissions = $this->service->getPermissions('table', 'field', $backendUser);

        self::assertArrayHasKey('reveal', $permissions);
        self::assertArrayHasKey('copy', $permissions);
        self::assertArrayHasKey('edit', $permissions);
        self::assertArrayHasKey('readOnly', $permissions);
        self::assertTrue($permissions['reveal']);
        self::assertFalse($permissions['readOnly']);
    }

    #[Test]
    public function isReadOnlyDelegatesCorrectly(): void
    {
        $backendUser = $this->createMockBackendUser(isAdmin: true);

        // Admins are never read-only
        self::assertFalse($this->service->isReadOnly('table', 'field', $backendUser));
    }

    #[Test]
    public function usesGlobalBackendUserWhenNotProvided(): void
    {
        $backendUser = $this->createMockBackendUser(isAdmin: true);
        $GLOBALS['BE_USER'] = $backendUser;

        $result = $this->service->isAllowed('table', 'field', VaultFieldPermission::Reveal);

        self::assertTrue($result);
    }

    #[Test]
    public function toBooleanReturnsTrueForTrueValues(): void
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('toBoolean');

        self::assertTrue($method->invoke($this->service, true));
        self::assertTrue($method->invoke($this->service, '1'));
        self::assertTrue($method->invoke($this->service, 'true'));
        self::assertTrue($method->invoke($this->service, 'TRUE'));
        self::assertTrue($method->invoke($this->service, 'yes'));
        self::assertTrue($method->invoke($this->service, 'YES'));
        self::assertTrue($method->invoke($this->service, 'on'));
        self::assertTrue($method->invoke($this->service, 'ON'));
        self::assertTrue($method->invoke($this->service, 1));
    }

    #[Test]
    public function toBooleanReturnsFalseForFalseValues(): void
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('toBoolean');

        self::assertFalse($method->invoke($this->service, false));
        self::assertFalse($method->invoke($this->service, '0'));
        self::assertFalse($method->invoke($this->service, 'false'));
        self::assertFalse($method->invoke($this->service, 'no'));
        self::assertFalse($method->invoke($this->service, 'off'));
        self::assertFalse($method->invoke($this->service, ''));
        self::assertFalse($method->invoke($this->service, 0));
    }

    #[Test]
    public function getBuiltInDefaultReturnsCorrectDefaults(): void
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('getBuiltInDefault');

        self::assertTrue($method->invoke($this->service, VaultFieldPermission::Reveal));
        self::assertTrue($method->invoke($this->service, VaultFieldPermission::Copy));
        self::assertTrue($method->invoke($this->service, VaultFieldPermission::Edit));
        self::assertFalse($method->invoke($this->service, VaultFieldPermission::ReadOnly));
    }

    #[Test]
    public function getNestedValueReturnsNullForMissingKey(): void
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('getNestedValue');

        $array = [];
        $result = $method->invoke($this->service, $array, ['nonexistent']);

        self::assertNull($result);
    }

    #[Test]
    public function getNestedValueReturnsValueForDirectKey(): void
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('getNestedValue');

        $array = ['key' => 'value'];
        $result = $method->invoke($this->service, $array, ['key']);

        self::assertSame('value', $result);
    }

    #[Test]
    public function getNestedValueHandlesTsConfigDotNotation(): void
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('getNestedValue');

        // TSconfig uses trailing dots for nested arrays
        $array = [
            'table.' => [
                'field.' => [
                    'permission' => '1',
                ],
            ],
        ];
        $result = $method->invoke($this->service, $array, ['table', 'field', 'permission']);

        self::assertSame('1', $result);
    }

    #[Test]
    public function getNestedValueHandlesMixedDotNotation(): void
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('getNestedValue');

        // Mix of dot notation and direct values
        $array = [
            'table.' => [
                'field' => 'direct_value',
            ],
        ];
        $result = $method->invoke($this->service, $array, ['table', 'field']);

        self::assertSame('direct_value', $result);
    }

    #[Test]
    public function differentFieldsHaveSeparateCacheEntries(): void
    {
        $backendUser = $this->createMockBackendUser(uid: 10, isAdmin: false);
        $cache = (new ReflectionClass($this->service))->getProperty('permissionCache');
        $cache->setValue(
            $this->service,
            [
                'table:field1:reveal:10' => false,
                'table:field2:reveal:10' => true,
            ],
        );

        self::assertFalse(
            $this->service->isAllowed(
                'table',
                'field1',
                VaultFieldPermission::Reveal,
                $backendUser,
            ),
        );
        self::assertTrue(
            $this->service->isAllowed(
                'table',
                'field2',
                VaultFieldPermission::Reveal,
                $backendUser,
            ),
        );
    }

    #[Test]
    public function differentPermissionsHaveSeparateCacheEntries(): void
    {
        $backendUser = $this->createMockBackendUser(uid: 10, isAdmin: false);
        $cache = (new ReflectionClass($this->service))->getProperty('permissionCache');
        $cache->setValue(
            $this->service,
            [
                'table:field:reveal:10' => false,
                'table:field:copy:10' => true,
                'table:field:readOnly:10' => true,
            ],
        );

        self::assertFalse(
            $this->service->isAllowed(
                'table',
                'field',
                VaultFieldPermission::Reveal,
                $backendUser,
            ),
        );
        self::assertTrue(
            $this->service->isAllowed(
                'table',
                'field',
                VaultFieldPermission::Copy,
                $backendUser,
            ),
        );
        self::assertTrue(
            $this->service->isAllowed(
                'table',
                'field',
                VaultFieldPermission::ReadOnly,
                $backendUser,
            ),
        );
    }

    #[Test]
    public function getNestedValueReturnsNullForNonArrayCurrent(): void
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('getNestedValue');

        // When traversing leads to a non-array value before reaching end of keys
        $array = [
            'key.' => 'not_an_array',
        ];
        $result = $method->invoke($this->service, $array, ['key', 'nested']);

        self::assertNull($result);
    }

    #[Test]
    public function isReadOnlyDelegatesWithExplicitNullBackendUser(): void
    {
        // With no backend user (null), isAllowed returns false, so isReadOnly also returns false
        $result = $this->service->isReadOnly('tx_table', 'field');

        self::assertFalse($result);
    }

    #[Test]
    public function getPermissionsIncludesAllFourPermissionsForAdmin(): void
    {
        // Verifies getPermissions iterates all VaultFieldPermission cases
        $backendUser = $this->createMockBackendUser(isAdmin: true);

        $permissions = $this->service->getPermissions('tx_table', 'field', $backendUser);

        self::assertCount(4, $permissions);
        self::assertArrayHasKey('reveal', $permissions);
        self::assertArrayHasKey('copy', $permissions);
        self::assertArrayHasKey('edit', $permissions);
        self::assertArrayHasKey('readOnly', $permissions);
    }

    #[Test]
    public function cacheIsKeyedByUserUid(): void
    {
        $first = $this->createMockBackendUser(uid: 10, isAdmin: false);
        $second = $this->createMockBackendUser(uid: 20, isAdmin: false);
        $cache = (new ReflectionClass($this->service))->getProperty('permissionCache');
        $cache->setValue(
            $this->service,
            [
                'tx_table:field:reveal:10' => false,
                'tx_table:field:reveal:20' => true,
            ],
        );

        self::assertFalse(
            $this->service->isAllowed(
                'tx_table',
                'field',
                VaultFieldPermission::Reveal,
                $first,
            ),
        );
        self::assertTrue(
            $this->service->isAllowed(
                'tx_table',
                'field',
                VaultFieldPermission::Reveal,
                $second,
            ),
        );
    }

    #[Test]
    public function cacheResultIsReturnedOnSecondCallForNonAdmin(): void
    {
        // Pre-seed cache to simulate a result from a previous non-admin checkPermission call.
        // Then verify the cached value is returned without invoking checkPermission again.
        $backendUser = $this->createMockBackendUser(uid: 55, isAdmin: false);

        $reflection = new ReflectionClass($this->service);
        $cacheProp = $reflection->getProperty('permissionCache');
        // Seed a deliberate value
        $cacheProp->setValue($this->service, ['tx_table:field:edit:55' => false]);

        // The cache hit should return false even though built-in default for Edit is true
        $result = $this->service->isAllowed('tx_table', 'field', VaultFieldPermission::Edit, $backendUser);

        self::assertFalse($result);
    }

    #[Test]
    public function userRecordWithNonIntUidDefaultsToZeroForCacheKey(): void
    {
        // When user record uid is not an int, cache key should use uid=0.
        // Pre-seed cache with key for uid=0 to verify the correct key is constructed.
        $backendUser = $this->createMock(BackendUserAuthentication::class);
        $backendUser->method('isAdmin')->willReturn(false);
        $backendUser->user = ['uid' => 'not-an-int'];

        $reflection = new ReflectionClass($this->service);
        $cacheProp = $reflection->getProperty('permissionCache');
        // Pre-seed result for uid=0 key
        $cacheProp->setValue($this->service, ['tx_table:field:reveal:0' => true]);

        // Should hit the cache for key 'tx_table:field:reveal:0'
        $result = $this->service->isAllowed('tx_table', 'field', VaultFieldPermission::Reveal, $backendUser);

        self::assertTrue($result);
    }

    #[Test]
    public function isReadOnlyForNonAdminReadsCachedPermission(): void
    {
        $backendUser = $this->createMockBackendUser(uid: 42, isAdmin: false);
        $cache = (new ReflectionClass($this->service))->getProperty('permissionCache');
        $cache->setValue(
            $this->service,
            ['tx_table:field:readOnly:42' => false],
        );

        self::assertFalse(
            $this->service->isReadOnly('tx_table', 'field', $backendUser),
        );
    }

    #[Test]
    public function isAllowedReturnsFalseForNonBackendUserInGlobals(): void
    {
        // GLOBALS has a non-BackendUserAuthentication object
        $GLOBALS['BE_USER'] = new stdClass();

        $result = $this->service->isAllowed('tx_table', 'field', VaultFieldPermission::Reveal);

        self::assertFalse($result);
    }

    #[Test]
    public function clearCacheEmptiesInternalCache(): void
    {
        $reflection = new ReflectionClass($this->service);
        $cacheProp = $reflection->getProperty('permissionCache');
        $cacheProp->setValue($this->service, ['tx_table:field:reveal:1' => true]);

        $this->service->clearCache();

        self::assertSame([], $cacheProp->getValue($this->service));
    }

    #[Test]
    public function isAllowedReturnsCachedValueOnSecondCallWithSameArgs(): void
    {
        $this->createMockBackendUser(uid: 7, isAdmin: true);

        // Admin bypasses cache (early return), so verify for non-admin
        $backendUser2 = $this->createMockBackendUser(uid: 99, isAdmin: false);

        $reflection = new ReflectionClass($this->service);
        $cacheProp = $reflection->getProperty('permissionCache');
        // Pre-seed cache for uid 99
        $cacheProp->setValue($this->service, ['tx_table:field:copy:99' => false]);

        $result = $this->service->isAllowed('tx_table', 'field', VaultFieldPermission::Copy, $backendUser2);

        // Should return the cached false even though built-in default for Copy is true
        self::assertFalse($result);
    }

    #[Test]
    public function getPermissionsReturnsAllFourPermissionKeysForNonAdmin(): void
    {
        $backendUser = $this->createMockBackendUser(uid: 33, isAdmin: false);

        // Pre-seed all four cache entries to avoid BackendUtility call
        $reflection = new ReflectionClass($this->service);
        $cacheProp = $reflection->getProperty('permissionCache');
        $cacheProp->setValue($this->service, [
            'tx_table:field:reveal:33' => true,
            'tx_table:field:copy:33' => true,
            'tx_table:field:edit:33' => true,
            'tx_table:field:readOnly:33' => false,
        ]);

        $permissions = $this->service->getPermissions('tx_table', 'field', $backendUser);

        self::assertCount(4, $permissions);
        self::assertTrue($permissions['reveal']);
        self::assertTrue($permissions['copy']);
        self::assertTrue($permissions['edit']);
        self::assertFalse($permissions['readOnly']);
    }

    #[Test]
    public function toBooleanHandlesIntegerOne(): void
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('toBoolean');

        self::assertTrue($method->invoke($this->service, 1));
        self::assertFalse($method->invoke($this->service, 0));
    }

    #[Test]
    public function getNestedValueReturnsNullWhenKeyMissingWithDotAndWithout(): void
    {
        $reflection = new ReflectionClass($this->service);
        $method = $reflection->getMethod('getNestedValue');

        // Neither 'missing' nor 'missing.' exists
        $result = $method->invoke($this->service, ['other' => 'value'], ['missing', 'sub']);

        self::assertNull($result);
    }
}
