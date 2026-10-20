<?php

/* Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service;

use Netresearch\NrVault\Service\VaultFieldPermission;
use Netresearch\NrVault\Service\VaultFieldPermissionService;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ReflectionMethod;
use ReflectionProperty;
use stdClass;
use TYPO3\CMS\Backend\Utility\BackendUtility;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Cache\CacheManager;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Core\Information\Typo3Version;
use TYPO3\CMS\Core\TypoScript\AST\Node\NodeInterface;
use TYPO3\CMS\Core\TypoScript\PageTsConfig;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * Real optional-user wrappers and native Core UID/group/admin conditions.
 */
final class VaultSelectedUserFieldPolicyTest extends FunctionalTestCase
{
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
        '../../Tests/Functional/Fixtures/Extensions/nr_vault_permission_config',
    ];

    protected array $coreExtensionsToLoad = ['backend'];

    protected function setUp(): void
    {
        parent::setUp();
        $this->importCSVDataSet(__DIR__ . '/Fixtures/be_users_permissions.csv');
        $this
            ->getConnectionPool()
            ->getConnectionForTable('be_groups')
            ->insert('be_groups', ['uid' => 5, 'title' => 'selected-policy-group']);
        $this
            ->getConnectionPool()
            ->getConnectionForTable('be_users')
            ->update('be_users', ['usergroup' => '5'], ['uid' => 2]);
    }

    #[Test]
    #[DataProvider('opposingPolicies')]
    public function everyPublicWrapperUsesTheSuppliedUser(
        bool $selectedAllowed,
    ): void {
        $selected = $this->login(2, $this->policy($selectedAllowed));
        $ambient = $this->login(3, $this->policy(!$selectedAllowed));
        $subject = new VaultFieldPermissionService();
        self::assertNotSame($selected, $ambient);
        self::assertSame(
            !$selectedAllowed,
            $subject->isAllowed('policy', 'field', VaultFieldPermission::Reveal),
        );
        $actual = [
            'allowed' => $subject->isAllowed(
                'policy',
                'field',
                VaultFieldPermission::Reveal,
                $selected,
            ),
            'permissions' => $subject->getPermissions('policy', 'field', $selected),
            'readOnly' => $subject->isReadOnly('policy', 'field', $selected),
        ];
        self::assertSame(
            [
                'allowed' => $selectedAllowed,
                'permissions' => [
                    'reveal' => $selectedAllowed,
                    'copy' => $selectedAllowed,
                    'edit' => $selectedAllowed,
                    'readOnly' => !$selectedAllowed,
                ],
                'readOnly' => !$selectedAllowed,
            ],
            $actual,
        );
        self::assertSame($ambient, $GLOBALS['BE_USER']);
    }

    /**
     * @return iterable<string,array{bool}>
     */
    public static function opposingPolicies(): iterable
    {
        yield 'selected denies, ambient grants' => [false];
        yield 'selected grants, ambient denies' => [true];
    }

    #[Test]
    #[DataProvider('nativeConditions')]
    public function nativeConditionsUseSelectedIdentityWithoutChangingAmbientState(
        string $table,
        int $ambientUid,
        bool $selectedExpected,
        bool $ambientExpected,
    ): void {
        $selected = $this->login(2, 'page.selected_only = selected');
        $ambient = $this->login($ambientUid, 'page.ambient_only = ambient');
        $context = GeneralUtility::makeInstance(Context::class);
        $ambientAspect = $context->getAspect('backend.user');
        $workspace = $context->getAspect('workspace');
        $ambientConfig = BackendUtility::getPagesTSconfig(0);
        self::assertSame(
            $ambientExpected ? '1' : '0',
            $this->policyValue($ambientConfig, $table),
        );
        $runtime = GeneralUtility::makeInstance(CacheManager::class)->getCache('runtime');
        $hash = $runtime->get('pageTsConfig-pid-to-hash-0');
        self::assertIsString($hash);
        $cached = $runtime->get('pageTsConfig-hash-to-object-' . $hash);
        /** @phpstan-ignore classConstant.internalClass */
        self::assertInstanceOf(PageTsConfig::class, $cached);
        $subject = new VaultFieldPermissionService();
        self::assertSame(
            $selectedExpected,
            $subject->isAllowed(
                $table,
                'field',
                VaultFieldPermission::Reveal,
                $selected,
            ),
            'The selected user supplies backend.user condition identity.',
        );
        self::assertFalse(
            $subject->isAllowed(
                'extension_default',
                'field',
                VaultFieldPermission::Reveal,
                $selected,
            ),
        );
        self::assertSame(
            $ambientExpected,
            $subject->isAllowed($table, 'field', VaultFieldPermission::Reveal),
        );
        $subject->clearCache();
        self::assertSame(
            $selectedExpected,
            $subject->isAllowed(
                $table,
                'field',
                VaultFieldPermission::Reveal,
                $selected,
            ),
        );
        self::assertSame($ambient, $GLOBALS['BE_USER']);
        self::assertSame($context, GeneralUtility::makeInstance(Context::class));
        self::assertSame($ambientAspect, $context->getAspect('backend.user'));
        self::assertSame($workspace, $context->getAspect('workspace'));
        self::assertSame($hash, $runtime->get('pageTsConfig-pid-to-hash-0'));
        self::assertSame(
            $cached,
            $runtime->get('pageTsConfig-hash-to-object-' . $hash),
        );
        self::assertSame($ambientConfig, BackendUtility::getPagesTSconfig(0));
    }

    /**
     * @return iterable<string,array{string,int,bool,bool}>
     */
    public static function nativeConditions(): iterable
    {
        yield 'UID2 versus UID3' => ['uid_condition', 3, true, false];
        yield 'group5 versus no group' => ['group_condition', 3, true, false];
        yield 'editor versus admin' => ['admin_condition', 1, false, true];
    }

    #[Test]
    public function selectedUserWithoutGlobalAccountRetainsNativeDefaultsAndAmbientContext(): void
    {
        $selected = $this->login(2, 'page.selected_only = selected');
        $ambient = $this->login(3, 'page.ambient_only = ambient');
        $context = GeneralUtility::makeInstance(Context::class);
        $aspect = $context->getAspect('backend.user');
        $runtime = GeneralUtility::makeInstance(CacheManager::class)->getCache('runtime');
        $marker = new stdClass();
        $runtime->set('selected-field-policy-marker', $marker);
        /** @var array{BE: array<string, mixed>} $configuration */
        $configuration = &$GLOBALS['TYPO3_CONF_VARS'];
        $oldDefault = $configuration['BE']['defaultPageTSconfig'] ?? null;
        $configuration['BE']['defaultPageTSconfig'] = 'global_default = legacy13';
        unset($GLOBALS['BE_USER']);

        try {
            $subject = new VaultFieldPermissionService();
            self::assertTrue(
                $subject->isAllowed(
                    'uid_condition',
                    'field',
                    VaultFieldPermission::Reveal,
                    $selected,
                ),
            );
            self::assertTrue(
                $subject->isAllowed(
                    'group_condition',
                    'field',
                    VaultFieldPermission::Reveal,
                    $selected,
                ),
            );
            self::assertFalse(
                $subject->isAllowed(
                    'extension_default',
                    'field',
                    VaultFieldPermission::Reveal,
                    $selected,
                ),
            );
            self::assertFalse(
                $subject->isAllowed(
                    'uid_condition',
                    'field',
                    VaultFieldPermission::Reveal,
                ),
            );
            $config = $this->snapshot($this->selectedConfig($subject, $selected))['array'];
            self::assertSame('selected', $config['selected_only'] ?? null);
            self::assertArrayNotHasKey('ambient_only', $config);
            if ((new Typo3Version())->getMajorVersion() === 13) {
                self::assertSame('legacy13', $config['global_default']);
            } else {
                self::assertArrayNotHasKey('global_default', $config);
            }

            self::assertArrayNotHasKey('BE_USER', $GLOBALS);
            self::assertSame($aspect, $context->getAspect('backend.user'));
            self::assertSame(
                3,
                $context->getPropertyFromAspect('backend.user', 'id'),
            );
            self::assertSame(
                $marker,
                $runtime->get('selected-field-policy-marker'),
            );
            self::assertFalse($runtime->get('pageTsConfig-pid-to-hash-0'));
        } finally {
            $GLOBALS['BE_USER'] = $ambient;
            if ($oldDefault === null) {
                unset($configuration['BE']['defaultPageTSconfig']);
            } else {
                $configuration['BE']['defaultPageTSconfig'] = $oldDefault;
            }
        }
    }

    #[Test]
    public function realSelectedPermissionEntriesStaySeparateAndInvalidateOnlyWhenCleared(): void
    {
        $allowed = $this->login(2, $this->policy(true));
        $denied = $this->login(3, $this->policy(false));
        $subject = new VaultFieldPermissionService();
        self::assertTrue(
            $subject->isAllowed(
                'policy',
                'field',
                VaultFieldPermission::Reveal,
                $allowed,
            ),
        );
        self::assertFalse(
            $subject->isAllowed(
                'policy',
                'field',
                VaultFieldPermission::Reveal,
                $denied,
            ),
        );
        $changed = $this->login(2, $this->policy(false));
        $ambient = $this->login(3, $this->policy(true));
        self::assertNotSame($allowed, $changed);
        self::assertTrue(
            $subject->isAllowed(
                'policy',
                'field',
                VaultFieldPermission::Reveal,
                $changed,
            ),
        );
        self::assertFalse(
            $subject->isAllowed(
                'policy',
                'field',
                VaultFieldPermission::Reveal,
                $ambient,
            ),
        );
        $subject->clearCache();
        self::assertFalse(
            $subject->isAllowed(
                'policy',
                'field',
                VaultFieldPermission::Reveal,
                $changed,
            ),
        );
        self::assertTrue(
            $subject->isAllowed(
                'policy',
                'field',
                VaultFieldPermission::Reveal,
                $ambient,
            ),
        );
        self::assertSame($ambient, $GLOBALS['BE_USER']);
    }

    #[Test]
    #[DataProvider('nativeConditions')]
    public function productionCoordinatorKeepsEarlierAstAndVerdictsIndependent(
        string $table,
        int $ambientUid,
        bool $selectedExpected,
        bool $ambientExpected,
    ): void {
        $selected = $this->login(2, 'page.selected_only = selected');
        $ambient = $this->login($ambientUid, 'page.ambient_only = ambient');
        $subject = new VaultFieldPermissionService();
        $first = $this->selectedConfig($subject, $selected);
        $firstSnapshot = $this->snapshot($first);
        $middle = $this->selectedConfig($subject, $ambient);
        $last = $this->selectedConfig($subject, $selected);
        $middleSnapshot = $this->snapshot($middle);
        $lastSnapshot = $this->snapshot($last);
        self::assertSame(
            $selectedExpected ? '1' : '0',
            $this->policyValue($firstSnapshot['array'], $table),
        );
        self::assertSame(
            $ambientExpected ? '1' : '0',
            $this->policyValue($middleSnapshot['array'], $table),
        );
        self::assertSame('selected', $firstSnapshot['array']['selected_only'] ?? null);
        self::assertArrayNotHasKey('ambient_only', $firstSnapshot['array']);
        self::assertSame('ambient', $middleSnapshot['array']['ambient_only']);
        self::assertArrayNotHasKey('selected_only', $middleSnapshot['array']);
        self::assertSame($firstSnapshot['array'], $lastSnapshot['array']);
        self::assertSame($firstSnapshot, $this->snapshot($first));
        self::assertSame($firstSnapshot['verdicts'], $lastSnapshot['verdicts']);
        self::assertNotSame(
            $firstSnapshot['verdicts'],
            $middleSnapshot['verdicts'],
        );
        self::assertNotSame($firstSnapshot['ast'], $middleSnapshot['ast']);
        self::assertNotSame($firstSnapshot['ast'], $lastSnapshot['ast']);
        self::assertSame(
            [],
            array_intersect($firstSnapshot['ids'], $middleSnapshot['ids']),
        );
        self::assertSame(
            [],
            array_intersect($firstSnapshot['ids'], $lastSnapshot['ids']),
        );
        self::assertSame($ambient, $GLOBALS['BE_USER']);
    }

    #[Test]
    public function selectedUserWithoutMaterializedUserTsConfigKeepsNativeDefaults(): void
    {
        $selected = $this->login(
            2,
            'page.vault.permissions.extension_default.field.reveal = 1',
        );
        $ambient = $this->login(3, 'page.ambient_only = ambient');
        (new ReflectionProperty(
            BackendUserAuthentication::class,
            'userTsConfig',
        ))->setValue($selected, null);
        /** @phpstan-ignore method.internal */
        self::assertNull($selected->getUserTsConfig());
        $subject = new VaultFieldPermissionService();
        self::assertTrue(
            $subject->isAllowed(
                'uid_condition',
                'field',
                VaultFieldPermission::Reveal,
                $selected,
            ),
        );
        self::assertFalse(
            $subject->isAllowed(
                'extension_default',
                'field',
                VaultFieldPermission::Reveal,
                $selected,
            ),
        );
        self::assertSame($ambient, $GLOBALS['BE_USER']);
    }

    private function login(int $uid, string $config): BackendUserAuthentication
    {
        $this
            ->getConnectionPool()
            ->getConnectionForTable('be_users')
            ->update('be_users', ['TSconfig' => $config], ['uid' => $uid]);
        GeneralUtility::makeInstance(CacheManager::class)
            ->getCache('runtime')
            ->flush();
        $this->setUpBackendUser($uid);
        $user = $GLOBALS['BE_USER'];
        self::assertInstanceOf(BackendUserAuthentication::class, $user);

        return $user;
    }

    private function policy(bool $allowed): string
    {
        $value = $allowed ? '1' : '0';
        $readOnly = $allowed ? '0' : '1';

        return "page.vault.permissions.default.reveal = {$value}\npage.vault.permissions.default.copy = {$value}\npage.vault.permissions.default.edit = {$value}\npage.vault.permissions.default.readOnly = {$readOnly}";
    }

    /**
     * The exact native type is checked below before this private test helper returns.
     */
    private function selectedConfig(
        VaultFieldPermissionService $subject,
        BackendUserAuthentication $user,
    ): PageTsConfig {
        // Observe the private coordinator's native result without adding a public seam.
        $result = (new ReflectionMethod($subject, 'getSelectedUserPageTsConfig'))->invoke(
            $subject,
            $user,
        );
        /** @phpstan-ignore classConstant.internalClass */
        self::assertInstanceOf(PageTsConfig::class, $result);

        return $result;
    }

    /**
     * Inspect physical native AST ownership without adding a public seam.
     *
     * @return list<int>
     *
     * @phpstan-ignore parameter.internalInterface
     */
    private function astIds(NodeInterface $node): array
    {
        $ids = [spl_object_id($node)];
        /** @phpstan-ignore method.internalInterface */
        foreach ($node->getNextChild() as $child) {
            $ids = [...$ids, ...$this->astIds($child)];
        }

        return $ids;
    }

    /**
     * Observe native Core state for the ADR049 independence oracle.
     *
     * @return array{array: array<array-key, mixed>, ast: NodeInterface, treeArray: array<string, mixed>, ids: list<int>, verdicts: array<mixed>}
     *
     * @phpstan-ignore parameter.internalClass, return.internalInterface
     */
    private function snapshot(PageTsConfig $config): array
    {
        /** @phpstan-ignore method.internalClass */
        $ast = $config->getPageTsConfigTree();

        return [
            /** @phpstan-ignore method.internalClass */
            'array' => $config->getPageTsConfigArray(),
            'ast' => $ast,
            /** @phpstan-ignore method.internalClass */
            'treeArray' => $ast->toArray(),
            'ids' => $this->astIds($ast),
            /** @phpstan-ignore method.internalClass */
            'verdicts' => $config->getConditionListWithVerdicts(),
        ];
    }

    /**
     * @param array<array-key, mixed> $config
     */
    private function policyValue(array $config, string $table): mixed
    {
        $vault = $config['vault.'];
        self::assertIsArray($vault);
        $permissions = $vault['permissions.'];
        self::assertIsArray($permissions);
        $tablePolicy = $permissions[$table . '.'];
        self::assertIsArray($tablePolicy);
        $field = $tablePolicy['field.'];
        self::assertIsArray($field);

        return $field['reveal'];
    }
}
