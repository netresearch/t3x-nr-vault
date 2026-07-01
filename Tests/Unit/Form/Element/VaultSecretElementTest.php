<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Form\Element;

use Netresearch\NrVault\Domain\Dto\SecretDetails;
use Netresearch\NrVault\Form\Element\VaultSecretElement;
use Netresearch\NrVault\Service\VaultFieldPermissionService;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use RuntimeException;
use TYPO3\CMS\Backend\Form\NodeFactory;
use TYPO3\CMS\Backend\Form\NodeInterface;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Cache\Frontend\FrontendInterface;
use TYPO3\CMS\Core\Imaging\Icon;
use TYPO3\CMS\Core\Imaging\IconFactory;
use TYPO3\CMS\Core\Imaging\IconRegistry;
use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Utility\GeneralUtility;

#[CoversClass(VaultSecretElement::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultSecretElementTest extends TestCase
{
    private const FIELD_LABEL = 'API Key';

    private const FIELD_DESCRIPTION = 'My field description';

    private const VAULT_IDENTIFIER = '01937b6e-4b6c-7abc-8def-0123456789ab';

    private const ITEM_FORM_EL_NAME = 'data[tx_test][1][api_key]';

    protected bool $resetSingletonInstances = true;

    private VaultSecretElement $subject;

    private VaultServiceInterface&MockObject $vaultService;

    private LanguageService&MockObject $languageService;

    private BackendUserAuthentication&MockObject $backendUser;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);

        $this->languageService = $this->createMock(LanguageService::class);
        $this->languageService->method('sL')->willReturnCallback(
            static fn (string $key): string => str_contains($key, 'LLL:') ? '' : $key,
        );

        $this->backendUser = $this->createMock(BackendUserAuthentication::class);
        $this->backendUser->method('shallDisplayDebugInformation')->willReturn(false);
        // Make the user an admin so VaultFieldPermissionService returns predictable values
        $this->backendUser->method('isAdmin')->willReturn(true);

        $GLOBALS['LANG'] = $this->languageService;
        $GLOBALS['BE_USER'] = $this->backendUser;

        // VaultFieldPermissionService is final, so we use a real instance
        // (admin user gives: reveal=true, copy=true, edit=true, readOnly=false)
        $permissionService = new VaultFieldPermissionService();

        // Build a real IconFactory with mocked dependencies
        $icon = $this->createMock(Icon::class);
        $icon->method('render')->willReturn('<span class="icon"></span>');

        $runtimeCache = $this->createMock(FrontendInterface::class);
        $runtimeCache->method('get')->willReturn($icon);

        $iconFactory = new IconFactory(
            $this->createMock(EventDispatcherInterface::class),
            $this->createMock(IconRegistry::class),
            $this->createMock(ContainerInterface::class),
            $runtimeCache,
        );

        $this->subject = new VaultSecretElement($iconFactory, $permissionService, $this->vaultService);

        // Set up NodeFactory mock for renderFieldInformation/renderFieldWizard
        $nodeFactory = $this->createMock(NodeFactory::class);
        $emptyNode = $this->createMock(NodeInterface::class);
        $emptyNode->method('render')->willReturn([
            'additionalHiddenFields' => [],
            'additionalInlineLanguageLabelFiles' => [],
            'stylesheetFiles' => [],
            'javaScriptModules' => [],
            'inlineData' => [],
            'html' => '',
        ]);
        $nodeFactory->method('create')->willReturn($emptyNode);
        $this->subject->injectNodeFactory($nodeFactory);
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['LANG'], $GLOBALS['BE_USER']);
        GeneralUtility::purgeInstances();
        parent::tearDown();
    }

    #[Test]
    public function renderOutputContainsPasswordInputWithArrayName(): void
    {
        $this->setUpData();

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        // Input name should use [value] suffix to avoid PHP form parsing conflict
        self::assertStringContainsString('name="data[tx_test][1][api_key][value]"', $result['html']);
    }

    #[Test]
    public function renderOutputContainsVaultIdentifierHiddenField(): void
    {
        $this->setUpData();

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        self::assertStringContainsString('name="data[tx_test][1][api_key][_vault_identifier]"', $result['html']);
    }

    #[Test]
    public function renderOutputContainsLabel(): void
    {
        $this->setUpData();

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        self::assertStringContainsString('<label for="', $result['html']);
        self::assertStringContainsString('form-label', $result['html']);
    }

    #[Test]
    public function renderOutputContainsDescriptionExactlyOnce(): void
    {
        // On TYPO3 v14 AbstractFormElement::renderLabel() emits the TCA
        // `description` (via renderDescription()); the element must NOT render a
        // second copy, or it appears twice. On v13 renderLabel() emits nothing,
        // so the element renders it itself. Either way the description must
        // appear exactly once — this is the discriminator the CI matrix
        // (^13.4 + ^14.3) exercises.
        $langService = $this->createMock(LanguageService::class);
        $langService->method('sL')->willReturnCallback(
            static fn (string $key): string => $key === self::FIELD_DESCRIPTION ? self::FIELD_DESCRIPTION : '',
        );
        $GLOBALS['LANG'] = $langService;

        $this->setUpData([
            'fieldConf' => [
                'label' => self::FIELD_LABEL,
                'description' => self::FIELD_DESCRIPTION,
                'config' => [
                    'type' => 'input',
                    'renderType' => 'vaultSecret',
                    'size' => 30,
                ],
            ],
        ]);

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        self::assertStringContainsString(self::FIELD_DESCRIPTION, $result['html']);
        // Exactly one description block — not the pre-fix duplicate.
        self::assertSame(1, substr_count($result['html'], 'form-description'));
    }

    #[Test]
    public function renderOutputOmitsDescriptionWhenNotPresent(): void
    {
        $this->setUpData();

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        self::assertStringNotContainsString('form-description', $result['html']);
    }

    #[Test]
    public function renderOutputContainsChecksumForExistingSecret(): void
    {
        $this->setUpExistingSecretData();

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        self::assertStringContainsString('_vault_checksum', $result['html']);
        $expectedChecksum = hash('sha256', self::VAULT_IDENTIFIER);
        self::assertStringContainsString($expectedChecksum, $result['html']);
    }

    #[Test]
    public function renderOutputOmitsChecksumForNewSecret(): void
    {
        $this->setUpData();

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        self::assertStringNotContainsString('_vault_checksum', $result['html']);
    }

    #[Test]
    public function renderOutputContainsToggleVisibilityButton(): void
    {
        $this->setUpData();

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        // Admin user has reveal permission
        self::assertStringContainsString('t3js-vault-toggle-visibility', $result['html']);
    }

    #[Test]
    public function renderOutputContainsCopyButtonForExistingSecret(): void
    {
        $this->setUpExistingSecretData();

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        self::assertStringContainsString('t3js-vault-copy', $result['html']);
    }

    #[Test]
    public function renderOutputOmitsCopyButtonForNewSecret(): void
    {
        $this->setUpData();

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        self::assertStringNotContainsString('t3js-vault-copy', $result['html']);
    }

    #[Test]
    public function renderOutputContainsClearButtonForExistingSecret(): void
    {
        $this->setUpExistingSecretData();

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        self::assertStringContainsString('t3js-vault-clear', $result['html']);
    }

    #[Test]
    public function renderOutputIncludesJavaScriptModule(): void
    {
        $this->setUpData();

        $result = $this->subject->render();

        self::assertIsArray($result['javaScriptModules']);
        self::assertNotEmpty($result['javaScriptModules']);
    }

    #[Test]
    public function renderOutputContainsMaxlengthWhenConfigured(): void
    {
        $this->setUpData([
            'fieldConf' => [
                'label' => self::FIELD_LABEL,
                'config' => [
                    'type' => 'input',
                    'renderType' => 'vaultSecret',
                    'size' => 30,
                    'max' => 128,
                ],
            ],
        ]);

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        self::assertStringContainsString('maxlength="128"', $result['html']);
    }

    #[Test]
    public function renderOutputContainsRequiredAttributeWhenConfigured(): void
    {
        $this->setUpData([
            'fieldConf' => [
                'label' => self::FIELD_LABEL,
                'config' => [
                    'type' => 'input',
                    'renderType' => 'vaultSecret',
                    'size' => 30,
                    'required' => true,
                ],
            ],
        ]);

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        self::assertStringContainsString('required="required"', $result['html']);
    }

    #[Test]
    public function renderOutputContainsPasswordManagerIgnoreAttributes(): void
    {
        $this->setUpData();

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        self::assertStringContainsString('data-1p-ignore', $result['html']);
        self::assertStringContainsString('data-lpignore', $result['html']);
        self::assertStringContainsString('data-bwignore', $result['html']);
    }

    #[Test]
    public function renderOutputContainsPlaceholderForExistingSecret(): void
    {
        $this->setUpExistingSecretData();

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        // Should contain a placeholder (either translated or fallback)
        self::assertStringContainsString('placeholder=', $result['html']);
    }

    #[Test]
    public function renderOutputContainsFormEngineFieldItemWrapper(): void
    {
        $this->setUpData();

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        self::assertStringContainsString('formengine-field-item', $result['html']);
        self::assertStringContainsString('t3js-formengine-field-item', $result['html']);
    }

    #[Test]
    public function renderOutputHandlesVaultServiceExceptionGracefully(): void
    {
        $vaultIdentifier = self::VAULT_IDENTIFIER;

        $this->vaultService
            ->method('getMetadata')
            ->willThrowException(new RuntimeException('Secret not found'));

        GeneralUtility::addInstance(VaultServiceInterface::class, $this->vaultService);

        $this->subject->setData([
            'tableName' => 'tx_test',
            'fieldName' => 'api_key',
            'parameterArray' => [
                'itemFormElName' => self::ITEM_FORM_EL_NAME,
                'itemFormElValue' => $vaultIdentifier,
                'fieldConf' => [
                    'label' => self::FIELD_LABEL,
                    'config' => [
                        'type' => 'input',
                        'renderType' => 'vaultSecret',
                        'size' => 30,
                    ],
                ],
            ],
        ]);

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        // Should not contain checksum (no valid secret)
        self::assertStringNotContainsString('_vault_checksum', $result['html']);
        // Should not contain copy button (no valid secret)
        self::assertStringNotContainsString('t3js-vault-copy', $result['html']);
    }

    #[Test]
    public function renderOutputSetsReadonlyWhenConfigReadOnlyIsTrue(): void
    {
        $this->setUpData([
            'fieldConf' => [
                'label' => self::FIELD_LABEL,
                'config' => [
                    'type' => 'input',
                    'renderType' => 'vaultSecret',
                    'size' => 30,
                    'readOnly' => true,
                ],
            ],
        ]);

        $result = $this->subject->render();

        self::assertIsString($result['html']);
        self::assertStringContainsString('readonly="readonly"', $result['html']);
    }

    /**
     * @param array<string, mixed> $parameterArrayOverrides
     */
    private function setUpData(array $parameterArrayOverrides = []): void
    {
        $defaultParameterArray = [
            'itemFormElName' => self::ITEM_FORM_EL_NAME,
            'itemFormElValue' => '',
            'fieldConf' => [
                'label' => self::FIELD_LABEL,
                'config' => [
                    'type' => 'input',
                    'renderType' => 'vaultSecret',
                    'size' => 30,
                ],
            ],
        ];

        $parameterArray = array_replace_recursive($defaultParameterArray, $parameterArrayOverrides);

        $this->subject->setData([
            'tableName' => 'tx_test',
            'fieldName' => 'api_key',
            'parameterArray' => $parameterArray,
        ]);
    }

    private function setUpExistingSecretData(): void
    {
        $vaultIdentifier = self::VAULT_IDENTIFIER;

        $metadata = $this->createMock(SecretDetails::class);
        $this->vaultService
            ->method('getMetadata')
            ->with($vaultIdentifier)
            ->willReturn($metadata);

        // Re-register vault service since addInstance is consumed per call
        GeneralUtility::addInstance(VaultServiceInterface::class, $this->vaultService);

        $this->subject->setData([
            'tableName' => 'tx_test',
            'fieldName' => 'api_key',
            'parameterArray' => [
                'itemFormElName' => self::ITEM_FORM_EL_NAME,
                'itemFormElValue' => $vaultIdentifier,
                'fieldConf' => [
                    'label' => self::FIELD_LABEL,
                    'config' => [
                        'type' => 'input',
                        'renderType' => 'vaultSecret',
                        'size' => 30,
                    ],
                ],
            ],
        ]);
    }
}
