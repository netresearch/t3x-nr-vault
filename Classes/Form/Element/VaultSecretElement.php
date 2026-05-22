<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Form\Element;

use Netresearch\NrVault\Service\VaultFieldPermissionService;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Throwable;
use TYPO3\CMS\Backend\Form\Element\AbstractFormElement;
use TYPO3\CMS\Core\Imaging\IconFactory;
use TYPO3\CMS\Core\Imaging\IconSize;
use TYPO3\CMS\Core\Page\JavaScriptModuleInstruction;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Utility\StringUtility;

/**
 * TCA form element for vault secrets.
 *
 * Renders a password field that stores values in the vault
 * instead of directly in the database.
 */
final class VaultSecretElement extends AbstractFormElement
{
    private const LINE_FEED = "\n";

    public function __construct(private readonly IconFactory $iconFactory) {}

    /**
     * @return array<string, mixed>
     */
    public function render(): array
    {
        /** @var array<string, mixed> $resultArray */
        $resultArray = $this->initializeResultArray();

        $context = $this->extractRenderContext();
        $hasValue = $this->probeHasValue($context['vaultIdentifier']);
        $placeholder = $this->resolvePlaceholder($hasValue, $context['config']);
        $attributes = $this->buildInputAttributes($context, $hasValue, $placeholder);

        $html = [];
        $html[] = $this->renderLabel($context['fieldId']);
        $html[] = '<div class="formengine-field-item t3js-formengine-field-item">';

        /** @var array<string, mixed> $fieldInformationResult */
        $fieldInformationResult = $this->renderFieldInformation();
        $html[] = \is_string($fieldInformationResult['html'] ?? null) ? $fieldInformationResult['html'] : '';
        /** @var array<string, mixed> $resultArray */
        $resultArray = $this->mergeChildReturnIntoExistingResult($resultArray, $fieldInformationResult, false);

        $descriptionHtml = $this->renderVaultDescription($context['fieldConf']);
        if ($descriptionHtml !== '') {
            $html[] = $descriptionHtml;
        }

        $html[] = '<div class="form-wizards-wrap">';
        $html[] = '<div class="form-wizards-element">';
        $html[] = '<div class="form-control-wrap" style="max-width: ' . $context['width'] . 'px">';
        $html[] = $this->renderInputGroup($attributes, $context['permissions'], $hasValue);
        $html[] = '</div>'; // form-control-wrap
        $html[] = '</div>'; // form-wizards-element

        /** @var array<string, mixed> $fieldWizardResult */
        $fieldWizardResult = $this->renderFieldWizard();
        $html[] = \is_string($fieldWizardResult['html'] ?? null) ? $fieldWizardResult['html'] : '';
        /** @var array<string, mixed> $resultArray */
        $resultArray = $this->mergeChildReturnIntoExistingResult($resultArray, $fieldWizardResult, false);

        $html[] = '</div>'; // form-wizards-wrap
        $html[] = '</div>'; // formengine-field-item
        $html[] = $this->renderHiddenFields($context['itemName'], $context['vaultIdentifier'], $hasValue);

        $resultArray['html'] = implode(self::LINE_FEED, $html);
        $resultArray['javaScriptModules'] = $this->appendJsModule($resultArray);

        return $resultArray;
    }

    /**
     * Unpack the FormEngine `$data` shape into a typed bundle so render()
     * doesn't drown in `\is_array(...) ? ... : []` guards.
     *
     * @return array{
     *     itemName: string,
     *     fieldId: string,
     *     width: int,
     *     vaultIdentifier: string,
     *     config: array<string, mixed>,
     *     fieldConf: array<string, mixed>,
     *     permissions: array<string, bool>,
     * }
     */
    private function extractRenderContext(): array
    {
        /** @var array<string, mixed> $data */
        $data = $this->data;
        /** @var array<string, mixed> $parameterArray */
        $parameterArray = \is_array($data['parameterArray'] ?? null) ? $data['parameterArray'] : [];
        /** @var array<string, mixed> $fieldConf */
        $fieldConf = \is_array($parameterArray['fieldConf'] ?? null) ? $parameterArray['fieldConf'] : [];
        /** @var array<string, mixed> $config */
        $config = \is_array($fieldConf['config'] ?? null) ? $fieldConf['config'] : [];

        $itemNameValue = $parameterArray['itemFormElName'] ?? '';
        $itemName = \is_string($itemNameValue) ? $itemNameValue : '';

        $sizeValue = $config['size'] ?? 30;
        $width = $this->formMaxWidth(is_numeric($sizeValue) ? (int) $sizeValue : 30);

        $tableValue = $data['tableName'] ?? '';
        $table = \is_string($tableValue) ? $tableValue : '';
        $fieldValue = $data['fieldName'] ?? '';
        $field = \is_string($fieldValue) ? $fieldValue : '';

        $permissionService = GeneralUtility::makeInstance(VaultFieldPermissionService::class);

        $itemFormElValue = $parameterArray['itemFormElValue'] ?? '';
        $vaultIdentifier = \is_string($itemFormElValue) ? $itemFormElValue : '';

        return [
            'itemName' => $itemName,
            'fieldId' => StringUtility::getUniqueId('formengine-vault-'),
            'width' => $width,
            'vaultIdentifier' => $vaultIdentifier,
            'config' => $config,
            'fieldConf' => $fieldConf,
            'permissions' => $permissionService->getPermissions($table, $field),
        ];
    }

    /**
     * Decide whether the vault has a value the user is allowed to see.
     * \getMetadata() throws SecretNotFoundException when the identifier
     * doesn't exist and AccessDeniedException when it exists but the
     * current user lacks read permission — both render as "no value".
     */
    private function probeHasValue(string $vaultIdentifier): bool
    {
        if ($vaultIdentifier === '') {
            return false;
        }

        try {
            $vaultService = GeneralUtility::makeInstance(VaultServiceInterface::class);
            $vaultService->getMetadata($vaultIdentifier);

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * "Has value" → bullets; otherwise → TCA-configured placeholder.
     *
     * @param array<string, mixed> $config
     */
    private function resolvePlaceholder(bool $hasValue, array $config): string
    {
        if ($hasValue) {
            return $this->getLanguageService()->sL(
                'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:vault_secret.placeholder_exists',
            ) ?: '••••••••';
        }

        $placeholderValue = $config['placeholder'] ?? '';

        return \is_string($placeholderValue) ? $placeholderValue : '';
    }

    /**
     * Build the `<input>` attribute array — password-manager opt-out flags,
     * data-* probes for the JS module, readonly/required toggles.
     *
     * @param array{
     *     itemName: string,
     *     fieldId: string,
     *     width: int,
     *     vaultIdentifier: string,
     *     config: array<string, mixed>,
     *     fieldConf: array<string, mixed>,
     *     permissions: array<string, bool>,
     * } $context
     *
     * @return array<string, string>
     */
    private function buildInputAttributes(array $context, bool $hasValue, string $placeholder): array
    {
        $config = $context['config'];
        $permissions = $context['permissions'];

        $attributes = [
            'type' => 'password',
            'id' => $context['fieldId'],
            'name' => $context['itemName'] . '[value]',
            'value' => '',
            'class' => implode(' ', ['form-control', 't3js-clearable', 'hasDefaultValue']),
            'data-formengine-validation-rules' => $this->getValidationDataAsJsonString($config),
            'data-formengine-input-name' => $context['itemName'],
            'data-vault-identifier' => $context['vaultIdentifier'],
            'data-vault-has-value' => $hasValue ? '1' : '0',
            'data-vault-can-reveal' => $permissions['reveal'] ? '1' : '0',
            'data-vault-can-copy' => $permissions['copy'] ? '1' : '0',
            'data-vault-can-edit' => $permissions['edit'] ? '1' : '0',
            'autocomplete' => 'off',
            'data-form-type' => 'other',
            'data-1p-ignore' => 'true',
            'data-lpignore' => 'true',
            'data-bwignore' => 'true',
            'data-protonpass-ignore' => 'true',
            'data-dashlane-ignore' => 'true',
        ];

        if ($placeholder !== '') {
            $attributes['placeholder'] = $placeholder;
        }

        $maxValue = $config['max'] ?? 0;
        if (is_numeric($maxValue) && (int) $maxValue > 0) {
            $attributes['maxlength'] = (string) (int) $maxValue;
        }

        $readOnlyConfig = $config['readOnly'] ?? false;
        if ($readOnlyConfig || $permissions['readOnly'] || !$permissions['edit']) {
            $attributes['readonly'] = 'readonly';
        }

        if ($config['required'] ?? false) {
            $attributes['required'] = 'required';
        }

        return $attributes;
    }

    /**
     * Optional field description from TCA — empty string if none.
     *
     * @param array<string, mixed> $fieldConf
     */
    private function renderVaultDescription(array $fieldConf): string
    {
        $fieldDescriptionValue = $fieldConf['description'] ?? '';
        if (!\is_string($fieldDescriptionValue) || $fieldDescriptionValue === '') {
            return '';
        }

        $description = $this->getLanguageService()->sL($fieldDescriptionValue);
        if ($description === '') {
            return '';
        }

        return '<div class="form-description">' . htmlspecialchars($description) . '</div>';
    }

    /**
     * Render the `<input>` + per-permission action buttons (reveal / copy /
     * clear) wrapped in `<div class="input-group">`.
     *
     * @param array<string, string> $attributes
     * @param array<string, bool> $permissions
     */
    private function renderInputGroup(array $attributes, array $permissions, bool $hasValue): string
    {
        $parts = ['<div class="input-group">'];
        $parts[] = '<input ' . GeneralUtility::implodeAttributes($attributes, true) . ' />';

        if ($permissions['reveal']) {
            $parts[] = '<button type="button" class="btn btn-secondary t3js-vault-toggle-visibility" title="Toggle visibility">';
            $parts[] = $this->renderIcon('actions-eye');
            $parts[] = '</button>';
        }

        if ($permissions['copy'] && $hasValue) {
            $parts[] = '<button type="button" class="btn btn-secondary t3js-vault-copy" title="Copy to clipboard">';
            $parts[] = $this->renderIcon('actions-clipboard');
            $parts[] = '</button>';
        }

        if ($hasValue && $permissions['edit'] && !$permissions['readOnly']) {
            $parts[] = '<button type="button" class="btn btn-secondary t3js-vault-clear" title="Clear secret">';
            $parts[] = $this->renderIcon('actions-delete');
            $parts[] = '</button>';
        }

        $parts[] = '</div>'; // input-group

        return implode(self::LINE_FEED, $parts);
    }

    /**
     * Hidden identifier + change-detection checksum. The checksum lets the
     * DataHandler hook tell "user typed a new value" from "user didn't
     * touch the field" without ever having the plaintext in the form.
     */
    private function renderHiddenFields(string $itemName, string $vaultIdentifier, bool $hasValue): string
    {
        $parts = [];
        $parts[] = '<input type="hidden" name="' . htmlspecialchars($itemName) . '[_vault_identifier]" value="' . htmlspecialchars($vaultIdentifier) . '" />';

        if ($hasValue && $vaultIdentifier !== '') {
            $parts[] = '<input type="hidden" name="' . htmlspecialchars($itemName) . '[_vault_checksum]" value="' . htmlspecialchars(hash('sha256', $vaultIdentifier)) . '" />';
        }

        return implode(self::LINE_FEED, $parts);
    }

    /**
     * Append the JS module to FormEngine's javaScriptModules array.
     *
     * @param array<string, mixed> $resultArray
     *
     * @return list<JavaScriptModuleInstruction>
     */
    private function appendJsModule(array $resultArray): array
    {
        /** @var list<JavaScriptModuleInstruction> $javaScriptModules */
        $javaScriptModules = \is_array($resultArray['javaScriptModules'] ?? null) ? $resultArray['javaScriptModules'] : [];
        $javaScriptModules[] = JavaScriptModuleInstruction::create(
            '@netresearch/nr-vault/vault-secret-element.js',
        );

        return $javaScriptModules;
    }

    /**
     * Render an icon using TYPO3's IconFactory.
     */
    private function renderIcon(string $identifier): string
    {
        $iconFactory = $this->iconFactory;

        return $iconFactory->getIcon($identifier, IconSize::SMALL)->render();
    }
}
