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

        /** @var array<string, mixed> $data */
        $data = $this->data;
        /** @var array<string, mixed> $parameterArray */
        $parameterArray = \is_array($data['parameterArray'] ?? null) ? $data['parameterArray'] : [];
        $fieldConf = \is_array($parameterArray['fieldConf'] ?? null) ? $parameterArray['fieldConf'] : [];
        /** @var array<string, mixed> $config */
        $config = \is_array($fieldConf['config'] ?? null) ? $fieldConf['config'] : [];

        $itemNameValue = $parameterArray['itemFormElName'] ?? '';
        $itemName = \is_string($itemNameValue) ? $itemNameValue : '';

        $fieldId = StringUtility::getUniqueId('formengine-vault-');
        $sizeValue = $config['size'] ?? 30;
        $width = $this->formMaxWidth(is_numeric($sizeValue) ? (int) $sizeValue : 30);

        $tableValue = $data['tableName'] ?? '';
        $table = \is_string($tableValue) ? $tableValue : '';
        $fieldValue = $data['fieldName'] ?? '';
        $field = \is_string($fieldValue) ? $fieldValue : '';

        // Get field permissions from TSconfig
        $permissionService = GeneralUtility::makeInstance(VaultFieldPermissionService::class);
        $permissions = $permissionService->getPermissions($table, $field);

        // UUID is stored directly in the field value
        $itemFormElValue = $parameterArray['itemFormElValue'] ?? '';
        $vaultIdentifier = \is_string($itemFormElValue) ? $itemFormElValue : '';

        // Check if secret exists in vault (UUID is non-empty)
        $hasValue = false;
        if ($vaultIdentifier !== '') {
            try {
                $vaultService = GeneralUtility::makeInstance(VaultServiceInterface::class);
                // Probe for existence — throws SecretNotFoundException (or
                // AccessDeniedException) when the identifier doesn't resolve.
                $vaultService->getMetadata($vaultIdentifier);
                $hasValue = true;
            } catch (Throwable) {
                // Secret doesn't exist yet (or current user can't read it)
            }
        }

        // Determine placeholder text
        $placeholder = '';
        if ($hasValue) {
            $placeholder = $this->getLanguageService()->sL(
                'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:vault_secret.placeholder_exists',
            ) ?: '••••••••';
        } else {
            $placeholderValue = $config['placeholder'] ?? '';
            $placeholder = \is_string($placeholderValue) ? $placeholderValue : '';
        }

        // Build attributes
        $attributes = [
            'type' => 'password',
            'id' => $fieldId,
            'name' => $itemName . '[value]',
            'value' => '',
            'class' => implode(' ', [
                'form-control',
                't3js-clearable',
                'hasDefaultValue',
            ]),
            'data-formengine-validation-rules' => $this->getValidationDataAsJsonString($config),
            'data-formengine-input-name' => $itemName,
            'data-vault-identifier' => $vaultIdentifier,
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

        // Apply readOnly from TCA config or TSconfig permissions
        $readOnlyConfig = $config['readOnly'] ?? false;
        if ($readOnlyConfig || $permissions['readOnly'] || !$permissions['edit']) {
            $attributes['readonly'] = 'readonly';
        }

        if ($config['required'] ?? false) {
            $attributes['required'] = 'required';
        }

        // Build HTML
        $html = [];

        // Render field label
        $html[] = $this->renderLabel($fieldId);

        $html[] = '<div class="formengine-field-item t3js-formengine-field-item">';

        // Render field information (description/help text)
        /** @var array<string, mixed> $fieldInformationResult */
        $fieldInformationResult = $this->renderFieldInformation();
        $html[] = \is_string($fieldInformationResult['html'] ?? null) ? $fieldInformationResult['html'] : '';
        /** @var array<string, mixed> $resultArray */
        $resultArray = $this->mergeChildReturnIntoExistingResult($resultArray, $fieldInformationResult, false);

        // Render field description if present
        $fieldDescriptionValue = $fieldConf['description'] ?? '';
        $fieldDescription = \is_string($fieldDescriptionValue) ? $fieldDescriptionValue : '';
        if ($fieldDescription !== '') {
            $description = $this->getLanguageService()->sL($fieldDescription);
            if ($description !== '') {
                $html[] = '<div class="form-description">' . htmlspecialchars($description) . '</div>';
            }
        }

        $html[] = '<div class="form-wizards-wrap">';
        $html[] = '<div class="form-wizards-element">';
        $html[] = '<div class="form-control-wrap" style="max-width: ' . $width . 'px">';
        $html[] = '<div class="input-group">';
        $html[] = '<input ' . GeneralUtility::implodeAttributes($attributes, true) . ' />';

        // Toggle visibility button (only if reveal permission is granted)
        if ($permissions['reveal']) {
            $html[] = '<button type="button" class="btn btn-secondary t3js-vault-toggle-visibility" title="Toggle visibility">';
            $html[] = $this->renderIcon('actions-eye');
            $html[] = '</button>';
        }

        // Copy button (only if copy permission is granted and value exists)
        if ($permissions['copy'] && $hasValue) {
            $html[] = '<button type="button" class="btn btn-secondary t3js-vault-copy" title="Copy to clipboard">';
            $html[] = $this->renderIcon('actions-clipboard');
            $html[] = '</button>';
        }

        // Clear button if value exists and edit permission is granted
        if ($hasValue && $permissions['edit'] && !$permissions['readOnly']) {
            $html[] = '<button type="button" class="btn btn-secondary t3js-vault-clear" title="Clear secret">';
            $html[] = $this->renderIcon('actions-delete');
            $html[] = '</button>';
        }

        $html[] = '</div>'; // input-group
        $html[] = '</div>'; // form-control-wrap
        $html[] = '</div>'; // form-wizards-element

        // Render field wizards
        /** @var array<string, mixed> $fieldWizardResult */
        $fieldWizardResult = $this->renderFieldWizard();
        $html[] = \is_string($fieldWizardResult['html'] ?? null) ? $fieldWizardResult['html'] : '';
        /** @var array<string, mixed> $resultArray */
        $resultArray = $this->mergeChildReturnIntoExistingResult($resultArray, $fieldWizardResult, false);

        $html[] = '</div>'; // form-wizards-wrap
        $html[] = '</div>'; // formengine-field-item

        // Hidden field to track vault identifier
        $html[] = '<input type="hidden" name="' . htmlspecialchars($itemName) . '[_vault_identifier]" value="' . htmlspecialchars($vaultIdentifier) . '" />';

        // Hidden checksum field to detect update vs. new operations
        if ($hasValue && $vaultIdentifier !== '') {
            $html[] = '<input type="hidden" name="' . htmlspecialchars($itemName) . '[_vault_checksum]" value="' . htmlspecialchars(hash('sha256', $vaultIdentifier)) . '" />';
        }

        $resultArray['html'] = implode(self::LINE_FEED, $html);

        // Add JavaScript module
        /** @var list<JavaScriptModuleInstruction> $javaScriptModules */
        $javaScriptModules = \is_array($resultArray['javaScriptModules'] ?? null) ? $resultArray['javaScriptModules'] : [];
        $javaScriptModules[] = JavaScriptModuleInstruction::create(
            '@netresearch/nr-vault/vault-secret-element.js',
        );
        $resultArray['javaScriptModules'] = $javaScriptModules;

        return $resultArray;
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
