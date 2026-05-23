<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Form\Element;

use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Utility\LocalisationHelper;
use Throwable;
use TYPO3\CMS\Backend\Form\Element\AbstractFormElement;
use TYPO3\CMS\Core\Imaging\IconFactory;
use TYPO3\CMS\Core\Imaging\IconSize;
use TYPO3\CMS\Core\Page\JavaScriptModuleInstruction;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Utility\StringUtility;

/**
 * TCA form element for direct secret input in tx_nrvault_secret table.
 *
 * This element is specifically for the vault's own secret table, allowing users to:
 * - Enter new secrets directly in FormEngine (new records)
 * - View masked secrets with reveal option (existing records)
 * - Rotate secrets by entering a new value (existing records)
 *
 * Unlike VaultSecretElement (which stores REFERENCES to secrets),
 * this element handles the actual secret value input for the vault table.
 */
final class VaultSecretInputElement extends AbstractFormElement
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

        /** @var array<string, mixed> $formData */
        $formData = $this->data;
        /** @var array<string, mixed> $parameterArray */
        $parameterArray = \is_array($formData['parameterArray'] ?? null) ? $formData['parameterArray'] : [];
        /** @var array<string, mixed> $fieldConf */
        $fieldConf = \is_array($parameterArray['fieldConf'] ?? null) ? $parameterArray['fieldConf'] : [];
        /** @var array<string, mixed> $config */
        $config = \is_array($fieldConf['config'] ?? null) ? $fieldConf['config'] : [];
        $itemName = \is_string($parameterArray['itemFormElName'] ?? null) ? $parameterArray['itemFormElName'] : '';

        $fieldId = StringUtility::getUniqueId('formengine-vault-input-');
        $sizeValue = $config['size'] ?? 50;
        $width = $this->formMaxWidth(is_numeric($sizeValue) ? (int) $sizeValue : 50);

        // Determine if this is a new or existing record
        /** @var array<string, mixed> $databaseRow */
        $databaseRow = \is_array($formData['databaseRow'] ?? null) ? $formData['databaseRow'] : [];
        $uid = $databaseRow['uid'] ?? 0;
        $uidString = \is_string($uid) || \is_int($uid) ? (string) $uid : '0';
        $isNewRecord = $uid === 0 || $uidString === 'NEW' || str_starts_with($uidString, 'NEW');

        // Get the secret identifier from the record
        $identifierRaw = $databaseRow['identifier'] ?? '';
        if (\is_array($identifierRaw)) {
            $identifier = \is_string($identifierRaw[0] ?? null) ? $identifierRaw[0] : '';
        } else {
            $identifier = \is_string($identifierRaw) ? $identifierRaw : '';
        }

        // Check if secret exists in vault for existing records
        $hasSecret = false;
        if (!$isNewRecord && $identifier !== '') {
            $hasSecret = $this->secretExists($identifier);
        }

        // Build HTML based on record state
        if ($isNewRecord) {
            $html = $this->renderNewRecordInput($fieldId, $itemName, $config, $width);
        } else {
            $html = $this->renderExistingRecordInput($fieldId, $itemName, $config, $width, $identifier, $hasSecret);
        }

        $resultArray['html'] = $html;

        // Add JavaScript module
        /** @var list<JavaScriptModuleInstruction> $javaScriptModules */
        $javaScriptModules = \is_array($resultArray['javaScriptModules'] ?? null) ? $resultArray['javaScriptModules'] : [];
        $javaScriptModules[] = JavaScriptModuleInstruction::create(
            '@netresearch/nr-vault/vault-secret-input.js',
        );
        $resultArray['javaScriptModules'] = $javaScriptModules;

        return $resultArray;
    }

    /**
     * Render input for new record - simple password field.
     *
     * @param array<string, mixed> $config
     */
    private function renderNewRecordInput(
        string $fieldId,
        string $itemName,
        array $config,
        int $width,
    ): string {
        $placeholder = $this->getLanguageService()->sL(
            'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:vault_secret_input.placeholder_new',
        ) ?: 'Enter secret value';

        $attributes = [
            'type' => 'password',
            'id' => $fieldId,
            'name' => $itemName,
            'value' => '',
            'class' => 'form-control',
            'placeholder' => $placeholder,
            'autocomplete' => 'off',
            'data-formengine-validation-rules' => $this->getValidationDataAsJsonString($config),
            'data-formengine-input-name' => $itemName,
            'data-vault-is-new' => '1',
            'data-form-type' => 'other',
            'data-1p-ignore' => 'true',
            'data-lpignore' => 'true',
            'data-bwignore' => 'true',
            'data-protonpass-ignore' => 'true',
            'data-dashlane-ignore' => 'true',
        ];

        if ($config['required'] ?? false) {
            $attributes['required'] = 'required';
        }

        $maxValue = $config['max'] ?? 0;
        if (is_numeric($maxValue) && (int) $maxValue > 0) {
            $attributes['maxlength'] = (string) (int) $maxValue;
        }

        $html = [];
        $html[] = '<div class="formengine-field-item t3js-formengine-field-item">';
        $html[] = '<div class="form-wizards-wrap">';
        $html[] = '<div class="form-wizards-element">';
        $html[] = '<div class="form-control-wrap" style="max-width: ' . $width . 'px">';
        $html[] = '<div class="input-group">';
        $html[] = '<input ' . GeneralUtility::implodeAttributes($attributes, true) . ' />';

        // Toggle visibility button
        $html[] = '<button type="button" class="btn btn-default t3js-vault-input-toggle" title="Toggle visibility">';
        $html[] = $this->renderIcon('actions-eye');
        $html[] = '</button>';

        $html[] = '</div>'; // input-group
        $html[] = '</div>'; // form-control-wrap
        $html[] = '</div>'; // form-wizards-element
        $html[] = '</div>'; // form-wizards-wrap

        // Help text
        $html[] = '<div class="form-text text-body-secondary mt-1">';
        $html[] = htmlspecialchars($this->getLanguageService()->sL(
            'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:vault_secret_input.help_new',
        ) ?: 'Enter the secret value. It will be encrypted when the record is saved.');
        $html[] = '</div>';

        $html[] = '</div>'; // formengine-field-item

        return implode(self::LINE_FEED, $html);
    }

    /**
     * Render input for existing record - masked display with reveal and rotate options.
     *
     * @param array<string, mixed> $config
     */
    private function renderExistingRecordInput(
        string $fieldId,
        string $itemName,
        array $config,
        int $width,
        string $identifier,
        bool $hasSecret,
    ): string {
        $html = [];
        $html[] = '<div class="formengine-field-item t3js-formengine-field-item">';
        $html[] = '<div class="form-wizards-wrap">';
        $html[] = '<div class="form-wizards-element">';
        $html[] = '<div class="form-control-wrap" style="max-width: ' . $width . 'px">';

        if ($hasSecret) {
            // Current secret display (masked)
            $html[] = '<div class="mb-2">';
            $html[] = '<label class="form-label fw-bold">';
            $html[] = htmlspecialchars($this->getLanguageService()->sL(
                'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:vault_secret_input.current_secret',
            ) ?: 'Current Secret');
            $html[] = '</label>';
            $html[] = '<div class="input-group">';
            $html[] = '<input type="password" ';
            $html[] = 'id="' . htmlspecialchars($fieldId) . '-display" ';
            $html[] = 'class="form-control font-monospace" ';
            $html[] = 'value="••••••••••••" ';
            $html[] = 'readonly ';
            $html[] = 'data-vault-identifier="' . htmlspecialchars($identifier) . '" ';
            $html[] = 'data-vault-display="true" ';
            $html[] = '/>';

            // Reveal button
            $html[] = '<button type="button" class="btn btn-default t3js-vault-input-reveal" ';
            $html[] = 'data-identifier="' . htmlspecialchars($identifier) . '" ';
            $html[] = 'title="Reveal secret">';
            $html[] = $this->renderIcon('actions-eye');
            $html[] = '</button>';

            // Copy button
            $html[] = '<button type="button" class="btn btn-default t3js-vault-input-copy" ';
            $html[] = 'data-identifier="' . htmlspecialchars($identifier) . '" ';
            $html[] = 'title="Copy to clipboard" style="display: none;">';
            $html[] = $this->renderIcon('actions-clipboard');
            $html[] = '</button>';

            $html[] = '</div>'; // input-group
            $html[] = '</div>'; // mb-2

            // Rotate section (collapsible)
            $collapseId = StringUtility::getUniqueId('vault-rotate-');
            $html[] = '<div class="mt-3">';
            $html[] = '<button class="btn btn-sm btn-warning t3js-vault-rotate-toggle" type="button" ';
            $html[] = 'data-bs-toggle="collapse" data-bs-target="#' . $collapseId . '" ';
            $html[] = 'aria-expanded="false" aria-controls="' . $collapseId . '">';
            $html[] = $this->renderIcon('actions-refresh') . ' ';
            $html[] = htmlspecialchars($this->getLanguageService()->sL(
                'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:vault_secret_input.rotate',
            ) ?: 'Rotate Secret');
            $html[] = '</button>';

            $html[] = '<div class="collapse mt-2" id="' . $collapseId . '">';
            $html[] = '<div class="card card-body">';
            $html[] = '<label for="' . htmlspecialchars($fieldId) . '" class="form-label">';
            $html[] = htmlspecialchars($this->getLanguageService()->sL(
                'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:vault_secret_input.new_secret',
            ) ?: 'New Secret Value');
            $html[] = '</label>';
        } else {
            // No secret exists yet - show input field directly
            $html[] = '<div class="alert alert-info mb-2">';
            $html[] = htmlspecialchars($this->getLanguageService()->sL(
                'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:vault_secret_input.no_secret',
            ) ?: 'No secret value stored. Enter a value below.');
            $html[] = '</div>';
            $html[] = '<label for="' . htmlspecialchars($fieldId) . '" class="form-label">';
            $html[] = htmlspecialchars($this->getLanguageService()->sL(
                'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:vault_secret_input.secret_value',
            ) ?: 'Secret Value');
            $html[] = '</label>';
        }

        // Input field for new/rotated secret
        $inputAttributes = [
            'type' => 'password',
            'id' => $fieldId,
            'name' => $itemName,
            'value' => '',
            'class' => 'form-control',
            'placeholder' => $this->resolvePlaceholder($hasSecret),
            'autocomplete' => 'off',
            'data-formengine-input-name' => $itemName,
            'data-vault-identifier' => $identifier,
            'data-vault-has-secret' => $hasSecret ? '1' : '0',
            'data-form-type' => 'other',
            'data-1p-ignore' => 'true',
            'data-lpignore' => 'true',
            'data-bwignore' => 'true',
            'data-protonpass-ignore' => 'true',
            'data-dashlane-ignore' => 'true',
        ];

        $maxValue = $config['max'] ?? 0;
        if (is_numeric($maxValue) && (int) $maxValue > 0) {
            $inputAttributes['maxlength'] = (string) (int) $maxValue;
        }

        $html[] = '<div class="input-group">';
        $html[] = '<input ' . GeneralUtility::implodeAttributes($inputAttributes, true) . ' />';

        // Toggle visibility button
        $html[] = '<button type="button" class="btn btn-default t3js-vault-input-toggle" title="Toggle visibility">';
        $html[] = $this->renderIcon('actions-eye');
        $html[] = '</button>';

        $html[] = '</div>'; // input-group

        // Help text for rotate
        if ($hasSecret) {
            $html[] = '<div class="form-text text-body-secondary mt-1">';
            $html[] = htmlspecialchars($this->getLanguageService()->sL(
                'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:vault_secret_input.help_rotate',
            ) ?: 'Leave empty to keep current secret. Enter a new value to rotate.');
            $html[] = '</div>';
            $html[] = '</div>'; // card-body
            $html[] = '</div>'; // collapse
            $html[] = '</div>'; // mt-3
        } else {
            $html[] = '<div class="form-text text-body-secondary mt-1">';
            $html[] = htmlspecialchars($this->getLanguageService()->sL(
                'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:vault_secret_input.help_new',
            ) ?: 'Enter the secret value. It will be encrypted when the record is saved.');
            $html[] = '</div>';
        }

        $html[] = '</div>'; // form-control-wrap
        $html[] = '</div>'; // form-wizards-element
        $html[] = '</div>'; // form-wizards-wrap
        $html[] = '</div>'; // formengine-field-item

        return implode(self::LINE_FEED, $html);
    }

    /**
     * Check if a secret exists in the vault.
     */
    private function secretExists(string $identifier): bool
    {
        if ($identifier === '') {
            return false;
        }

        try {
            $vaultService = GeneralUtility::makeInstance(VaultServiceInterface::class);
            $vaultService->getMetadata($identifier);

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Render an icon using TYPO3's IconFactory.
     */
    private function renderIcon(string $identifier): string
    {
        $iconFactory = $this->iconFactory;

        return $iconFactory->getIcon($identifier, IconSize::SMALL)->render();
    }

    /**
     * Pick the appropriate placeholder text based on whether the record
     * already has a secret stored — rotate hint for existing secrets,
     * create hint for new ones. Falls back to English defaults when the
     * XLIFF lookup returns an empty string.
     */
    private function resolvePlaceholder(bool $hasSecret): string
    {
        $key = $hasSecret
            ? 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:vault_secret_input.placeholder_rotate'
            : 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_tca.xlf:vault_secret_input.placeholder_new';
        $fallback = $hasSecret ? 'Enter new secret value to rotate' : 'Enter secret value';

        return LocalisationHelper::translateOrFallback($this->getLanguageService(), $key, $fallback);
    }
}
