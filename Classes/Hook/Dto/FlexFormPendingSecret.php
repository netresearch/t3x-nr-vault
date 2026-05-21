<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Hook\Dto;

use SensitiveParameter;

/**
 * Data Transfer Object for pending FlexForm secret storage.
 *
 * Replaces array{flexField: string, sheet: string, fieldPath: string, value: string, identifier: string, originalChecksum: string, isNew: bool}
 * for type-safe FlexForm secret handling during record save operations.
 */
readonly class FlexFormPendingSecret
{
    public function __construct(
        public string $flexField,
        public string $sheet,
        public string $fieldPath,
        #[SensitiveParameter]
        public string $value,
        public string $identifier,
        public string $originalChecksum,
        public bool $isNew,
    ) {}

    /**
     * Create a new pending FlexForm secret (not yet stored).
     */
    public static function createNew(
        string $flexField,
        string $sheet,
        string $fieldPath,
        #[SensitiveParameter]
        string $value,
        string $identifier,
    ): self {
        return new self(
            flexField: $flexField,
            sheet: $sheet,
            fieldPath: $fieldPath,
            value: $value,
            identifier: $identifier,
            originalChecksum: '',
            isNew: true,
        );
    }

    /**
     * Create an updated pending FlexForm secret (already exists).
     */
    public static function createUpdate(
        string $flexField,
        string $sheet,
        string $fieldPath,
        #[SensitiveParameter]
        string $value,
        string $identifier,
        string $originalChecksum,
    ): self {
        return new self(
            flexField: $flexField,
            sheet: $sheet,
            fieldPath: $fieldPath,
            value: $value,
            identifier: $identifier,
            originalChecksum: $originalChecksum,
            isNew: false,
        );
    }

    /**
     * Get the full FlexForm path for this secret.
     */
    public function getFullPath(): string
    {
        return \sprintf('%s/%s/%s', $this->flexField, $this->sheet, $this->fieldPath);
    }

    /**
     * Check if the value has changed from the original.
     */
    public function hasChanged(string $currentChecksum): bool
    {
        return $this->originalChecksum !== $currentChecksum;
    }

    /**
     * Convert to array for serialization.
     *
     * @return array{flexField: string, sheet: string, fieldPath: string, value: string, identifier: string, originalChecksum: string, isNew: bool}
     */
    public function toArray(): array
    {
        return [
            'flexField' => $this->flexField,
            'sheet' => $this->sheet,
            'fieldPath' => $this->fieldPath,
            'value' => $this->value,
            'identifier' => $this->identifier,
            'originalChecksum' => $this->originalChecksum,
            'isNew' => $this->isNew,
        ];
    }
}
