<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

/**
 * Generic context data for audit entries.
 *
 * Use this for simple key-value context data that doesn't warrant a dedicated DTO.
 */
final readonly class GenericContext implements AuditContextInterface
{
    /**
     * @param array<string, scalar|null> $data
     */
    public function __construct(
        private array $data,
    ) {}

    /**
     * Create from key-value pairs.
     */
    public static function fromArray(mixed ...$values): self
    {
        $data = [];
        foreach ($values as $key => $value) {
            if (\is_string($key) && (\is_scalar($value) || $value === null)) {
                $data[$key] = $value;
            }
        }

        return new self($data);
    }

    public function toArray(): array
    {
        return $this->data;
    }

    /**
     * @return array<string, scalar|null>
     */
    public function jsonSerialize(): array
    {
        return $this->data;
    }
}
