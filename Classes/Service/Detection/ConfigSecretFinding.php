<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Detection;

/**
 * A detected secret in configuration (LocalConfiguration or extension config).
 */
final readonly class ConfigSecretFinding implements SecretFinding
{
    /**
     * @param list<string> $patterns
     */
    public function __construct(
        public string $path,
        public Severity $severity,
        public bool $isLocalConfiguration,
        public array $patterns = [],
        public ?string $message = null,
    ) {}

    public function getKey(): string
    {
        return $this->isLocalConfiguration
            ? "config:{$this->path}"
            : $this->path;
    }

    public function getSource(): string
    {
        return 'config';
    }

    public function getSeverity(): Severity
    {
        return $this->severity;
    }

    public function getPatterns(): array
    {
        return $this->patterns;
    }

    public function getDetails(): string
    {
        if ($this->message !== null) {
            return $this->message;
        }

        return $this->isLocalConfiguration ? 'LocalConfiguration.php' : 'Extension config';
    }

    /**
     * @return array{source: string, path: string, severity: string, patterns: list<string>, message?: string}
     */
    public function jsonSerialize(): array
    {
        $data = [
            'source'   => $this->isLocalConfiguration ? 'LocalConfiguration' : 'configuration',
            'path'     => $this->path,
            'severity' => $this->severity->value,
            'patterns' => $this->patterns,
        ];

        if ($this->message !== null) {
            $data['message'] = $this->message;
        }

        return $data;
    }
}
