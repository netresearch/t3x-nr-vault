<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

/**
 * Context data for HTTP API call audit entries.
 *
 * Immutable value object capturing HTTP request details for audit logging.
 */
final readonly class HttpCallContext implements AuditContextInterface
{
    public function __construct(
        public string $method,
        public string $host,
        public string $path,
        public int $statusCode,
    ) {}

    /**
     * Create from request details.
     */
    public static function fromRequest(string $method, string $url, int $statusCode): self
    {
        $parsed = parse_url($url);

        return new self(
            method: $method,
            host: $parsed['host'] ?? 'unknown',
            path: $parsed['path'] ?? '/',
            statusCode: $statusCode,
        );
    }

    public function toArray(): array
    {
        return [
            'method'      => $this->method,
            'host'        => $this->host,
            'path'        => $this->path,
            'status_code' => $this->statusCode,
        ];
    }

    /**
     * @return array<string, scalar|null>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
