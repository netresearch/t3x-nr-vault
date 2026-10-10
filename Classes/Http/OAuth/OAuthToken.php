<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Http\OAuth;

use DateTimeImmutable;
use Error;
use ValueError;

/**
 * Represents an OAuth 2.0 access token.
 */
final readonly class OAuthToken
{
    public function __construct(
        public string $accessToken,
        public string $tokenType,
        public DateTimeImmutable $expiresAt,
        public ?string $scope = null,
    ) {}

    /**
     * Check expiry at the current instant, preserving the signed buffer in seconds.
     *
     * @param int $buffer Positive seconds advance expiry; negative seconds give grace
     */
    public function isExpired(int $buffer = 0): bool
    {
        return $this->isExpiredAt(new DateTimeImmutable(), $buffer);
    }

    /**
     * Get the Authorization header value.
     */
    public function getAuthorizationHeader(): string
    {
        return $this->tokenType . ' ' . $this->accessToken;
    }

    /**
     * Get seconds until token expires.
     */
    public function getExpiresIn(): int
    {
        $now = new DateTimeImmutable();
        $diff = $this->expiresAt->getTimestamp() - $now->getTimestamp();

        return max(0, $diff);
    }

    private function isExpiredAt(DateTimeImmutable $now, int $buffer): bool
    {
        if ($buffer === 0) {
            return $now >= $this->expiresAt;
        }

        try {
            $expirySeconds = $this->expiresAt->getTimestamp();
            $nowSeconds = $now->getTimestamp();
        } catch (Error $failure) {
            if (!$failure instanceof ValueError && !is_a($failure, 'DateRangeError')) {
                throw $failure;
            }

            // Preserve native conversion-range behavior without requiring PHP 8.3 symbols.
            return $now >= $this->expiresAt->modify("-{$buffer} seconds");
        }

        // Guard subtraction before PHP can promote an overflowing integer to float.
        if ($buffer > 0 && $expirySeconds < PHP_INT_MIN + $buffer) {
            return true;
        }

        if ($buffer < 0 && $expirySeconds > PHP_INT_MAX + $buffer) {
            return false;
        }

        $adjustedExpiry = $expirySeconds - $buffer;
        if ($nowSeconds !== $adjustedExpiry) {
            return $nowSeconds > $adjustedExpiry;
        }

        return $now->format('u') >= $this->expiresAt->format('u');
    }
}
