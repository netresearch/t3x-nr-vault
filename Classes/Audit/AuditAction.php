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
 * Enumerates every audit-log action written to the tamper-evident chain.
 *
 * The backing string values are the canonical action identifiers persisted in
 * `tx_nrvault_audit_log.action` and bound into the HMAC hash payload. They MUST
 * remain byte-for-byte stable: changing a value would break verification of
 * every historical row that used the old string.
 *
 * @see AuditLogService for the hash-chain implementation
 */
enum AuditAction: string
{
    case Create = 'create';
    case Read = 'read';
    case Update = 'update';
    case Delete = 'delete';
    case Rotate = 'rotate';
    case MetadataUpdate = 'metadata_update';
    case AccessDenied = 'access_denied';
    case HttpCall = 'http_call';
    case MasterKeyRotateStart = 'master_key_rotate_start';
    case MasterKeyRotateEnd = 'master_key_rotate_end';
    case AuditChainRekey = 'audit_chain_rekey';
    case OAuthRefreshFailed = 'oauth_refresh_failed';
    case OAuthFallbackClientCredentials = 'oauth_fallback_client_credentials';
    case OAuthRefreshStoreFailed = 'oauth_refresh_store_failed';
    case AuditReadLoggingChanged = 'audit_read_logging_changed';
    case AuditAnchorReset = 'audit_anchor_reset';

    /**
     * Human-readable label for backend filter dropdowns.
     */
    public function label(): string
    {
        return ucwords(str_replace('_', ' ', $this->value));
    }
}
