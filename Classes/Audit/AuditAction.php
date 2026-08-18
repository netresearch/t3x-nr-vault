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
    /**
     * The cancellation signal stopped an IN-FLIGHT request — written by
     * `VaultHttpClient::sendCancellable()` only, and by nothing else.
     *
     * This action means exactly one thing: the credential was retrieved,
     * injected into the request and handed to the transport, and then the
     * caller's signal turned true and the transfer was torn down. Treat the
     * credential as exposed.
     *
     * Because it means only that, "which calls were abandoned after their
     * credential went out?" is answerable by querying this single action value.
     * Nothing else is filed here:
     *
     * - a cancellation BEFORE the send is `HttpCallCancelledBeforeSend` — no
     *   secret was read, nothing egressed, and an auditor must be able to
     *   exclude those rows without parsing an error string;
     * - the tick loop's defensive wall-clock bound and an unexpected throwable
     *   are `HttpCall` with `success = false`. They are failures, not
     *   cancellations: nobody asked for them, and counting them here would put
     *   a second meaning back on this action.
     *
     * Distinct from `HttpCall` with `success = false` because status `0` is
     * already overloaded there: a connection refusal and an SSRF middleware
     * rejection produce the same tuple, and folding a deliberate abort into it
     * would make the question above unanswerable by query.
     */
    case HttpCallCancelled = 'http_call_cancelled';
    /**
     * The cancellation signal was already true when
     * `VaultHttpClient::sendCancellable()` was entered, so the call was refused
     * before the send began.
     *
     * The one abandoned outcome in which NO credential was involved: the vault
     * was never read and nothing was handed to the transport. It is a separate
     * case rather than a distinguishing error string so that it is separately
     * filterable and countable — an error message is free text an auditor
     * cannot query on, while the action drives the backend's filter dropdown.
     *
     * The row is written even though nothing egressed: the log is complete with
     * respect to CALLS, not merely with respect to egress, so an operator
     * asking "what did this run do?" gets an answer for every send that was
     * asked for.
     */
    case HttpCallCancelledBeforeSend = 'http_call_cancelled_before_send';
    case MasterKeyRotateStart = 'master_key_rotate_start';
    case MasterKeyRotateEnd = 'master_key_rotate_end';
    case AuditChainRekey = 'audit_chain_rekey';
    /**
     * One OAuth token-endpoint round trip attempted by `OAuthTokenManager` —
     * the outbound POST that carries the `client_secret` (issue #303).
     *
     * Written once per attempted round trip, success and failure alike, from
     * the moment the credentials have been read from the vault: a completed
     * fetch, a non-200 answer, a transport failure, the `allowed_hosts`
     * rejection of the token endpoint, and a cancelled transfer each leave
     * exactly one row. The row's context carries method, endpoint host/path
     * and the HTTP status; which failure it was is a fixed literal (or the
     * redacted upstream message) in `error_message`.
     *
     * Its own action rather than `http_call`: that action means "a caller's
     * request through `VaultHttpClient`", and the token leg is an extra
     * outbound call the manager makes on its own behalf — an auditor counting
     * caller traffic must be able to exclude these rows by query, and one
     * asking "when did the client credential go out?" must not have to parse
     * messages. The `oauth_refresh_*` actions below record refresh-flow
     * EVENTS (a rejected refresh token, the fallback, a failed store); this
     * one records the round trip itself.
     */
    case OAuthTokenRequest = 'oauth_token_request';
    case OAuthRefreshFailed = 'oauth_refresh_failed';
    case OAuthFallbackClientCredentials = 'oauth_fallback_client_credentials';
    case OAuthRefreshStoreFailed = 'oauth_refresh_store_failed';
    case AuditReadLoggingChanged = 'audit_read_logging_changed';
    case AuditAnchorReset = 'audit_anchor_reset';
    case BreakGlassActivated = 'break_glass_activated';
    case BreakGlassDeactivated = 'break_glass_deactivated';

    /**
     * Human-readable label for backend filter dropdowns.
     */
    public function label(): string
    {
        return ucwords(str_replace('_', ' ', $this->value));
    }
}
