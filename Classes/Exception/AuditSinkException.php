<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

/**
 * Thrown when an external audit sink cannot deliver a record.
 *
 * Unlike {@see AuditWriteException}, this NEVER fails the audited vault
 * operation: the database table is the chain-authoritative sink and has already
 * committed by the time a sink runs. Every instance is caught by
 * {@see \Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface}, which logs
 * it, counts it, and raises a `SINK_FAILURE` integrity alert.
 *
 * Sinks throw rather than swallow deliberately. A sink that quietly returns on
 * failure looks identical to a working one, and an audit pipeline that stopped
 * flowing without anyone noticing is the failure mode this whole subsystem
 * exists to prevent.
 *
 * Messages must stay free of secret material and of credentials embedded in
 * configuration (webhook URLs, file paths are acceptable; tokens are not).
 */
final class AuditSinkException extends VaultException
{
    /**
     * The record could not be written to its destination.
     */
    public static function writeFailed(string $sinkIdentifier, string $detail): self
    {
        return new self(
            \sprintf('Audit sink "%s" write failed: %s.', $sinkIdentifier, $detail),
            1753900001,
        );
    }

    /**
     * The record could not be serialised for transport.
     */
    public static function encodingFailed(string $sinkIdentifier, string $detail): self
    {
        return new self(
            \sprintf('Audit sink "%s" could not encode the record: %s.', $sinkIdentifier, $detail),
            1753900002,
        );
    }

    /**
     * The remote endpoint rejected the record (non-2xx response).
     */
    public static function rejectedByEndpoint(string $sinkIdentifier, int $statusCode): self
    {
        return new self(
            \sprintf(
                'Audit sink "%s" endpoint returned HTTP %d; the record was not accepted.',
                $sinkIdentifier,
                $statusCode,
            ),
            1753900003,
        );
    }

    /**
     * The transport itself failed (DNS, TLS, timeout, refused connection).
     */
    public static function transportFailed(string $sinkIdentifier, string $detail): self
    {
        return new self(
            \sprintf('Audit sink "%s" transport failed: %s.', $sinkIdentifier, $detail),
            1753900004,
        );
    }
}
