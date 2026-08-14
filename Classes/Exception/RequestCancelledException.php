<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

/**
 * A `sendCancellable()` call was aborted by its cancellation signal.
 *
 * Thrown for both cancellation outcomes — before the send began and after the
 * credential was injected — so a caller has one exception type to catch. The
 * two are distinguished in the audit log, which is where the distinction
 * matters: only one of them means a credential was put on the wire.
 *
 * The message is always a fixed literal — both throw sites pass a constant, and
 * both constants are asserted on `getMessage()` of the exception a caller
 * receives by
 * `VaultHttpClientCancellableTest::cancellingBeforeSendReadsNoSecretAndStillLeavesADistinguishableRow()`,
 * `…::aPreFlightSignalIsHonouredEvenWhenCancellationIsUnsupported()`,
 * `…::cancellingMidFlightAbortsTheTransferAndAuditsItAsCancelled()` and
 * `…::theTwoCancellationOutcomesAreToldApartByTheirAction()`, which also assert
 * the exception codes and the audit row. The row is not the exception: pinning
 * the literal there alone would have left this class free to append the request
 * URI to the message with the suite staying green — and for
 * `SecretPlacement::QueryParam` that URI carries the secret. The promise's own
 * rejection reason is
 * deliberately not carried through: transport error strings on this client can
 * contain the injected secret, and they are redacted only by
 * `AuditLogService::sanitizeErrorMessage()` on the way into the audit row. An
 * exception handed back to a consumer does not pass that boundary.
 */
final class RequestCancelledException extends VaultException {}
