.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-040-cancellable-send-bounds-silence:

=====================================================================
ADR-040: Without a total timeout, the cancellable send bounds silence
=====================================================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted (amends :ref:`adr-037-cancellable-outbound-send`)

Date
====

2026-09-27

Context
=======

:ref:`adr-037-cancellable-outbound-send` gave the tick loop of :php:`sendCancellable()` a defensive wall-clock bound of ``timeout + connect_timeout + 5 s`` and justified it with one sentence: it "sits strictly above libcurl's own deadlines", so it can only trip when the handler stopped settling its promise.

That sentence is true only when a total ``timeout`` is set.
``timeout = 0`` is the default on TYPO3 13.4 and 14.3, and it gives libcurl no total deadline at all.
The bound is then ``connect_timeout + 5 s`` — 15 s with the default ``connect_timeout`` of 10 — and it sits above nothing: it ends every call that takes longer, however much the server is still sending, while :php:`sendRequest()` on the same client completes the same call.

Measured in the review of `#392 <https://github.com/netresearch/t3x-nr-vault/pull/392>`__ with ``timeout = 0``, ``connect_timeout = 1`` and a server sending 12 events 700 ms apart: :php:`sendRequest()` completed after 7.72 s, :php:`sendCancellable()` was aborted after 6.01 s (`#394 <https://github.com/netresearch/t3x-nr-vault/issues/394>`__).
The functional test named under Consequences reproduces it against the unchanged code: the call fails with ``Cancellable transfer exceeded its wall-clock budget and was aborted``, audited as ``http_call`` / ``success = false``.
The same loop runs the OAuth token leg (``OAuthTokenManager::dispatchCancellable()``) inside a cancellable call, with the same bound and therefore the same defect.

:ref:`adr-039-streaming-send-keeps-the-dns-pin` met the same problem on the streaming send and decided it there: with a total timeout keep the wall-clock budget, without one bound the server's silence — 60 s (``SecureHttpClientFactory::STREAMING_IDLE_BUDGET_SECONDS``), reset by every final head and every body byte after one.
The factory already puts that idle budget on every transport it builds without a total timeout; only the streaming send read it.

Decision
========

Every send on the cancellable transport applies the rule of ADR-039: :php:`sendStreaming()`, :php:`sendCancellable()` and the OAuth token leg.

- **With a total timeout** (``timeout > 0``, the platform value or ``withTimeout()``) nothing changes. libcurl enforces the timeout, and the wall-clock budget ``timeout + connect_timeout + 5 s`` sits above it, measured from the start of the transfer. Progress does not extend it (``withATotalTimeoutProgressDoesNotExtendTheWallClockBudget()``), and the factory still computes it as before (``theFactoryGivesTheCancellableSendAnIdleBoundOnlyWithoutATotalTimeout()``).
- **Without a total timeout** the wall-clock budget is not applied. The call ends when nothing has arrived for the idle budget, with its own fixed literal and code, audited as a failure under ``http_call`` / ``success = false`` — the reasoning of ADR-037 for the wall-clock bound applies unchanged: nobody asked for it, so it is not a cancellation.

.. list-table::
   :header-rows: 1

   * - Send
     - Literal
     - Code
   * - :php:`sendCancellable()`
     - ``Cancellable transfer received nothing within its idle limit and was aborted``
     - ``1786579206``
   * - OAuth token leg
     - ``Cancellable OAuth token transfer received nothing within its idle limit and was aborted``
     - ``1786579307`` (``OAuthException``)

One mechanism, not a copy
-------------------------

The loop in :php:`sendCancellable()` and the one in the token leg were private copies of the step ``StreamingTransfer::advance()`` already performs — poll the signal, check the bound, ``tick()``, drain the promise queue, observe settlement through ``then()`` handlers.
Both now drive a ``StreamingTransfer`` instead of their own loop, so the idle bound, the rule that it is checked after the tick, and the rule that a settled transfer is never aborted are the ones ADR-039 records, not a third version of them.
What stays local is the classification of the outcome: the literals, the exception types and, for :php:`sendCancellable()`, the audit ladder.
ADR-037's arguments for this loop's shape — no ``wait()``, no ``SYNCHRONOUS``, settlement through handlers, one teardown on every abnormal exit — hold for ``StreamingTransfer`` as they held for the copy.

What counts as progress
-----------------------

The rule is ADR-039's, and it now lives in one class, ``TransferProgress``, which all three sends use: a final response head (status 200 and above) counts, and so do the body bytes the sink took while a final head was the current one.
A ``1xx`` head resets the current head, so a server repeating ``100 Continue`` buys no time on any Guzzle version, and the raw bytes behind an unsolicited ``101 Switching Protocols`` count as nothing (``aRepeatedInterimHeadBuysNoTime()``, ``bytesAfterAnUnsolicitedSwitchingProtocolsHeadBuyNoTime()``, token leg ``aRepeatedInterimHeadBuysTheTokenLegNoTime()``).
A final head after an interim one counts, and so does a trickle after it (``aTrickleAfterAFinalHeadCompletesAlthoughAnInterimHeadCameFirst()``).

:php:`sendCancellable()` buffers the whole body, so it has no streaming sink to count.
Guzzle's curl handler writes the body into a ``php://temp`` stream when no ``sink`` is given; the send now opens that stream itself and passes it as ``sink``, together with an ``on_headers`` callback, and counts the stream's size.
The body returned is that stream, as before.
It is deliberately not the streaming send's ``StreamingSink``: that one holds at most 16 MiB, and :php:`sendCancellable()` has never limited a body (``aBodyLargerThanTheStreamingBufferIsReturnedWhole()``).
``sink`` and ``on_headers`` are request options the send sets itself; the send still takes no options from its caller, and ``stream`` is still never set.

Consequences
============

- A cancellable call without a total timeout that keeps receiving completes, however long it takes (``withoutATotalTimeoutACallStillDeliveringOutlivesTheWallClockBudget()``; on the wire ``StreamingSendTest::withoutATotalTimeoutACancellableCallStillDeliveringOutlivesTheOldBudget()``, the measurement from #394, red before this change with the wall-clock literal).
- A server that accepts the connection and sends nothing ends the call after 60 s instead of ``connect_timeout + 5 s`` (``withoutATotalTimeoutASilentServerEndsAtTheIdleBound()``, ``withoutATotalTimeoutACallThatGoesQuietAfterItsHeadEndsAtTheIdleBound()``; on the wire, with the bound shortened to 1 s, ``withoutATotalTimeoutASilentServerEndsACancellableCallAtTheIdleBound()``; token leg ``withoutATotalTimeoutASilentTokenEndpointEndsAtTheIdleBound()``, ``withoutATotalTimeoutASlowTokenEndpointStillCompletes()``).
  That is later than before; the signal still ends such a call at any moment.
- At ``timeout = 0`` the 60 s window starts when the transfer is built, so it also covers the connect, the TLS handshake and the upload of the request body: a slow upload to a server that sends nothing back until it has the whole body gets 60 s, where the wall-clock budget gave it ``connect_timeout + 5 s`` (15 s by default), and with a ``connect_timeout`` above 55 s the window is tighter than that budget was.
- A server that trickles a byte every few seconds keeps the call open indefinitely, exactly as it keeps :php:`sendRequest()` open at ``timeout = 0``. An operator who needs a hard ceiling sets ``timeout`` or calls ``withTimeout()``. ADR-039 gives the reason a low-speed limit is not added.
- ``SecureHttpClientFactory::STREAMING_IDLE_BUDGET_SECONDS`` keeps its name although it now bounds non-streaming sends too; renaming a public constant is not worth the break.
- A refresh-token round trip that ends at the idle bound throws ``OAuthException`` with its own code, like one that ends at the wall-clock bound; ``fetchTokenWithFallback()`` falls back to ``client_credentials`` only for a rejected refresh token, so neither bound triggers a second round trip.
