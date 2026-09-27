.. include:: /Includes.rst.txt

.. _adr-039-streaming-send-keeps-the-dns-pin:

======================================================================
ADR-039: A streaming send drives the pinned curl transfer from read()
======================================================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-09-27

Context
=======

A consumer that asks a provider for a streamed answer receives nothing until the whole answer is complete (`#391 <https://github.com/netresearch/t3x-nr-vault/issues/391>`__).
Every send through ``VaultHttpClient`` waits for the full body: :php:`sendRequest()` goes to the blocking ``CurlHandler``, and :php:`sendCancellable()` settles its promise only when the transfer has ended.
Measured on a TYPO3 14.3.7 installation, the first raw chunk of an LLM stream reached PHP 13 to 19 ms before the end of a 6.7 to 7.1 s transfer.

The obvious fix is Guzzle's ``stream => true`` option, and it is the one this package must not use.
That option routes the request to ``StreamHandler``, which does not use curl and ignores ``$options['curl']`` — including the ``CURLOPT_RESOLVE`` entry the ``ssrf-dns-pin`` middleware sets (:ref:`adr-026-dns-rebinding-defence`).
``CancellableHttpClientInterface`` documents this as the reason there is no per-request option surface, and :ref:`adr-037-cancellable-outbound-send` names it as a security decision.

A probe on the same installation drove the handler stack ``createCancellable()`` builds with a loop over ``tick()`` and a sink that timestamped every write.
Lines sent at about 120 ms were written at 116, 135 and 141 ms, with ``primary_ip`` the pinned address; a pin to an unreachable address timed out without a request; without the pin, plain DNS reached a different host.
The curl-multi transport already delivers the body incrementally with the pin in place — what was missing is a way to hand those bytes to a caller before the transfer ends.

Decision
========

A second calling interface, not an option
-----------------------------------------

``StreamingHttpClientInterface`` declares ``sendStreaming(RequestInterface $request, ?CancellationSignalInterface $signal = null): ResponseInterface`` and ``supportsStreaming(): bool``.
``VaultHttpClient`` implements it beside ``VaultHttpClientInterface`` and ``CancellableHttpClientInterface``.

It is a calling interface, so the 1.0 compatibility promise lets a minor release add it; it is not an extension point and carries no ``#[ExtensionPoint]`` mark.
It is separate rather than a method added to ``VaultHttpClientInterface`` for the reason ``CancellableHttpClientInterface`` was: a consumer feature-detects with ``instanceof`` and keeps working against older nr-vault releases.

The method takes the request and the signal and nothing else (``VaultHttpClientStreamingTest::sendStreamingTakesTheRequestAndTheSignalAndNothingElse()``).
Every public method of ``VaultHttpClient`` still returns a clone, a PSR-7 response or a bool (``VaultHttpClientCancellableTest::theCredentialBearingClientExportsNoTransportAndNoPromise()``); the promise and the transport stay inside the response body object, which exposes neither.

The same guards, through the same private methods
--------------------------------------------------

``sendStreaming()`` runs ``sendCancellable()``'s sequence statement for statement, and calls the same private methods to do it: ``assertSchemeIsAllowed()``, ``assertHostIsAllowed()``, the pre-flight signal check, ``resolveCancellableTransportAudited()`` and ``injectAuthenticationAudited()``.
The credential therefore reaches the request by exactly the code :php:`sendRequest()` uses, not by a copy of it (``VaultHttpClientStreamingTest::theCredentialIsInjectedOnTheRequestTheTransportSends()``, and on the wire ``StreamingSendTest::theCredentialIsInjectedExactlyAsOnSendRequest()``).

When the instance cannot build a curl-multi transport — the inner client was supplied by the caller, or the platform lacks ``curl_multi_*`` — the call degrades to ``sendBlocking()``, the one blocking send-and-audit helper, and the body is complete when it is returned (``aCallerSuppliedClientDegradesToABlockingSendWithACompleteBody()``).
``supportsStreaming()`` returns what ``supportsCancellation()`` returns, because the two run on the same transport.

The transport is the pinned one, and ``stream`` is never set
------------------------------------------------------------

The transfer runs on ``SecureHttpClientFactory::createCancellable()``'s transport: the hardened option set, the ``ssrf-dns-pin`` middleware, and a ``CurlMultiHandler`` at the bottom.
``sendAsync()`` receives four options and no others:

``allow_redirects => false``
   Pinned per request, as on the cancellable path: an async send would otherwise take the platform default, and a followed redirect leaves a pin computed for the original host.
``http_errors => false``
   The status is the caller's to judge.
``sink``
   A ``BufferStream`` the curl handler writes the body into as it arrives. Its high-water mark is unbounded, because ``BufferStream::write()`` answers ``0`` once the mark is reached and curl takes a short write as a transfer error.
``on_headers``
   A callback that records the final response head. A ``1xx`` interim head passes through it too and is skipped; the callback never throws, because it runs inside a curl callback and a throw there aborts the transfer.

``stream`` and ``synchronous`` are absent (``theTransportGetsSinkAndOnHeadersAndNeverTheStreamOption()``, which also reads the ``CURLOPT_RESOLVE`` entry off the options that reached the bottom handler).
On the wire, every request in ``StreamingSendTest`` goes to a name under ``.test``, which no resolver answers, so a transfer that reaches the server reached it through the pin (``theTransferReachesTheServerOnlyThroughTheDnsPin()``); a pin to a loopback address nothing listens on fails instead of falling back to DNS (``aPinToAnotherAddressFailsInsteadOfFallingBackToDns()``).

Return at the head, advance on read
-----------------------------------

``sendStreaming()`` steps the transport until ``on_headers`` has seen a final head or the promise has settled, and returns the head with a ``StreamingResponseBody`` in place of the sink.
The step is one class, ``StreamingTransfer``, shared by the wait for the head and every ``read()``: poll the signal, check the wall-clock bound, ``tick()``, run the promise queue.

``StreamingResponseBody::read()`` returns buffered bytes when there are any and otherwise steps the transport until bytes arrive or the transfer ends.
``StreamingSendTest::theFirstBytesAreReadableBeforeTheServerHasFinished()`` pins the property the issue asks for with timestamps from both ends: against a server that sends three lines 600 ms apart, ``sendStreaming()`` returns and the first line is readable before the server has sent the third.

Settlement is observed through ``then()`` handlers, never through promise state, and ``wait()`` is never called — the reasons are those of :ref:`adr-037-cancellable-outbound-send`, and the stubbed transfer counts wait calls (``itReturnsAtTheHeadAndReadsTheBodyAsItArrives()``).

A transfer that fails is never a short body
-------------------------------------------

End of stream is reported only when the transport fulfilled its promise.
A rejected transfer throws from ``read()`` once the bytes that did arrive have been handed out, as a ``VaultException`` with a fixed literal and the transport's exception as its previous one; ``eof()`` stays false, and ``getContents()`` and ``__toString()`` throw rather than return what arrived (``aFailureAfterTheHeadThrowsFromReadOnceTheArrivedBytesAreOut()``, ``getContentsAndToStringThrowInsteadOfReturningAShortBody()``; on the wire ``aTransferThatFailsMidStreamThrowsFromReadAfterTheBytesThatArrived()``, a response that announces 1000 bytes and sends 16).

A transfer that has already failed when the head is about to be returned is reported as the failure, the way the blocking send reports it, rather than handed out as a response whose first read throws (``aHeadAndAFailureInTheSameStepAreReportedAsTheFailure()``).

A stalled stream ends
---------------------

Two bounds, one per layer, both derived from settings the transport already has:

- libcurl enforces the transport's ``timeout`` (``CURLOPT_TIMEOUT_MS``) on every tick, and every ``read()`` that waits is a loop of ticks — so a read cannot outlive the timeout that ``withTimeout()`` or the platform configured. ``StreamingSendTest::aStalledStreamEndsAtTheTransferTimeout()`` reads the first line of a route that then stalls for 30 s, under ``withTimeout(2)``, and requires the next read to throw within 5 s.
- ``StreamingTransfer`` checks the transport's wall-clock budget (``timeout + connect_timeout + 5 s``, measured from the start of the transfer) before every step, head and body alike. It only trips when the handler stopped settling its promise, and it is the bound a test can drive without a socket (``anExhaustedBudgetBeforeTheHeadAbortsTheTransferAndAuditsAFailure()``, ``anExhaustedBudgetWhileReadingEndsTheRead()``).

There is no separate idle bound: an idle stream ends at the transfer timeout, and a long stream needs ``withTimeout()`` exactly as a long blocking call does.

An abandoned body closes the transfer
-------------------------------------

``close()``, ``detach()`` and the destructor of ``StreamingResponseBody`` cancel the transport's promise, which runs the cancel function ``CurlMultiHandler`` attached: the easy handle is removed from the multi handle and closed.
A signal that fires while the body is read does the same and throws ``RequestCancelledException``.
Unit tests count the cancel calls (``closingTheBodyCancelsTheTransfer()``, ``detachingTheBodyCancelsTheTransferAndHandsOutNoResource()``, ``droppingTheResponseCancelsTheTransfer()``, ``aSignalWhileReadingAbortsTheTransferAndClosesTheBody()``); on the wire, ``StreamingSendTest`` reads the handle count of the real ``CurlMultiHandler`` before and after (``closingTheBodyRemovesTheTransferFromTheMultiHandle()``, ``droppingTheBodyRemovesTheTransferFromTheMultiHandle()``, ``aSignalFiredWhileReadingAbortsTheTransfer()``).

Exactly one audit row, written when ``sendStreaming()`` returns or throws
-------------------------------------------------------------------------

The row is the one :php:`sendRequest()` writes — ``http_call``, the status, ``success = true`` for any HTTP status — and it is written at the point the method returns: when the head arrived.
Every outcome before the head takes the ladder of the cancellable path, from a ``finally`` that opens on the first statement after the credential was injected:

.. list-table::
   :header-rows: 1

   * - Situation
     - Action
     - success
     - Test in ``VaultHttpClientStreamingTest``
   * - The head arrived (any HTTP status)
     - ``http_call``
     - true
     - ``itReturnsAtTheHeadAndReadsTheBodyAsItArrives()``
   * - The signal was already true on entry
     - ``http_call_cancelled_before_send``
     - false
     - ``anAlreadyCancelledSignalReadsNoSecretAndSendsNothing()``
   * - The signal stopped the transfer before the head
     - ``http_call_cancelled``
     - false
     - ``aSignalBeforeTheHeadAbortsTheTransferAndAuditsItAsCancelled()``
   * - The transport failed before the head, or together with it
     - ``http_call``
     - false
     - ``aTransportRejectionBeforeTheHeadIsRethrownAndAudited()``, ``aHeadAndAFailureInTheSameStepAreReportedAsTheFailure()``
   * - The wall-clock bound before the head
     - ``http_call``
     - false
     - ``anExhaustedBudgetBeforeTheHeadAbortsTheTransferAndAuditsAFailure()``
   * - A rejection without a Throwable, a settlement that is not a response
     - ``http_call``
     - false
     - ``aRejectionWithoutAThrowableIsRefusedWithAFixedLiteral()``, ``aSettlementThatIsNotAResponseIsRefused()``
   * - A throw from Guzzle's option handling or the caller's signal
     - ``http_call``
     - false
     - ``aThrowFromTheSendItselfStillLeavesARow()``, ``aSignalThatThrowsBeforeTheHeadStillLeavesARowAndTearsTheTransferDown()``

The body is never logged: the row is built from the pre-injection request by ``logHttpCall()``, as on every other send, and nothing in ``StreamingResponseBody`` writes a row.

The row is not deferred to the end of the body.
Writing it from the body's last read, ``close()`` or destructor would be the handle object :ref:`adr-037-cancellable-outbound-send` rejected: whether a call that put a credential on the wire leaves a row would depend on what the consumer does with the body.
Written at the head, it cannot be skipped by a consumer that stops reading, and it records what an auditor needs to know — which secret went to which host, and what the server answered.

Where the guarantee stops
=========================

**A failure or an abandon after the head writes no second row.**
The row says the call was made and what status came back; it does not say whether the body arrived complete, or whether a signal stopped the read.
The caller learns it from the exception ``read()`` throws.
Recording it would take a second row per call, which breaks "every call leaves exactly one row", or a new audit action, which is Ask First in this repository and is not needed to answer the question the audit log exists for.

**Only reading advances the transfer.**
Between two reads nothing ticks the transport, so a consumer that holds a body without reading it keeps the easy handle, its socket and the credential-bearing request alive until the body is closed or destroyed.
libcurl's timeout counts that time too, so the next read after a long pause can fail with a timeout.

**The OAuth token leg is not streamed.**
It precedes the transfer and runs as :ref:`adr-037-cancellable-outbound-send` describes; only the call it authenticates streams.

**TLS to a public provider is not measured here.**
The functional tests run over plain HTTP on loopback, like the probe in #391.
libcurl applies ``CURLOPT_RESOLVE`` before the TLS handshake and verifies the certificate against the requested name, so nothing in this change depends on the transport being plain HTTP — but it has not been observed against a provider.

**The tick loop runs a process-global queue**, as on the cancellable path: reading a streaming body runs pending callbacks of unrelated Guzzle clients in the same process.

Consequences
============

Positive
--------

A consumer that already feature-detects ``CancellableHttpClientInterface`` can read a provider's stream as it arrives, with the DNS pin, the host allowlist, the credential injection and the audit row it had before.
Installations on older nr-vault releases keep the blocking behaviour through the same ``instanceof`` check.

Cost
----

The transport is built per call, as for :php:`sendCancellable()`, and lives as long as the body.
A streaming body holds its transfer on the transport until it is read to the end, closed or destroyed; a consumer that reads half a body and keeps the object pays for an open socket until then.
