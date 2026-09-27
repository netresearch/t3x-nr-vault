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
``sendAsync()`` receives four request options and adds no raw cURL option:

``allow_redirects => false``
   Pinned per request, as on the cancellable path: an async send would otherwise take the platform default, and a followed redirect leaves a pin computed for the original host.
``http_errors => false``
   The status is the caller's to judge.
``sink``
   A ``StreamingSink``, the bounded buffer the curl handler writes the body into as it arrives (see `One step cannot flood memory`_).
``on_headers``
   A callback that records the latest response head (see `The returned head is the origin's`_). It never throws, because it runs inside a curl callback and a throw there aborts the transfer.

``stream`` and ``synchronous`` are absent, and the ``curl`` array that reaches the bottom handler holds exactly one key, the ``CURLOPT_RESOLVE`` pin the middleware added (``theTransportGetsSinkAndOnHeadersAndNeverTheStreamOption()``).
On the wire, every request in ``StreamingSendTest`` goes to a name under ``.test``, which no resolver answers, so a transfer that reaches the server reached it through the pin (``theTransferReachesTheServerOnlyThroughTheDnsPin()``); a pin to a loopback address nothing listens on fails instead of falling back to DNS (``aPinToAnotherAddressFailsInsteadOfFallingBackToDns()``).

Return at the first body bytes, advance on read
-----------------------------------------------

``sendStreaming()`` steps the transport until ``on_headers`` has seen a final head *and* body bytes have reached the sink, or until the promise has settled, and returns the head with a ``StreamingResponseBody`` in place of the sink.
For a streaming consumer the time to the first readable byte is the same as returning at the head and reading at once; the audit row is written at this moment (see below).
The step is one class, ``StreamingTransfer``, shared by the wait for the head and every ``read()``: poll the signal, check the wall-clock bound, ``tick()``, run the promise queue.

``StreamingResponseBody::read()`` returns buffered bytes when there are any and otherwise steps the transport until bytes arrive or the transfer ends.
``StreamingSendTest::theFirstBytesAreReadableBeforeTheServerHasFinished()`` pins the property the issue asks for with timestamps from both ends: against a server that sends three lines 600 ms apart, ``sendStreaming()`` returns and the first line is readable before the server has sent the third.

Settlement is observed through ``then()`` handlers, never through promise state, and ``wait()`` is never called — the reasons are those of :ref:`adr-037-cancellable-outbound-send`, and the stubbed transfer counts wait calls (``itReturnsAtTheFirstBodyBytesAndReadsTheRestAsItArrives()``).

The returned head is the origin's
---------------------------------

Every head the transfer sees passes through ``on_headers``: a ``1xx`` interim head, and — on Guzzle 7 — the ``200 Connection established`` reply of a tunnelling proxy, before the origin's own head.
Guzzle 8 sets ``CURLOPT_SUPPRESS_CONNECT_HEADERS`` itself; Guzzle 7.10 to 7.15 do not, and ``composer.json`` allows both majors.
A first version of this send returned the first head of status 200 or above, so behind a proxy configured in ``$GLOBALS['TYPO3_CONF_VARS']['HTTP']['proxy']`` or ``HTTPS_PROXY`` an origin's ``401`` came back as ``200 Connection established`` with the proxy's headers — and was audited as ``success = true``, status ``200`` (found by an adversarial review of `#392 <https://github.com/netresearch/t3x-nr-vault/pull/392>`__).

The rule is the one the blocking path follows: a later head replaces an earlier one, and a ``1xx`` head is never final.
A head counts as final once body bytes have arrived or the transfer has ended; RFC 9110 §9.3.6 gives a 2xx reply to ``CONNECT`` no content, so a body byte always belongs to the origin's head.
The rule does not depend on the Guzzle major or on how the proxy was configured (``aProxyConnectHeadIsReplacedByTheOriginHead()``, ``aHeadAloneDoesNotReturnUntilBodyBytesArrive()``, ``aHeadWhoseTransferEndsWithoutABodyIsReturned()``; on the wire, through a real ``CONNECT`` proxy to a TLS origin, ``throughATunnellingProxyTheOriginHeadIsReturnedNotTheProxyReply()``, which is red without the rule on Guzzle 7 and passes either way on Guzzle 8).

Setting ``CURLOPT_SUPPRESS_CONNECT_HEADERS`` on this send was the alternative, and it was not taken: it is a raw cURL option in the same ``curl`` array that carries the pin, Guzzle 7.12 and later emit a deprecation for it on every call, and Guzzle 8 rejects raw options outside its allow-list — so it would need a gate on the Guzzle major and would still leave a ``1xx`` head to a separate rule.

One step cannot flood memory
----------------------------

libcurl decodes ``Content-Encoding`` inside a transport step, and a step runs until the socket has no more data.
With an unbounded buffer, 260,934 bytes of gzip grew the process by about 190 MiB before ``sendStreaming()`` returned, against 14 MiB on the blocking path, which spills its body to ``php://temp`` (same review).

``StreamingSink`` holds at most 16 MiB of unread body.
A write that would pass that bound is refused whole and ``write()`` answers ``0``; both Guzzle majors abort the transfer on a short write, so it fails closed — Guzzle 7 reports cURL error 23, Guzzle 8.2 ``Unable to write to stream``.
The sink records the refusal, and that record, not the transport's message, is what the translation below keys on.
The failure carries its own fixed literal, ``Streaming transfer aborted: one step delivered more body than the 16 MiB streaming buffer holds``, from ``sendStreaming()`` (code ``1790487102``, and the literal is the audit row's message with ``success = false``) or from ``read()`` (code ``1790487103``), with the transport's exception as the previous one — so an operator can tell the bound from a dropped connection.
Before throwing from ``sendStreaming()`` the sink is closed: the transport's exception carries the response it had built, whose body is the sink, and a caller holding the exception would otherwise keep up to 16 MiB alive (``aStepThatOverflowsTheSinkBeforeReturnFailsWithItsOwnLiteral()``, ``aCompressionBombFailsClosedWithBoundedMemory()``).

The bound counts unread bytes, and ``read()`` steps the transport only when the buffer is empty, so it limits what one step may deliver.
Measured on loopback against a server writing 64 MiB of plain data in 64 KiB writes, the largest single step delivered 360,448 bytes (three runs, all equal), and the whole body streamed to the end (``aLargePlainBodyStreamsToTheEndUnderTheBufferLimit()``).
A 128 MiB gzip body fails before ``sendStreaming()`` returns and grows the process by about 28 MiB (``aCompressionBombFailsClosedWithBoundedMemory()``, which bounds the growth at 64 MiB).

``decode_content`` keeps Guzzle's default, as on :php:`sendRequest()`.
Turning it off would hand a caller compressed bytes it never asked for, and it would not remove the need for a bound: a server can send ``Content-Encoding`` unasked, and plain bytes per step are not bounded by anything else either.

``StreamingSink::read()`` moves an offset instead of copying the rest of the buffer on every call, and drops the consumed prefix once it is at least half the buffer, so draining a full buffer in small reads costs linear time (``StreamingSinkTest``).

A transfer that fails is never a short body
-------------------------------------------

End of stream is reported only when the transport fulfilled its promise.
A rejected transfer throws from ``read()`` once the bytes that did arrive have been handed out, as a ``VaultException`` with a fixed literal and the transport's exception as its previous one; ``eof()`` stays false, and ``getContents()`` and ``__toString()`` throw rather than return what arrived (``aFailureAfterTheHeadThrowsFromReadOnceTheArrivedBytesAreOut()``, ``getContentsAndToStringThrowInsteadOfReturningAShortBody()``; on the wire ``aTransferThatFailsMidStreamThrowsFromReadAfterTheBytesThatArrived()``, a response that announces 1000 bytes and sends 16).

End of stream also requires the buffer to be empty: a step that delivers the last bytes and completes the transfer leaves ``eof()`` false until those bytes are read, so a ``while (!eof()) read()`` loop does not lose the final event (``bytesAndCompletionInOneStepAreNotAnEndUntilTheBytesAreRead()``).

A transfer that has already failed when ``sendStreaming()`` is about to return is reported as the failure, the way the blocking send reports it, rather than handed out as a response whose first read throws (``aHeadAndAFailureInTheSameStepAreReportedAsTheFailure()``).

A stalled stream ends
---------------------

Which bound applies depends on whether a total ``timeout`` is configured.

**With a total timeout** (``timeout > 0``, the platform value or ``withTimeout()``), two bounds, one per layer:

- libcurl enforces the transport's ``timeout`` (``CURLOPT_TIMEOUT_MS``) on every tick, and every ``read()`` that waits is a loop of ticks — so a read cannot outlive the configured timeout. ``StreamingSendTest::aStalledStreamEndsAtTheTransferTimeout()`` reads the first line of a route that then stalls for 30 s, under ``withTimeout(2)``, and requires the next read to throw within 5 s.
- ``StreamingTransfer`` checks the transport's wall-clock budget (``timeout + connect_timeout + 5 s``, measured from the start of the transfer) before every step, head and body alike. It only trips when the handler stopped settling its promise. It holds before the first step and between steps (``anExhaustedBudgetBeforeTheHeadAbortsTheTransferAndAuditsAFailure()``, ``anExhaustedBudgetWhileReadingEndsTheRead()``, ``theWallClockBudgetAlsoEndsATransferAfterItHasBeenStepped()``).

A long stream needs ``withTimeout()`` exactly as a long blocking call does.

**Without a total timeout** (``timeout = 0``, the default on TYPO3 13.4 and 14.3), libcurl has no total bound and :php:`sendRequest()` waits as long as the server takes.
A first version of this send still applied the wall-clock budget, which is then ``connect_timeout + 5 s``: an event stream that was still delivering died at that point — 9 of 12 events at 6.00 s in the round-3 review's probe, where :php:`sendRequest()` completed in 7.72 s.

The bound is on silence instead: ``SecureHttpClientFactory::STREAMING_IDLE_BUDGET_SECONDS``, 60 s, carried by ``CancellableTransport::idleBudgetSeconds()`` only when no total timeout exists.
Every step that received something — the response head, body bytes — moves the deadline forward, so a stream that keeps delivering lives, and one that falls silent ends with its own literal (``Streaming transfer received nothing within its idle limit and was aborted``; code ``1790487201`` before :php:`sendStreaming()` returns, also the audit message, ``1790487202`` from ``read()``).
The window also covers the wait for the head: a server that accepts the connection and sends nothing ends after 60 s.
TYPO3 has no idle setting to derive the window from; 60 s is the default read timeout of common reverse proxies, which would cut a longer-silent stream anyway.
Tests: ``withoutATotalTimeoutADeliveringStreamOutlivesTheIdleBound()``, ``withoutATotalTimeoutAStallWhileReadingEndsAtTheIdleBound()``, ``withoutATotalTimeoutASilentServerEndsAtTheIdleBoundBeforeReturn()``, ``theFactoryGivesAnIdleBoundOnlyWhenNoTotalTimeoutIsSet()``; on the wire ``withoutATotalTimeoutAStreamStillDeliveringOutlivesTheOldBudget()`` (12 lines 700 ms apart under ``timeout = 0, connect_timeout = 1``) and ``withoutATotalTimeoutAStalledStreamEndsAtTheIdleBound()``.

What the idle bound does not bound is a trickle: a server that sends one byte every few seconds keeps the transfer alive indefinitely.
That is the blocking path's behaviour at ``timeout = 0`` too; the only per-transfer remedy, ``CURLOPT_LOW_SPEED_LIMIT``, is a raw cURL option this send does not add (see above). An operator who needs a hard ceiling sets ``timeout`` or calls ``withTimeout()``.

An abandoned body closes the transfer
-------------------------------------

``close()``, ``detach()`` and the destructor of ``StreamingResponseBody`` cancel the transport's promise, which runs the cancel function ``CurlMultiHandler`` attached: the easy handle is removed from the multi handle and closed.
A signal that fires while the body is read does the same and throws ``RequestCancelledException``.
So does any throw during a step — a signal that breaks its "must not throw" contract, the ticker: ``StreamingTransfer::advance()`` tears the transfer down before the throwable leaves, and the body is closed, so the connection does not wait for the object to be destroyed (``aSignalThatThrowsWhileReadingTearsTheTransferDown()``, on the wire ``aSignalThatThrowsWhileReadingReleasesTheTransferAtOnce()``).
Unit tests count the cancel calls (``closingTheBodyCancelsTheTransfer()``, ``detachingTheBodyCancelsTheTransferAndHandsOutNoResource()``, ``droppingTheResponseCancelsTheTransfer()``, ``aSignalWhileReadingAbortsTheTransferAndClosesTheBody()``); on the wire, ``StreamingSendTest`` reads the handle count of the real ``CurlMultiHandler`` before and after (``closingTheBodyRemovesTheTransferFromTheMultiHandle()``, ``droppingTheBodyRemovesTheTransferFromTheMultiHandle()``, ``aSignalFiredWhileReadingAbortsTheTransfer()``).

The body's PSR-7 contract, and the one deliberate deviation
-----------------------------------------------------------

``__toString()`` throws.
PSR-7 (psr/http-message 2.0) says it MUST NOT, and asks for ``''`` or a partial string on error instead — which is exactly the short body this class exists to refuse: a caller could not tell a truncated answer from a complete one.
So ``(string) $body`` returns the whole body whenever the transfer completes, error statuses included — a ``401`` with its JSON error document is returned as a string like any other body — and throws only when the transfer failed, was cancelled, or exceeded the limit below.
A caller that must not see an exception, for example one that formats a ``4xx`` body into its own error message, calls ``getContents()`` inside a ``try`` and decides what a failed read means for it.

``getContents()`` and ``__toString()`` are bounded at ``StreamingSink::DEFAULT_LIMIT_BYTES`` (16 MiB).
Without a bound, calling either on an endless stream ended in a PHP memory fatal, where ``read()`` throws a catchable timeout.
Past the limit the transfer is torn down and a ``VaultException`` with the literal ``Streaming response body is larger than getContents() returns; read it in chunks with read()`` (code ``1790487205``) is thrown (``getContentsPastTheLimitThrowsAndTearsTheTransferDown()``).
Both are for bodies known to be small; a large or open-ended body is read in chunks with ``read()``.

``read(0)`` returns ``''`` without stepping the transport, so a zero-length read never moves the transfer or trips a bound (``aZeroLengthReadReturnsNothingAndDoesNotStepTheTransport()``).
A negative length is refused with a ``VaultException`` (code ``1790487203``, and ``1790487204`` from ``StreamingSink::read()``): ``substr()`` would read it as "all but the last n bytes" and hand out a truncated chunk (``aNegativeLengthIsRefusedAndConsumesNothing()`` in both test classes).

Exactly one audit row, written when ``sendStreaming()`` returns or throws
-------------------------------------------------------------------------

The row is the one :php:`sendRequest()` writes — ``http_call``, the status, ``success = true`` for any HTTP status — and it is written at the point the method returns: when the origin's head and the first body bytes have arrived, or the transfer has ended.
Every outcome before that takes the ladder of the cancellable path, from a ``finally`` that opens on the first statement after the credential was injected:

.. list-table::
   :header-rows: 1

   * - Situation
     - Action
     - success
     - Test in ``VaultHttpClientStreamingTest``
   * - The head and the first body bytes arrived, or the transfer ended (any HTTP status)
     - ``http_call``
     - true
     - ``itReturnsAtTheFirstBodyBytesAndReadsTheRestAsItArrives()``, ``aProxyConnectHeadIsReplacedByTheOriginHead()`` (the status is the origin's)
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
   * - Nothing received for the idle bound (no total timeout configured)
     - ``http_call``
     - false
     - ``withoutATotalTimeoutASilentServerEndsAtTheIdleBoundBeforeReturn()``
   * - A throw from Guzzle's option handling or the caller's signal
     - ``http_call``
     - false
     - ``aThrowFromTheSendItselfStillLeavesARow()``, ``aSignalThatThrowsBeforeTheHeadStillLeavesARowAndTearsTheTransferDown()``
   * - One step delivered more body than the 16 MiB buffer holds
     - ``http_call``
     - false
     - ``aStepThatOverflowsTheSinkBeforeReturnFailsWithItsOwnLiteral()`` (the message is the bound's literal, not cURL's)

The body is never logged: the row is built from the pre-injection request by ``logHttpCall()``, as on every other send, and nothing in ``StreamingResponseBody`` writes a row.

The row is not deferred to the end of the body.
Writing it from the body's last read, ``close()`` or destructor would be the handle object :ref:`adr-037-cancellable-outbound-send` rejected: whether a call that put a credential on the wire leaves a row would depend on what the consumer does with the body.
Written when the method returns, it cannot be skipped by a consumer that stops reading, and it records what an auditor needs to know — which secret went to which host, and what the server answered.

Where the guarantee stops
=========================

**A failure or an abandon after the method returned writes no second row.**
That includes a step that overflows the buffer while the body is read.
The row says the call was made and what status came back; it does not say whether the body arrived complete, or whether a signal stopped the read.
The caller learns it from the exception ``read()`` throws.
Recording it would take a second row per call, which breaks "every call leaves exactly one row", or a new audit action, which is Ask First in this repository and is not needed to answer the question the audit log exists for.

**Only reading advances the transfer.**
Between two reads nothing ticks the transport, so a consumer that holds a body without reading it keeps the easy handle, its socket and the credential-bearing request alive until the body is closed or destroyed.
libcurl's timeout counts that time too, so the next read after a long pause can fail with a timeout.

**The OAuth token leg is not streamed.**
It precedes the transfer and runs as :ref:`adr-037-cancellable-outbound-send` describes; only the call it authenticates streams.

**TLS to a public provider is not measured here.**
The functional tests run over plain HTTP on loopback, like the probe in #391, apart from the proxy case, which tunnels to a loopback TLS origin with verification off.
libcurl applies ``CURLOPT_RESOLVE`` before the TLS handshake and verifies the certificate against the requested name, so nothing in this change depends on the transport being plain HTTP — but it has not been observed against a provider.

**CI resolves Guzzle 8 only.**
The CONNECT-head defect exists on Guzzle 7 alone, and ``composer.json`` allows ``^7.10``; the shared CI workflow has no input that pins a single dependency, so no matrix cell runs Guzzle 7.
The unit tests carry the rule on both majors; the proxy test proves it on the wire only when run against Guzzle 7, which was done locally for this change.

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
