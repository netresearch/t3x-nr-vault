.. include:: /Includes.rst.txt

.. _adr-037-cancellable-outbound-send:

===============================================================
ADR-037: A cancellable send is a method, not an exported handle
===============================================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-08-13

Context
=======

A consumer that cancels a long-running operation cannot stop the outbound HTTP call nr-vault started on its behalf.
The call runs to its timeout — for `netresearch/t3x-nr-llm#774 <https://github.com/netresearch/t3x-nr-llm/issues/774>`__ that is up to about 45 seconds across the three legs of one tool step, long after the work it was serving was abandoned.

Two independent reasons block an abort today, either sufficient on its own.
PSR-18 ``sendRequest()`` returns a response, never a handle, so there is nothing for a caller to cancel.
And Guzzle's ``Client::sendRequest()`` sets ``RequestOptions::SYNCHRONOUS``, which routes the send to the blocking ``CurlHandler``: its promise is already settled by the time it exists, and its ``cancel()`` is a no-op.
Guzzle promises support cancellation in general; that one does not.

A genuine abort needs ``CurlMultiHandler``, which attaches a real cancel function to its promise and exposes ``tick()``.
Both are unreachable from outside this package: the Guzzle client is built inside ``SecureHttpClientFactory::create()``, its handler stack is local to that method, and ``VaultHttpClientInterface`` exposes only PSR-18 plus four withers.

The obvious blocking alternative was rejected on evidence rather than taste.
Aborting from ``CURLOPT_PROGRESSFUNCTION`` without going async needs ``CURLOPT_NOPROGRESS => false`` set alongside the callback; Guzzle's curl factory sets both together for its own ``progress`` option, and nothing sets it on the raw ``curl`` seam.
A progress callback registered by hand there is therefore never invoked.
It fails by doing nothing, which is the worst possible failure mode for a security-relevant abort.

Decision
========

The primitive is a **method on** ``VaultHttpClient``
----------------------------------------------------

``sendCancellable(RequestInterface $request, CancellationSignalInterface $signal): ResponseInterface``, declared on a new ``CancellableHttpClientInterface``.

This is not a stylistic preference about where to put a method — it follows from where the protections actually live.
Of the seven properties that make this client safe, only two are properties of the handler stack:

.. list-table::
   :header-rows: 1

   * - Protection
     - Where it lives
     - Survives a different send method?
   * - Scheme allowlist (``http``/``https`` only)
     - plain code in the sending method
     - **No**
   * - ``allowed_hosts`` gate
     - plain code in the sending method
     - **No**
   * - Credential injection
     - plain code in the sending method
     - **No**
   * - Audit write
     - plain code in the sending method
     - **No**
   * - SSRF reject (dangerous IP, legacy ``inet_aton`` forms)
     - ``ssrf-dns-pin`` middleware
     - Yes
   * - ``CURLOPT_RESOLVE`` DNS pin
     - ``ssrf-dns-pin`` middleware
     - Yes
   * - Proxy, TLS and timeout settings
     - client option set
     - Yes, for the same client object

Any shape that handed a consumer the inner client, the handler or a promise would drop the first four — including the allowlist that runs *before the credential reaches the request*, and the audit row that records the call happened at all.

The two legs order that differently, and only one of them reads the secret after the gate.
On the outer request the gate runs before any vault read: ``assertHostIsAllowed()`` precedes ``injectAuthentication()``.
On the OAuth token leg the credentials are read first, in ``buildTokenRequestParams()`` (``OAuthTokenManager.php:286-306``), and ``isHostAllowed()`` runs afterwards in ``dispatchTokenRequest()`` (``:337``) — still before the body carrying ``client_secret`` is built (``:351``).
Nothing egresses before the gate either way; "before the secret is read" would be the wrong verb for the second leg.
A handle object (``startRequest()`` → ``tick()`` → ``response()``) fails the same test from the other direction: it makes the audit write conditional on consumer discipline, because a caller that breaks out of its loop or drops the handle produces an outbound call, credential already on the wire, with no audit row.

The invariant this shape protects
--------------------------------

It is **not** "no transport type crosses the package boundary" — the codebase has never had that, and asserting it would be wrong.
``SecureHttpClientFactory::create()`` was already public before this change and already returned a raw ``ClientInterface``; nr-llm injects the factory directly in three places (``McpHttpTransport``, ``SecureHttpDispatchTrait``, ``ModelDiscovery``).
``createCancellable()`` adds a second such entry point, returning a ``CancellableTransport`` that exposes a Guzzle client and its ticker.

The boundary is two-tier, and the narrower statement is the one that must hold:

.. list-table::
   :header-rows: 1

   * - Tier
     - What a caller gets
     - What it carries
   * - ``create()`` / ``createCancellable()`` — public, supported
     - a raw transport
     - SSRF reject middleware and the ``CURLOPT_RESOLVE`` DNS pin. **No** vault credential, no scheme guard, no ``allowed_hosts`` gate, no audit write
   * - ``VaultHttpClient`` — ``sendRequest()`` / ``sendCancellable()``
     - PSR-7 in, PSR-7 out
     - everything the first tier carries, plus the four inline ones: the scheme
       guard, the ``allowed_hosts`` gate, credential injection and the audit write

**Nothing hands a caller a client that already carries a vault secret**, and ``VaultHttpClient`` is the only place nr-vault attaches a secret to a *caller's* request.
That is the invariant, stated at the width it actually holds, and the half of it a test can hold to that width is the export surface: ``theCredentialBearingClientExportsNoTransportAndNoPromise()`` fails the moment a public method of ``VaultHttpClient`` returns anything other than a configured clone, a PSR-7 response or a bool.
A caller who wants a hardened transport *without* vault credentials is a supported case, which is why the first tier is public.

The wider statement — "no credential-bearing send exists outside ``VaultHttpClient``" — is **false**, and two senders inside this package are the counterexamples.
They are named here, where a reader checks the invariant, and not only under `Where the guarantee stops`_:

.. list-table::
   :header-rows: 1

   * - Sender
     - Credential
     - Client
   * - ``TransitMasterKeyProvider::callTransit()`` (``TransitMasterKeyProvider.php:282``)
     - ``X-Vault-Token`` header
     - the plain Guzzle client ``MasterKeyProviderFactory`` builds (``MasterKeyProviderFactory.php:52``) — no middleware, no allowlist, deliberately, for on-prem RFC1918 Vault
   * - ``OAuthTokenManager::dispatchTokenRequest()`` (``OAuthTokenManager.php:357``)
     - ``client_secret`` in the form body built at ``OAuthTokenRequestParams.php:60``
     - the hardened inner client, with the ``allowed_hosts`` gate applied at ``OAuthTokenManager.php:337`` but no audit write

Neither is a *caller's* request: the transit call belongs to master-key handling, and the token leg runs inside ``injectAuthentication()`` on nr-vault's own behalf.
Both are covered further under `Where the guarantee stops`_.

What the shape enforces, and what enforces it: every public method of ``VaultHttpClient`` returns a configured clone, a PSR-7 response or a bool — no client, no handler, no promise — and ``sendCancellable()`` has no options parameter through which a caller could reach the transport.
Both are asserted by ``VaultHttpClientCancellableTest::theCredentialBearingClientExportsNoTransportAndNoPromise()``, so a future method that hands one of them back fails a test rather than quietly widening the surface.

The transport is composed, not swapped
--------------------------------------

``SecureHttpClientFactory::create()`` is unchanged in behaviour; its option-building block moved into a shared private ``buildOptions()`` so the blocking and cancellable transports cannot drift apart — asserted option by option by ``theBlockingAndCancellableTransportsCarryTheSameOptions()``, which compares the two clients' full request-option sets and excludes only the handler.
A new ``createCancellable()`` builds the second transport from the same options and pushes the same ``ssrf-dns-pin`` middleware — that the middleware really runs on this transport is asserted by ``ssrfDnsPinIsInstalledOnTheCancellableTransport()``, which reads the ``CURLOPT_RESOLVE`` entry off the request that reached the bottom handler.

Two details that are easy to get wrong:

The multi handler is **not** passed bare.
Guzzle's own handler selection composes ``Proxy::wrapStreaming(Proxy::wrapSync($multi, new CurlHandler()), new StreamHandler())``; passing the bare handler would silently delete both the sync and the streaming branch.
Re-composing preserves both and yields the ``$multi`` reference the loop needs.

The capability gate is ``curl_multi_exec``, not ``curl_init``.
``CurlMultiHandler``'s constructor is lazy and only fatals on first property access, so gating on the wrong function would turn the documented curl-less degraded mode into a hard failure.
Without ``curl_multi_exec`` the factory returns ``null`` and ``sendCancellable()`` completes the call blocking, with an ordinary audit row.
That blocking fallback is the same private helper ``sendRequest()`` uses, not a second copy of it: two copies of the send-and-audit body would let the audit behaviour differ by which method a consumer entered through.

**A caller's client is never replaced by a cancellable transport** (``anInjectedGuzzleClientIsNeverSwappedForACancellableTransport()``, ``anInjectedTransportNeverDisplacesACallerSuppliedClient()``).
An abort needs the ``CurlMultiHandler`` reference that ``createCancellable()`` hands out beside its client, so no inner client passed into ``VaultHttpClient``'s constructor can serve a cancellable send.
That leaves one question: what to do for an instance whose inner client came from a caller.
The answer is to degrade, not to substitute.

The wider claim — "the cancellable transport is *always* one the factory built" — is **false** and is not made: the ``@internal`` ``$cancellableTransport`` parameter is public, and a transport handed in that way is used as it was built.
What the seam cannot do is displace a caller's client, and that is the half with a test.

A supplied client may carry that caller's middleware, proxy or handler stack, and swapping in a factory-built one behind their back would silently drop all of it — on the cancellable path only, which is the worst place for a difference to hide.
So ``supportsCancellation()`` reports **false** whenever the inner client was supplied, and ``sendCancellable()`` completes such a call blocking, on that client, with an ordinary ``http_call`` row.
Only a factory-built inner client gets a cancellable sibling; ``VaultHttpClientFactory`` therefore leaves the construction to ``VaultHttpClient`` itself rather than passing a client in, and the ``with*()`` clones carry the fact along with the client.

**That fact cannot be asserted by a caller** (``aCallerCannotAssertTheFactoryBuiltFactByCloningFromAnotherInstance()``), which is what makes the rule above a property of the code rather than of consumer discipline.
The constructor takes no "this client is factory-built" flag.
It takes the instance the client is being forwarded *from* (``$clonedFrom``, passed by the ``with*()`` clones and by nothing else) and inherits the fact only when the forwarded client is the identical object that instance holds.
Reaching that branch requires already holding a factory-built instance, so ``new VaultHttpClient(innerClient: $factory->create(5), …)`` cannot claim it — and with it goes the mismatch it would otherwise buy, a blocking client at 5 s beside a cancellable one at 30.

The parameter is typed as the class itself, which is what makes it unforgeable and also what makes ``Services.yaml`` pin it: autowiring would otherwise read it as a dependency of ``VaultHttpClient`` on ``VaultHttpClient`` and refuse the whole container with a circular reference.
An explicit ``arguments: {$clonedFrom: null}`` entry leaves every other argument autowired.
Two alternatives were rejected: a ``WeakMap`` of clients the factory built would accept a client whose handler stack the caller mutated after ``create()``, which is the substitution the rule exists to prevent; and having the clones drop the client and let the constructor rebuild it would emit the ``verify => false`` operator warning once per wither instead of once per client.

This also settles the timeout for a transport the client builds itself: it is built from the same remembered override the inner client was built with, so it cannot outlive the blocking path — cancellation is an early exit, and a transport that could run *longer* than the send it replaces would be the opposite of one.
``theTransportTheClientResolvesForItselfCarriesTheRememberedTimeout()`` asserts both halves against one client, with an override-free control so the number cannot have arrived by coincidence.

Where that stops, and it is worth naming because the sentence above is the one a reader will generalise: ``withTimeout()`` **does** replace a client the caller supplied.
PSR-18 carries no per-request options, so the override has to be baked into a client, and the one that gets built comes from the factory — which also flips ``supportsCancellation()`` to true for the clone (``withTimeoutRebuildsACallerSuppliedClientAndTurnsCancellationOn()``).

Tests that need to drive the loop inject a ``CancellableTransport`` through the ``$cancellableTransport`` constructor parameter.
That parameter is ``@internal``, and it is **not** a way around the rule above: ``supportsCancellation()`` checks the factory-built fact *first*, so an injected transport on an instance whose client came from a caller is never read and the call degrades to a blocking send on that client.
What the seam remains able to do is substitute the transport of an instance that has no caller-supplied client — the four inline protections still run, but the transport's own hardening is then whatever was handed in.
It is a test seam, documented as one; PHP offers no way to make a constructor parameter unreachable while the constructor is public.

Two posture changes are handled explicitly, not inherited
---------------------------------------------------------

``allow_redirects => false`` is re-pinned per request.
``Client::sendRequest()`` pins it for every PSR-18 send; an async send sets nothing and falls back to the client default, which honours ``$GLOBALS['TYPO3_CONF_VARS']['HTTP']['allow_redirects']`` when an operator set it.
On such an install the cancellable path alone would start following redirects — past a DNS pin computed for the *original* host, which is precisely the hole this client exists to close.
This was measured, not inferred: the same factory-built client answered ``302 not followed`` synchronously and ``200 followed`` asynchronously.
``redirectsStayOffOnTheCancellablePathEvenWhenTypo3EnablesThem()`` is the regression guard, and it fails on the status rather than by hanging.

``sendCancellable()`` accepts **no per-request option surface**.
That is a security decision, not an omission.
A caller-supplied ``stream => true`` would route the request to the stream handler, which ignores ``$options['curl']`` entirely and drops the DNS pin without warning; a caller-supplied ``curl`` array is applied last by Guzzle's curl factory and would overwrite the vetted ``CURLOPT_RESOLVE`` entry.
Adding an options parameter later requires revisiting both.

Cancellation is an early exit, never an extension
-------------------------------------------------

``timeout`` and ``connect_timeout`` are per-handle curl options and libcurl enforces them inside the multi interface exactly as inside the blocking path.
Whichever fires first wins; a timeout expiry still surfaces as the existing ``http_call`` / ``success=false`` / status ``0`` row.

The loop's blocking bound is ``select_timeout``, set to **0.1 s**.
Measured against a stalling local TCP server that timestamps the moment it observes the peer close, with the signal turning true at +1.5 s (three runs each):

.. code-block:: text

   select_timeout=1      3 ticks   worst tick 1.001 s   peer close at +2.002 s
   select_timeout=0.1   16 ticks   worst tick 0.100 s   peer close at +1.504 s
   select_timeout=0.05  31 ticks   worst tick 0.050 s   peer close at +1.506 s

Guzzle's default of 1 second costs up to a full second of overshoot and is unusable here.
Between the other two the measurement shows no latency problem at 0.1, so the CPU-conservative value wins: 0.05 doubles the wakeups to buy 50 ms that nothing in the motivating case can perceive.

A defensive wall-clock bound of ``timeout + connect_timeout + 5 s`` sits strictly above libcurl's own deadlines (``theFactoryBuildsACancellableTransportWithABudgetAboveTheTransferDeadlines()``).
If it ever trips, the handler stopped settling its promise — better to abort and audit than to hang a TYPO3 request.

``withTimeout()`` does not carry a transport across.
A client rebuilt with a new timeout while the caller keeps ticking the previous client's event loop would tick a loop that serves nothing, and spin to the wall-clock bound.
The transport is built on demand from the remembered override instead, so the two cannot disagree (``withTimeoutDropsTheTransportAndRemembersTheOverride()``).

Settlement is observed through a handler, not through promise state
--------------------------------------------------------------------

A Guzzle promise counts as fulfilled the moment it is resolved *with another promise*, which may still be pending.
Reading ``getState()`` would therefore call an unfinished transfer done and hand the caller a value that is not a response.
A ``then()`` handler fires only when the chain has resolved all the way down to a real value, so the loop uses that.

``wait()`` is never called.
Its wait function is ``CurlMultiHandler::execute()``, which loops until *every* handle on that handler completes — no cancellation window at all.
The stubbed transfer counts invocations of its promise's wait function and ``cancellingMidFlightAbortsTheTransferAndAuditsItAsCancelled()`` asserts that count is zero, so a loop that started waiting fails a test instead of quietly becoming uncancellable.

Every call leaves one row, and each action means exactly one thing
------------------------------------------------------------------

**Every call leaves exactly one row from this client**, on ``sendCancellable()`` and on ``sendRequest()`` alike, so the log is complete with respect to **calls** and not merely with respect to egress — including the call that was already cancelled when it began, the one refused by an allowlist, and the one whose credential could not be obtained.
That overrides the "no row when nothing egressed" position the design proposed: the operator expectation is that a call that was asked for is a call that shows up.

The rightmost column is what keeps that sentence honest: an outcome with no test in it is an outcome nobody has checked writes a row.
Three of these rows are new here — the scheme guard, the host guard and the vault read between them and the send all used to throw before anything was written.

.. list-table::
   :header-rows: 1

   * - Situation
     - Action
     - success
     - statusCode
     - Test
   * - Completed (any HTTP status)
     - ``http_call``
     - true
     - real status
     - ``anUncancelledCallReturnsTheResponseAndAuditsAnOrdinaryHttpCall()``
   * - Scheme outside http/https
     - ``http_call``
     - false
     - 0
     - ``aRefusedSchemeIsAuditedAsAFailedHttpCall()``, ``schemeGuardRunsOnTheCancellablePathBeforeAnySecretIsRead()``
   * - Host outside ``allowed_hosts``
     - ``http_call``
     - false
     - 0
     - ``aRefusedHostIsAuditedAsAFailedHttpCall()``, ``hostAllowlistRunsOnTheCancellablePathBeforeAnySecretIsRead()``
   * - The cancellable transport could not be built (``sendCancellable()`` only)
     - ``http_call``
     - false
     - 0
     - ``aThrowFromTheTransportResolutionLeavesAnAuditRow()``
   * - The credential could not be obtained (missing secret, denied read, failed token leg)
     - ``http_call``
     - false
     - 0
     - ``aFailedCredentialInjectionIsAuditedAsAFailedHttpCall()``, ``aFailedCredentialInjectionOnTheCancellablePathLeavesARow()``
   * - Transport failure, incl. SSRF rejection
     - ``http_call``
     - false
     - 0
     - ``anSsrfRejectionSettlesBeforeTheFirstTickAndStillWritesItsRow()``
   * - A rejection whose reason is not a Throwable
     - ``http_call``
     - false
     - 0
     - ``aRejectionWithoutAThrowableIsRefusedWithAFixedLiteral()``
   * - A settlement that is not a response
     - ``http_call``
     - false
     - 0
     - ``aNonResponseSettlementIsRefusedInsteadOfReturned()``
   * - The wall-clock bound
     - ``http_call``
     - false
     - 0
     - ``anExhaustedWallClockBudgetAbortsTheTransferAndAuditsIt()``
   * - A throw from the signal, the ticker or Guzzle's option handling
     - ``http_call``
     - false
     - 0
     - ``aSignalThatThrowsMidFlightStillLeavesAnAuditRow()``, ``aThrowFromTheSendItselfStillLeavesAnAuditRow()``, ``aThrowFromTheDegradedBlockingSendStillLeavesAnAuditRow()``
   * - The signal stopped an in-flight request
     - ``http_call_cancelled``
     - false
     - 0
     - ``cancellingMidFlightAbortsTheTransferAndAuditsItAsCancelled()``, ``theTwoCancellationOutcomesAreToldApartByTheirAction()``
   * - The signal was already true on entry
     - ``http_call_cancelled_before_send``
     - false
     - 0
     - ``cancellingBeforeSendReadsNoSecretAndStillLeavesADistinguishableRow()``, ``aPreFlightSignalIsHonouredEvenWhenCancellationIsUnsupported()``

The action is what an auditor can filter and count on; the error message is free text they cannot.
So the question this feature exists to answer — **which calls were abandoned after their credential went out?** — is answerable by querying **one** action value, which requires that action to carry exactly one meaning.
``SELECT … WHERE action = 'http_call_cancelled'`` is therefore the whole answer, with no post-filtering on message text.

Two consequences are deliberate.

**The wall-clock bound and an unexpected throwable are failures, not cancellations.**
Nobody asked for either: the bound only trips when the handler stopped settling its promise, and the throwable comes from code neither the caller nor this class intended to run. Filing them under the cancellation action would restore the overloading the action was created to prevent — the auditor would be back to reading messages.
They keep ``http_call`` / ``success = false``, alongside the connection refusal and the SSRF rejection that already share that tuple, and the fixed literal in the row is what tells them apart *within* that action.

**The pre-flight case is its own action, not a message on the shared one.**
It is the only abandoned outcome with no credential involved, so it is the one an auditor must be able to *exclude* by query rather than by reading. ``http_call_cancelled`` gets a ``warning`` badge — every row under it means a credential went out; ``http_call_cancelled_before_send`` gets ``info``, because there is nothing to act on.

**The early rejections are audited, and under no new action.**
``assertSchemeIsAllowed()`` and ``assertHostIsAllowed()`` ran before any audit write and threw, so a rejected scheme or a host nobody approved left no row at all — pre-existing on ``sendRequest()``, and the one thing an operator would most want to find.
They now write one, on both send paths, before the same unchanged exception is thrown; the vault read between the guards and the send does too.

No new enum case for them, deliberately.
``http_call`` / ``success = false`` / status ``0`` already *is* "a refused outbound call" here — the SSRF middleware rejection lands in that tuple and is the same kind of egress-policy refusal, caught one layer later.
A fourth action would split one meaning across two values without giving an auditor a question they could not already ask: the destination is on the row, and the fixed literal says which gate refused it.
The audit vocabulary is Ask First in this repository, and this change does not need it.

Because these run on a pre-existing path, the exception a caller receives is pinned character for character by three characterization tests written before the row existed — ``sendRequestRefusesAnUnsupportedSchemeWithAnUnchangedException()``, ``sendRequestRefusesAHostOutsideTheAllowlistWithAnUnchangedException()``, ``sendRequestRefusesAMissingSecretWithAnUnchangedException()``.
An audit row is additive; the refusal itself must not move.

The row's ``error_message`` is a **fixed literal**, rendered by the audit module under the badge (``Audit/List.html:116``), and identifies the situation *within* an action rather than carrying the distinction on its own.
Five of them append one variable: the offending scheme, or the original message of a throw that came from somewhere else.

.. list-table::
   :header-rows: 1

   * - Literal
     - Action
     - What it means
   * - ``Request cancelled before send: nothing egressed and no secret was retrieved``
     - ``http_call_cancelled_before_send``
     - The signal was already true. No vault read, nothing handed to the transport.
   * - ``Request cancelled after send began: credential injected and transfer handed to the transport``
     - ``http_call_cancelled``
     - Treat the credential as exposed.
   * - ``Cancellable transfer exceeded its wall-clock budget and was aborted``
     - ``http_call``
     - The defensive bound tripped; the handler stopped settling its promise.
   * - ``Cancellable transport settled with a value that is not an HTTP response``
     - ``http_call``
     - The transfer settled with something unusable.
   * - ``Cancellable transfer aborted by an unexpected error after the credential was injected: …``
     - ``http_call``
     - Guzzle's option handling, the caller's signal or the ticker threw.
   * - ``Blocking send aborted by an unexpected error after the credential was injected: …``
     - ``http_call``
     - The blocking send threw something that is not a PSR-18 ``ClientExceptionInterface``. Reachable through the degraded cancellable branch and through plain ``sendRequest()`` alike.
   * - ``Request refused before any secret was read: unsupported URI scheme "…"``
     - ``http_call``
     - The scheme guard refused the URI. The scheme is appended because ``HttpCallContext`` records method, host, path and status and has nowhere else to put it.
   * - ``Request refused before any secret was read: host is not in the allowed hosts list``
     - ``http_call``
     - The ``allowed_hosts`` gate refused the destination; the host itself is on the row, in the context.
   * - ``Credential injection failed; nothing was sent: …``
     - ``http_call``
     - The vault read or the OAuth token leg threw. Nothing egressed.
   * - ``Cancellable transport could not be built; nothing was sent: …``
     - ``http_call``
     - ``SecureHttpClientFactory::createCancellable()`` threw. The resolution runs after the guards and before the credential injection, so nothing egressed and no secret was read (``aThrowFromTheTransportResolutionLeavesAnAuditRow()``).
   * - ``Cancellable transfer was rejected``
     - ``http_call``
     - The promise rejected with a reason that is not a ``Throwable``, so there is no foreign message to append (``aRejectionWithoutAThrowableIsRefusedWithAFixedLiteral()``).

Note what the second literal does **not** claim.
The signal can turn true on the first pass through the loop, before the first tick, and at that moment the handler has only queued the easy handle — no byte need have left yet.
What is certain is that the secret was retrieved, injected into the request and handed to the transport, which is the property an auditor must act on. Claiming "the credential left the process" would be a stronger statement than the code can support in that one case.

Adding enum cases is safe for the tamper-evident chain: the rule is that existing backing values must never *change*, because that would break verification of historical rows. A new value only ever appears in new rows.
The two new values are pinned against literals by ``AuditControllerTest::theCancellationActionValuesAreFrozen()``, and ``AuditControllerTest::everyActionTheHttpClientWritesReachesTheFilterDropdown()`` keeps them filterable in the module.

The audit write for the cancellable transfer sits in a ``finally``, and that ``finally`` opens on the **first statement** after the credential was injected — not after the send was started.
Three of the moving parts belong to somebody else: Guzzle's own option handling inside ``sendAsync()`` (``Client::applyOptions()`` raises ``InvalidArgumentException`` *outside* ``Client::transfer()``'s try/catch, so a bad option set leaves ``sendAsync()`` as a throw rather than as a rejected promise), the caller's signal, and the ticker seam.
A throw from any of them would otherwise escape the one method whose purpose is to leave a trace when a credential went out, and the window between injection and the ``try`` is exactly where such a throw would land.
The same ``finally`` also tears the transfer down before rethrowing, so an abandoned request does not leave a socket open behind it.

**The blocking send gets the same treatment**, because otherwise "every call leaves exactly one row" would be true of one branch of ``sendCancellable()`` and false of the other.
``sendBlocking()`` caught only ``ClientExceptionInterface``, and ``Client::applyOptions()`` throws outside ``Client::transfer()``'s try/catch on the synchronous path exactly as on the async one — so a degraded cancellable call, credential already injected, could leave no row.
It now writes from a ``finally`` too.
That also closes the same hole on plain ``sendRequest()``, which runs the same helper; the pre-existing outcomes (a status row on success, status ``0`` plus the transport's message on a ``ClientExceptionInterface``) are unchanged.

The exceptions this class *raises* on the cancellable path carry fixed literals, because an exception handed back to a consumer does not pass ``AuditLogService::sanitizeErrorMessage()`` and transport error strings on this client can contain the injected secret — for ``SecretPlacement::QueryParam`` the URI *is* the secret.
The tests in the table above pin the audit-row literals and the exception codes; they do not pin the message a caller receives, and until they did, this class could have started appending the URI to either cancellation message with the suite staying green.
Every code it raises there is now asserted on ``getMessage()`` as well: ``1786579201`` by ``cancellingBeforeSendReadsNoSecretAndStillLeavesADistinguishableRow()`` and ``aPreFlightSignalIsHonouredEvenWhenCancellationIsUnsupported()``, ``1786579202`` by ``cancellingMidFlightAbortsTheTransferAndAuditsItAsCancelled()`` and ``theTwoCancellationOutcomesAreToldApartByTheirAction()``, ``1786579203`` by ``anExhaustedWallClockBudgetAbortsTheTransferAndAuditsIt()``, ``1786579204`` by ``aRejectionWithoutAThrowableIsRefusedWithAFixedLiteral()``, ``1786579205`` by ``aNonResponseSettlementIsRefusedInsteadOfReturned()``.
The guards' own messages are pinned by the three characterization tests.

Exceptions this class does not raise are rethrown **unchanged**, which is the other half and was not stated before: an async rejection reason is rethrown as it arrived (``anSsrfRejectionSettlesBeforeTheFirstTickAndStillWritesItsRow()`` asserts the transport's own text reaching the caller), and so is a throw from the caller's signal or the ticker (``aSignalThatThrowsMidFlightStillLeavesAnAuditRow()``).
Rethrowing them unchanged is what ``sendRequest()`` has always done, and it is not free: a transport error string quotes the URL it failed on, which for ``QueryParam`` placement carries the secret.
That is a pre-existing property of every send on this client, it is unchanged here, and it is why the *audit* boundary redacts rather than the exception boundary.

The ticker is an interface
--------------------------

``TransportTickerInterface`` exists so the feature is provable.
The suite's only in-process HTTP seam replaces a client's bottom handler, which destroys the very ``CurlMultiHandler`` a cancellation loop would have to tick — a primitive holding that handler privately could not be exercised by any unit test, only read.
With the ticker behind an interface, a test drives the real middleware stack from a closure and the abort is provable without a socket, a sleep or a flake.
This mirrors the ``DnsResolverInterface`` injection precedent in the same namespace.

Guzzle becomes a declared dependency
------------------------------------

``composer.json`` now requires ``guzzlehttp/guzzle`` directly.
Production code already imported ``GuzzleHttp\Client``, ``HandlerStack`` and ``RequestException`` while the manifest named only the PSR interfaces and relied on ``typo3/cms-core`` to drag Guzzle in.
This change reaches deeper still — ``CurlMultiHandler``, ``Proxy``, ``StreamHandler``, promise cancel semantics — and a Guzzle major arriving through a third path would break it with no warning in our own manifest.

Where the guarantee stops
=========================

Each of these is a real residual gap, not a hypothetical.

Each is filed, so it can be argued somewhere: `#303 <https://github.com/netresearch/t3x-nr-vault/issues/303>`__ (OAuth leg), `#304 <https://github.com/netresearch/t3x-nr-vault/issues/304>`__ (double DNS resolve), `#306 <https://github.com/netresearch/t3x-nr-vault/issues/306>`__ (api-surface snapshot), `#307 <https://github.com/netresearch/t3x-nr-vault/issues/307>`__ (mutation gate scope).
`#305 <https://github.com/netresearch/t3x-nr-vault/issues/305>`__ (unaudited rejections) is closed by this change: the scheme and host guards write a row, and so does a failed credential injection.
`#309 <https://github.com/netresearch/t3x-nr-vault/issues/309>`__ asked for a second audit action for the pre-flight case; it is implemented here as ``http_call_cancelled_before_send``.

**The OAuth token round trip stays uncancellable.**
``injectAuthentication()`` → ``injectOAuth()`` → ``OAuthTokenManager::getAccessToken()`` performs a blocking PSR-18 send *before* the cancellable transfer, on a client the timeout override and the signal never reach.
That manager is also constructed without an audit log service, so the token call is unaudited today and stays so.
For OAuth-configured clients only part of the "three legs" complaint is addressed.

**The two blocking DNS lookups stay.**
``isHostAllowed()`` resolves the host, and the middleware resolves it again at request time.
Both are synchronous, both precede the socket, neither is interruptible.

**The OAuth token leg still writes no** ``http_call`` **row of its own.**
A *failed* token leg is audited from this client now, as a failed credential injection, because ``injectAuthentication()`` runs inside the audited region.
A *successful* one is not: the token request itself egresses with ``client_secret`` in its body and leaves no row from ``OAuthTokenManager``, which has no audit log service. `#303 <https://github.com/netresearch/t3x-nr-vault/issues/303>`__.

**The other two egress paths are untouched.**
``MasterKeyProviderFactory`` builds a plain Guzzle client with no middleware and no allowlist (deliberately, for on-prem RFC1918 Vault), and ``WebhookAuditSink`` uses a factory-built client but calls neither the allowlist gate nor the audit write.
This primitive lives on ``VaultHttpClient`` and covers neither.

**That cancellation closes a real socket is a property of libcurl, not of our code.**
It is verified by a recorded probe, not by CI.
A local TCP server accepts the connection, reads the 81 request bytes and never answers; the signal turns true at +1.500 s; ``sendCancellable()`` returns at +1.506 s and the server observes the peer close in the same millisecond (3 runs, php 8.5.9 / curl 8.5.0). The probe drives the production path and substitutes only the ticker, wrapped so it can watch the server side between ticks.
This repository has no socket-based test infrastructure, and a timing-sensitive socket test in the unit suite would be a flake generator.

**The tick loop runs a process-global queue.**
``CurlMultiHandler::tick()`` adds to and runs Guzzle's static promise task queue, so a vault-owned loop will execute pending callbacks belonging to unrelated Guzzle clients elsewhere in the same TYPO3 request, reentrantly.
No security invariant is lost, but it is a real boundary effect.

Consequences
============

Positive
--------

A consumer that already holds a ``VaultHttpClientInterface`` can feature-detect and abort a call without a version floor and without learning anything about the transport.
The change is purely additive: ``VaultHttpClientInterface`` is untouched, and the single in-repo implementor and every downstream consumer keep compiling.
The audit log gains a queryable answer to "which outbound calls were abandoned after their credential went out?", which it did not have before — one action value, no message parsing — and a second action for the calls that were abandoned before anything was read or sent.

Cost
----

A second transport is built per cancellable send rather than shared, so the primitive costs one extra client construction per call — deliberate, so the overwhelmingly more common ``sendRequest()`` path pays nothing.
The abort is not sub-second end to end and must not be advertised as such: ``select_timeout`` is only the last of several serial stages, preceded by two blocking DNS lookups and, for OAuth clients, a full token round trip.
Against the ~45 s it replaces, it is still the win the issue asked for.
