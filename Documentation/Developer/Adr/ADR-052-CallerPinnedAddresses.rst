.. SPDX-License-Identifier: GPL-2.0-or-later
.. SPDX-FileCopyrightText: Netresearch DTT GmbH

.. include:: /Includes.rst.txt

.. _adr-052-caller-pinned-addresses:

=======================================================
ADR-052: Sending to addresses the caller resolved
=======================================================

Status
======

Accepted

Date
====

2026-11-11

Context
=======

A consumer that sends to a URL a user or a remote party supplied runs its own
destination check: it resolves the host, checks every address and only then
sends. nr-llm's A2A client is the first such consumer. Its check is worth
nothing if the transport resolves the name a second time, because a DNS answer
can change between the check and the connect.

nr-vault already pins what its own resolver returned (:ref:`adr-026-dns-rebinding-defence`),
but there was no supported way to hand it addresses. A spike built
``new VaultHttpClient(..., secureHttpClientFactory: new SecureHttpClientFactory($resolver))``
with a resolver returning the consumer's addresses. That works, but it rests on
two things nr-vault never promised: :php:`DnsResolverInterface` is not an
extension point, and outside code implementing it is unsupported
(:ref:`api-extension-points`); and the resolver is also the source of the
5-second memo and the ``allowed_hosts`` gate's lookup, so a per-request
implementation couples the consumer to internals.

Decision
========

Add :php:`PinnedAddressHttpClientInterface` with one method,
``withPinnedAddresses(string $host, array $addresses): static``, implemented by
:php:`VaultHttpClient`, and the same method on :php:`SecureHttpClientFactory`
returning a pinned copy of the factory.

*   The pin lives in the factory. For the pinned host, its addresses are the
    resolver's answer: the resolver is not asked, the answer is not memoised,
    and a memo entry the original factory held for that host is dropped.
    Every other host resolves as before.
*   The addresses pass the same range check as a resolver answer. A private,
    loopback or metadata address is refused unless the host has a literal
    ``allowed_hosts`` entry, both at the ``allowed_hosts`` gate and in the
    ``ssrf-dns-pin`` middleware. The caller's check does not replace nr-vault's.
*   A transfer that cannot honour ``CURLOPT_RESOLVE`` (no ext-curl, or Guzzle's
    ``stream`` option) is refused for a pinned host. On such a transfer the
    transport resolves the name itself, so the promise cannot be kept. For other
    hosts that path is unchanged.
*   The client clone is built as :php:`withTimeout()` builds its clone: neither
    the inner client nor the cancellable transport is forwarded, because both
    came from the unpinned factory. A client passed to the constructor is
    therefore replaced, and the clone supports cancellation and streaming
    wherever ``curl_multi_*`` exists. The OAuth token manager is forwarded for
    its token cache; the token request stays on the unpinned client.
*   The method takes only scalars. No resolver, transport or option array
    crosses the boundary, so the rule of :ref:`adr-037-cancellable-outbound-send`
    that nothing hands out a credential-bearing transport is untouched.
*   Input is checked when the clone is made: the host must be a host name
    (an IP literal needs no pin), every address a bare IP address, and the list
    must not be empty. Codes ``1794317201`` to ``1794317203``.

Redirects and retries are not new behaviour, but the consumer relies on them,
so they are now tested on all three sends of a pinned client: a ``3xx`` is
returned and not followed even when the platform sets ``allow_redirects``, and
a ``503`` is sent once.

Limit
=====

Behind a forward proxy (``$GLOBALS['TYPO3_CONF_VARS']['HTTP']['proxy']`` or
``HTTPS_PROXY``) curl connects to the proxy, and the proxy resolves the origin.
The pin then chooses nothing. This is true of every nr-vault pin, not only of
this one; the operator's proxy is the egress point the installation trusts.
``behindAProxyThePinDoesNotChooseTheAddress()`` pins the limit: with a pin to an
address nothing listens on, the origin is still reached through the proxy.

Consequences
============

*   A consumer gets the vault credential, the audit row, cancellation and
    streaming on a send whose destination it checked, through
    :php:`VaultServiceInterface::http()` and an ``instanceof`` check.
*   A consumer with a private destination still needs the operator's literal
    ``allowed_hosts`` entry.
*   The interface is a calling interface: a minor release may add methods to it.

Tests
=====

.. list-table::
   :header-rows: 1

   * - Property
     - Tests
   * - The pinned host connects to the given addresses only, on all three sends
     - ``StreamingSendTest::aPinnedNameReachesTheServerWithTheCredential()``,
       ``…::aPinToAnotherAddressFailsInsteadOfResolvingTheName()``,
       ``SecureHttpClientFactoryPinnedAddressesTest::thePinnedHostIsPinnedToTheGivenAddressesAndNeverResolved()``
   * - The pin survives the other with-methods, in either order
     - ``StreamingSendTest::thePinSurvivesTheOtherWithMethodsInEitherOrder()``,
       ``VaultHttpClientTest::withPinnedAddressesReplacesASuppliedClientAndLeavesTheOriginalAlone()``
   * - Pinned addresses pass the range check
     - ``StreamingSendTest::aPinnedPrivateAddressNeedsALiteralAllowedHostsEntry()``,
       ``SecureHttpClientFactoryPinnedAddressesTest::aPinnedPrivateAddressIsRefusedLikeAResolvedOne()``,
       ``…::aPinnedPrivateAddressPassesWithALiteralAllowedHostsEntry()``,
       ``VaultHttpClientTest::aPinnedPrivateAddressIsRefusedByTheHostGateBeforeAnySecretIsRead()``
   * - A transfer that cannot pin is refused
     - ``SecureHttpClientFactoryPinnedAddressesTest::aStreamedTransferToAPinnedHostIsRefused()``
   * - A memoised answer does not outrank the pin
     - ``SecureHttpClientFactoryPinnedAddressesTest::anAnswerTheOriginalFactoryMemoisedDoesNotOutrankThePin()``
   * - Redirects are returned, not followed
     - ``StreamingSendTest::aPinnedClientReturnsARedirectWithoutFollowingIt()``
   * - Nothing is retried
     - ``StreamingSendTest::aPinnedClientSendsAFailedRequestExactlyOnce()``
   * - The stream is delivered while it arrives
     - ``StreamingSendTest::aPinnedStreamDeliversTheFirstLineBeforeTheServerHasFinished()``

Each of these was seen to fail against a mutation of the guarantee it names:
the pin ignored by the resolver lookup, the clone forwarding the unpinned inner
client, the refusal of an unpinnable transfer removed, the memo entry kept,
``allow_redirects => false`` dropped from the cancellable and the streaming send,
the blocking send switched to Guzzle's ``send()``, a retry middleware pushed onto
both transports, and ``sendStreaming()`` routed to the blocking send.

References
==========

*   :ref:`adr-026-dns-rebinding-defence`
*   :ref:`adr-037-cancellable-outbound-send`
*   :ref:`adr-039-streaming-send-keeps-the-dns-pin`
*   :ref:`api-http-pinned-addresses`
