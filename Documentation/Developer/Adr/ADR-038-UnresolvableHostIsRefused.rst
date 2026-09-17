.. include:: /Includes.rst.txt

.. _adr-038-unresolvable-host-is-refused:

=================================================================
ADR-038: A host we cannot resolve is refused, not handed to curl
=================================================================

.. contents:: Table of contents
   :local:
   :depth: 2

Status
======

Accepted

Date
====

2026-09-17

Context
=======

:ref:`adr-026-dns-rebinding-defence` closed the TOCTOU race between the SSRF check and the connect by pinning the checked address through ``CURLOPT_RESOLVE``.
It left one answer unhandled, and said so in step 6: "Unresolvable hosts pass through without a pin."

The reasoning behind that sentence was that a name nobody can resolve cannot be connected to either, so the transport would fail with its usual connection error and nothing would be reached.
Both halves of the SSRF guard were built on it.
``isHostAllowed()`` ran its rebinding check through ``resolvesToDangerousIp()``, which iterates the resolver's answer and therefore returns ``false`` for an empty one, and then fell through to default-allow.
``buildResolveEntries()`` returned the empty list for an empty answer, and the middleware read that as "nothing to pin" and called the handler.

The reasoning does not hold, because the two resolvers are not the same resolver.
``DefaultDnsResolver`` wraps ``dns_get_record()``, which speaks DNS and nothing else.
curl resolves through ``getaddrinfo()``, which consults ``/etc/hosts``, every NSS module the machine has configured, and mDNS.
A name that is invisible to the first is routinely reachable through the second, and a container host, a ``search`` domain or a wildcard NSS module makes that the ordinary case rather than an exotic one.

Measured on one machine, with a server bound to loopback only and no proxy configured:

..  code-block:: none

    dns_get_record("vault-review.localhost", A | AAAA)  ->  false
    curl http://vault-review.localhost/                 ->  200, remote_ip=127.0.0.1

So the empty answer never meant "unreachable".
It meant "no address was checked", and the code treated the two as the same thing.
The consequence is a fail-open path: for any host not covered by a restricting allowlist, a resolver answer we cannot use let the request through unpinned, and the transport then resolved the name itself and connected to whatever came back — which is exactly the address nobody range-checked.

Installing ext-curl does not help: the curl path passes the empty answer on just as the stream path does.
Blocking ``localhost`` by name does not help either, because the defect is the disagreement between the two resolvers, not any one name.

Decision
========

An answer that yields no usable address refuses the request, for any host that is not listed literally in ``allowed_hosts``.

Concretely:

1.  ``isHostAllowed()`` requires a hostname to resolve to at least one well-formed address, none of them in a dangerous range.
    ``resolvesToDangerousIp()`` is replaced by ``resolvesToVerifiedSafeAddress()``, which answers the question the gate actually needs: is there a checked address here.
2.  ``buildResolveEntries()`` throws instead of returning the empty list when a name yields no usable address.
    It receives the ``RequestInterface`` and raises the ``RequestException`` itself, which also removes the ``null`` sentinel the middleware used to translate.
3.  The two rejections carry different messages.
    A disallowed range and an address that could not be established at all are the same event to the code and opposite events to an operator: a typo in a configured URL produces the second one, and must not be logged as a rebinding attempt.
4.  An answer whose records are not parseable IPs counts as no answer.
    ``DnsResolverInterface`` is a public seam, and a value that cannot be range-checked cannot be pinned either.
5.  A literal ``allowed_hosts`` entry keeps the old behaviour — the transport's error path becomes the operator's business, as it already is for a private address they opted into.
    A wildcard entry does not: wildcards have never bypassed the IP guard, and letting them bypass the address requirement would make the guard optional for anyone who owns a zone.

A failed resolution is still never memoised.
An empty answer now rejects, so freezing one for the memo TTL would turn a single lost packet into a minute of refused requests.

Consequences
============

Positive
--------

-  The fail-open path is closed in both halves of the guard, and closed at the point where no verified address exists rather than at a list of known-bad names.
-  The gate and the middleware now answer the same question, so a consumer that asks ``isHostAllowed()`` first and sends later cannot get a "yes" the middleware then overrules.
-  The rejection is provable rather than assumed: the regression tests assert that the transport is not reached, not merely that an exception was raised. An exception thrown after the request went out would satisfy a message assertion and leak the request anyway.

Negative
--------

-  **This is a behaviour change for installations whose hosts are not in DNS.**
   A vault or webhook endpoint served by ``/etc/hosts``, by an NSS module, or by a container runtime's embedded resolver used to work without configuration and is now refused.
   The fix is one literal entry in ``$GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts']``, which is the same opt-in the guard already documents for private addresses, and the rejection message names it.
-  A transient DNS failure now refuses the request instead of letting the transport report a connection error. The observable difference is which component reports the failure and in which words; both end with no request delivered.

Verified
========

-  Probed in position, by making each half fail open again and re-running:
   restoring the pass-through for an empty answer fails the four tests that assert the refusal, and making ``resolvesToVerifiedSafeAddress()`` return ``true`` unconditionally fails the two gate tests.
-  The middleware tests assert the transport was not reached — for a first request and for a redirect hop, which never passes the caller-side gate at all.
-  The allowlisted cases assert the opposite: a literal entry still reaches the transport with no pin.

References
==========

-  Amends :ref:`adr-026-dns-rebinding-defence` step 6, whose closing sentence no longer describes the behaviour.
-  Related: :ref:`adr-010-secure-outbound`
